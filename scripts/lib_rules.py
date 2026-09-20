"""
lib_rules.py —— capa 风格的能力规则引擎

设计目标：把「这段代码在干什么」从**人肉读反汇编**变成**规则匹配**。

参考 mandiant/capa 的规则格式（Apache-2.0），但**不是移植**：capa 依赖
PyYAML / vivisect / 大型特征提取框架，而本项目受「零第三方依赖」硬约束，
所以这里：

  1. 自己写一个**极简 YAML 子集解析器**（只够读规则文件，不支持锚点/多行
     折叠/流式集合等我们不用的语法）。写它的代价远小于引入 PyYAML。
  2. 特征提取复用我们已有的反汇编与语义层（lib_disasm / lib_code /
     lib_semantics），不另起一套。
  3. 规则文件是纯数据（YAML），可**不依赖本项目**单独编辑与分发；内置一份
     常用行为规则库，也支持 `--rules 目录` 加载第三方规则。

规则格式（与 capa 兼容的子集）：

    rule:
      meta:
        name: 创建进程
        namespace: host-interaction/process/create
        scope: function            # instruction | basic block | function | file
        att_ck:
          - Execution::Command and Scripting Interpreter [T1059]
        description: 创建新进程
      features:
        - or:
          - api: kernel32.CreateProcess
          - api: kernel32.WinExec

判定语义要点（这些是 capa 的实际行为，别想当然）：

  * `features` 是一个**逻辑树**：`and` / `or` / `not` / `optional` 作为
    key，值是该节点的子节点列表；叶子是 `特征类型: 值`。
  * `optional:` 在 `and` 语境下表示「匹配到更好，但不匹配也不算失败」，
    用于提高置信度而不破坏命中。
  * `not` 只作用于其子节点整体。
  * 同一规则内**同名特征会去重**（`api: A` 写两次等价于一次）。
  * `scope` 决定特征从哪个粒度抽取：
      instruction   —— 单条指令上判定（寄存器/立即数/助记符级）
      basic block   —— 基本块内（用来做「同一小块里同时出现 X 和 Y」的局部约束）
      function      —— 函数内（默认，最常用）
      file          —— 全文件（用于结构/节名/导入表这类整体特征）

设计原则（和整个项目一致）：**认不出来就说认不出来**。
规则有自己的命名空间、作者、出处，命中结果带 `rule` / `scope` / 证据位置，
不把「规则命中」包装成「确定结论」。
"""

from __future__ import annotations

import os
import re

# ================================================================ 极简 YAML

class YamlError(ValueError):
    """规则文件语法错误。带行号，方便定位。"""


def _strip_comment(line: str) -> str:
    """
    去掉行尾注释，但保留引号内的 #。

    快速路径（重要）：绝大多数 YAML 行既没有引号也没有 `#`。若不做判断就
    逐字符走 Python 循环，那么一行 4 MB 的纯缩进（深嵌套畸形规则的产物）
    要花约 1 秒，而**成本正比于字节数、与是否有结构无关**——也就是说
    攻击者只要交一个几十 MB 的纯空格文件，就能在真正做结构校验之前
    先耗掉几十秒 CPU。这里先用 C 实现的 find 判断，无引号无注释直接返回。
    """
    # 没有引号、也没有 `#`：注释剥离是恒等变换，无需逐字符走一遍。
    # （`'` 和 `"` 都不在串里，说明不存在引号内的 `#`）
    if "#" not in line and "'" not in line and '"' not in line:
        return line
    out = []
    q = None
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        else:
            if c in "\"'":
                q = c
                out.append(c)
            elif c == "#" and (not out or out[-1] in " \t"):
                break
            else:
                out.append(c)
        i += 1
    return "".join(out)


def _scalar(tok: str):
    """把 YAML 标量转成 Python 值。只支持我们需要的类型。"""
    t = tok.strip()
    if not t:
        return ""
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    # 十进制 / 0x 十六进制 / 负数。带下划线的也认（1_000）。
    m = re.fullmatch(r"[-+]?(?:0[xX][0-9a-fA-F_]+|\d[\d_]*)", t)
    if m:
        try:
            return int(t.replace("_", ""), 0)
        except ValueError:  # lint:ok 正则已判定格式，失败只能是超长数字等极端情况，退回字符串是正确的
            pass
    m = re.fullmatch(r"[-+]?(?:\d[\d_]*\.\d*|\d*\.\d+)(?:[eE][-+]?\d+)?", t)
    if m:
        try:
            return float(t.replace("_", ""))
        except ValueError:  # lint:ok 同上：正则已判定格式，失败即退回字符串，不是吞异常
            pass
    return t


def _is_keyed(rest: str) -> bool:
    """
    判断列表项 `- xxx` 里的 xxx 是不是 `key: value` 形式。

    关键陷阱：C++ 作用域 `::` 和 URL 里的 `://` 不是键分隔符。
    `- Execution::Foo` 里的冒号后面紧跟 `:`，说明它是 `::`，
    整条是标量而非映射。误判会把标量拆成字典，静默产出错结构。
    """
    if rest.startswith(("http://", "https://", "ftp://")):
        return False
    i = rest.find(":")
    if i <= 0:
        return False
    # `::` → 不是分隔符
    if i + 1 < len(rest) and rest[i + 1] == ":":
        return False
    key = rest[:i].strip()
    return bool(re.fullmatch(r"[A-Za-z_][\w./\- ]*", key))


def _indent_of(line: str) -> int:
    n = 0
    for c in line:
        if c == " ":
            n += 1
        elif c == "\t":
            # YAML 不允许 tab 缩进；宽容处理成 1 列，但别静默错位
            n += 1
        else:
            break
    return n


# 单个 YAML 文档的体积上限（字节）。正常规则文件是几十 KB 量级，
# 32 MB 已是三个数量级的余量，足以容纳任何真实规则库并挡住畸形输入。
_YAML_MAX_BYTES = 32 * 1024 * 1024


def yaml_load(text: str):
    """
    解析 YAML 的一个实用子集。

    支持：
      * 嵌套映射（缩进）
      * 列表（`- ` 项），列表项可以是标量、映射、或单键映射
      * 标量：字符串（可带引号）、整数（10/16 进制）、浮点、bool、null
      * 行尾注释、空行

    不支持（遇到会给出明确报错，而不是静默产出错结构）：
      * 锚点/别名（& *）、多文档（--- 文档分隔我们只用作列表元素）
      * 多行折叠块（| >）、流式集合（{a: b} / [a, b]）

    这条「不支持就报错」的规矩很重要：静默降级会让规则看起来加载成功、
    实际少了一半特征，最后表现为「规则不命中」——极难排查。
    """
    # 【解析前体积上限】
    # 解析耗时正比于**字节数**（缩进是空白，也要逐字符扫）。规则文件来自
    # 用户目录，一个几十 MB 的畸形文件会让"加载规则"这一步长时间占满 CPU。
    # 注意：这里不能只按行数限制——攻击者可以用极少的行、极深的缩进凑出
    # 巨大体积。所以按字符数先卡一道，给出可读错误而不是慢慢磨。
    if len(text) > _YAML_MAX_BYTES:
        raise YamlError(
            "规则文件体积 %d 字节，超过上限 %d 字节（约 %.1f MB）—— 疑似畸形文件"
            % (len(text), _YAML_MAX_BYTES, _YAML_MAX_BYTES / 1048576.0))

    lines = []
    for ln, raw in enumerate(text.splitlines(), 1):
        s = _strip_comment(raw).rstrip()
        if not s.strip():
            continue
        if s.strip() in ("---", "..."):
            continue
        if s.lstrip().startswith("%"):     # 指令（%YAML 1.2 之类）
            continue
        body = s.strip()
        if body.startswith("&") or body.startswith("*") or body.startswith("<<"):
            raise YamlError("第 %d 行：不支持锚点/别名（%s）" % (ln, body[:20]))
        if body[0] in "|>" and (len(body) == 1 or body[1] in " \t-+"):
            raise YamlError("第 %d 行：不支持多行块标量（%s）" % (ln, body[:20]))
        if body[0] in "{[":
            raise YamlError("第 %d 行：不支持流式集合（%s）" % (ln, body[:20]))
        # 值位置上的锚点/别名/流式集合也要拦（`a: &x b` / `a: *x` / `a: {..}`）
        _v = body.partition(":")[2].strip() if ":" in body else ""
        if _v:
            if _v.startswith("&") or _v.startswith("*") or _v.startswith("<<"):
                raise YamlError("第 %d 行：不支持锚点/别名（%s）" % (ln, _v[:20]))
            if _v[0] in "{[":
                raise YamlError("第 %d 行：不支持流式集合（%s）" % (ln, _v[:20]))
            if _v[0] in "|>" and (len(_v) == 1 or _v[1] in " \t-+"):
                raise YamlError("第 %d 行：不支持多行块标量（%s）" % (ln, _v[:20]))
        lines.append((ln, _indent_of(s), s.strip()))

    if not lines:
        return None

    pos = 0
    # 【YAML 解析深度上限】
    # parse_block / parse_list / parse_map 三个函数互相递归。规则文件来自
    # 用户目录（rules/*.yml），一个刻意深缩进的畸形文件就能把调用栈打爆。
    # 实测 depth=2000 尚可通过，但那是靠 Python 默认上限兜着——一旦宿主
    # 调高了 setrecursionlimit，或缩进更省（例如用 1 空格），就会先崩。
    # 这里显式设限：超过 _YAML_MAX_DEPTH 层直接给可读错误，不靠解释器兜底。
    _YAML_MAX_DEPTH = 200
    depth_state = {"n": 0}

    def next_indent(after: int) -> int:
        """返回下一个有效行的缩进（必须 > after）。没有则返回 after+1。"""
        if pos < len(lines):
            return lines[pos][1]
        return after + 1

    def parse_block(indent):
        """解析同一缩进层级的映射或列表。indent 是该层级的实际缩进。"""
        nonlocal pos
        if pos >= len(lines):
            return None
        depth_state["n"] += 1
        try:
            if depth_state["n"] > _YAML_MAX_DEPTH:
                raise YamlError(
                    "嵌套层级超过 %d 层（第 %d 行）—— 规则文件疑似畸形"
                    % (_YAML_MAX_DEPTH, lines[pos][0]))
            ln, ind, body = lines[pos]
            if ind < indent:
                return None
            # 判定这一层是列表还是映射
            if body == "-" or body.startswith("- "):
                return parse_list(ind)
            return parse_map(ind)
        finally:
            depth_state["n"] -= 1

    def parse_list(indent):
        nonlocal pos
        out = []
        while pos < len(lines):
            ln, ind, body = lines[pos]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(
                    "第 %d 行：列表项缩进比同级项更深（同级=%d，本行=%d）"
                    % (ln, indent, ind))
            if not (body == "-" or body.startswith("- ")):
                break
            rest = body[2:].strip() if body.startswith("- ") else ""
            pos += 1
            if not rest:
                # `-` 后面换行，内容在更深一层
                child = parse_block(next_indent(indent))
                out.append(child)
                continue
            # `- key: value` 形式：先起一个映射，后续更深的同层映射项
            # （以及该 key 的更深值）都要收进来。
            #
            # 注意：必须确认冒号**后面**是「值」而不是 C++ 的 `::`。像
            # `- api: Kernel32::CreateFile` 或独立的 `- Execution::Foo`
            # 里的 `::` 不是键分隔符，误判会把整条标量拆成映射（真 bug）。
            if _is_keyed(rest):
                key, _, val = rest.partition(":")
                k = key.strip()
                if re.fullmatch(r"[A-Za-z_][\w./\- ]*", k):
                    kk = _scalar(k)
                    m = {}
                    if val.strip():
                        m[kk] = _scalar(val)
                    else:
                        # `- or:` 后面跟更深一层的内容，那是这个 key 的值
                        m[kk] = parse_block(next_indent(indent + 1))
                    # 继续收拢同层（缩进 > 列表缩进）的其它映射键
                    deep = next_indent(indent + 1)
                    while pos < len(lines):
                        ln2, ind2, body2 = lines[pos]
                        if ind2 <= indent:
                            break
                        if body2.startswith("- ") or body2 == "-":
                            break
                        if ind2 < deep:
                            break
                        deep = ind2
                        k2, sep2, v2 = body2.partition(":")
                        if not sep2:
                            raise YamlError("第 %d 行：期望 key: value" % ln2)
                        k3 = _scalar(k2)
                        pos += 1
                        if v2.strip():
                            m[k3] = _scalar(v2)
                        else:
                            m[k3] = parse_block(next_indent(ind2 + 1))
                    out.append(m)
                    continue
            out.append(_scalar(rest))
        return out

    def parse_map(indent):
        nonlocal pos
        out = {}
        while pos < len(lines):
            ln, ind, body = lines[pos]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(
                    "第 %d 行：映射项缩进比同级项更深（同级=%d，本行=%d）"
                    % (ln, indent, ind))
            if body.startswith("- ") or body == "-":
                break
            # 同 _is_keyed：`Execution::Foo` 这类不是 `key: value`
            key, sep, val = body.partition(":")
            if not sep or (val.startswith(":") and
                           not re.fullmatch(r"[A-Za-z_][\w./\- ]*", key.strip())):
                raise YamlError("第 %d 行：缺少冒号（%s）" % (ln, body[:30]))
            if re.fullmatch(r"[A-Za-z_][\w./\- ]*", key.strip()) and \
                    key.strip().startswith(("&", "*")):
                raise YamlError("第 %d 行：不支持锚点/别名" % ln)
            k = _scalar(key.strip())
            pos += 1
            if val.strip():
                out[k] = _scalar(val)
            else:
                out[k] = parse_block(next_indent(indent))
        return out

    return parse_block(lines[0][1])


def yaml_parse_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml_load(f.read())


def split_documents(text: str) -> list[str]:
    """
    按 YAML 文档分隔符 `---` 切分多文档。

    规则库习惯把一个主题的多条规则放进同一个文件、用 `---` 分隔。
    如果只当单文档解析，**只有第一条会被读到，其余静默丢失** —— 表现
    为"规则没命中"，极难排查。所以这里显式支持多文档。

    `---` 必须在行首（允许前导空格）。带内容的行内 `---` 不切分。
    """
    docs = []
    cur: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if any(x.strip() for x in cur):
                docs.append("\n".join(cur))
            cur = []
            continue
        cur.append(line)
    if any(x.strip() for x in cur):
        docs.append("\n".join(cur))
    return docs if docs else [text]


def yaml_load_all_file(path: str) -> list:
    """解析一个文件里的全部 YAML 文档。"""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    out = []
    for chunk in split_documents(text):
        d = yaml_load(chunk)
        if d is not None:
            out.append(d)
    return out


# ================================================================ 规则模型

SCOPES = ("instruction", "basic block", "function", "file")

# 叶子特征类型。与 capa 同名的尽量同名，方便规则互通。
#
#   api            调用的 API（内部会做 dll 名剥离 + 大小写不敏感）
#   number         立即数 / 常量（支持 0x 与十进制，支持 = 语法糖）
#   string         字符串字面量（子串匹配）
#   substring      字符串子串（与 string 同义，capa 里 string/substring 有区别，
#                  我们统一成子串语义并在文档里说明）
#   mnemonic       助记符
#   characteristic 行为特征（nzxor / memcpy / loop / call / ...）
#   section        节名
#   import         导入表里的符号
#   export         导出表里的符号
#   function-name  已知函数名（符号还原后）
#   bytes          字节序列（支持 `..` 通配）
#   tag            语义标签（来自 lib_semantics 的标签体系）
#   os             目标操作系统
#   arch           架构
#   format         文件格式
#   match          引用另一条规则（规则依赖）
LEAF_TYPES = {
    "api", "number", "string", "substring", "mnemonic", "characteristic",
    "section", "import", "export", "function-name", "bytes", "tag",
    "os", "arch", "format", "match",
}

LOGIC_KEYS = {"and", "or", "not", "optional"}

# 引擎**实际可能产出**的 characteristic 取值全集。
#
# 为什么要把这张表写出来：规则里写 `characteristic: xxx` 时，如果 xxx 拼错了
# （例如 rc4-ksa vs rc4_ksa），匹配会永远为假，而且**不报任何错** ——
# 规则静默失效、看起来像"没命中"。这正是本项目最忌讳的失败模式。
# 有了这张表，load_rules() 就能在加载期直接把这类拼写问题报出来。
#
# 新增 characteristic 的流程（两边必须同时改，否则就是死规则）：
#   1) 在这里登记名字；
#   2) 在 build_features() 里真的产出它；
#   3) 跑 selftest 的「规则引用的 characteristic 均可产出」用例。
ENGINE_CHARACTERISTICS = frozenset((
    "debug",            # 语义层标签「反调试」提升而来（强信号，非"弱"）
    "peb-access",       # 手工读 PEB.BeingDebugged（gs:[0x02]）
    "packed",           # 加壳/压缩信号（来自格式层的 packer_signals）
    # 以下来自语义层 summarize_functions 的 features 字段
    "loop",             # 函数内存在回边（features.loop）
    "nzxor",            # 异或密度高，疑似字符串加解密（features.xor_dense）
    # 以下来自 lib_libscan.CONST_SIGS 的 key，是"能签名就不猜"的高置信证据
    "aes_sbox",         # AES 正向 S-box
    "aes_inv_sbox",     # AES 逆 S-box
    "rc4_ksa",          # RC4 KSA 初始化序列 0x00..0xFF
    "crc32_table",      # CRC32 表
    "md5_sha1_init",    # MD5/SHA-1 初始常量
    "sha256_init",      # SHA-256 初始常量
    "sha512_init",      # SHA-512 初始常量
    "base64",           # Base64 字母表
    "base32",           # Base32 字母表
))


class RuleError(ValueError):
    pass


class Rule:
    __slots__ = ("name", "namespace", "scope", "authors", "description",
                 "att_ck", "references", "features", "source", "raw")

    def __init__(self, d: dict, source: str = ""):
        if not isinstance(d, dict) or "rule" not in d:
            raise RuleError("规则文件顶层必须是 `rule:`")
        r = d["rule"]
        if not isinstance(r, dict):
            raise RuleError("`rule:` 下面必须是映射")
        meta = r.get("meta") or {}
        if not isinstance(meta, dict):
            raise RuleError("`meta:` 必须是映射")
        feats = r.get("features")
        if feats is None:
            raise RuleError("缺少 `features:`")
        self.name = str(meta.get("name") or "").strip()
        if not self.name:
            raise RuleError("缺少 `meta.name`")
        self.namespace = str(meta.get("namespace") or "").strip()
        scope = str(meta.get("scope") or "function").strip().lower()
        if scope not in SCOPES:
            raise RuleError("未知 scope：%r（可选 %s）" % (scope, "/".join(SCOPES)))
        self.scope = scope
        a = meta.get("authors") or meta.get("author")
        if isinstance(a, str):
            a = [a]
        self.authors = [str(x) for x in (a or [])]
        self.description = str(meta.get("description") or "").strip()
        ac = meta.get("att_ck") or meta.get("att&ck") or meta.get("attack")
        if isinstance(ac, str):
            ac = [ac]
        self.att_ck = [str(x) for x in (ac or [])]
        rf = meta.get("references") or []
        if isinstance(rf, str):
            rf = [rf]
        self.references = [str(x) for x in rf]
        self.features = feats
        self.source = source
        self.raw = r
        self._validate(feats)

    # ---------------------------------------------------------- 校验
    def _validate(self, node, depth=0):
        if depth > 32:
            raise RuleError("特征树过深（>32 层），疑似写错缩进")
        if isinstance(node, list):
            # 裸列表：隐式 and（capa 里 features 列表本身就是 and 语义）
            for x in node:
                self._validate(x, depth + 1)
            return
        if not isinstance(node, dict):
            raise RuleError("特征节点必须是映射或列表，得到 %s" % type(node).__name__)
        if not node:
            raise RuleError("空的特征节点")
        for k, v in node.items():
            if k in LOGIC_KEYS:
                if k == "not":
                    self._validate(v if isinstance(v, list) else [v], depth + 1)
                else:
                    if not isinstance(v, list):
                        raise RuleError("`%s:` 的值必须是列表" % k)
                    self._validate(v, depth + 1)
            elif k in LEAF_TYPES:
                if isinstance(v, (dict, list)) and k != "bytes":
                    raise RuleError("叶子特征 `%s:` 的值必须是标量" % k)
                # characteristic 的值必须落在引擎真能产出的集合里。
                # 拼错一个字母（rc4-ksa vs rc4_ksa）会让这条规则**永远不命中且不报错**，
                # 属于最危险的静默失效，所以放在加载期就拦下来。
                if k == "characteristic":
                    for one in (v if isinstance(v, list) else [v]):
                        if str(one) not in ENGINE_CHARACTERISTICS:
                            raise RuleError(
                                "未知 characteristic %r（引擎可产出的有：%s）"
                                % (one, ", ".join(sorted(ENGINE_CHARACTERISTICS))))
            else:
                raise RuleError(
                    "未知特征类型 `%s`（支持：%s）"
                    % (k, ", ".join(sorted(LEAF_TYPES))))

    def to_dict(self) -> dict:
        return {
            "name": self.name, "namespace": self.namespace, "scope": self.scope,
            "authors": self.authors, "description": self.description,
            "att_ck": self.att_ck, "references": self.references,
            "source": os.path.basename(self.source) if self.source else "",
        }


def load_rules(path: str) -> tuple[list[Rule], list[str]]:
    """
    从文件或目录加载规则。返回 (规则列表, 错误列表)。

    错误不抛异常而是收集起来：规则库里一条写坏不该让整个分析失败，
    但**必须报出来**（否则表现为「静默少匹配」，最难查）。
    """
    rules: list[Rule] = []
    errs: list[str] = []
    files: list[str] = []
    if os.path.isdir(path):
        for root, _dirs, fns in os.walk(path):
            for fn in sorted(fns):
                if fn.lower().endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, fn))
    elif os.path.isfile(path):
        files.append(path)
    else:
        return [], ["规则路径不存在：%s" % path]

    for fp in files:
        try:
            docs = yaml_load_all_file(fp)
        except YamlError as e:
            errs.append("%s: YAML 语法错误：%s" % (os.path.basename(fp), e))
            continue
        except Exception as e:
            errs.append("%s: %s: %s" % (os.path.basename(fp),
                                        type(e).__name__, e))
            continue
        for d in docs:
            if not isinstance(d, dict):
                errs.append("%s: 文档顶层不是映射，已跳过" % os.path.basename(fp))
                continue
            if "rule" not in d:
                # 容错：顶层直接是 meta/features
                if "features" in d:
                    d = {"rule": d}
                else:
                    errs.append("%s: 缺少 `rule:` 块" % os.path.basename(fp))
                    continue
            try:
                rules.append(Rule(d, fp))
            except RuleError as e:
                errs.append("%s: %s" % (os.path.basename(fp), e))
        if not rules or rules[-1].source != fp:
            # 该文件一条规则都没产出 —— 必须报出来，否则表现为"静默少匹配"
            if not any(r.source == fp for r in rules):
                errs.append("%s: 未产出任何规则" % os.path.basename(fp))

    # 重名检测：重名会让依赖引用产生歧义
    seen = {}
    for r in rules:
        if r.name in seen:
            errs.append("规则重名：%r（%s 与 %s）"
                        % (r.name, seen[r.name], os.path.basename(r.source)))
        seen[r.name] = os.path.basename(r.source)
    return rules, errs


# ================================================================ 特征提取

def _norm_api(s: str) -> tuple[str, str]:
    """
    归一化 API 名 -> (dll, 函数名)，两者都小写、不带扩展名。

    接受的写法（都归一化成同一个二元组）：
        'kernel32.CreateProcess' -> ('kernel32', 'createprocess')
        'kernel32!CreateProcess' -> ('kernel32', 'createprocess')
        'KERNEL32.dll!CreateProcess' -> ('kernel32', 'createprocess')
        'CreateProcess' -> ('', 'createprocess')

    【已修 bug】原实现只按 '.' 切分，完全不认 '!' 分隔符。
    但语义层的 iat_map 产出的恰恰是 'kernel32!Sleep' 这种形态
    （见 lib_disasm.resolve_iat 与 lib_semantics.split_api），
    于是每个 api 特征都被存成 '|kernel32!sleep'，
    而规则侧产出的是 'kernel32|sleep' —— 两边永远对不上，
    所有 api: 规则 100% 漏报，且不报任何错。
    这一条 bug 是「全部 20 条规则零命中」的直接原因。
    """
    s = str(s).strip()
    # 【注意顺序】必须先把 '!' 前面的模块名尾巴（.dll/.sys）去掉，再把 '!' 换成 '.'。
    # 反过来做会得到 'KERNEL32.dll.CreateProcess'，此时 .dll 已经不在结尾，
    # 末尾锚定的正则匹配不到，结果 dll 被切成 'kernel32.dll' 而规则侧给的是
    # 'kernel32' —— 又是一次静默漏配。这个顺序不能改。
    s = re.sub(r"(?i)^([a-z0-9_\-]+)\.(?:dll|sys|drv|ocx)!", r"\1!", s)
    if "!" in s:
        s = s.replace("!", ".")
    # 兜底：形如 'kernel32.dll'（没有函数名）时也去掉扩展名
    s = re.sub(r"(?i)\.(dll|sys|drv|ocx)$", "", s)
    if "." in s:
        dll, _, fn = s.rpartition(".")
        return (dll.strip().lower(), fn.strip().lower())
    return ("", s.lower())


def build_features(path: str, ident: dict, idx, funcs: list[dict],
                   iat_map: dict[int, str] | None = None,
                   sem: dict | None = None) -> dict:
    """
    从已解析的目标里抽取「文件级 + 函数级」两套特征。

    返回 {file: {...}, functions: {vma: {特征类别: set(...)}}, errors: [...]}。
    函数级特征按 capa 的粒度组织，instruction / basic block 两级在
    匹配阶段按需下钻（避免把所有指令都展开成集合，内存会爆）。
    errors 里是特征抽取期间的非致命失败（如字符串扫描挂了）——
    调用方必须把它报给用户：抽不到特征和规则没命中，结果看起来是一样的。
    """
    iat_map = iat_map or {}
    det = ident.get("detail") or {}
    # 特征抽取期间的非致命错误。必须一路带出去给调用方看 ——
    # 抽不到特征和"没命中规则"在结果上长得一模一样，不区分就无法排障。
    errs_out: list[str] = []

    f_file = {
        "section": set(), "import": set(), "export": set(),
        "string": set(), "function-name": set(),
        "os": set(), "arch": set(), "format": set(),
        "characteristic": set(),
    }
    # 文件级
    fmt = ident.get("format") or ""
    if fmt:
        f_file["format"].add(str(fmt).lower())
    label = str(ident.get("label") or "").lower()
    # 【已修 bug】原先只从 label 里做字符串匹配（"x86" in label 之类），
    # ident 明明有结构化的 arch/bits 字段却不用。label 是人读的展示文案，
    # 随时可能改措辞，拿它当判定依据必然哪天就静默失效。
    # 现在优先读结构字段，label 只作最后兜底。
    raw_arch = str(ident.get("arch") or "").lower()
    bits = ident.get("bits")
    arch = ""
    if raw_arch in ("x86", "i386", "i686"):
        arch = "x86-64" if bits == 64 else "x86"
    elif raw_arch in ("x86-64", "x86_64", "amd64"):
        arch = "x86-64"
    elif raw_arch.startswith("arm"):
        arch = "arm64" if bits == 64 else "arm"
    elif raw_arch in ("aarch64",):
        arch = "arm64"
    elif raw_arch and raw_arch != "unknown":
        arch = raw_arch
    elif "x86" in label or "amd64" in label:
        arch = "x86" if "64" not in label else "x86-64"
    elif "arm" in label:
        arch = "arm64" if "64" in label else "arm"
    if arch:
        f_file["arch"].add(arch)
    # os 推断：格式 + 依赖库
    if fmt in ("pe", "mz"):
        f_file["os"].add("windows")
    elif fmt == "elf":
        f_file["os"].add("linux")
    elif fmt == "macho":
        f_file["os"].add("macos")
    elif fmt in ("apk", "dex"):
        f_file["os"].add("android")

    for sec in (det.get("sections") or []):
        nm = sec.get("name")
        if nm:
            f_file["section"].add(str(nm).strip().lower())

    for mod in (det.get("imports") or []):
        dll = str(mod.get("dll") or "")
        for fn in (mod.get("functions") or []):
            n = fn.get("name") if isinstance(fn, dict) else fn
            if n:
                f_file["import"].add("%s|%s" % _norm_api("%s.%s" % (dll, n)))

    for ex in (det.get("exports") or []):
        n = ex if isinstance(ex, str) else ex.get("name")
        if not n:
            continue
        if str(n).startswith("?") or str(n).startswith("_Z"):
            f_file["export"].add("mangled:" + str(n)[:80])
        else:
            f_file["export"].add(str(n).lower())

    for s in (ident.get("strings_sample") or []):
        v = s.get("s") if isinstance(s, dict) else s
        if v:
            f_file["string"].add(str(v))

    # 【已修 bug】identify() 不会填充 strings_sample（那只在 PE 的 Rich/资源路径下偶尔有），
    # 于是文件级 string 特征恒为空，"string: xxx" 类规则静默全不命中。
    # 这里在拿不到时显式补一次字符串扫描。扫描失败**必须**留下痕迹，
    # 否则又会退化成"看起来没命中其实是没抽到特征"的静默失败。
    if not f_file["string"]:
        try:
            from lib_analyze import scan_strings
            res = scan_strings(path, min_len=5, max_items=20000, categorize=False)
            for it in (res or {}).get("items", []):
                v = it.get("value") if isinstance(it, dict) else it
                if v:
                    f_file["string"].add(str(v))
        except Exception as e:                      # 扫描失败不拖垮主流程，但要报出来
            errs_out.append("strings: %s: %s" % (type(e).__name__, e))

    for h in (det.get("packer_signals") or det.get("packer_hits") or []):
        f_file["characteristic"].add("packed")

    # 已知常量表签名（AES S-box / CRC32 表 / RC4 KSA 序列 / Base64 字母表…）。
    # 这些是**能签名就签名**的高置信证据，比用助记符组合去猜算法可靠得多
    # （踩过坑：mnemonic 合取在函数粒度上等于没约束，见 crypto.yml 的误报教训）。
    # 恒等映射：CONST_SIGS 的 key（aes_sbox）直接当作 characteristic 名，
    # 规则里写 `characteristic: aes_sbox` 即可，不做二次命名以免对不上。
    const_hits: list[dict] = []
    try:
        from lib_libscan import scan_const_tables
        const_hits = scan_const_tables(path, ident) or []
        for h in const_hits:
            k = h.get("key") if isinstance(h, dict) else None
            if k:
                f_file["characteristic"].add(str(k))
    except Exception as e:                  # 扫描失败不拖垮主流程，但必须报出来
        errs_out.append("const-sigs: %s: %s" % (type(e).__name__, e))

    # ---------- 函数级 ----------
    per_func: dict[int, dict] = {}
    for f in funcs:
        v = f.get("start_vma")
        try:
            v = int(v, 16) if isinstance(v, str) else int(v)
        except Exception:
            continue
        feats = {
            "api": set(), "number": set(), "string": set(), "mnemonic": set(),
            "characteristic": set(), "tag": set(), "section": set(),
            "function-name": set(), "bytes": set(), "export": set(),
            "import": set(),
        }
        nm = f.get("name") or ""
        if nm:
            feats["function-name"].add(str(nm).lower())
        per_func[v] = feats

    # 语义层：API 调用 + 标签（已经是函数粒度的）
    if isinstance(sem, dict):
        for s in (sem.get("functions") or []):
            v = s.get("start_vma")
            try:
                v = int(v, 16) if isinstance(v, str) else int(v)
            except Exception:  # lint:ok 同上层：单条坏数据跳过
                continue
            feats = per_func.get(v)
            if feats is None:
                continue
            # 【已修 bug】原先这里读 s["apis"]，但 summarize_functions 实际输出的是
            # "api_calls"（元素形如 {"api": "kernel32!Sleep", "count": N}）。
            # 字段名不匹配 → 每个函数都拿不到任何 api 特征 → 所有 api: 规则 100% 漏报，
            # 而且不报错（静默失败，正是本项目最忌讳的那类缺陷）。
            # 下面按真实字段名读取，并保留 "apis" 作为旧字段名的兼容分支。
            for a in (s.get("api_calls") or s.get("apis") or []):
                an = a.get("api") if isinstance(a, dict) else a
                if an:
                    feats["api"].add("%s|%s" % _norm_api(an))
            for t in (s.get("tags") or []):
                feats["tag"].add(str(t))
            # 反调试强信号：把语义层的标签提升成 capa 风格的 characteristic: debug，
            # 规则里就能写 `characteristic: debug` 而不用罗列十几个 API 名。
            # 只认强信号标签「反调试」，「反调试(弱)」是线索不是结论，不提升（不猜）。
            if "反调试" in (s.get("tags") or []):
                feats["characteristic"].add("debug")
            # 语义层的 features.loop / features.xor_dense 提升成 characteristic。
            # 这两个字段本来就在算（summarize_functions 里），但不提升的话
            # 规则里写 `characteristic: loop` 永远是死规则 —— 实测确实漏了。
            sfeat = s.get("features") or {}
            if sfeat.get("loop"):
                feats["characteristic"].add("loop")
            # xor_dense 是「异或指令占比 > 12%」，但这个占比在**短函数**上极不稳定：
            # 实测 notepad.exe 的 sub_140001f98（计时函数，5 条 xor / 约 30 条指令）
            # 也能过线，把计时函数误判成解密例程。
            # 因此这里额外要求异或的**绝对条数**（xor_count ≥ 8）：
            # 真正的字节/字级解密循环异或次数远高于此，而小函数凑不够。
            if sfeat.get("xor_dense") and (sfeat.get("xor_count") or 0) >= 8:
                feats["characteristic"].add("nzxor")
            for r in (s.get("strings") or []):
                feats["string"].add(str(r))

    # 指令级：助记符 / 立即数 / 特征（下钻时现算，这里只做轻量聚合）
    if idx is not None:
        insn_map = getattr(idx, "insn", None) or {}
        # 【已修 bug】原实现在这里为每个函数**线性扫描整个 funcs 列表**找 _offs，
        # 整体是 O(函数数²)。notepad.exe（308 个函数）还看不出来，但换成
        # 静态链接的二进制（几万个函数）就是几亿次比较，直接卡死。
        # 改成先建一次 VMA -> _offs 索引，再线性遍历。
        offs_by_vma: dict[int, list] = {}
        for f in funcs:
            fv = f.get("start_vma")
            try:
                fv = int(fv, 16) if isinstance(fv, str) else int(fv)
            except (TypeError, ValueError):  # lint:ok 建索引时单条坏数据跳过
                continue
            o = f.get("_offs")
            if o:
                offs_by_vma[fv] = o
        for v, feats in per_func.items():
            offs = offs_by_vma.get(v) or []
            for o in offs[:20000]:
                ins = insn_map.get(o)
                if ins is None:
                    continue
                # 【已修 bug】指令对象的助记符字段叫 "mnem"（见 lib_x86.Insn.__slots__），
                # 原先只读 "mnemonic"，于是 feats["mnemonic"] 恒为空集 ——
                # 所有 `mnemonic: xxx` 规则静默失效（实测 mnemonic=0）。
                mn = (getattr(ins, "mnem", None)
                      or getattr(ins, "mnemonic", None))
                if not mn and isinstance(ins, dict):
                    mn = ins.get("mnem") or ins.get("mnemonic")
                if mn:
                    feats["mnemonic"].add(str(mn).lower())
                for imm in _imms_of(ins):
                    feats["number"].add(imm & 0xFFFFFFFFFFFFFFFF)
                # PEB / TEB 手工遍历：反分析里很典型（不调 API，直接读
                # fs:[0x30] / gs:[0x60] 拿 PEB，再读 BeingDebugged）。
                # 这是**强特征**，单凭它配合固定偏移就能定性，见 anti-analysis.yml。
                if _is_peb_access(ins):
                    feats["characteristic"].add("peb-access")
    return {"file": f_file, "functions": per_func, "errors": errs_out}


# PEB 里与**反调试**真正相关的字段偏移。
# 【误报教训】第一版把 0x18 / 0x20 / 0x60 / 0xbc 都算进来，结果 notepad.exe 里
# 一堆函数都被标成 peb-access —— 因为 gs:[0x60] 在 x64 下是**访问 TEB 本身**的标准
# 写法（GetLastError / SEH / 栈探测全都这么写），0x60 是 PEB 指针的偏移，
# 不是"读 BeingDebugged"。这么标等于给全程序打标。
# 真正只服务反调试的是读 BeingDebugged（PEB+0x02）这个 1 字节标志，
# 以及 32 位下经 fs:[0x30] 取 PEB 后跟的 0x02。因此只认 0x2。
PEB_DEBUG_OFFSETS = frozenset((0x2,))


def _is_peb_access(ins) -> bool:
    """
    判断一条指令是否在**手工读取 PEB.BeingDebugged**（反调试的典型手法）。

    要求同时满足：
      1) 内存操作数用到段寄存器 fs/gs（TEB 挂在这里）；
      2) 位移恰好是 PEB 里 BeingDebugged 的偏移 0x02。

    只认 0x02，不认 0x60/0xbc —— 后者是访问 TEB/PEB 指针本身，
    正常代码里遍地都是，拿来当反调试特征必然把整个程序标满。
    保守策略：宁可漏，不可把全程序都判成在反调试。
    """
    ops = getattr(ins, "ops", None)
    if ops is None and isinstance(ins, dict):
        ops = ins.get("ops") or ins.get("operands")
    if not isinstance(ops, str):
        return False
    low = ops.lower()
    if "fs:" not in low and "gs:" not in low:
        return False
    disp = getattr(ins, "disp", None)
    if disp is None and isinstance(ins, dict):
        disp = ins.get("disp")
    return isinstance(disp, int) and disp in PEB_DEBUG_OFFSETS


def _imms_of(ins) -> list[int]:
    """
    取一条指令里的立即数（含内存位移）。

    【已修 bug】原先按 "operands 列表 + op.imm" 的形态去读，
    但 lib_x86.Insn 根本没有 operands 列表：
        __slots__ = (..., "ops", "imm", "disp", ...)
    立即数和位移是**指令自身的标量字段**（imm / disp），ops 只是渲染好的文本。
    字段形态读错 → 一个立即数都取不到 → feats["number"] 恒为空集 →
    所有 `number: 0x...` 规则静默失效（实测 number=0）。
    现在同时兼容「标量字段」与「operands 列表」两种形态。
    """
    out: list[int] = []

    # 形态 1（本项目实际形态）：指令自身的 imm / disp 标量字段
    for attr in ("imm", "disp"):
        v = getattr(ins, attr, None)
        if v is None and isinstance(ins, dict):
            v = ins.get(attr)
        if isinstance(v, int):
            out.append(v)

    # 形态 2（兼容其它后端的 operands 列表）
    ops = getattr(ins, "operands", None)
    if ops is None and isinstance(ins, dict):
        ops = ins.get("operands")
    if isinstance(ops, (list, tuple)):
        for op in ops:
            for attr in ("imm", "disp", "value"):
                v = getattr(op, attr, None)
                if v is None and isinstance(op, dict):
                    v = op.get(attr)
                if isinstance(v, int):
                    out.append(v)
    return out


# ================================================================ 匹配引擎

class _Ctx:
    """一次匹配的上下文：缓存已判定的规则（支持规则依赖）。"""
    __slots__ = ("rules_by_name", "memo", "stack")

    def __init__(self, rules):
        self.rules_by_name = {r.name: r for r in rules}
        self.memo = {}
        self.stack = []


def match_rules(rules: list[Rule], feats: dict, max_calls: int = 200000
                ) -> dict:
    """
    执行全部规则。返回：
      {"hits": [...], "by_namespace": {...}, "att_ck": [...], "errors": [...]}

    每个 hit：
      {rule, namespace, scope, description, att_ck, evidence:[...], location}

    【参数校验】这是公开 API，调用方可能直接传 None（比如规则加载失败后
    把失败值一路传下来）。原实现会在 `_Ctx.__init__` 里抛
    `TypeError: 'NoneType' object is not iterable` —— 信息量为零，
    排查时看不出是"没加载到规则"还是"引擎坏了"。现在显式校验并说明。
    """
    if rules is None:
        return {"hits": [], "by_namespace": {}, "att_ck": [], "errors": [],
                "empty": True, "reason": "rules 为 None（规则未加载）"}
    if not isinstance(rules, (list, tuple)):
        return {"hits": [], "by_namespace": {}, "att_ck": [], "errors": [],
                "empty": True,
                "reason": "rules 类型应为 list，实际是 %s" % type(rules).__name__}
    if not rules:
        return {"hits": [], "by_namespace": {}, "att_ck": [], "errors": [],
                "empty": True, "reason": "rules 为空（没有可执行的规则）"}
    if not isinstance(feats, dict):
        return {"hits": [], "by_namespace": {}, "att_ck": [], "errors": [],
                "empty": True,
                "reason": "feats 类型应为 dict，实际是 %s" % type(feats).__name__}

    hits: list[dict] = []
    by_ns: dict[str, list[str]] = {}
    att: set[str] = set()
    errors: list[str] = []
    ctx = _Ctx(rules)

    # 规则依赖可能成环 —— 用栈检测
    def eval_rule(rule: Rule, scope_key):
        if rule.name in ctx.stack:
            raise RuleError("规则依赖成环：%s -> %s"
                            % (" -> ".join(ctx.stack), rule.name))
        key = (rule.name, scope_key)
        if key in ctx.memo:
            return ctx.memo[key]
        ctx.stack.append(rule.name)
        try:
            got = eval_node(rule.features, scope_key, rule)
        finally:
            ctx.stack.pop()
        res = bool(got)
        ctx.memo[key] = res
        return res

    counters = {"n": 0, "depth": 0}
    # 递归深度独立于步数计数：max_calls 管的是"总共求值多少次"，
    # 但一个**深度**极大、宽度为 1 的嵌套结构（如 5000 层 and 套一个 match）
    # 在步数远未到上限时就已经把调用栈打爆了。
    # 两个维度必须分别设限，否则等于没设。
    _MAX_EVAL_DEPTH = 200

    def eval_node(node, scope_key, rule: Rule) -> bool:
        counters["n"] += 1
        if counters["n"] > max_calls:
            raise RuleError("匹配步数超过上限（%d），疑似规则成环或数据异常"
                            % max_calls)
        counters["depth"] += 1
        try:
            if counters["depth"] > _MAX_EVAL_DEPTH:
                raise RuleError(
                    "匹配嵌套深度超过 %d 层（规则 %r）—— 疑似畸形规则文件"
                    % (_MAX_EVAL_DEPTH, rule.name))
            return _eval_node_inner(node, scope_key, rule)
        finally:
            counters["depth"] -= 1

    def _eval_node_inner(node, scope_key, rule: Rule) -> bool:
        # 裸列表 = and
        if isinstance(node, list):
            return all(eval_node(x, scope_key, rule) for x in node) if node else False
        if not isinstance(node, dict) or not node:
            return False
        # 逻辑节点：整个 dict 应当是单键（capa 约定）
        if len(node) != 1:
            # 多键 dict 视作 and（容错，但语义要明确）
            return all(eval_node({k: v}, scope_key, rule) for k, v in node.items())
        k, v = next(iter(node.items()))
        if k == "and":
            return all(eval_node(x, scope_key, rule) for x in (v or []))
        if k == "or":
            return any(eval_node(x, scope_key, rule) for x in (v or []))
        if k == "not":
            sub = v if isinstance(v, list) else [v]
            return not any(eval_node(x, scope_key, rule) for x in sub)
        if k == "optional":
            # optional 不改变真值：命中加分，不命中不扣
            return True
        if k == "match":
            names = v if isinstance(v, list) else [v]
            for nm in names:
                r2 = ctx.rules_by_name.get(str(nm))
                if r2 is None:
                    errors.append("规则 %r 引用了不存在的规则 %r"
                                  % (rule.name, nm))
                    return False
                if not eval_rule(r2, scope_key):
                    return False
            return True
        return eval_leaf(k, v, scope_key, rule)

    def eval_leaf(kind, val, scope_key, rule: Rule) -> bool:
        ff = feats.get("file") or {}
        # file 作用域 + 任何作用域都先看文件级特征（capa 里 file 特征在
        # function 作用域下同样可见）
        if scope_key is None:
            bag = ff
        else:
            fn_bag = (feats.get("functions") or {}).get(scope_key)
            if fn_bag is None:
                return False
            bag = dict(ff)
            for kk, vv in fn_bag.items():
                bag.setdefault(kk, set())
            # 合并
            merged = {}
            for src in (ff, fn_bag):
                for kk, vv in (src or {}).items():
                    merged.setdefault(kk, set()).update(vv)
            bag = merged

        vals = val if isinstance(val, list) else [val]
        for one in vals:
            if _leaf_hit(kind, one, bag, ff):
                return True
        return False

    def _leaf_hit(kind, one, bag, ff) -> bool:
        if kind == "api":
            dll, fn = _norm_api(one)
            pool = bag.get("api") or set()
            if dll:
                if "%s|%s" % (dll, fn) in pool:
                    return True
            return any(p.endswith("|" + fn) for p in pool)
        if kind == "number":
            try:
                n = int(one)
            except Exception:
                return False
            pool = bag.get("number") or set()
            u = n & 0xFFFFFFFFFFFFFFFF
            if u in pool:
                return True
            # 32 位立即数可能在 64 位语境里以符号扩展出现
            if n >= 0 and (n | 0xFFFFFFFF00000000) & 0xFFFFFFFFFFFFFFFF in pool:
                return True
            return False
        if kind in ("string", "substring"):
            want = str(one)
            for s in (bag.get("string") or set()):
                if want in str(s):
                    return True
            return False
        if kind == "mnemonic":
            return str(one).lower() in (bag.get("mnemonic") or set())
        if kind == "characteristic":
            return str(one).lower() in (bag.get("characteristic") or set())
        if kind == "tag":
            return str(one) in (bag.get("tag") or set())
        if kind == "section":
            return str(one).strip().lower() in (ff.get("section") or set())
        if kind == "import":
            dll, fn = _norm_api(one)
            pool = ff.get("import") or set()
            if dll:
                return "%s|%s" % (dll, fn) in pool
            return any(p.endswith("|" + fn) for p in pool)
        if kind == "export":
            return str(one).lower() in (ff.get("export") or set())
        if kind == "function-name":
            return str(one).lower() in (bag.get("function-name") or set())
        if kind == "os":
            return str(one).lower() in (ff.get("os") or set())
        if kind == "arch":
            return str(one).lower() in (ff.get("arch") or set())
        if kind == "format":
            return str(one).lower() in (ff.get("format") or set())
        if kind == "bytes":
            # 字节序列特征需要原始数据，本引擎在无文件句柄时确实判不了。
            # 【已修 bug】注释写的是「但要报出来（不能静默当成不命中）」，
            # 旧实现却只有裸 `return False`：规则整条不命中，errors 里一个
            # 字都没有，用户看到的是「样本干净」，真相是「这条规则没能力
            # 判」。现在真的登记出去。
            errors.append(
                "%s: 使用了 bytes 字节序列特征，本规则引擎无文件句柄，"
                "该叶子判据无法求值（不是不命中，是没判）" % (_cur_rule[0] or "?"))
            return False
        return False

    # 自顶向下跑：file 作用域只跑一次；其余按函数跑
    _cur_rule = [None]   # 供叶子判据登记「是哪条规则」的轻量上下文
    for r in rules:
        _cur_rule[0] = getattr(r, "name", None)
        try:
            if r.scope == "file":
                if eval_rule(r, None):
                    hits.append(_mk_hit(r, None))
            else:
                for v in (feats.get("functions") or {}):
                    if eval_rule(r, v):
                        hits.append(_mk_hit(r, v))
        except RuleError as e:
            errors.append("%s: %s" % (r.name, e))

    for h in hits:
        by_ns.setdefault(h["namespace"] or "(未分类)", []).append(h["rule"])
        for t in h["att_ck"]:
            att.add(t)
    # 去重（同一规则在多个函数命中时 by_ns 只留一次）
    for k in by_ns:
        seen = []
        for n in by_ns[k]:
            if n not in seen:
                seen.append(n)
        by_ns[k] = seen
    return {"hits": hits, "by_namespace": by_ns,
            "att_ck": sorted(att), "errors": errors}


def _mk_hit(r: Rule, vma) -> dict:
    h = r.to_dict()
    h["rule"] = r.name
    h.pop("name", None)
    if vma is not None:
        h["location"] = "0x%x" % vma
    return h


def summarize(res: dict) -> dict:
    """给报告用的概要。"""
    return {
        "rule_count": len(res.get("hits") or []),
        "namespaces": len(res.get("by_namespace") or {}),
        "att_ck": res.get("att_ck") or [],
        "top": sorted((res.get("by_namespace") or {}).keys())[:24],
    }
