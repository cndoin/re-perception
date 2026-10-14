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
from collections import namedtuple

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
    # capa 计数算子 `2 or more:` —— 键以数字开头但是真键。
    # 不能放宽整体正则（十六进制哈希 `7204e3ef...:0x4073c0` 这类标量
    # 会被误判成映射），所以单独精确放行。
    if re.fullmatch(r"\d+ or more", key):
        return True
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
                # 与 _is_keyed 同一口径：普通键 + capa 计数算子 `N or more`
                if re.fullmatch(r"[A-Za-z_][\w./\- ]*", k) or \
                        re.fullmatch(r"\d+ or more", k):
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
#   bytes          字节序列（支持 `??` / `..` 通配，按指令字节或文件字节判定）
#   offset         内存操作数位移（指令级：ins.disp）
#   tag            语义标签（来自 lib_semantics 的标签体系）
#   os             目标操作系统
#   arch           架构
#   format         文件格式
#   match          引用另一条规则（规则依赖）
LEAF_TYPES = {
    "api", "number", "string", "substring", "mnemonic", "characteristic",
    "section", "import", "export", "function-name", "bytes", "offset",
    "tag", "os", "arch", "format", "match",
}

LOGIC_KEYS = {"and", "or", "not", "optional"}

# 指令级包装节点（capa 语法）：`instruction: <子树>` 表示子树的全部约束
# 必须在**同一条指令**上共现。与 and/or 不同，它不是纯逻辑算子而是
# 作用域收缩算子 —— 少了它，「同一条指令 xor + 立即数 4」会被放松成
# 「函数里既有 xor 又有 4」，正是 193 条降级规则误报的根源。
SCOPE_NODE_KEYS = {"instruction"}

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


# 正则字符串编译缓存：同一 pattern 会被成千上万次求值复用，
# 编译一次即可（re 模块自带缓存是有限的，这里显式持有避免抖动）。
_RX_CACHE: dict = {}


def _rx_compile(pattern: str, flags: str):
    """编译 capa 风格正则（flags: i=忽略大小写）。失败返回 None。"""
    key = (pattern, flags)
    rx = _RX_CACHE.get(key)
    if rx is not None:
        return rx
    try:
        f = re.IGNORECASE if "i" in flags else 0
        rx = re.compile(pattern, f)
    except re.error:
        return None
    _RX_CACHE[key] = rx
    return rx


class Rule:
    __slots__ = ("name", "namespace", "scope", "authors", "description",
                 "att_ck", "references", "features", "source", "raw", "lib")

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
        # 辅助规则（capa 的 lib/ 构件库）：只应被 `match:` 引用，
        # 不构成能力结论。判定口径：meta.lib 显式标记，或 namespace 为 lib。
        # （capa 的 lib/ 目录规则没有 namespace，翻译器会如实标成 lib。）
        lib_mark = meta.get("lib")
        self.lib = bool(lib_mark) if lib_mark is not None else (
            self.namespace == "lib" or self.namespace.startswith("lib/"))
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
            elif k in SCOPE_NODE_KEYS:
                # instruction: 是作用域收缩节点，值是任意特征子树
                if not isinstance(v, (dict, list)) or not v:
                    raise RuleError("`%s:` 的值必须是特征子树" % k)
                self._validate(v, depth + 1)
            elif re.fullmatch(r"\d+ or more", str(k)):
                # capa 计数算子：至少 N 个子项命中
                if not isinstance(v, list):
                    raise RuleError("`%s:` 的值必须是列表" % k)
                if not v:
                    raise RuleError("`%s:` 不能是空列表" % k)
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
                # 正则字符串必须**加载期**就编译验证：写坏的正则如果拖到
                # 求值期，表现是「永远不命中且不报错」—— 静默失效最难查。
                if k in ("string", "substring"):
                    for one in (v if isinstance(v, list) else [v]):
                        m = re.match(r"^/(.*)/([ia]*)$", str(one))
                        if m and _rx_compile(m.group(1), m.group(2)) is None:
                            raise RuleError("非法正则字符串：%r" % one)
            else:
                raise RuleError(
                    "未知特征类型 `%s`（支持：%s）"
                    % (k, ", ".join(sorted(LEAF_TYPES))))

    def to_dict(self) -> dict:
        return {
            "name": self.name, "namespace": self.namespace, "scope": self.scope,
            "authors": self.authors, "description": self.description,
            "att_ck": self.att_ck, "references": self.references,
            "lib": self.lib,
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
                   sem: dict | None = None,
                   thunk_map: dict[int, str] | None = None,
                   str_map: dict[int, str] | None = None) -> dict:
    """
    从已解析的目标里抽取「文件级 + 函数级 + 逐指令级」三层特征。

    返回 {file: {...}, functions: {vma: {特征类别: set(...), insns: [...],
    blocks: [...]}}, errors: [...]}。

    逐指令记录（InsnFeat）供 instruction / basic block 作用域求值：
    capa 的「同一条指令共现」语义必须在单指令粒度判定，用函数级集合
    近似会把它放松成「函数里两样都有」（实测误报根源）。记录用
    namedtuple 紧凑存储，20 万条指令量级下内存可控。

    api / 字符串特征**全函数覆盖**（不走语义层的 limit 上限）：
    旧实现只有前 limit 个函数有 api 特征，其余函数的 api 规则
    永不命中且无任何提示 —— 静默漏报。

    errors 里是特征抽取期间的非致命失败（如字符串扫描挂了）——
    调用方必须把它报给用户：抽不到特征和规则没命中，结果看起来是一样的。
    """
    iat_map = iat_map or {}
    thunk_map = thunk_map or {}
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
            "import": set(), "offset": set(),
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

    # 指令级：一次遍历同时产出聚合特征与逐指令记录（供细粒度作用域下钻）
    if idx is not None:
        insn_map = getattr(idx, "insn", None) or {}
        dec_at = getattr(idx, "decode_at", None)
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
        from lib_semantics import _candidate_addrs as _addrs_of
        for v, feats in per_func.items():
            offs = offs_by_vma.get(v) or []
            recs: list = []
            tgts: set = set()
            back_edges: set = set()
            for o in offs[:_INSN_CAP]:
                ins = insn_map.get(o)
                if ins is None and callable(dec_at):
                    # CodeIndex.insn 是懒加载的：未预热时 .get() 静默返回
                    # None。这里退回 decode_at（lib_semantics.ins_at 的口径），
                    # 不让「没解码」伪装成「没指令」。
                    try:
                        ins = dec_at(o)
                    except Exception:      # lint:ok 单条解码失败跳过，下同
                        ins = None
                if ins is None:
                    continue
                # 【已修 bug】指令对象的助记符字段叫 "mnem"（见 lib_x86.Insn.__slots__），
                # 原先只读 "mnemonic"，于是 feats["mnemonic"] 恒为空集 ——
                # 所有 `mnemonic: xxx` 规则静默失效（实测 mnemonic=0）。
                mn = (getattr(ins, "mnem", None)
                      or getattr(ins, "mnemonic", None))
                if not mn and isinstance(ins, dict):
                    mn = ins.get("mnem") or ins.get("mnemonic")
                mn = str(mn).lower() if mn else ""
                if mn:
                    feats["mnemonic"].add(mn)
                imms = tuple(i & 0xFFFFFFFFFFFFFFFF for i in _imms_of(ins))
                for i in imms:
                    feats["number"].add(i)
                # offset 特征（内存操作数位移）：与 number 分开 —— capa 里
                # `offset:` 判的是位移量，不是任意立即数。掩码成 64 位无符号
                # 存储，负位移（disp=-4）与规则里的 0xFF..FC 写法才对得上。
                disp = getattr(ins, "disp", None)
                if disp is None and isinstance(ins, dict):
                    disp = ins.get("disp")
                if isinstance(disp, int):
                    feats["offset"].add(disp & 0xFFFFFFFFFFFFFFFF)
                # PEB / TEB 手工遍历：反分析里很典型（不调 API，直接读
                # fs:[0x30] / gs:[0x60] 拿 PEB，再读 BeingDebugged）。
                # 这是**强特征**，单凭它配合固定偏移就能定性，见 anti-analysis.yml。
                flags = 0
                if _is_peb_access(ins):
                    feats["characteristic"].add("peb-access")
                    flags |= 1
                # 单指令 nzxor（flags 位 2）：xor 且两操作数文本不同（即
                # 非 `xor eax, eax` 式零化）。指令级 `characteristic: nzxor`
                # 靠这个下钻；函数级密度判定的 nzxor 是另一个粒度的同名特征，
                # 在 features["characteristic"] 里，互不混淆。
                if mn == "xor":
                    ops_txt = str(getattr(ins, "ops", None) or
                                  (ins.get("ops") if isinstance(ins, dict) else "") or "")
                    parts = [p.strip() for p in ops_txt.split(",")]
                    if len(parts) == 2 and parts[0] != parts[1]:
                        flags |= 2
                # 调用点 API 还原（IAT 直调 / thunk 跳板）：这里是 api 特征的
                # **全函数覆盖**来源，语义层的 api_calls（有 limit 上限）只作补充。
                kind = str(getattr(ins, "kind", None) or
                           (ins.get("kind") if isinstance(ins, dict) else "") or "")
                api = ""
                # kind 取值见 lib_x86 的 K_* 常量（字符串常量，这里用字面量
                # 保持本模块零额外依赖，_CTRL_KINDS 同源）
                ins_vma = getattr(ins, "vma", 0)
                if kind in ("call", "jmp"):
                    tgt = getattr(ins, "target", None)
                    if tgt is not None:
                        tgts.add(tgt)
                        # 回边（目标在跳转指令之前）= 循环存在的直接证据。
                        # 块级 `characteristic: loop` 靠这个判定，比函数级
                        # 密度启发精确（capa 的 loop 就是块级特征）。
                        if tgt < ins_vma:
                            back_edges.add(tgt)
                    for a in (tgt, getattr(ins, "mem_ref", None)):
                        if a is None:
                            continue
                        nm2 = iat_map.get(a) or thunk_map.get(a)
                        if nm2:
                            api = "%s|%s" % _norm_api(nm2)
                            feats["api"].add(api)
                            break
                elif kind == "cjmp":
                    tgt = getattr(ins, "target", None)
                    if tgt is not None:
                        tgts.add(tgt)
                        if tgt < ins_vma:
                            back_edges.add(tgt)
                # 字符串交叉引用（同样全函数覆盖，替代语义层的 refs 上限）
                strs = ()
                if str_map:
                    got = []
                    for a in _addrs_of(ins):
                        s = str_map.get(a)
                        if s:
                            got.append(str(s))
                            feats["string"].add(str(s))
                    if got:
                        strs = tuple(got)
                raw = getattr(ins, "bytes", None)
                if raw is None and isinstance(ins, dict):
                    raw = ins.get("bytes")
                recs.append(InsnFeat(getattr(ins, "vma", 0), mn, imms, api,
                                     strs, getattr(ins, "disp", None),
                                     raw or b"", kind, flags))
            if len(offs) > _INSN_CAP:
                errs_out.append(
                    "函数 0x%x 指令数超过 %d，逐指令特征只覆盖前 %d 条"
                    % (v, _INSN_CAP, _INSN_CAP))
            feats["insns"] = recs
            feats["blocks"] = blocks = _blocks_of(recs, tgts)
            # 块级 loop：回边目标落在哪个块，哪个块就是循环体（capa 语义）。
            # 函数级 loop 特征同源于此 —— 有回边即有循环，比只依赖语义层
            # summarize_functions 的 features.loop 覆盖更全（后者有函数上限）。
            loop_blocks: set = set()
            if back_edges:
                feats["characteristic"].add("loop")
                v2i = {r.vma: i for i, r in enumerate(recs)}
                for t in back_edges:
                    j = v2i.get(t)
                    if j is None:
                        continue
                    for bi, (s, e) in enumerate(blocks):
                        if s <= j < e:
                            loop_blocks.add(bi)
                            break
            feats["loop_blocks"] = loop_blocks
    return {"file": f_file, "functions": per_func, "errors": errs_out}


# 逐指令特征记录（细粒度作用域求值用）。
# 用 namedtuple 而不是 dict：kernel32 级样本 20 万条指令，dict 每条 200B+
# 会把内存打爆；tuple 字段访问靠属性名，兼顾可读与体积。
InsnFeat = namedtuple("InsnFeat",
                      "vma mnem imms api strs disp raw kind flags")

_INSN_CAP = 20000   # 单函数逐指令记录上限（超限会登记到 errors，不静默）

# 会终结一个基本块的控制流指令（call 也断块：与 vivisect/capa 的块粒度一致）
_CTRL_KINDS = frozenset(("call", "jmp", "cjmp", "ret", "hlt", "int"))


def _blocks_of(recs: list, tgts: set) -> list[tuple[int, int]]:
    """
    线性扫描式基本块划分（左闭右开的下标区间）。

    块首 = 函数入口 / 直接跳转目标 / 控制流指令的下一条；
    块尾 = 控制流指令（含 call）。直接跳转目标可用指令里的 target
    直接拿，间接跳转无法静态定目标 —— 按「控制流后必是块首」处理，
    宁可多切（过切只会让共现约束更严，不会放过不该放过的）。
    """
    if not recs:
        return []
    vma_to_i = {r.vma: i for i, r in enumerate(recs)}
    leaders = {0}
    for i, r in enumerate(recs):
        if r.kind in _CTRL_KINDS and i + 1 < len(recs):
            leaders.add(i + 1)
    for t in tgts:
        j = vma_to_i.get(t)
        if j is not None:
            leaders.add(j)
    starts = sorted(leaders)
    blocks = []
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(recs)
        if e > s:
            blocks.append((s, e))
    return blocks


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

# 指令级产出的 characteristic（只在产出它的指令上成立，不随函数整体继承）
#   peb-access  手工读 PEB（flags 位 1）
#   nzxor       非零化异或单指令（flags 位 2）
# loop 是块级（回边目标所在块），见 build_features 的 loop_blocks。
_INSN_CHARS = frozenset(("peb-access", "nzxor"))

# 文件级**事实类** characteristic：常量表签名 / 加壳信号等。
# 这些是「文件里存在该证据」的事实，在任何作用域求值都应可见 ——
# 函数级规则写 `characteristic: aes_sbox` 判的就是文件里有 AES 表，
# 不该因为作用域下钻就丢失。
# （对比：debug/loop/nzxor/peb-access 是函数/块/指令粒度的事实，
#   只在自己的粒度上成立，不下放。）
_FILE_FACT_CHARS = frozenset((
    "packed", "aes_sbox", "aes_inv_sbox", "rc4_ksa", "crc32_table",
    "md5_sha1_init", "sha256_init", "sha512_init", "base64", "base32",
))


def _num_cands(n: int) -> set:
    """
    数值/位移的判等候选集：同一物理值在规则里的不同写法都要对得上。
    - 规则写 0xFFFFFFFC（32 位字面）↔ 实际 disp=-4（64 位符号扩展）
    - 规则写 -4 ↔ 存储值是掩码后的 0xFF..FC
    双向归一到 64 位无符号 + 32 位符号扩展两个候选，命中任一即算。
    """
    out = {n & 0xFFFFFFFFFFFFFFFF}
    n32 = n & 0xFFFFFFFF
    if n32 >= 0x80000000:
        out.add((n32 | 0xFFFFFFFF00000000) & 0xFFFFFFFFFFFFFFFF)
    if n >= 0:
        out.add((n | 0xFFFFFFFF00000000) & 0xFFFFFFFFFFFFFFFF)
    return out


def _parse_num(one):
    """capa 数值面值可能带 `= 注释` 后缀（如 `0xCC = INT3`），取等号左边。"""
    s = re.split(r"\s*=\s*", str(one), maxsplit=1)[0].strip()
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        return None


_BYTES_RX_CACHE: dict = {}


def _bytes_rx(pattern):
    """`01 02 ?? 03` 风格字节模式 → bytes 正则（?? / .. / ? 是通配字节）。
    capa 的 bytes 值带 `= CLSID_xxx` 注释后缀，先剥掉（纵深兜底，
    翻译器侧已剥一层，手写规则也可能带）。"""
    key = re.split(r"\s*=\s*", str(pattern), maxsplit=1)[0].strip()
    if key in _BYTES_RX_CACHE:
        return _BYTES_RX_CACHE[key]
    out = bytearray()
    for p in key.split():
        if p in ("??", "..", "?"):
            out += b"."
        else:
            try:
                out += re.escape(bytes([int(p, 16)]))
            except ValueError:
                _BYTES_RX_CACHE[key] = None
                return None
    try:
        rx = re.compile(bytes(out), re.DOTALL)
    except re.error:
        rx = None
    _BYTES_RX_CACHE[key] = rx
    return rx


def _rules_use_bytes(rules) -> bool:
    """规则集里是否有 bytes 叶子（决定要不要物化逐指令字节，省内存）。"""
    def walk(node):
        if isinstance(node, list):
            return any(walk(x) for x in node)
        if isinstance(node, dict):
            if "bytes" in node:
                return True
            return any(walk(v) for v in node.values())
        return False
    return any(walk(getattr(r, "features", None)) for r in rules)


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
      {"hits": [...], "aux_hits": [...], "by_namespace": {...},
       "att_ck": [...], "errors": [...]}

    每个 hit：
      {rule, namespace, scope, description, att_ck, location, ...}

    【结论与构件分离】lib 辅助规则（capa 的 lib/ 构件库）只经 `match:`
    引用求值，**不进 hits**：「contain loop」这种构件不是能力结论，
    混进结论就是把积木当成品卖（实测 89/116 的命中是这种噪声）。
    辅助规则被引用且命中时记入 aux_hits，供证据链复核，不静默丢弃。

    【作用域语义】scope 决定特征共现的粒度（与 capa 一致）：
      instruction   —— 全部特征在**同一条指令**上成立
      basic block   —— 同一个基本块内成立
      function      —— 同一函数内成立
      file          —— 全文件
    `match:` 引用另一条规则时按**被引规则自己的 scope** 在当前作用域项的
    外包/内含项上求值（函数上下文引用块规则 = 存在量化某个块）。

    【参数校验】这是公开 API，调用方可能直接传 None（比如规则加载失败后
    把失败值一路传下来）。原实现会在 `_Ctx.__init__` 里抛
    `TypeError: 'NoneType' object is not iterable` —— 信息量为零，
    排查时看不出是"没加载到规则"还是"引擎坏了"。现在显式校验并说明。
    """
    if rules is None:
        return {"hits": [], "aux_hits": [], "by_namespace": {}, "att_ck": [],
                "errors": [], "empty": True,
                "reason": "rules 为 None（规则未加载）"}
    if not isinstance(rules, (list, tuple)):
        return {"hits": [], "aux_hits": [], "by_namespace": {}, "att_ck": [],
                "errors": [], "empty": True,
                "reason": "rules 类型应为 list，实际是 %s" % type(rules).__name__}
    if not rules:
        return {"hits": [], "aux_hits": [], "by_namespace": {}, "att_ck": [],
                "errors": [], "empty": True,
                "reason": "rules 为空（没有可执行的规则）"}
    if not isinstance(feats, dict):
        return {"hits": [], "aux_hits": [], "by_namespace": {}, "att_ck": [],
                "errors": [], "empty": True,
                "reason": "feats 类型应为 dict，实际是 %s" % type(feats).__name__}

    hits: list[dict] = []
    by_ns: dict[str, list[str]] = {}
    att: set[str] = set()
    errors: list[str] = []
    ctx = _Ctx(rules)
    fns: dict = feats.get("functions") or {}
    ff = feats.get("file") or {}
    aux_seen: set = set()

    # ---------- 字符串叶子：命中集预计算 ----------
    # 【性能】kernel32（2392 函数）上 match_rules 实测 657 秒，热点是
    # 字符串叶子：每次求值都对整个字符串池（文件级可达 2 万条）逐条跑
    # re.Pattern.search，cProfile 实测 8.15 亿次调用、290 秒纯开销。
    # 同一判据在一次匹配里的字符串池是**固定的**，命中集算一次即可；
    # 之后叶子求值退化成集合交。字面子串同理。
    pool_all: set = set(ff.get("string") or ())
    for _fb in fns.values():
        pool_all |= ((_fb or {}).get("string") or set())
        for _rec in ((_fb or {}).get("insns") or ()):
            pool_all.update(_rec.strs)
    _str_cache: dict = {}

    def _str_match_set(want: str):
        got = _str_cache.get(want)
        if got is not None:
            return got
        m = re.match(r"^/(.*)/([ia]*)$", want)
        if m:
            rx = _rx_compile(m.group(1), m.group(2))
            got = (frozenset() if rx is None else
                   frozenset(s for s in pool_all if rx.search(str(s))))
        else:
            got = frozenset(s for s in pool_all if want in str(s))
        _str_cache[want] = got
        return got

    # ---------- 逐函数指令索引（候选预过滤用，按需构建） ----------
    _fn_idx_cache: dict = {}

    def _fn_index(vma):
        ix = _fn_idx_cache.get(vma)
        if ix is not None:
            return ix
        fb = fns.get(vma) or {}
        recs = fb.get("insns") or ()
        blocks = fb.get("blocks") or ()
        blk_of = [-1] * len(recs)
        for bi, (s, e) in enumerate(blocks):
            for i in range(max(0, s), min(len(recs), e)):
                blk_of[i] = bi
        ix = {"api": {}, "mnemonic": {}, "characteristic": {}, "blk_of": blk_of}
        for i, r in enumerate(recs):
            if r.api:
                ix["api"].setdefault(r.api, set()).add(i)
                ix["api"].setdefault(r.api.split("|", 1)[1], set()).add(i)
            if r.mnem:
                ix["mnemonic"].setdefault(r.mnem, set()).add(i)
            if r.flags & 1:
                ix["characteristic"].setdefault("peb-access", set()).add(i)
            if r.flags & 2:
                ix["characteristic"].setdefault("nzxor", set()).add(i)
        _fn_idx_cache[vma] = ix
        return ix

    def _leaf_sites(vma, kind, one):
        """叶子在该函数的候选指令下标集；None = 无法收窄。"""
        if kind == "api":
            dll, fn = _norm_api(one)
            ix = _fn_index(vma)
            key = "%s|%s" % (dll, fn) if dll else fn
            s = ix["api"].get(key)
            return set(s) if s else set()
        if kind == "mnemonic":
            s = _fn_index(vma)["mnemonic"].get(str(one).lower())
            return set(s) if s else set()
        if kind == "characteristic":
            # 只有指令级产出的特征（peb-access/nzxor）可按指令收窄；
            # loop（块级）/packed/aes_sbox（文件级）等收不了窄（返回 None）。
            key = str(one).lower()
            if key not in _INSN_CHARS:
                return None
            s = _fn_index(vma)["characteristic"].get(key)
            return set(s) if s else set()
        if kind == "bytes":
            # bytes 模式命中块的全部指令下标（超集）。
            # 【为什么必须收窄】DES/AES 的 S-box 模式规则是「or of 30+ bytes」，
            # 作用域是 basic block —— 不收窄就是全文件 1 万块 × 30 叶子
            # 逐块求值，实测直接打爆 20 万步预算（结论残缺）。
            # 模式对块字节流命中一次后缓存，跨规则复用。
            rx = _bytes_rx(one)
            if rx is None:
                return set()
            ix = _fn_index(vma)
            cache = ix.setdefault("bytes_hits", {})
            got = cache.get(one)
            if got is None:
                fb = fns.get(vma) or {}
                blocks = fb.get("blocks") or ()
                recs = fb.get("insns") or ()
                got = set()
                for bi, (s, e) in enumerate(blocks):
                    stream = b"".join(r.raw for r in
                                      recs[max(0, s):min(len(recs), e)] if r.raw)
                    if stream and rx.search(stream):
                        got.update(range(max(0, s), min(len(recs), e)))
                cache[one] = got
            return set(got)
        return None

    def _prefilter(node, vma):
        """
        返回候选指令下标集（**超集**，只用于收窄求值点）；None = 不可收窄。
        AND 取交、OR 取并；not / optional / match / 计数算子一概不收窄。
        实测意义：块级规则 × 全部块是百万级求值，先用顶层合取里最稀疏的
        可索引叶子（api/mnemonic/characteristic）收窄到候选，再跑完整树。
        """
        if isinstance(node, list):
            known = None
            for x in node:
                s = _prefilter(x, vma)
                if s is None:
                    continue
                known = s if known is None else (known & s)
            return known
        if not isinstance(node, dict) or not node or len(node) != 1:
            return None
        k, v = next(iter(node.items()))
        if k == "and":
            return _prefilter(v or [], vma)
        if k == "or":
            out = set()
            for x in (v or []):
                s = _prefilter(x, vma)
                if s is None:
                    return None
                out |= s
            return out
        if k in SCOPE_NODE_KEYS:
            return _prefilter(v, vma)
        if k in ("not", "optional", "match"):
            return None
        vals = v if isinstance(v, list) else [v]
        out = None
        for one in vals:
            s = _leaf_sites(vma, k, one)
            if s is None:
                return None
            out = s if out is None else (out | s)
        return out

    def _fn_of(key):
        return key[1] if isinstance(key, tuple) else key

    def _expand(key, want):
        """当前作用域项 key → want 粒度的求值项（外包上卷 / 内含存在量化）。"""
        if want == "file":
            return [None]
        vma = _fn_of(key)
        if want == "function":
            return [vma] if vma is not None else list(fns)
        if vma is None:
            # 文件上下文引用块/指令规则：存在量化全部函数的全部项
            out = []
            for v2, fb2 in fns.items():
                if want == "basic block":
                    out.extend(("blk", v2, bi)
                               for bi in range(len((fb2 or {}).get("blocks") or ())))
                else:
                    out.extend(("ins", v2, i)
                               for i in range(len((fb2 or {}).get("insns") or ())))
            return out
        fb = fns.get(vma) or {}
        if want == "basic block":
            if isinstance(key, tuple) and key[0] == "blk":
                return [key]
            blocks = fb.get("blocks") or ()
            if isinstance(key, tuple) and key[0] == "ins":
                for bi, (s, e) in enumerate(blocks):
                    if s <= key[2] < e:
                        return [("blk", vma, bi)]
                return []
            return [("blk", vma, bi) for bi in range(len(blocks))]
        # want == "instruction"
        if isinstance(key, tuple) and key[0] == "ins":
            return [key]
        recs = fb.get("insns") or ()
        if isinstance(key, tuple) and key[0] == "blk":
            blocks = fb.get("blocks") or ()
            if not (0 <= key[2] < len(blocks)):
                return []
            s, e = blocks[key[2]]
            return [("ins", vma, i) for i in range(max(0, s), min(len(recs), e))]
        return [("ins", vma, i) for i in range(len(recs))]

    def _eval_at(rule: Rule, scope_key):
        """在**指定作用域项**上求值一条规则（记忆化 + 成环检测）。"""
        key = (rule.name, scope_key)
        if key in ctx.memo:
            return ctx.memo[key]
        if rule.name in ctx.stack:
            raise RuleError("规则依赖成环：%s -> %s"
                            % (" -> ".join(ctx.stack), rule.name))
        ctx.stack.append(rule.name)
        try:
            got = eval_node(rule.features, scope_key, rule)
        finally:
            ctx.stack.pop()
        res = bool(got)
        ctx.memo[key] = res
        return res

    def _narrow(items, node):
        """
        按可索引叶子（api/mnemonic/指令级 characteristic）把候选求值项
        收窄成**超集**。收不动（子树含 string/number/offset/match/not 等
        不可索引叶子）就原样返回 —— 收窄只影响性能不影响语义。
        实测意义：指令/块级规则 × 全部指令/块是百万级求值；先用最稀疏的
        可索引叶子定位候选，再跑完整树（_prefilter 保证是超集，不会漏）。
        """
        if not items:
            return items
        out = []
        by_vma = {}
        for k2 in items:
            if not isinstance(k2, tuple):
                # 文件/函数粒度项（None / vma）没有细粒度下标可收窄，透传。
                # （_expand 对不同 want 返回的项形态不统一：file/function 是
                #   裸 None/int，block/instruction 是三元组。）
                out.append(k2)
                continue
            by_vma.setdefault(k2[1], []).append(k2)
        for vma, ks in by_vma.items():
            cand = _prefilter(node, vma)
            if cand is None:
                out.extend(ks)
                continue
            if ks[0][0] == "ins":
                out.extend(k2 for k2 in ks if k2[2] in cand)
            else:
                blk_of = _fn_index(vma).get("blk_of") or ()
                keep = set()
                for i in cand:
                    if 0 <= i < len(blk_of) and blk_of[i] >= 0:
                        keep.add(blk_of[i])
                out.extend(k2 for k2 in ks if k2[2] in keep)
        return out

    def eval_rule(rule: Rule, scope_key):
        """`match:` 引用求值：按被引规则自身 scope 在当前项的内外包项上求值。"""
        for k2 in _narrow(_expand(scope_key, rule.scope), rule.features):
            if _eval_at(rule, k2):
                return True
        return False

    counters = {"n": 0, "depth": 0}
    # 递归深度独立于步数计数：max_calls 管的是"总共求值多少次"，
    # 但一个**深度**极大、宽度为 1 的嵌套结构（如 5000 层 and 套一个 match）
    # 在步数远未到上限时就已经把调用栈打爆了。
    # 两个维度必须分别设限，否则等于没设。
    _MAX_EVAL_DEPTH = 200

    def eval_node(node, scope_key, rule: Rule) -> bool:
        counters["n"] += 1
        if counters["n"] > max_calls:
            # 措辞要精确：预算耗尽与「规则成环」是完全不同的故障。
            # 成环由下面的 ctx.stack 环检测单独报；这里只说预算。
            raise RuleError(
                "本条规则的匹配步数超过上限（%d）—— 预算耗尽，"
                "该规则未跑完，结论不完整（可调大 max_calls 或减少函数范围）"
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
        if k in SCOPE_NODE_KEYS:
            # instruction: 子树必须在**同一条指令**上成立（capa 语义）。
            # 在当前项的指令里存在量化：∃ 一条指令满足子树。
            # 少了这个收缩，「同一条指令 xor + 立即数 4」会被放松成
            # 「函数里既有 xor 又有 4」—— 实测误报根源。
            return any(eval_node(v, k2, rule)
                       for k2 in _narrow(
                           _expand(scope_key, "instruction"), v))
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
                if getattr(r2, "lib", False):
                    # 辅助规则命中：登记进证据链（不进能力结论）
                    aux_seen.add((r2.name, scope_key))
            return True
        m_cnt = re.fullmatch(r"(\d+) or more", str(k))
        if m_cnt:
            # capa 计数算子：至少 N 个子项命中。
            # 求值全部子项（不做短路）——每项都要计数，语义上没有短路空间。
            need = int(m_cnt.group(1))
            hit = 0
            for x in (v or []):
                if eval_node(x, scope_key, rule):
                    hit += 1
                    if hit >= need:
                        return True
            return False
        return eval_leaf(k, v, scope_key, rule)

    # 【性能】判定袋按 scope_key 记忆化。
    # 原实现每求值一个叶子判据就重建一次 dict(ff) + 合并（同一行的 bag
    # 赋值随后立刻被覆盖，纯浪费）。规模放大后这是主要开销：
    # 2392 个函数 × 20 条规则 × 每规则若干叶子 → 十万次级重复建字典。
    # 合并结果只依赖 (文件级特征, 该函数特征)，整个 match_rules 内不变，
    # 所以按 scope_key 缓存是安全的。
    _merged_cache: dict = {}

    def _fine_bag(scope_key):
        """
        ("ins", vma, n) / ("blk", vma, n) → 逐指令记录聚合的判定袋。
        指令级/块级的共现语义在这里落地：袋里只装**本指令/本块**的特征，
        「同一条指令 xor + 立即数 4」才不会被放松成「函数里两样都有」。
        """
        tag, vma, n = scope_key
        fb = fns.get(vma) or {}
        recs = fb.get("insns") or ()
        if tag == "ins":
            sel = recs[n:n + 1] if 0 <= n < len(recs) else ()
        else:
            blocks = fb.get("blocks") or ()
            if not (0 <= n < len(blocks)):
                return None
            s, e = blocks[n]
            sel = recs[max(0, s):min(len(recs), e)]
        bag = {"api": set(), "number": set(), "string": set(),
               "mnemonic": set(), "characteristic": set(), "offset": set(),
               "tag": set(), "function-name": set()}
        for k in ("tag", "function-name"):
            got = fb.get(k)
            if got:
                bag[k].update(got)
        raws = []
        for r in sel:
            if r.mnem:
                bag["mnemonic"].add(r.mnem)
            if r.api:
                bag["api"].add(r.api)
            bag["number"].update(r.imms)
            bag["string"].update(r.strs)
            if r.disp is not None:
                bag["offset"].add(r.disp & 0xFFFFFFFFFFFFFFFF)
            if r.flags & 1:
                bag["characteristic"].add("peb-access")
            if r.flags & 2:
                bag["characteristic"].add("nzxor")
            if r.raw:
                raws.append(r.raw)
        if tag == "blk" and n in (fb.get("loop_blocks") or ()):
            bag["characteristic"].add("loop")
        # bytes 判据的字节流：capa 的 bytes 特征匹配**作用域字节流**
        # （DES S-box 之类是 60+ 字节的表，跨指令边界）——
        # 必须把选中指令的字节连成流再匹配，只搜单指令（≤15B）会让
        # 长模式永不命中。块内指令在文件里连续（_offs 线性扫描保证），
        # join 是「这些指令的字节连起来」的精确语义。
        bag["insn_bytes"] = (b"".join(raws),) if raws else ()
        return bag

    def _bag_for(scope_key):
        """
        返回 (bag, ff)：bag 是当前作用域项的判定袋。
          file（None）   —— 文件级袋
          函数（vma）    —— 函数个性特征 + 文件级事实类 characteristic
          细粒度元组     —— 逐指令聚合，同样带文件级事实类

        【语义修正】个性特征（api/number/string/mnemonic/offset…）只看
        **本作用域项**。旧实现把文件级 string 全池并进函数袋，函数级
        `string:` 判据退化成「文件里有就算」，把共现约束放松成存在约束。
        文件级事实类（常量表签名/加壳信号）则在任何作用域可见 ——
        它们本来就是「文件里有该证据」的事实。
        """
        ff = feats.get("file") or {}
        if scope_key is None:
            return ff, ff
        hit = _merged_cache.get(scope_key)
        if hit is not None:
            # 缓存里存的已经是 (bag, ff) 二元组，直接返回；
            # 若写成 `return hit, ff` 会变成 ((bag, ff), ff)，
            # 调用方解包后 bag 变成元组 → 后续 .get() 全炸。
            return hit
        if isinstance(scope_key, tuple):
            core = _fine_bag(scope_key)
        else:
            fn_bag = (feats.get("functions") or {}).get(scope_key)
            if fn_bag is None:
                _merged_cache[scope_key] = (None, ff)
                return None, ff
            core = {k: (set(v) if isinstance(v, set) else v)
                    for k, v in fn_bag.items()
                    if k not in ("insns", "blocks", "loop_blocks")}
            recs = fn_bag.get("insns") or ()
            if recs:
                # 函数级 bytes 判据同理：函数体字节流（指令连缀）
                joined = b"".join(r.raw for r in recs if r.raw)
                core["insn_bytes"] = (joined,) if joined else ()
        if core is None:
            _merged_cache[scope_key] = (None, ff)
            return None, ff
        fact = ff.get("characteristic")
        if fact:
            cur = core.setdefault("characteristic", set())
            for c in fact:
                if c in _FILE_FACT_CHARS:
                    cur.add(c)
        _merged_cache[scope_key] = (core, ff)
        return core, ff

    def eval_leaf(kind, val, scope_key, rule: Rule) -> bool:
        bag, ff = _bag_for(scope_key)
        if bag is None:
            return False

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
            # capa 数值面值可能带 `= 注释`（0xCC = INT3），用 _parse_num 剥离
            n = _parse_num(one)
            if n is None:
                return False
            pool = bag.get("number") or set()
            return any(c in pool for c in _num_cands(n))
        if kind == "offset":
            # 内存操作数位移（capa offset 特征）。与 number 分开判定，
            # 但判等同样要双向归一（-4 ↔ 0xFF..FC ↔ 0xFFFFFFFC）。
            n = _parse_num(one)
            if n is None:
                return False
            pool = bag.get("offset") or set()
            return any(c in pool for c in _num_cands(n))
        if kind in ("string", "substring"):
            want = str(one)
            pool = bag.get("string") or set()
            if not pool:
                return False
            # 【性能】命中集预计算（见 _str_match_set）：同一判据的字符串池
            # 在一次匹配里是固定的，正则/子串扫一遍就够，叶子求值退化成
            # 集合交。旧实现每次求值都全池重扫 —— kernel32 上实测 8.15 亿次
            # re.search，match_rules 跑 657 秒。语义不变：正则 search /
            # 字面子串，判定约定（只有 /pat/i 尾部形态算正则）见 _str_match_set。
            return bool(pool & _str_match_set(want))
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
            # 指令字节序列（capa bytes 特征是指令级：指令字节含该模式）。
            # 逐指令 raw 已随 InsnFeat 物化，函数/块/指令作用域都能判；
            # 只有 file 级（全文件字节流）没有句柄，判不了 —— 那种情况
            # 必须报出来（不是不命中，是没判），否则又成静默失效。
            rx = _bytes_rx(one)
            if rx is None:
                errors.append("%s: bytes 模式非法：%r"
                              % (_cur_rule[0] or "?", one))
                return False
            pool = bag.get("insn_bytes") or ()
            for raw in pool:
                if raw and rx.search(raw):
                    return True
            if not pool:
                errors.append(
                    "%s: bytes 判据在 file 作用域无文件句柄，"
                    "该叶子无法求值（不是不命中，是没判）" % (_cur_rule[0] or "?"))
            return False
        return False

    # 自顶向下跑：file 作用域只跑一次；其余按函数跑
    _cur_rule = [None]   # 供叶子判据登记「是哪条规则」的轻量上下文
    for r in rules:
        if getattr(r, "lib", False):
            # 【结论与构件分离】lib 辅助规则（capa 的 lib/ 构件库）不单独
            # 作为能力结论求值 —— 只经 `match:` 引用，命中时记入 aux_seen
            # 供证据链复核。「contain loop」这种积木不是能力，混进结论
            # 就是把积木当成品卖（实测 89/116 的命中是这种噪声）。
            continue
        _cur_rule[0] = getattr(r, "name", None)
        # 【重要·修复】预算是**每条规则独立**的，不是全局共享。
        # 原实现用全局 counters["n"]，前面的规则（大 scope、规则依赖多）
        # 会吃光预算，导致后面的规则一条都跑不完就被截断 —— 实测
        # kernel32.dll（2392 函数）上 20 条规则有 7 条以「步数超上限」收场，
        # 而 errors 的措辞是「疑似规则成环」，把「预算耗尽」误报成
        # 「规则有问题」，用户拿到的是**残缺的 capabilities 却 ok:true**。
        # 现在每条规则重新计数：单条超预算只影响它自己，且措辞改成
        # 「预算耗尽」而非「成环」（两者是完全不同的故障）。
        counters["n"] = 0
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

    def _loc_str(sk):
        if sk is None:
            return ""
        if isinstance(sk, tuple):
            tag, vma, n = sk
            return ("0x%x[block %d]" if tag == "blk"
                    else "0x%x[insn %d]") % (vma, n)
        return "0x%x" % sk

    # 辅助规则命中登记（证据链复核用）：不进能力结论，但也不静默丢弃
    aux_hits = []
    for nm, sk in sorted(aux_seen, key=lambda t: (t[0], str(t[1]))):
        h = {"rule": nm, "auxiliary": True}
        loc = _loc_str(sk)
        if loc:
            h["location"] = loc
        aux_hits.append(h)
    return {"hits": hits, "aux_hits": aux_hits, "by_namespace": by_ns,
            "att_ck": sorted(att), "errors": errors}


def _mk_hit(r: Rule, vma) -> dict:
    h = r.to_dict()
    h["rule"] = r.name
    h.pop("name", None)
    if vma is not None:
        h["location"] = "0x%x" % vma
    else:
        # 文件级命中的证据位置就是全文件。不给 location 会让
        # 「命中必须可复核」的契约检查落空，也违背命中自带证据的约定。
        h["location"] = "file"
    return h


def summarize(res: dict) -> dict:
    """给报告用的概要。"""
    return {
        "rule_count": len(res.get("hits") or []),
        "namespaces": len(res.get("by_namespace") or {}),
        "att_ck": res.get("att_ck") or [],
        "top": sorted((res.get("by_namespace") or {}).keys())[:24],
    }
