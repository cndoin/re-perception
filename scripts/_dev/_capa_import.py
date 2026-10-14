#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
_capa_import.py — 把 mandiant/capa-rules（Apache-2.0）翻译成本项目规则格式

用法：
    python _capa_import.py <capa-rules 目录> <输出目录>

设计原则（对应「拿最好的方案过来」+ 本项目的诚实契约）：

1. **语义保持的删减**：引擎求不了值的叶子（bytes / offset / call 等）按
   「≡ False」参与逻辑化简 ——
   - `and` 遇到 → 整条规则放弃（and 里有一个恒假就是恒假）；
   - `or`  遇到 → 只删这个分支（or 里有一个恒假不影响其余分支）；
   - `not` 遇到 → 该节点 ≡ True，从父节点里消失。
   绝不做「把 and 里不支持的叶子直接删掉」这种**放宽语义**的操作 ——
   那会让规则比原意更容易命中，产出假能力。

2. **正则字符串原样保留**：`/pattern/flags` 语法引擎已支持（含 i 标志），
   非法正则在规则加载期就会报错，不会静默失效。

3. **作用域真实保留**：capa 的 instruction / basic block scope 原样保留，
   `instruction:` 节点嵌套输出 —— 引擎已支持单指令/基本块共现求值
  （见 lib_rules 的 SCOPE_NODE_KEYS 与 fine bag），不再降级成函数级
   近似合取。曾经的降级把「同一条指令 xor + 立即数 4」放松成
   「函数里两样都有」，实测造成 hide window / parse PE 等大量误报。

4. **`match` 依赖做不动点裁剪**：引用了没翻译进来的规则 ≡ 恒假，
   同样按上述语义化简，不允许悬空引用（悬空引用会每次运行报错）。

5. **署名义务**：每条规则保留原作者（authors）并在 references 里带来源
   仓库 URL；Apache-2.0 要求保留出处，见 rules/imported/NOTICE.md。
"""

from __future__ import annotations

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.dirname(_HERE)
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import lib_rules as R  # noqa: E402  需要先补 sys.path 再导入

SRC_URL = "https://github.com/mandiant/capa-rules"

# capa characteristic 名 → 引擎 ENGINE_CHARACTERISTICS 名。
# 只映射两边语义完全一致的；没列进来的一律按「引擎产不出」处理。
CHAR_MAP = {
    "peb access": "peb-access",
    "peb-access": "peb-access",
    "loop": "loop",
    "nzxor": "nzxor",
}

# 引擎可直接求值的叶子种类（与 lib_rules.LEAF_TYPES 对齐；bytes/offset
# 引擎已支持指令级求值（InsnFeat.raw / disp），不再恒假放弃）
LEAF_OK = {
    "api", "number", "string", "substring", "mnemonic", "characteristic",
    "section", "import", "export", "function-name", "tag", "os", "arch",
    "format", "match", "bytes", "offset",
}

# capa 的 static scope → 本项目 scope（真实保留，不降级）。
# call scope（调用点级）本引擎无此作用域，仍按无法求值处理。
SCOPE_MAP = {
    "function": "function",
    "basic block": "basic block",
    "instruction": "instruction",
    "global": "file",
    "file": "file",
}

TRUE, FALSE = object(), object()   # 逻辑化简哨兵（恒真 / 恒假）


# --------------------------------------------------------------- 统计
STATS = {
    "扫描": 0, "解析失败": 0, "无 scope": 0, "动态only": 0,
    "翻译成功": 0, "恒假放弃": 0, "match悬空放弃": 0,
    "指令级保留": 0, "块级保留": 0, "offset保留": 0, "bytes保留": 0,
}


# --------------------------------------------------------------- 特征树化简
def xform(node, match_names: set):
    """把 capa 特征树翻译成引擎特征树。返回新树 / TRUE / FALSE。"""
    if isinstance(node, list):
        # 裸列表 = 隐式 and
        return _xform_and(node, match_names)
    if not isinstance(node, dict) or not node:
        return FALSE
    if len(node) != 1:
        return _xform_and([{k: v} for k, v in node.items()], match_names)
    k, v = next(iter(node.items()))
    if k == "and":
        return _xform_and(v or [], match_names)
    if k == "or":
        return _xform_or(v or [], match_names)
    if k == "not":
        sub = v if isinstance(v, list) else [v]
        # not 语义：任一子项为真则整体为假
        r = _xform_or(sub, match_names)
        if r is TRUE:
            return FALSE
        if r is FALSE:
            return TRUE
        return {"not": r}
    if k == "optional":
        # capa 语义 = 「匹配到加分、不匹配不扣分」，真值恒为 True
        return TRUE
    if k == "instruction":
        # 指令级包装：真实保留为 instruction: 节点（引擎按「∃ 同一条指令
        # 满足子树」求值）。子树内部正常翻译 + 语义保持化简。
        sub = v if isinstance(v, list) else [v]
        r = _xform_and(sub, match_names)
        if r is TRUE:
            return TRUE
        if r is FALSE:
            return FALSE
        STATS["指令级保留"] += 1
        return {"instruction": r}
    if k == "call":
        # call 作用域（调用点级）本引擎表达不了
        return FALSE
    m_cnt = re.fullmatch(r"(\d+) or more", str(k))
    if m_cnt:
        return _xform_count(int(m_cnt.group(1)), v or [], match_names)
    return _xform_leaf({k: v}, match_names)


def _xform_count(need: int, items, match_names):
    """计数算子「至少 N 个子项命中」的语义保持化简。

    FALSE 子项不计数直接丢弃；TRUE 子项直接计入命中数；
    剩余树总数不足 N → 恒假；TRUE 已够 N → 恒真；
    否则输出阈值下调后的计数节点（阈值 = N - 已恒真数）。
    """
    true_n = 0
    trees = []
    for it in _strip_desc(items):
        r = xform(it, match_names)
        if r is FALSE:
            continue
        if r is TRUE:
            true_n += 1
            continue
        trees.append(r)
    if true_n >= need:
        return TRUE
    if true_n + len(trees) < need:
        return FALSE
    left = need - true_n
    if left == 1:
        return trees[0] if len(trees) == 1 else {"or": trees}
    if left == len(trees):
        return trees[0] if len(trees) == 1 else {"and": trees}
    return {"%d or more" % left: trees}


def _strip_desc(items):
    """去掉叶子旁的 description 注释键（同级 dict 形式）。"""
    out = []
    for it in items:
        if isinstance(it, dict):
            it = {k: v for k, v in it.items() if k != "description"}
            if it:
                out.append(it)
        else:
            out.append(it)
    return out


def _xform_and(items, match_names):
    kids = []
    for it in _strip_desc(items):
        r = xform(it, match_names)
        if r is FALSE:
            return FALSE
        if r is TRUE:
            continue
        kids.append(r)
    if not kids:
        return TRUE
    if len(kids) == 1:
        return kids[0]
    return {"and": kids}


def _xform_or(items, match_names):
    kids = []
    for it in _strip_desc(items):
        r = xform(it, match_names)
        if r is TRUE:
            return TRUE
        if r is FALSE:
            continue
        kids.append(r)
    if not kids:
        return FALSE
    if len(kids) == 1:
        return kids[0]
    return {"or": kids}


def _xform_leaf(d: dict, match_names: set):
    """翻译单个叶子。返回新叶子 / TRUE / FALSE。"""
    if len(d) != 1:
        return _xform_and([{k: v} for k, v in d.items()], match_names)
    kind, val = next(iter(d.items()))
    if kind not in LEAF_OK:
        return FALSE          # bytes / offset 等引擎产不出
    if kind == "match":
        names = val if isinstance(val, list) else [val]
        names = [str(x) for x in names]
        if all(n in match_names for n in names):
            return {"match": names[0] if len(names) == 1 else names}
        return FALSE          # 悬空引用 ≡ 恒假
    if kind == "characteristic":
        mapped = CHAR_MAP.get(str(val).strip().lower())
        if mapped and mapped in R.ENGINE_CHARACTERISTICS:
            return {"characteristic": mapped}
        return FALSE
    if kind == "string" or kind == "substring":
        s = str(val)
        m = re.match(r"^/(.*)/([ia]*)$", s)
        if m and R._rx_compile(m.group(1), m.group(2)) is None:
            return FALSE      # 非法正则：宁可放弃也不静默失效
        return {kind: s}
    if kind == "number":
        # capa 数值特征带 `= 注释` 后缀（如 `0xCC = INT3`），取等号左边
        s = re.split(r"\s*=\s*", str(val), maxsplit=1)[0].strip()
        try:
            return {"number": int(s, 0)}
        except (TypeError, ValueError):
            return FALSE      # 带通配/区间的复杂数值，引擎判不了
    if kind == "offset":
        # 位移特征：引擎已支持（InsnFeat.disp），同样剥注释
        s = re.split(r"\s*=\s*", str(val), maxsplit=1)[0].strip()
        try:
            STATS["offset保留"] += 1
            return {"offset": int(s, 0)}
        except (TypeError, ValueError):
            return FALSE
    if kind == "bytes":
        # 字节序列：引擎已支持指令级求值（InsnFeat.raw），原样保留。
        # capa 的 bytes 值同样带 `= CLSID_xxx` 注释后缀，先剥掉 ——
        # 不剥的话 _bytes_rx 把注释当模式文本，报「模式非法」。
        s = re.split(r"\s*=\s*", str(val), maxsplit=1)[0].strip()
        if s:
            STATS["bytes保留"] += 1
            return {"bytes": s}
        return FALSE
    # 其余标量叶子：api / mnemonic / section / import / export /
    # function-name / tag / os / arch / format
    s = str(val).strip()
    if not s:
        return FALSE
    return {kind: s}


# --------------------------------------------------------------- YAML 输出
def _scalar_out(v) -> str:
    """输出一个标量。引号只用最朴素的形式，与自研解析器 _scalar 对齐。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v).replace("\n", " ").strip()
    # 必须加引号的情形：
    # 1) 会被 _scalar 误判成布尔/数字/空的值；
    # 2) 以 [ { & * ! | > 等开头（自研解析器会当成流式集合/锚点拒绝）；
    # 3) 含 ": " 或 " #"（会被当成 key: value 或注释截断）
    need_quote = (
        not s
        or s.lower() in ("true", "yes", "false", "no", "null", "~")
        or re.fullmatch(r"[-+]?(?:0[xX][0-9a-fA-F_]+|\d[\d_]*)", s)
        or re.fullmatch(r"[-+]?(?:\d[\d_]*\.\d*|\d*\.\d+)(?:[eE][-+]?\d+)?", s)
        or s[0] in "[{'\"&*!|>%@`,#-"
        or s.endswith(":")
        or ": " in s
        or " #" in s
    )
    if need_quote:
        s = s.replace('"', "'")
        return '"%s"' % s
    return s


def _emit(node, indent: int, out: list):
    pad = "  " * indent
    if isinstance(node, list):
        for it in node:
            if isinstance(it, dict):
                first = True
                for k, v in it.items():
                    if first and not isinstance(v, (dict, list)):
                        out.append("%s- %s: %s" % (pad, k, _scalar_out(v)))
                    elif first:
                        out.append("%s- %s:" % (pad, k))
                        _emit(v, indent + 2, out)
                    else:
                        if isinstance(v, (dict, list)):
                            out.append("%s  %s:" % (pad, k))
                            _emit(v, indent + 2, out)
                        else:
                            out.append("%s  %s: %s" % (pad, k, _scalar_out(v)))
                    first = False
            elif isinstance(it, list):
                out.append("%s-" % pad)
                _emit(it, indent + 1, out)
            else:
                out.append("%s- %s" % (pad, _scalar_out(it)))
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                out.append("%s%s:" % (pad, k))
                _emit(v, indent + 1, out)
            else:
                out.append("%s%s: %s" % (pad, k, _scalar_out(v)))
        return
    out.append("%s%s" % (pad, _scalar_out(node)))


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:70] or "rule"


# --------------------------------------------------------------- 主流程
def load_all(src: str):
    """扫出所有 capa 规则文档，返回 (路径, doc) 列表。"""
    docs = []
    for root, dirs, fns in os.walk(src):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fn in sorted(fns):
            if not fn.endswith((".yml", ".yaml")):
                continue
            fp = os.path.join(root, fn)
            try:
                for d in R.yaml_load_all_file(fp):
                    if isinstance(d, dict) and "rule" in d:
                        STATS["扫描"] += 1
                        docs.append((fp, d["rule"]))
            except Exception:
                STATS["解析失败"] += 1
    return docs


def convert(docs):
    """两阶段：先收集可翻译规则名（match 依赖），再不动点裁剪。"""
    # 阶段一：叶子层翻译（不含 match 裁剪），收集全部名字
    prepared = {}
    for fp, rule in docs:
        meta = rule.get("meta") or {}
        name = str(meta.get("name") or "").strip()
        if not name:
            continue
        scopes = meta.get("scopes") or {}
        st = str((scopes or {}).get("static") or meta.get("scope") or "").strip().lower()
        if not st:
            STATS["无 scope"] += 1
            continue
        if st not in SCOPE_MAP:
            STATS["动态only"] += 1
            continue
        prepared[name] = {"fp": fp, "rule": rule, "meta": meta, "static": st}

    all_names = set(prepared)
    # 阶段二：不动点裁剪（match 链逐层坍缩到稳定）
    alive = set(all_names)
    while True:
        removed = False
        for name in list(alive):
            feats = prepared[name]["rule"].get("features")
            r = xform(feats, alive)
            if r is FALSE:
                alive.discard(name)
                removed = True
        if not removed:
            break

    # 不动点阶段会重复化简同一条规则，保留计数只统计最终产出的一遍
    STATS["指令级保留"] = 0
    STATS["块级保留"] = 0
    STATS["offset保留"] = 0
    STATS["bytes保留"] = 0

    out_rules = []
    for name in sorted(alive):
        p = prepared[name]
        meta = p["meta"]
        scope = SCOPE_MAP[p["static"]]
        if scope == "basic block":
            STATS["块级保留"] += 1
        r = xform(p["rule"].get("features"), alive)
        if r is TRUE:
            continue
        # 没有逻辑包装的单叶子要包一层，features 直接是叶子 dict 也合法
        features = r
        refs = []
        rf = meta.get("references") or []
        if isinstance(rf, str):
            rf = [rf]
        refs.extend(str(x) for x in rf)
        refs.append("%s（规则来源，Apache-2.0）" % SRC_URL)

        nm = {
            "name": name,
            # capa 的 lib/ 共享辅助规则没有 namespace。空 namespace 会让
            # CLI 契约检查落空、命中被归到「未分类」——如实标成 lib。
            "namespace": str(meta.get("namespace") or "").strip() or "lib",
            "scope": scope,
            "authors": [str(a) for a in (meta.get("authors") or [])],
            "description": (str(meta.get("description") or "").strip()
                            or name),
            "references": refs,
        }
        # 辅助规则标记（capa 的 lib: true）：只应被 match: 引用，
        # 不构成能力结论（引擎 Rule.lib 据此剔除）。
        if meta.get("lib"):
            nm["lib"] = True
        ac = meta.get("att_ck") or meta.get("att&ck") or meta.get("attack")
        if isinstance(ac, str):
            ac = [ac]
        if ac:
            nm["att_ck"] = [str(x) for x in ac]
        out_rules.append((nm, features))
    STATS["翻译成功"] = len(out_rules)
    return out_rules


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    os.makedirs(dst, exist_ok=True)
    docs = load_all(src)
    rules = convert(docs)

    for nm, feats in rules:
        lines = ["rule:", "  meta:"]
        _emit(nm, 2, lines)
        lines.append("  features:")
        # features 是「列表」时逐项挂到 features: 下；单节点包一层列表
        _emit(feats if isinstance(feats, list) else [feats], 2, lines)
        fp = os.path.join(dst, _slug(nm["name"]) + ".yml")
        with open(fp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    # 自检：产出的规则必须能被自家加载器零错误载入
    loaded, errs = R.load_rules(dst)
    print("翻译统计：", STATS)
    print("产出规则：%d 条 → %s" % (len(loaded), dst))
    if errs:
        print("加载错误（必须为 0）：")
        for e in errs[:10]:
            print("  -", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
