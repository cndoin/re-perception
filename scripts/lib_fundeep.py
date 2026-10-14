"""
lib_fundeep.py —— 函数深度挖掘（fundeep）。

对**单个函数**做全维度深挖，把散在 funcs/cfg/struct/ir/semantics/xref 里的
视图聚合到一份「函数档案」上，并补上三个真正的深挖维度：

  1. 调用链递归展开 —— 从目标函数向下展开 N 层（--depth），每层给函数摘要，
     外部导入算叶子；预算耗尽如实标 partial；
  2. 数据引用归集 —— 本函数指令引用了哪些字符串 / 导入 API / 大常量
     （按 imm / mem_ref 与字符串表、IAT 槽位精确命中登记）；
  3. 相似函数 —— 目标函数指纹与同文件其他函数逐个比对（compare_funcs
     统一裁决点），给 top-k 与相似判定（verdict/三项分）。

再给一份「下一步建议」（hints）：按本次挖掘出的证据列出多条可走的分析路径
（每条给具体命令），把选择权交给调用方（人或模型）。

诚实边界：
  · addr 不在识别出的函数里 → ok:false + 候选地址清单，不猜、不取最近的；
  · 调用链/相似比对有预算，触顶 → partial + truncated_note 说明缺了哪段；
  · 字符串/常量引用只按精确命中登记，不按「地址相近」发散；
  · 语义标签来自 lib_semantics 的启发式画像，是线索不是定论。
"""

from __future__ import annotations

from lib_code import (CodeIndex, compare_funcs, find_functions, build_xrefs)
from lib_disasm import UnsupportedArch, code_regions, entry_points, \
    symbols_from
from lib_formats import Reader
from lib_ir import structure_function

# 预算：调用链展开
_CHAIN_MAX_NODES = 80        # 展开的函数节点总数上限
_CHAIN_FANOUT = 10           # 每个节点最多继续展开的出边数
_SIM_TOP = 5                 # 相似函数 top-k
_SIM_MIN_SCORE = 0.5         # 低于此分不算相似
_CONST_MIN = 0x10000         # 大常量阈值


def _parse_addr(addr) -> int | None:
    """地址容错解析：int / '0x...' / 裸 hex 串都收，**一律按十六进制**
    （与 cfg/struct 的 addr 契约一致：'140001094' 即 0x140001094）。
    解析不了返回 None。"""
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        s = addr.strip().replace("0x", "").replace("0X", "")
        try:
            return int(s, 16)
        except ValueError:
            return None
    return None


def _call_chain(funcs_by_vma: dict[int, dict], iat: dict[int, str],
                thunks: dict[int, str], start_vmas: list[int],
                depth: int) -> tuple[list[dict], bool, int]:
    """从 start_vmas BFS 向下展开 depth 层，返回 (nodes, truncated, skipped)。

    internal 函数给摘要并继续展开；import（IAT/thunk 命中）与 unknown
    是叶子。预算触顶如实报告，不把半棵树当整棵树。
    """
    nodes: list[dict] = []
    seen: set[int] = set()
    frontier: list[tuple[int, int]] = [(v, 1) for v in start_vmas]
    truncated = False
    skipped = 0
    while frontier:
        vma, d = frontier.pop(0)
        if vma in seen:
            continue
        seen.add(vma)
        if len(nodes) >= _CHAIN_MAX_NODES:
            truncated = True
            skipped += len(frontier)
            break
        f = funcs_by_vma.get(vma)
        api = thunks.get(vma) or iat.get(vma)
        if f is not None:
            nodes.append({
                "depth": d, "addr": hex(vma), "name": f.get("name"),
                "kind": "internal", "size": f.get("size"),
                "insn_count": f.get("insn_count"),
            })
            if d < depth:
                for c in (f.get("calls") or [])[:_CHAIN_FANOUT]:
                    if c not in seen:
                        frontier.append((c, d + 1))
        elif api:
            nodes.append({"depth": d, "addr": hex(vma), "name": api,
                          "kind": "import"})
        else:
            nodes.append({"depth": d, "addr": hex(vma), "name": None,
                          "kind": "unknown"})
    return nodes, truncated, skipped


def _data_refs(idx: CodeIndex, f: dict, str_map: dict[int, str],
               iat: dict[int, str], thunks: dict[int, str]) -> dict:
    """归集本函数指令引用的字符串 / 导入 API / 大常量（只按精确命中）。"""
    strings: list[dict] = []
    imports: list[dict] = []
    consts: list[dict] = []
    seen_s: set[int] = set()
    seen_i: set[str] = set()
    seen_c: set[int] = set()
    for o in f.get("_offs") or []:
        ins = idx.insn.get(o)
        if ins is None:
            continue
        # 字符串：imm / mem_ref 直接命中字符串表键
        for a in (ins.imm, ins.mem_ref):
            if isinstance(a, int) and a in str_map and a not in seen_s:
                seen_s.add(a)
                strings.append({"vma": hex(a), "text": str_map[a][:80]})
        # 导入：call/jmp 目标或内存引用命中 IAT 槽位 / thunk 跳板
        for t in (ins.target, ins.mem_ref):
            if not isinstance(t, int):
                continue
            api = thunks.get(t) or iat.get(t)
            if api and api not in seen_i:
                seen_i.add(api)
                imports.append({"vma": hex(t), "api": api})
        # 大常量：排除已有归属（字符串/导入地址）的值
        im = ins.imm
        if (isinstance(im, int) and abs(im) >= _CONST_MIN
                and im not in seen_c and im not in str_map
                and im not in iat and im not in thunks):
            seen_c.add(im)
            consts.append({"value": hex(im & 0xFFFFFFFFFFFFFFFF)})
    return {"strings": strings[:16], "imports": imports[:16],
            "constants": consts[:12]}


def _similar(target: dict, funcs: list[dict]) -> list[dict]:
    """目标函数指纹 vs 同文件其他函数，逐个比对取 top-k。"""
    tfp = target.get("fingerprint") or {}
    out: list[dict] = []
    for g in funcs:
        if g.get("start_vma") == target.get("start_vma"):
            continue
        r = compare_funcs(tfp, g.get("fingerprint") or {})
        score = r.get("score", 0.0)
        if score >= _SIM_MIN_SCORE:
            out.append({
                "addr": hex(g.get("start_vma") or 0),
                "name": g.get("name"),
                "score": score,
                "verdict": r.get("verdict"),
                "mnem_jaccard": r.get("mnem_jaccard"),
                "simhash_distance": r.get("simhash_distance"),
                "size_affinity": r.get("size_affinity"),
            })
    out.sort(key=lambda x: -x["score"])
    return out[:_SIM_TOP]


def _hints(d: dict) -> list[dict]:
    """按挖掘证据生成多条下一步路径（每条给具体命令），选择权交给调用方。"""
    hs: list[dict] = []
    t = d.get("target") or {}
    addr = t.get("addr", "")
    path = d.get("path", "")
    st = d.get("structure") or {}
    if st.get("switches"):
        hs.append({"why": "识别到 %d 个 switch，值得看分支全景"
                          % len(st["switches"]),
                   "cmd": "struct %s %s --ir" % (path, addr)})
    if st.get("loops"):
        hs.append({"why": "识别到 %d 个循环，看循环条件与出口"
                          % len(st["loops"]),
                   "cmd": "cfg %s %s" % (path, addr)})
    if (d.get("calls") or {}).get("callees"):
        hs.append({"why": "有 %d 个出向调用，可对照完整调用图"
                          % len(d["calls"]["callees"]),
                   "cmd": "xref %s" % path})
    sem = d.get("semantics") or {}
    if sem.get("api_calls"):
        hs.append({"why": "调用了 %d 个 API，可看行为标签与 ATT&CK 映射"
                          % len(sem["api_calls"]),
                   "cmd": "capability %s" % path})
    if (d.get("data_refs") or {}).get("strings"):
        hs.append({"why": "引用了 %d 条字符串，可看混淆字符串恢复"
                          % len(d["data_refs"]["strings"]),
                   "cmd": "obfstr %s" % path})
    if d.get("similar"):
        hs.append({"why": "找到 %d 个相似函数，可用 sim 与另一份样本对比验证"
                          % len(d["similar"]),
                   "cmd": "sim <样本A> <样本B>"})
    if not hs:
        hs.append({"why": "线索较少，从完整反汇编入手",
                   "cmd": "disasm %s" % path})
    hs.append({"why": "把本函数结论包装成可溯源证据",
               "cmd": "evidence add --text '<结论>' --source fundeep"})
    return hs


def deep_function(path: str, addr, depth: int = 2, with_ir: bool = False,
                  no_strings: bool = False, no_libscan: bool = False,
                  max_insns: int = 300000, max_functions: int = 2000,
                  region: str | None = None) -> dict:
    """函数深度挖掘入口。addr 必填（VMA），给出该函数的全维度档案。"""
    from lib_disasm import identify, resolve_iat
    from lib_semantics import (resolve_thunks, string_vma_map,
                               summarize_functions)

    try:
        ident = identify(path, deep=True)
    except (OSError, ValueError) as e:
        return {"ok": False, "error": "识别失败：%s" % e}

    regions = code_regions(ident)
    if not regions:
        return {"ok": False, "error": "未找到可执行代码区",
                "format": ident.get("format")}
    r = regions[0]
    if region:
        for cand in regions:
            if cand["name"].lower() == region.lower():
                r = cand
                break

    with Reader(path) as rd:
        code = rd.read(r["file_off"], r["size"])
    if not code:
        return {"ok": False, "error": "代码区读取失败"}

    # 架构分发走 lib_disasm.backend 唯一裁决点（CodeIndex 构造即分发），
    # 未知架构 fail-closed，绝不拿 x86 解码器兜底。
    try:
        idx = CodeIndex(code, base_vma=r["vma"], bits=r["bits"],
                        arch=r["arch"], max_insns=max_insns)
    except UnsupportedArch as e:
        return {"ok": False, "error": str(e), "arch": r["arch"],
                "unsupported_arch": True}

    want = _parse_addr(addr)
    if want is None:
        return {"ok": False, "error": "地址格式错误: %s" % addr}

    stats: dict = {}
    funcs = find_functions(idx, seeds=entry_points(ident),
                           symbols=symbols_from(ident),
                           max_functions=max(1, max_functions),
                           stats=stats)
    target = None
    for f in funcs:
        if f["start_vma"] == want or (f["start_vma"] <= want < f["end_vma"]):
            target = f
            break
    if target is None:
        return {
            "ok": False,
            "error": "未找到地址 %s 对应的函数" % addr,
            "hint": "共识别 %d 个函数，候选入口：%s" % (
                len(funcs),
                "、".join(hex(g["start_vma"]) for g in funcs[:8])),
        }

    funcs_by_vma = {g["start_vma"]: g for g in funcs}
    xrefs = build_xrefs(idx, funcs)
    iat = resolve_iat(ident)
    thunks = resolve_thunks(idx, funcs, iat)

    str_map: dict[int, str] = {}
    str_err = None
    if not no_strings:
        try:
            str_map = string_vma_map(path, ident)
        except Exception as e:          # 字符串映射失败不该拖垮主流程
            str_err = "%s: %s" % (type(e).__name__, e)

    # 语义画像：只取目标函数条目，弹掉 _ 前缀的传播用私有字段
    sem = {}
    sums = summarize_functions(idx, funcs, iat, str_map,
                               limit=max_functions, thunk_map=thunks)
    for s in sums:
        if s.get("start_vma") == hex(target["start_vma"]):
            sem = {k: v for k, v in s.items() if not k.startswith("_")}
            break

    # 静态库函数/密码学常量识别（失败不该拖垮主流程）
    lib_hint = None
    lib_err = None
    if not no_libscan:
        try:
            from lib_libscan import identify_libfuncs, scan_const_tables
            const_hits = scan_const_tables(path, ident)
            hints_map = identify_libfuncs(idx, funcs, const_hits)
            h = hints_map.get(target["start_vma"])
            if h:
                lib_hint = {k: v for k, v in h.items() if k != "start_vma"}
        except Exception as e:
            lib_err = "%s: %s" % (type(e).__name__, e)

    structure = structure_function(idx, target.get("_offs") or [],
                                   name=target.get("name", ""),
                                   with_ir=with_ir)

    # 调用面：callees 分类 + callers + 递归展开
    callees = []
    for c in target.get("calls") or []:
        api = thunks.get(c) or iat.get(c)
        if c in funcs_by_vma:
            callees.append({"addr": hex(c), "name": funcs_by_vma[c]["name"],
                            "kind": "internal"})
        elif api:
            callees.append({"addr": hex(c), "name": api, "kind": "import"})
        else:
            callees.append({"addr": hex(c), "name": None, "kind": "unknown"})
    callers = [{"addr": a, "name": (funcs_by_vma.get(_parse_addr(a)) or {})
                .get("name")}
               for a in (xrefs["callers"].get(hex(target["start_vma"])) or [])]
    chain, chain_trunc, chain_skipped = _call_chain(
        funcs_by_vma, iat, thunks,
        [c for c in (target.get("calls") or [])], max(1, depth))

    similar = _similar(target, funcs)

    partial = bool(idx.truncated) or bool(stats.get("skipped_seeds")) \
        or chain_trunc
    notes = []
    if idx.truncated:
        notes.append("指令预算 %d 已用尽，只覆盖已解码片段" % idx.max_insns)
    if stats.get("skipped_seeds"):
        notes.append("还有 %d 个候选函数没识别（达到上限）"
                     % stats["skipped_seeds"])
    if chain_trunc:
        notes.append("调用链展开到 %d 个节点即触顶，还有 %d 个节点没展开；"
                     "提高 --depth 或 --max-functions 可补全"
                     % (_CHAIN_MAX_NODES, chain_skipped))
    if str_err:
        notes.append("字符串映射失败，data_refs.strings 不完整：%s" % str_err)
    if lib_err:
        notes.append("库函数识别失败，lib_hint 缺失：%s" % lib_err)

    out = {
        "ok": True,
        "path": path,
        "format": ident.get("format"),
        "arch": r["arch"],
        "region": r["name"],
        "base_vma": hex(r["vma"]),
        "target": {
            "addr": hex(target["start_vma"]),
            "name": target.get("name"),
            "end": hex(target["end_vma"]),
            "size": target.get("size"),
            "insn_count": target.get("insn_count"),
            "bb_count": target.get("bb_count"),
            "fingerprint": target.get("fingerprint"),
        },
        "structure": {k: v for k, v in structure.items() if k != "ir"},
        "calls": {
            "callees": callees,
            "callers": callers,
            "chain": chain,
            "chain_depth": max(1, depth),
        },
        "data_refs": _data_refs(idx, target, str_map, iat, thunks),
        "semantics": sem,
        "similar": similar,
        "partial": partial,
    }
    if with_ir:
        out["ir"] = structure.get("ir") or []
    if lib_hint:
        out["lib_hint"] = lib_hint
    if notes:
        out["truncated_note"] = "；".join(notes)
    out["hints"] = _hints(out)
    return out
