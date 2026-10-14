"""
lib_ir.py —— 轻量 IR 提升 + 控制流结构化（if / loop / switch 识别）

这是「看懂程序」的分水岭层：把指令流折算成中间表示，再把 CFG 折算成
人能读的控制流结构（哪里是循环、哪里是分支、哪里是 switch）。

两件事：
  1. 轻量 IR 提升（lift_insn）：把 lib_x86 / lib_arm 解出的 Insn 归类成
     语义操作（assign / binop / load / store / call / branch / cond / ret ...），
     并从渲染出的操作数文本里解析 dst / srcs / imm。
  2. 控制流结构化（structure_function）：支配树 + 后支配树 + 回边分析，
     识别自然循环（while / do-while）、条件分支（if-then / if-then-else /
     if-exit）、比较链 switch、间接跳转候选，输出函数级结构摘要与
     伪代码骨架文本。

算法取舍（参照开源实现，写明边界）：
  · 支配树用 Cooper-Harvey-Kennedy 迭代算法（Ghidra/IDA 同族做法）；
    循环识别用「回边 + 自然循环」——这是 Cifuentes《dcc 反编译器》结构化
    算法的第一步，只对**可归约 CFG** 保证正确；不可归约区域如实降级为
    原始块清单，不硬凑结构。
  · if 识别用后支配树找汇合点（join）：两臂都到达 join → if-then-else；
    一臂直达 join → if-then；到不了共同汇合点（各自 return）→ if-exit。
  · switch 识别两条证据线：①比较链（≥3 个条件节点比较同一寄存器且
    fallthrough 串成链）；②间接跳转（jmp reg / jmp [mem]）。后者**只报
    候选**——静态上无法与虚调用/尾调用区分，不硬说是 switch。

诚实边界（很重要，别删）：
  · IR 的 dst/srcs 来自**渲染文本的解析**（不是完整操作数解码），
    带括号内存/ARM 寄存器对的复杂形态标 approx=True。
  · 条件表达式（cond.text）由块内最后一条 cmp/test + 跳转极性推导，
    是启发式；推不出时只给原始助记符，不编造。
  · 预算截断（max_insns / max_functions）如实标 partial + truncated_note。

公开接口：
    lift_insn(ins) -> dict                  单条指令 → IR 语句
    structure_function(idx, offs, ...) -> dict   单函数结构化
    structure_file(path, ...) -> dict            文件级入口（CLI 用）
"""

from collections import defaultdict

from lib_x86 import (K_CALL, K_CJMP, K_JMP, K_RET, K_HLT, K_INT, K_INVALID,
                     Insn)

# ---------------------------------------------------------------- IR 分类表

# 直接按语义归类的助记符（两架构共用；优先按 kind 判，kind 无法区分时用这里）
_M_ASSIGN = {"mov", "movzx", "movsx", "movsxd", "movabs", "lea", "xchg",
             "movz", "movk", "movn", "adr", "adrp", "sxtb", "sxth", "sxtw",
             "uxtb", "uxth", "bfxil", "ubfx", "sbfx", "extr", "rev", "rev16",
             "rev32", "rev64", "clz", "rbit", "crc32", "csel", "cset", "csinc",
             "csinv", "csneg", "csetm"}
_M_BINOP = {"add", "sub", "adc", "sbb", "and", "or", "xor", "shl", "shr",
            "sar", "rol", "ror", "rcl", "rcr", "imul", "mul", "div", "idiv",
            "bt", "bts", "btr", "btc", "andn", "orn", "eon", "lsl", "lsr",
            "asr", "madd", "msub", "smull", "umull", "sdiv", "udiv", "udiv",
            "negs", "adcs", "sbcs", "bics"}
_M_UNOP = {"inc", "dec", "neg", "not", "ngc"}
_M_CMP = {"cmp", "test", "tst", "cmn", "cmpp"}
_M_STACK = {"push", "pop", "pushf", "popf", "pusha", "popa"}
_M_TRAP = {"syscall", "sysenter", "int", "int1", "int3", "ud2", "hlt",
           "svc", "brk", "smc", "hvc", "udf"}
_M_NOP = {"nop", "endbr64", "endbr32", "hint", "yield", "wfe", "wfi", "sev",
          "sevl", "isb", "dsb", "dmb", "clrex", "yield"}
_M_BITOP = {"bsf", "bsr", "popcnt", "tzcnt", "lzcnt", "bswap"}

_ASSIGN_PREFIX = ("cmov", "vmov", "movd", "movq", "set")
_SIMD_ARITH_PREFIX = ("addp", "subp", "andp", "or", "xor", "padd", "psub",
                      "pmul", "pand", "por", "pxor")


def _split_ops(ops: str) -> list[str]:
    """按顶层逗号切分操作数（忽略 [] 内的逗号——ARM 的 [sp, #-16]! 这类）。"""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in ops or "":
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            piece = "".join(cur).strip()
            if piece:
                out.append(piece)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _has_mem(tok: str) -> bool:
    return "[" in tok or "ptr" in tok


def _imm_of(ins, operands: list[str]):
    """取立即数：优先解码器给的 ins.imm，否则从操作数文本里认。"""
    if ins.imm is not None:
        return ins.imm
    for tok in reversed(operands):
        t = tok.strip().lstrip("#")
        try:
            return int(t, 0)
        except ValueError:
            continue
    return None


def lift_insn(ins: Insn) -> dict:
    """
    单条指令 → 轻量 IR 语句：
        {op, dst, srcs, imm, target, mnem, text, vma, approx}

    分类顺序：kind（控制流类别，两架构解码器都标得很准）优先，
    其次助记符表，最后兜底 other。绝不抛异常。
    """
    mn = (ins.mnem or "").lower()
    operands = _split_ops(ins.ops)
    approx = False

    # ---- kind 优先：控制流语义与架构无关 ----
    if ins.kind == K_CALL:
        op = "call"
    elif ins.kind == K_CJMP:
        op = "cond"
    elif ins.kind == K_JMP:
        op = "branch"
    elif ins.kind == K_RET:
        op = "ret"
    elif ins.kind in (K_HLT,):
        op = "trap"
    elif ins.kind == K_INT:
        op = "trap" if mn in _M_TRAP else "other"
    elif ins.kind == K_INVALID:
        op = "invalid"
    else:
        op = None

    # ---- 助记符表 ----
    if op is None:
        if mn in _M_CMP:
            op = "cmp"
        elif mn in _M_ASSIGN or mn.startswith(_ASSIGN_PREFIX):
            op = "assign"
        elif mn in _M_BINOP:
            op = "binop"
        elif mn in _M_UNOP:
            op = "unop"
        elif mn in _M_STACK:
            op = "stack"
        elif mn in _M_TRAP:
            op = "trap"
        elif mn in _M_NOP:
            op = "nop"
        elif mn in _M_BITOP:
            op = "binop"
        elif mn.startswith("ldr") or mn.startswith("ldp") or mn.startswith("ldur"):
            op = "load"
        elif mn.startswith("str") or mn.startswith("stp") or mn.startswith("stur"):
            op = "store"
        elif mn.startswith(_SIMD_ARITH_PREFIX):
            op = "binop"
        else:
            op = "other"

    # ---- load / store 细分（x86 的 mov 内存形态 / ARM 已由前缀定） ----
    if op == "assign" and operands:
        if _has_mem(operands[0]):
            op = "store"
        elif len(operands) > 1 and _has_mem(operands[1]):
            op = "load"

    # ---- dst / srcs ----
    dst, srcs = None, []
    if op in ("assign", "binop", "unop", "load", "cmp"):
        if operands:
            dst = operands[0]
            srcs = operands[1:]
    elif op == "store":
        # 内存是目的、寄存器/立即数是源
        if operands:
            dst = operands[0]
            srcs = operands[1:]
    elif op in ("call", "branch", "cond", "ret", "trap", "stack", "other",
                "invalid", "nop"):
        srcs = list(operands)
        if op == "call" and operands:
            dst = operands[0]          # call 的目标记在 dst（对齐 xref 语义）

    # 括号内存 / 多寄存器对这类复杂形态，文本解析保真度有限，如实标注：
    # ① 括号内部带逗号（ARM [sp, #-16]! 这类）；
    # ② 数据移动类指令三操作数及以上（ldp x0,x1,[sp] 寄存器对 /
    #    imul eax,ebx,5）—— dst/srcs 二元模型表达不了，硬拆会错。
    joined = " ".join(operands)
    if "[" in joined and ("," in joined.split("[", 1)[-1]):
        approx = True
    if len(operands) > 2 and op in ("assign", "load", "store", "binop"):
        approx = True

    out = {
        "op": op,
        "dst": dst,
        "srcs": srcs,
        "imm": _imm_of(ins, operands),
        "target": hex(ins.target) if ins.target is not None else None,
        "mem_ref": hex(ins.mem_ref) if ins.mem_ref is not None else None,
        "mnem": mn,
        "text": ins.text,
        "vma": hex(ins.vma),
        "approx": approx,
    }
    return out


# ---------------------------------------------------------------- 图算法

def _dominators(nodes: list[int], succs: dict, entry: int) -> dict:
    """Cooper-Harvey-Kennedy 迭代求支配集。nodes 用块 id。"""
    if not nodes:
        return {}
    all_set = set(nodes)
    dom = {n: set(all_set) for n in nodes}
    dom[entry] = {entry}
    # 前驱表只算一次（曾放在内层循环里，O(n³) 级浪费）
    preds = _preds_of(succs, nodes)
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == entry:
                continue
            pl = preds.get(n, [])
            if not pl:
                new = {n}
            else:
                new = set(dom[pl[0]])
                for p in pl[1:]:
                    new &= dom[p]
                new.add(n)
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom


def _preds_of(succs: dict, nodes: list[int]) -> dict:
    preds: dict[int, list[int]] = {n: [] for n in nodes}
    for u in nodes:
        for v in succs.get(u, []):
            if v in preds:
                preds[v].append(u)
    return preds


def _post_dominators(nodes: list[int], succs: dict, entry: int) -> dict:
    """
    后支配集：把图反向后求支配。多出口（多个 ret）通过虚拟出口 ⊥ 汇聚，
    ⊥ 只在内部使用，不出现在结果里。
    """
    if not nodes:
        return {}
    EX = -1                      # 虚拟出口
    rsuccs: dict[int, list[int]] = {n: [] for n in nodes}
    rsuccs[EX] = []
    for n in nodes:
        out_edges = [v for v in succs.get(n, [])]
        if not out_edges:
            rsuccs[EX].append(n)     # 反向图里 ⊥ → 出口块
        for v in out_edges:
            if v in rsuccs:
                rsuccs[v].append(n)
    all_nodes = list(nodes) + [EX]
    pdom = _dominators(all_nodes, rsuccs, EX)
    return {n: (pdom.get(n, set()) - {EX}) for n in nodes}


def _natural_loops(nodes, succs, preds, dom):
    """回边（v 支配 u 的边 u→v）→ 自然循环。返回 [(header, tail, loop_nodes)]。"""
    loops = []
    for u in nodes:
        for v in succs.get(u, []):
            if v not in dom.get(u, set()):
                continue                     # 不是回边
            body = {v}
            stack = [u]
            while stack:
                x = stack.pop()
                if x in body:
                    continue
                body.add(x)
                stack.extend(preds.get(x, []))
            loops.append((v, u, body))
    return loops


# ---------------------------------------------------------------- 条件推导

# x86 条件码 → 运算符（jcc 的 mnem[1:] 就是条件码）
_CC_TEXT = {
    "e": "==", "z": "==", "ne": "!=", "nz": "!=",
    "l": "<", "ge": ">=", "le": "<=", "g": ">",
    "b": "<(u)", "ae": ">=(u)", "be": "<=(u)", "a": ">(u)",
    # 符号标志条件作用于最近运算结果，等价于「结果与 0 比符号」：
    # cmp x,y 后 jns ≡ x>=y；test x,x 后 jns ≡ x>=0。因此映射成普通
    # 运算符、由渲染层拼右操作数。曾映射为 "<0"/">=0"，会渲染出
    # `eax >=0 0` 这种畸形文本。
    "s": "<", "ns": ">=",
    "o": "溢出", "no": "不溢出", "p": "偶校验", "np": "奇校验",
}
# ARM b.cond 的条件码（去掉点前缀后匹配）
_CC_TEXT.update({
    "eq": "==", "ne": "!=", "lt": "<", "ge": ">=", "le": "<=", "gt": ">",
    "mi": "<", "pl": ">=",
    "vs": "溢出", "vc": "不溢出",
})
# 描述类条件码（无法表达成二元比较，渲染时不拼操作数）
_CC_DESC = {"溢出", "不溢出", "偶校验", "奇校验"}


def _cond_of_block(idx, block_offs: list[int], term_mnem: str):
    """
    由块内最后一条 cmp/test + 终结跳转的极性，推导条件表达式。
    推不出来返回 None（只给原始助记符），不编造。
    """
    # 找块内最后一条比较指令
    cmp_ins = None
    for o in reversed(block_offs):
        ins = idx.insn.get(o)
        if ins is None:
            continue
        mn = (ins.mnem or "").lower()
        if mn in _M_CMP:
            cmp_ins = ins
            break
    mn = (term_mnem or "").lower()

    # cbz / cbnz / tbz / tbnz（ARM）自带比较语义
    if mn in ("cbz", "cbnz", "tbz", "tbnz"):
        ops = _split_ops(idx.insn[block_offs[-1]].ops if block_offs else "")
        reg = ops[0] if ops else "?"
        if mn == "cbz":
            return {"text": "%s == 0" % reg, "approx": False}
        if mn == "cbnz":
            return {"text": "%s != 0" % reg, "approx": False}
        bit = ops[1] if len(ops) > 1 else "?"
        return {"text": "%s 的 %s 位 %s" % (reg, bit,
                                          "为 0" if mn == "tbz" else "非 0"),
                "approx": False}

    # 极性：x86 jCC → CC；ARM b.CC / b.eq → CC
    cc = None
    if mn.startswith("j") and len(mn) > 1:
        cc = mn[1:]
    elif mn.startswith("b."):
        cc = mn[2:]
    if cc is None:
        return None
    op_text = _CC_TEXT.get(cc)
    if op_text is None:
        return {"text": "%s（极性 %s）" % (mn, cc), "approx": True}
    if op_text in _CC_DESC:
        return {"text": "%s（%s）" % (mn, op_text), "approx": True}

    if cmp_ins is None:
        return {"text": "条件码 %s（比较指令不可见）" % cc, "approx": True}
    # 操作数文本归一化（ARM 立即数的 # 前缀去掉，与 x86 风格统一）
    cargs = [c.lstrip("#") for c in _split_ops(cmp_ins.ops)]
    cmn = (cmp_ins.mnem or "").lower()
    if cmn in ("test", "tst") and len(cargs) >= 2 and cargs[0] == cargs[1]:
        return {"text": "%s %s 0" % (cargs[0], op_text), "approx": False}
    if cmn in ("test", "tst") and len(cargs) >= 1:
        return {"text": "%s %s 0" % (cargs[0], op_text), "approx": True}
    if len(cargs) >= 2:
        return {"text": "%s %s %s" % (cargs[0], op_text, cargs[1]),
                "approx": False}
    return {"text": "%s %s ?" % (cmp_ins.ops, op_text), "approx": True}


# ---------------------------------------------------------------- 结构化

def _succs_from_edges(nodes, edges):
    """CFG 边 → 后继表。call 边（to=None）不参与结构（它是被调函数）。"""
    succs: dict[int, list[str]] = {n: [] for n in nodes}
    types: dict[tuple, str] = {}
    for e in edges:
        if e.get("to") is None or e.get("type") == "call":
            continue
        u, v = e["from"], e["to"]
        if v in succs:
            succs[u].append(v)
            types[(u, v)] = e["type"]
    return succs, types


def structure_function(idx, offs: list[int], name: str = "",
                       with_ir: bool = False, max_blocks: int = 4000) -> dict:
    """
    结构化单个函数。返回（可 JSON 化）：
        {name, start_vma, end_vma, blocks, edges, cyclomatic,
         loops: [...], conditionals: [...], switches: [...],
         ir_summary: {...}, structure: [文本行], ir: [...]（with_ir 时）,
         partial, notes: [...]}

    只对可归约 CFG 给结构结论；不可归约/预算截断一律如实降级。
    """
    from lib_code import basic_blocks, build_cfg

    notes: list[str] = []
    partial = False
    if not offs:
        return {"ok": False, "error": "函数体为空", "name": name}

    blocks = basic_blocks(idx, offs)
    cfg = build_cfg(idx, offs)
    node_offs = [b["start"] for b in blocks]
    start2id = {b["start"]: i for i, b in enumerate(blocks)}
    nodes = [n["id"] for n in cfg["nodes"]]
    if len(nodes) > max_blocks:
        partial = True
        notes.append("基本块数 %d 超过预算 %d，只结构化前 %d 个块"
                     % (len(nodes), max_blocks, max_blocks))
        keep = set(nodes[:max_blocks])
        cfg["nodes"] = [n for n in cfg["nodes"] if n["id"] in keep]
        cfg["edges"] = [e for e in cfg["edges"]
                        if e["from"] in keep and (e.get("to") in keep
                                                  or e.get("to") is None)]
        nodes = [n["id"] for n in cfg["nodes"]]

    succs, etypes = _succs_from_edges(nodes, cfg["edges"])
    preds = _preds_of(succs, nodes)
    entry = nodes[0] if nodes else 0

    dom = _dominators(nodes, succs, entry)
    pdom = _post_dominators(nodes, succs, entry)

    # ---- 循环（回边 + 自然循环） ----
    loops_raw = _natural_loops(nodes, succs, preds, dom)
    loops = []
    loop_of_node: dict[int, int] = {}       # 块 id → 最内层循环序号
    for hi, (header, tail, body) in enumerate(loops_raw):
        exits = sorted({v for u in body for v in succs.get(u, [])
                        if v not in body})
        # 类型：回边源是条件跳（一腿回 header、一腿出）→ do-while；
        #       header 是条件跳（一腿进 body、一腿出）→ while；
        #       无条件跳回自身 → self-loop；其他如实标注。
        # 注意顺序：单块 `dec ecx; jnz top` 的 tail==header 但回边是条件边，
        # 它是 do-while 而不是 self-loop（jmp $ 那种才是 self-loop）。
        tail_cond = (etypes.get((tail, header)) in ("cond_true", "cond_false")
                     or _is_cond_node(succs, etypes, tail))
        head_cond = _is_cond_node(succs, etypes, header)
        if tail == header and not tail_cond:
            ltype = "self-loop"
        elif tail_cond:
            ltype = "do-while"
        elif head_cond:
            ltype = "while"
        else:
            ltype = "loop"
        cond = None
        if head_cond or tail_cond:
            anchor = header if head_cond else tail
            cond = _cond_of_block(idx, blocks[anchor]["offs"],
                                  idx.insn[blocks[anchor]["offs"][-1]].mnem
                                  if blocks[anchor]["offs"] else "")
        loops.append({
            "id": "L%d" % (len(loops) + 1),
            "type": ltype,
            "header": hex(idx.off2vma(node_offs[header])),
            "tail": hex(idx.off2vma(node_offs[tail])),
            "nodes": [hex(idx.off2vma(node_offs[b])) for b in sorted(body)],
            "exits": [hex(idx.off2vma(node_offs[b])) for b in exits],
            "cond": cond,
        })
        for b in body:
            loop_of_node.setdefault(b, len(loops) - 1)

    # ---- switch（比较链）先识别，被消费的条件节点不再当 if 报 ----
    switches, consumed = _find_switches(idx, blocks, nodes, succs, etypes,
                                        node_offs)

    # ---- 条件分支（if） ----
    conditionals = []
    for n in nodes:
        if n in consumed or not _is_cond_node(succs, etypes, n):
            continue
        if any(l["header"] == hex(idx.off2vma(node_offs[n])) for l in loops):
            continue                        # 循环条件已在 loop 里报
        if any(l["tail"] == hex(idx.off2vma(node_offs[n])) for l in loops):
            continue
        taken = None
        for v in succs.get(n, []):
            if etypes.get((n, v)) == "cond_true":
                taken = v
        fall = None
        for v in succs.get(n, []):
            if etypes.get((n, v)) == "cond_false":
                fall = v
        if taken is None or fall is None:
            continue
        join = _ipdom(pdom, n)
        # 一臂直达汇合点 → if-then；两臂都有体 → if-then-else；
        # 找不到共同汇合点（都奔出口）→ if-exit
        if join is None:
            kind = "if-exit"
        elif taken == join or fall == join:
            kind = "if-then"
        else:
            kind = "if-then-else"
        body_t = _reach_until(succs, taken, {join, n} if join is not None else {n})
        body_f = _reach_until(succs, fall, {join, n} if join is not None else {n})
        term = idx.insn.get(blocks[n]["offs"][-1]) if blocks[n]["offs"] else None
        conditionals.append({
            "id": "C%d" % (len(conditionals) + 1),
            "kind": kind,
            "at": hex(idx.off2vma(node_offs[n])),
            "cond": _cond_of_block(idx, blocks[n]["offs"],
                                   term.mnem if term else ""),
            "branch_taken": hex(idx.off2vma(node_offs[taken])),
            "branch_fallthrough": hex(idx.off2vma(node_offs[fall])),
            "join": hex(idx.off2vma(node_offs[join])) if join is not None else None,
            "taken_nodes": [hex(idx.off2vma(node_offs[b])) for b in sorted(body_t)],
            "fallthrough_nodes": [hex(idx.off2vma(node_offs[b]))
                                  for b in sorted(body_f)],
            "loop": (loops[loop_of_node[n]]["id"] if n in loop_of_node else None),
        })

    # ---- 圈复杂度 ----
    edge_count = sum(len(v) for v in succs.values())
    cyclomatic = edge_count - len(nodes) + 2 if nodes else 0

    # ---- IR 汇总 / 明细 ----
    ir_summary: dict[str, int] = defaultdict(int)
    ir_list = []
    for b in blocks:
        for o in b["offs"]:
            ins = idx.insn.get(o)
            if ins is None:
                continue
            stmt = lift_insn(ins)
            ir_summary[stmt["op"]] += 1
            if with_ir:
                ir_list.append({"block": start2id.get(b["start"]),
                                "vma": stmt["vma"], **stmt})

    # ---- 伪代码骨架 ----
    skeleton = _skeleton(name or "func", idx, node_offs, loops, conditionals,
                         switches, len(nodes), edge_count, cyclomatic)

    out = {
        "ok": True,
        "name": name,
        "start_vma": hex(idx.off2vma(offs[0])),
        "end_vma": hex(idx.off2vma(offs[-1] + (idx.insn[offs[-1]].size
                                               if offs[-1] in idx.insn else 1))),
        "blocks": len(nodes),
        "edges": edge_count,
        "cyclomatic": cyclomatic,
        "loops": loops,
        "conditionals": conditionals,
        "switches": switches,
        "ir_summary": dict(ir_summary),
        "structure": skeleton,
        "partial": partial,
    }
    if with_ir:
        out["ir"] = ir_list
    if notes:
        out["notes"] = notes
    return out


def _is_cond_node(succs, etypes, n) -> bool:
    kinds = {etypes.get((n, v)) for v in succs.get(n, [])}
    return "cond_true" in kinds


def _ipdom(pdom: dict, n: int):
    """n 的直接后支配点 = 后支配 n 且不被其它后支配点后支配的最近点。"""
    cands = [x for x in pdom.get(n, set()) if x != n]
    best = None
    for x in cands:
        if best is None or x in pdom.get(best, set()):
            best = x
    return best


def _reach_until(succs, start, stop) -> set:
    """从 start 可达、但不越过 stop 集合的节点集（不含 stop）。"""
    seen: set = set()
    stack = [start]
    while stack:
        x = stack.pop()
        if x in stop or x in seen:
            continue
        seen.add(x)
        stack.extend(succs.get(x, []))
    return seen


def _find_switches(idx, blocks, nodes, succs, etypes, node_offs):
    """
    比较链 switch：≥3 个条件节点比较同一寄存器、fallthrough 串成链。
    间接跳转（jmp reg / jmp [mem]）单列为候选——静态无法与虚调用/尾调用
    区分，只报 evidence 不下结论。
    返回 (switches, consumed_节点集合)。
    """
    switches = []
    consumed: set = set()

    # 间接跳转候选
    for i, b in enumerate(blocks):
        if not b["offs"]:
            continue
        ins = idx.insn.get(b["offs"][-1])
        if ins is None:
            continue
        if ins.kind == K_JMP and ins.target is None:
            switches.append({
                "kind": "indirect-jump",
                "at": hex(idx.off2vma(b["start"])),
                "reg_or_mem": ins.ops,
                "mem_ref": hex(ins.mem_ref) if ins.mem_ref is not None else None,
                "note": "间接跳转：可能是 switch 跳转表，也可能是虚调用/尾调用，"
                        "静态无法区分；case 目标需读表解析",
            })

    # 比较链：条件节点 + fallthrough 后继仍是条件节点 + 比较同一操作数
    def cmp_reg(n):
        for o in reversed(blocks[n]["offs"]):
            ins = idx.insn.get(o)
            if ins is not None and (ins.mnem or "").lower() in _M_CMP:
                args = _split_ops(ins.ops)
                return (args[0] if args else None), ins
        return None, None

    starts = []
    fall_into = set()
    for n in nodes:
        if not _is_cond_node(succs, etypes, n):
            continue
        for v in succs.get(n, []):
            if etypes.get((n, v)) == "cond_false" and \
                    _is_cond_node(succs, etypes, v):
                fall_into.add(v)
    for n in nodes:
        if _is_cond_node(succs, etypes, n) and n not in fall_into:
            starts.append(n)

    for s in starts:
        chain = []
        cur = s
        reg0 = None
        default_v = None          # 各 break 路径下都必须有定义（否则 NameError）
        while _is_cond_node(succs, etypes, cur):
            reg, _cins = cmp_reg(cur)
            if reg is None:
                break
            if reg0 is None:
                reg0 = reg
            if reg != reg0:
                break
            taken = fall = None
            for v in succs.get(cur, []):
                if etypes.get((cur, v)) == "cond_true":
                    taken = v
                elif etypes.get((cur, v)) == "cond_false":
                    fall = v
            if taken is None or fall is None:
                break
            chain.append((cur, taken))
            if _is_cond_node(succs, etypes, fall):
                cur = fall
            else:
                default_v = fall
                break
        if len(chain) >= 3:
            cases = []
            for cn, tgt in chain:
                _r, cins = cmp_reg(cn)
                args = _split_ops(cins.ops) if cins is not None else []
                val = None
                if len(args) >= 2:
                    try:
                        val = int(args[1].lstrip("#"), 0)
                    except ValueError:
                        val = args[1]
                cases.append({"value": val,
                              "target": hex(idx.off2vma(node_offs[tgt]))})
            switches.append({
                "kind": "compare-chain",
                "at": hex(idx.off2vma(node_offs[s])),
                "reg": reg0,
                "case_count": len(cases),
                "cases": cases,
                "default": (hex(idx.off2vma(node_offs[default_v]))
                            if default_v is not None else None),
                "note": "同寄存器比较链（%d 路），按 switch 报告" % len(cases),
            })
            for cn, _t in chain:
                consumed.add(cn)
    return switches, consumed


def _skeleton(name, idx, node_offs, loops, conditionals, switches,
              n_blocks, n_edges, cyclomatic) -> list[str]:
    """函数级伪代码骨架（按地址排序，循环/分支/switch 标注）。"""
    lines = ["%s:  blocks=%d edges=%d cyclomatic=%d"
             % (name, n_blocks, n_edges, cyclomatic)]
    events = []
    for l in loops:
        events.append((l["tail"], 1, "loop", l))
    for c in conditionals:
        events.append((c["at"], 0, "cond", c))
    for s in switches:
        events.append((s["at"], 2 if s["kind"] == "compare-chain" else 3,
                       "switch", s))
    events.sort(key=lambda e: (int(e[0], 16), e[1]))
    for at, _o, kind, item in events:
        if kind == "loop":
            c = item.get("cond")
            ct = c["text"] if c else "条件未推导"
            lines.append("  loop[%s] @%s header=%s exit=%s  (%s)"
                         % (item["type"], item["tail"], item["header"],
                            ",".join(item["exits"]) or "-", ct))
        elif kind == "cond":
            c = item.get("cond")
            ct = c["text"] if c else item.get("kind", "if")
            lines.append("  %s @%s: if (%s) then %s else %s join=%s"
                         % (item["kind"], at, ct, item["branch_taken"],
                            item["branch_fallthrough"], item["join"] or "-"))
        else:
            if item["kind"] == "compare-chain":
                lines.append("  switch(%s) @%s cases=%d default=%s"
                             % (item["reg"], at, item["case_count"],
                                item["default"] or "-"))
            else:
                lines.append("  switch? @%s 间接跳转 %s（%s）"
                             % (at, item["reg_or_mem"], item["note"][:22]))
    if not (loops or conditionals or switches):
        lines.append("  （直线代码：无循环/分支/switch）")
    return lines


# ---------------------------------------------------------------- 文件级入口

def structure_file(path: str, ident: dict | None = None,
                   addr: str | None = None, with_ir: bool = False,
                   max_insns: int = 300000, max_functions: int = 8,
                   region: str | None = None) -> dict:
    """
    文件级结构化入口。addr 给定 → 只结构化该函数；否则按地址序取前
    max_functions 个函数。x86 / x86-64 / ARM64 / Thumb 均走同一套
    函数识别（call 目标播种 + 递归下降）。
    """
    from lib_disasm import (code_regions, entry_points, identify,
                            symbols_from, UnsupportedArch)
    from lib_code import CodeIndex, find_functions

    if ident is None:
        try:
            ident = identify(path)
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

    from lib_formats import Reader
    with Reader(path) as rd:
        code = rd.read(r["file_off"], r["size"])
    if not code:
        return {"ok": False, "error": "代码区读取失败"}

    # 架构分发交给 lib_disasm.backend（唯一裁决点，别在这里维护第二份
    # 白名单）。不支持的架构不拿 x86 解码器兜底，与 analyze_file 同约定
    # 返回明确错误 dict（ok:false + unsupported_arch）。
    try:
        idx = CodeIndex(code, base_vma=r["vma"], bits=r["bits"], arch=r["arch"],
                        max_insns=max_insns)
    except UnsupportedArch as e:
        return {"ok": False, "error": str(e), "arch": r["arch"],
                "unsupported_arch": True}
    stats: dict = {}
    funcs = find_functions(idx, seeds=entry_points(ident),
                           symbols=symbols_from(ident),
                           max_functions=max(1, max_functions * 4),
                           stats=stats)

    want = None
    if addr:
        try:
            want = int(str(addr).replace("0x", "").replace("0X", ""), 16)
        except ValueError:
            return {"ok": False, "error": "地址格式错误: %s" % addr}

    out_fns = []
    for f in funcs:
        if want is not None:
            if f["start_vma"] != want and not (f["start_vma"] <= want
                                               < f["end_vma"]):
                continue
        elif len(out_fns) >= max_functions:
            break
        st = structure_function(idx, f.get("_offs") or [],
                                name=f.get("name", ""),
                                with_ir=with_ir)
        out_fns.append(st)
        if want is not None:
            break

    if want is not None and not out_fns:
        return {"ok": False,
                "error": "未找到地址 %s 对应的函数" % addr,
                "hint": "共识别 %d 个函数" % len(funcs)}

    partial = bool(idx.truncated) or bool(stats.get("skipped_seeds"))
    notes = []
    if idx.truncated:
        notes.append("指令预算 %d 已用尽，结构只覆盖已解码片段；"
                     "提高 --max-insns 可得完整结果" % idx.max_insns)
    if stats.get("skipped_seeds"):
        notes.append("还有 %d 个候选函数没处理（达到上限），"
                     "不是全部函数" % stats["skipped_seeds"])
    if addr is None and len(funcs) > max_functions:
        partial = True
        notes.append("共 %d 个函数，只结构化了前 %d 个；"
                     "用 --addr 指定要看的函数" % (len(funcs), max_functions))

    out = {
        "ok": True,
        "path": path,
        "format": ident.get("format"),
        "arch": r["arch"],
        "region": r["name"],
        "base_vma": hex(r["vma"]),
        "function_count": len(funcs),
        "structured_count": len(out_fns),
        "functions": out_fns,
        "partial": partial,
    }
    if notes:
        out["truncated_note"] = "；".join(notes)
    return out
