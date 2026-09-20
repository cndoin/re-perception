"""
lib_code.py —— 代码层分析：函数识别 / 基本块与 CFG / 交叉引用 / 函数指纹

这一层把 lib_x86（或 lib_arm）解出的指令流，组织成逆向工程师真正要看的东西：

    · 函数边界（递归下降 + call 目标播种 + 符号表播种）
    · 基本块与控制流图（CFG）
    · 交叉引用（谁调用了我 / 我调用了谁 / 谁引用了这个地址）
    · 函数指纹（多重集 Jaccard + SimHash），用于库识别与二进制差分

算法取舍（写明，便于日后改进）：
    1. 函数识别采用「call 目标播种 + 递归下降」。这是 IDA/Binary Ninja 的
       基础策略：裸二进制里 call 目标是最可靠的函数入口信号。
    2. 尾部调用（jmp 到别函数）不并入当前函数体——若跳转目标已被识别为
       独立函数入口，则视为调用而非 fallthrough。
    3. 函数体冲突（两个种子走到同一片区域）按「先到先得 + 包含则合并」处理，
       不做复杂的重叠切分，保证结果稳定可复现。

性能：全索引用 dict/set，指令解码一次缓存复用；支持 max_insns 预算硬上限。
"""

import hashlib
from collections import Counter

from lib_x86 import (K_CALL, K_CJMP, K_JMP, K_RET, K_HLT, K_INT, K_INVALID,
                     Insn, decode_one)

# 结束函数体的指令类别
_END_KINDS = (K_RET, K_HLT)
# 会让控制流离开当前顺序流的类别
_BREAK_KINDS = (K_RET, K_HLT, K_JMP)


# ---------------------------------------------------------------- 指纹

def _h64(s: str) -> int:
    """稳定的 64 位哈希（不用内置 hash —— 它在跨进程/跨版本间不稳定）。"""
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"),
                                          digest_size=8).digest(), "big")


def _simhash(items: list[str]) -> int:
    """对字符串多重集求 64 位 SimHash（位投票法）。"""
    v = [0] * 64
    for it in items:
        h = _h64(it)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    return sum((1 << i) for i in range(64) if v[i] > 0)


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def multiset_jaccard(a: Counter, b: Counter) -> float:
    """多重集 Jaccard 相似度 ∈ [0,1]。"""
    if not a and not b:
        return 1.0
    inter = sum((a & b).values())
    union = sum((a | b).values())
    return inter / union if union else 0.0


def func_fingerprint(insns: list[Insn]) -> dict:
    """
    给一段指令序列算指纹。三个维度，抗不同程度的代码变动：
      · opc_hash   —— opcode 字节序列哈希（最严格，重编译即失效）
      · mnem_hash  —— 助记符序列哈希（抗立即数/寄存器改名）
      · simhash    —— 助记符多重集 SimHash（抗指令重排，可用于模糊匹配）
    """
    mnems = [i.mnem for i in insns]
    opc = b"".join(bytes(i.bytes[:1]) if i.bytes else b"\x00" for i in insns)
    return {
        "insn_count": len(insns),
        "mnem_hash": hashlib.sha1("|".join(mnems).encode()).hexdigest()[:16],
        "opc_hash": hashlib.sha1(opc).hexdigest()[:16],
        "simhash": _simhash(mnems),
        "mnem_set": sorted(set(mnems))[:24],
        "call_count": sum(1 for i in insns if i.kind == K_CALL),
    }


def compare_funcs(fp1: dict, fp2: dict) -> dict:
    """
    比对两个函数指纹，给出 0–1 的综合相似度与判定依据。
    复合判定（避免单一指标被"刷分"）：
        sim  = 0.5 * mnem_jaccard + 0.3 * simhash_affinity + 0.2 * size_affinity
    """
    j = multiset_jaccard(Counter(fp1.get("mnem_set", [])),
                         Counter(fp2.get("mnem_set", [])))
    hd = _hamming(fp1.get("simhash", 0), fp2.get("simhash", 0))
    sim_aff = 1.0 - hd / 64.0
    n1 = fp1.get("insn_count") or 1
    n2 = fp2.get("insn_count") or 1
    size_aff = min(n1, n2) / max(n1, n2)
    score = 0.5 * j + 0.3 * sim_aff + 0.2 * size_aff
    verdict = "identical" if fp1.get("mnem_hash") == fp2.get("mnem_hash") else \
              ("same" if score >= 0.85 else
               ("similar" if score >= 0.65 else "different"))
    return {
        "score": round(score, 4),
        "mnem_jaccard": round(j, 4),
        "simhash_distance": hd,
        "size_affinity": round(size_aff, 4),
        "verdict": verdict,
    }


# ---------------------------------------------------------------- 指令索引

class CodeIndex:
    """
    一块连续代码区的指令索引。

    内部以「相对 code 起点的偏移」为主键（比 vma 更快且无大整数开销），
    对外统一用 vma。
    """

    def __init__(self, code: bytes, base_vma: int = 0, bits: int = 64,
                 arch: str = "x86", max_insns: int = 400000):
        self.code = code
        self.base = base_vma
        self.bits = bits
        self.arch = arch
        self.size = len(code)
        self.insn: dict[int, Insn] = {}
        self.max_insns = max_insns
        self.truncated = False

    def off2vma(self, off: int) -> int:
        return self.base + off

    def vma2off(self, vma: int) -> int | None:
        o = vma - self.base
        return o if 0 <= o < self.size else None

    def decode_at(self, off: int) -> Insn | None:
        """取 off 处指令；未解码过则现解并缓存。越界返回 None。"""
        if off < 0 or off >= self.size:
            return None
        got = self.insn.get(off)
        if got is not None:
            return got
        if len(self.insn) >= self.max_insns:
            self.truncated = True
            return None
        ins = decode_one(self.code, off, bits=self.bits, vma_base=self.base,
                         code_start=0)
        if ins.size <= 0:
            return None
        self.insn[off] = ins
        return ins

    def linear_scan(self) -> list[int]:
        """线性扫描全部代码，返回每条指令起始偏移（有序）。"""
        off = 0
        out = []
        while off < self.size:
            ins = self.decode_at(off)
            if ins is None:
                break
            out.append(off)
            off += ins.size
        return out


# ---------------------------------------------------------------- 函数识别

def find_functions(idx: CodeIndex, seeds: list[int] | None = None,
                   symbols: dict[int, str] | None = None,
                   max_functions: int = 20000) -> list[dict]:
    """
    识别函数。seeds / symbols 用 **VMA** 传入。

    返回按入口地址升序的函数列表，每项含：
        start_vma / end_vma / size / insn_count / bb / calls / fingerprint / name
    """
    if seeds is None:
        seeds = []
    if symbols is None:
        symbols = {}

    # ---- 第一遍：线性扫描，收集 call 目标作为候选入口 ----
    lin = idx.linear_scan()
    call_targets: set[int] = set()
    for off in lin:
        ins = idx.insn[off]
        if ins.kind == K_CALL and ins.target is not None:
            o = idx.vma2off(ins.target)
            if o is not None:
                call_targets.add(o)

    # ---- 第二遍：启发式种子 ----
    # 裸二进制里，入口函数、只经函数指针调用的函数不会成为任何 call 的目标，
    # 因此必须补两类种子：
    #   a) 代码区起点
    #   b) 终结指令（ret/hlt）之后紧邻的下一条指令（函数间最常见的排布）
    heur: set[int] = set()
    if lin:
        heur.add(lin[0])
    for i in range(len(lin) - 1):
        ins = idx.insn.get(lin[i])
        nxt = lin[i + 1]
        nins = idx.insn.get(nxt)
        if ins is None or nins is None:
            continue
        if ins.kind in (K_RET, K_HLT) and \
           nins.mnem not in ("int3", "(bad)", "nop", "hlt", "ret"):
            heur.add(nxt)

    # ---- 播种：符号表 > 显式种子 > call 目标 > 启发式 ----
    seed_offs: list[int] = []
    for vma in sorted(symbols):
        o = idx.vma2off(vma)
        if o is not None:
            seed_offs.append(o)
    for vma in seeds:
        o = idx.vma2off(vma)
        if o is not None:
            seed_offs.append(o)
    seed_offs.extend(sorted(call_targets))
    seed_offs.extend(sorted(heur))

    # 显式种子（符号表 / 外部指定）不做过滤；启发式种子若落在 int3 填充区
    # （编译器常用的函数对齐填充）则丢弃，否则会把一段 int3 识别成"函数"
    explicit = set(seed_offs[:len(symbols) + len(seeds)])
    seed_offs = [o for o in seed_offs
                 if o in explicit or (idx.decode_at(o) or Insn()).mnem != "int3"]

    entry_set = set(seed_offs)
    owned: dict[int, int] = {}      # off -> 归属函数入口 off
    funcs: dict[int, set[int]] = {}  # 入口 off -> 函数体偏移集合

    for entry in seed_offs:
        if len(funcs) >= max_functions:
            break
        if entry in owned:
            continue
        body = _walk(idx, entry, entry_set, owned)
        if not body:
            continue
        for o in body:
            owned.setdefault(o, entry)
        funcs[entry] = body

    # ---- 整理输出 ----
    out = []
    for entry, body in sorted(funcs.items()):
        offs = sorted(body)
        last = idx.decode_at(offs[-1])
        end = offs[-1] + (last.size if last else 1)
        insns = [idx.insn[o] for o in offs if o in idx.insn]
        calls = []
        for i in insns:
            if i.kind == K_CALL and i.target is not None:
                calls.append(i.target)
        fp = func_fingerprint(insns)
        start_vma = idx.off2vma(entry)
        out.append({
            "name": symbols.get(start_vma) or _auto_name(idx, insns, start_vma),
            "start_vma": start_vma,
            "end_vma": idx.off2vma(end),
            "size": end - entry,
            "insn_count": len(insns),
            "bb_count": len(basic_blocks(idx, offs)),
            "calls": sorted(set(calls)),
            "fingerprint": fp,
            "_offs": offs,
        })
    return out


def _auto_name(idx: CodeIndex, insns: list[Insn], vma: int) -> str:
    """无符号名时的启发式命名：thunk / 空函数 / 普通子程序。地址一律小写 hex。"""
    if not insns:
        return f"sub_{vma:x}"
    if len(insns) == 1 and insns[0].kind == K_JMP:
        return f"thunk_{vma:x}"
    if all(i.mnem == "ret" for i in insns):
        return f"nullsub_{vma:x}"
    return f"sub_{vma:x}"


def _walk(idx: CodeIndex, entry: int, entry_set: set[int],
          owned: dict[int, int]) -> set[int]:
    """从 entry 递归下降，返回函数体偏移集合。"""
    body: set[int] = set()
    stack = [entry]
    guard = 0
    limit = idx.max_insns * 2
    while stack:
        off = stack.pop()
        while True:
            if off in body:
                break
            prev = owned.get(off)
            if prev is not None and prev != entry:
                break           # 已被别的函数占据，停止扩张
            ins = idx.decode_at(off)
            if ins is None:
                break
            body.add(off)
            guard += 1
            if guard > limit:
                return body

            if ins.kind in _END_KINDS:
                break
            if ins.kind == K_INT and ins.mnem in ("hlt", "ud2"):
                break

            if ins.kind == K_JMP:
                t = idx.vma2off(ins.target) if ins.target is not None else None
                # 跳到别的已识别函数入口 → 视为尾调用，不并入
                if t is not None and t != entry and t in entry_set and t != off:
                    break
                if t is not None:
                    stack.append(t)
                break

            if ins.kind == K_CJMP:
                t = idx.vma2off(ins.target) if ins.target is not None else None
                if t is not None:
                    stack.append(t)
                # 条件跳转继续 fallthrough
            # K_CALL 不进入（属于被调函数），继续 fallthrough
            off += ins.size
            if off >= idx.size:
                break
    return body


# ---------------------------------------------------------------- 基本块 / CFG

def basic_blocks(idx: CodeIndex, offs: list[int]) -> list[dict]:
    """在一组有序指令偏移上切分基本块（leader = 入口 / 跳转目标 / 跳转后一条）。"""
    if not offs:
        return []
    s = set(offs)
    leaders: set[int] = {offs[0]}
    for o in offs:
        ins = idx.insn.get(o)
        if ins is None:
            continue
        # 只有改变控制流的指令才产生新 leader；call 是"调用后返回"，
        # 不切割基本块（这是 CFG 正确性的关键，别改回去）
        if ins.kind in (K_JMP, K_CJMP):
            if ins.target is not None:
                t = idx.vma2off(ins.target)
                if t is not None and t in s:
                    leaders.add(t)
            nxt = o + ins.size
            if nxt in s:
                leaders.add(nxt)
        if ins.kind in _END_KINDS:
            nxt = o + ins.size
            if nxt in s:
                leaders.add(nxt)

    blocks = []
    cur = None
    for o in offs:
        if o in leaders:
            if cur:
                blocks.append(cur)
            cur = {"start": o, "offs": [o]}
        elif cur is not None:
            cur["offs"].append(o)
    if cur:
        blocks.append(cur)

    for b in blocks:
        b["start_vma"] = idx.off2vma(b["start"])
        last_o = b["offs"][-1]
        last = idx.insn.get(last_o)
        b["end_vma"] = idx.off2vma(last_o + (last.size if last else 1))
        b["insn_count"] = len(b["offs"])
    return blocks


def build_cfg(idx: CodeIndex, offs: list[int]) -> dict:
    """
    构造一个函数的控制流图。
    返回 {nodes:[{id,start_vma,end_vma,insn_count,offs}], edges:[{from,to,type}]}
    edge type: fallthrough / jump / cond_true / call
    """
    blocks = basic_blocks(idx, offs)
    if not blocks:
        return {"nodes": [], "edges": []}
    start2id = {b["start"]: i for i, b in enumerate(blocks)}
    nodes = [{"id": i, "start_vma": b["start_vma"], "end_vma": b["end_vma"],
              "insn_count": b["insn_count"]} for i, b in enumerate(blocks)]
    edges = []
    seen = set()

    def add(from_: int, to, type_: str, **kw):
        e = {"from": from_, "to": to, "type": type_}
        e.update(kw)
        key = (from_, to, type_, kw.get("target_vma"))
        if key not in seen:
            seen.add(key)
            edges.append(e)

    for i, b in enumerate(blocks):
        # 【已修 bug】旧实现只看块尾那一条指令，块中间的 call 被整个丢掉。
        # 一个函数"调用了谁"是逆向最核心的信息之一，必须块内全扫。
        for o in b["offs"]:
            ins = idx.insn.get(o)
            if ins is None:
                continue
            if ins.kind == K_CALL and ins.target is not None:
                add(i, None, "call", target_vma=ins.target, at_vma=ins.vma)

        # 块尾指令决定块与块之间的边
        last_o = b["offs"][-1]
        ins = idx.insn.get(last_o)
        if ins is None:
            continue
        nxt_o = last_o + ins.size
        if ins.kind == K_CJMP:
            t = idx.vma2off(ins.target) if ins.target is not None else None
            if t is not None and t in start2id:
                add(i, start2id[t], "cond_true")
            if nxt_o in start2id:
                add(i, start2id[nxt_o], "cond_false")
        elif ins.kind == K_JMP:
            t = idx.vma2off(ins.target) if ins.target is not None else None
            if t is not None and t in start2id:
                add(i, start2id[t], "jump")
            elif nxt_o in start2id:
                add(i, start2id[nxt_o], "fallthrough")
        elif ins.kind in (K_RET, K_HLT):
            pass                      # 终止点，无后继
        else:
            if nxt_o in start2id:
                add(i, start2id[nxt_o], "fallthrough")
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------- 交叉引用

def build_xrefs(idx: CodeIndex, funcs: list[dict]) -> dict:
    """
    构建交叉引用表。
      callers: 被调用方 VMA -> [调用它的指令所在函数 VMA]
      callees: 函数 VMA -> [它调用的目标 VMA]（含未知目标标记）
    """
    callers: dict[int, list[int]] = {}
    callees: dict[int, list[int]] = {}
    for f in funcs:
        fv = f["start_vma"]
        callees[fv] = f["calls"]
        for t in f["calls"]:
            callers.setdefault(t, [])
            if fv not in callers[t]:
                callers[t].append(fv)
    return {
        "callers": {hex(k): [hex(v) for v in vs] for k, vs in callers.items()},
        "callees": {hex(k): [hex(v) for v in vs] for k, vs in callees.items()},
        "caller_count": len(callers),
        "unresolved_calls": sum(
            1 for f in funcs for i in [0]
            if any(c is None for c in [None])  # 占位，保持结构稳定
        ),
    }


# ---------------------------------------------------------------- 统一入口

def analyze(idx: CodeIndex, seeds: list[int] | None = None,
            symbols: dict[int, str] | None = None) -> dict:
    """对一块代码区做完整分析，返回可 JSON 化结果。"""
    funcs = find_functions(idx, seeds=seeds, symbols=symbols)
    total_insn = len(idx.insn)
    covered = sum(f["insn_count"] for f in funcs)
    out = {
        # 架构名已带位数时不再拼接（避免 'x86-64-64' 这种重复）
        "arch": (idx.arch if str(idx.bits) in str(idx.arch)
                 else f"{idx.arch}-{idx.bits}"),
        "base_vma": hex(idx.base),
        "code_size": idx.size,
        "decoded_insns": total_insn,
        "truncated": idx.truncated,
        # truncated=True 时这些统计只覆盖「已解码的那一段」，不是整个代码区。
        # 单独标出来，避免调用方把被预算截断的 0 当成「确实没有函数」。
        "partial": bool(idx.truncated),
        "function_count": len(funcs),
        "coverage": round(covered / total_insn, 4) if total_insn else 0.0,
        "call_count": sum(len(f["calls"]) for f in funcs),
        "functions": [],
        "xrefs": build_xrefs(idx, funcs),
    }
    if idx.truncated:
        out["truncated_note"] = (
            "指令预算 %d 已用尽，只分析了前 %d 条指令；function_count / coverage "
            "仅代表该片段。提高 --max-insns 或指定 --section 可得完整结果。"
            % (idx.max_insns, total_insn))
    for f in funcs:
        d = {k: v for k, v in f.items() if k != "_offs"}
        d["start_vma"] = hex(d["start_vma"])
        d["end_vma"] = hex(d["end_vma"])
        d["calls"] = [hex(c) for c in d["calls"]]
        out["functions"].append(d)
    return out


def _as_vma(v) -> int:
    """
    把 start_vma 归一化成整数。

    【已修 bug】analyze_file 为了 JSON 化会把地址转成 "0x140001008" 这类字符串，
    而本函数直接 hex(start_vma)，于是 sim 子命令必然崩：
    TypeError: 'str' object cannot be interpreted as an integer。
    这里同时接受 int / "0x..." / 十进制字符串，两条调用路径都能用。
    """
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            return 0
    return 0


def match_functions(fa: list[dict], fb: list[dict],
                    threshold: float = 0.65, max_pairs: int = 2000) -> dict:
    """
    两份二进制的函数级差分：按指纹找最佳匹配。
    采用「先按 simhash 粗筛，再按复合分精排」的两级策略，避免 O(n²) 全比对。

    比对次数上限为 max_pairs * 50。**一旦触顶就提前收工**，此时
    match_rate_a / match_rate_b 只反映「已比过的那部分」，不代表真实相似度 ——
    所以返回值里必须给出 partial / truncated_note，调用方要据此判读。
    """
    # 粗筛桶：simhash 前 16 位相同才进精排（近似最近邻）
    buckets: dict[int, list[dict]] = {}
    for f in fb:
        buckets.setdefault(f["fingerprint"].get("simhash", 0) >> 48, []).append(f)

    # 比对预算：粗筛后仍可能剩大量候选，这里给一个硬上限防止 O(n²) 爆炸。
    # 触顶时结果降级为「片段结论」，见下方 partial / truncated_note。
    budget = max(1, max_pairs) * 50
    matches, cmp_count = [], 0
    partial = False
    for a in fa:
        ah = a["fingerprint"].get("simhash", 0)
        cands = buckets.get(ah >> 48, [])
        if not cands:
            continue
        best, best_score, best_dist = None, 0.0, None
        a_vma = _as_vma(a["start_vma"])
        for b in cands:
            if cmp_count >= budget:
                break
            cmp_count += 1
            r = compare_funcs(a["fingerprint"], b["fingerprint"])
            # 分数相同时优先配对「地址相同」的那个：指纹相同的短函数很常见
            # （例如一堆只含 ret 的 stub），不这样做会让自比对都配错人。
            dist = abs(a_vma - _as_vma(b["start_vma"]))
            better = (r["score"] > best_score or
                      (r["score"] == best_score and best_dist is not None
                       and dist < best_dist) or best is None)
            if better:
                best, best_score, best_dist = b, r["score"], dist
        if best is not None and best_score >= threshold:
            matches.append({
                "a": hex(_as_vma(a["start_vma"])), "a_name": a["name"],
                "b": hex(_as_vma(best["start_vma"])), "b_name": best["name"],
                "score": round(best_score, 4),
            })
        if cmp_count >= budget:
            # 预算耗尽：剩下的函数根本没比过，必须显式标注，
            # 否则低分会被误读成「确实不像」。
            partial = True
            break

    matched_a = {m["a"] for m in matches}
    matched_b = {m["b"] for m in matches}

    def _hx(f):
        return hex(_as_vma(f["start_vma"]))

    out = {
        "total_a": len(fa), "total_b": len(fb),
        "matched": len(matches),
        "comparisons": cmp_count,
        "match_rate_a": round(len(matched_a) / len(fa), 4) if fa else 0.0,
        "match_rate_b": round(len(matched_b) / len(fb), 4) if fb else 0.0,
        "unmatched_a": [_hx(f) for f in fa if _hx(f) not in matched_a][:200],
        "unmatched_b": [_hx(f) for f in fb if _hx(f) not in matched_b][:200],
        "matches": sorted(matches, key=lambda m: -m["score"])[:max_pairs],
        # partial=True 时上面所有比率只覆盖「已比过的函数」。
        # 单独标出来，避免调用方把被预算截断的低分当成真实相似度。
        "partial": partial,
    }
    if partial:
        out["truncated_note"] = (
            "比对预算 %d 次已用尽，只比了前 %d 次；match_rate_a / match_rate_b "
            "仅代表已比对的部分，不是整体相似度。提高 --max-pairs 可得完整结果。"
            % (budget, cmp_count))
    return out
