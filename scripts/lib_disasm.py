"""
lib_disasm.py —— 反汇编统一入口：挑代码区、选架构、调度 x86/ARM 解码器

这一层把「文件结构」（lib_formats）和「指令解码」（lib_x86 / lib_arm）
粘起来，并对 CLI 暴露三个稳定入口：

    code_regions(ident)              选可执行代码区
    disasm_file(path, ident, ...)    反汇编（线性 / 指定区间）
    analyze_file(path, ident, ...)   完整代码分析（函数 / CFG / XREF / 指纹）

架构扩展点：新增一种指令集只需在 ARCH_BACKEND 里注册解码函数。
"""

import os

from lib_formats import Reader, identify

# ---------------------------------------------------------------- 架构调度

def _x86_decode(code, off, bits, base):
    from lib_x86 import decode_one
    return decode_one(code, off, bits=bits, vma_base=base, code_start=0)


def _x86_linear(code, base, bits, max_insns):
    from lib_x86 import disasm_linear
    return disasm_linear(code, base_vma=base, bits=bits, max_insns=max_insns)


def _arm_decode(code, off, bits, base):
    from lib_arm import decode_one
    return decode_one(code, off, bits=bits, vma_base=base)


def _arm_linear(code, base, bits, max_insns):
    from lib_arm import disasm_linear
    return disasm_linear(code, base_vma=base, bits=bits, max_insns=max_insns)


ARCH_BACKEND = {
    "x86": (_x86_decode, _x86_linear),
    "x86-64": (_x86_decode, _x86_linear),
    "x86_64": (_x86_decode, _x86_linear),
    "amd64": (_x86_decode, _x86_linear),
    "i386": (_x86_decode, _x86_linear),
    "arm64": (_arm_decode, _arm_linear),
    "aarch64": (_arm_decode, _arm_linear),
    "arm": (_arm_decode, _arm_linear),
}


def normalize_arch(ident: dict) -> tuple[str, int]:
    """从识别结果归纳 (架构名, 位宽)。无法判定时返回 ('x86-64', 64) 兜底。"""
    a = (ident.get("arch") or "").lower()
    bits = ident.get("bits") or 64
    if a in ("x86", "i386", "x86-32", "80386"):
        return "x86", 32
    if a in ("x86-64", "x86_64", "amd64", "x64"):
        return "x86-64", 64
    if a in ("arm64", "aarch64", "armv8", "arm64e"):
        return "arm64", 64
    if a in ("arm", "armv7", "arm32", "thumb"):
        return "arm", 32
    if a in ("mips", "mips64", "ppc", "ppc64", "riscv", "sparc"):
        return a, bits
    return "x86-64", 64


class UnsupportedArch(Exception):
    """目标架构没有对应解码器。

    【为什么不许兜底到 x86】这里曾经写成
        `return ARCH_BACKEND.get(arch, ARCH_BACKEND["x86-64"])`
    后果比报错严重得多：拿一段 MIPS/PPC/RISC-V 机器码去按 x86-64 解，
    会解出一堆语法完全合法、语义完全错误的指令，而且 `ok:true`、
    `arch:"MIPS"` 照常返回。上层 find_functions 甚至能"识别出函数"。
    一个说得通但完全错误的结论，比一个明确的报错危险一百倍——
    后者只会让人重跑，前者会让人把它写进报告。
    """
    def __init__(self, arch, supported):
        self.arch = arch
        self.supported = supported
        Exception.__init__(
            self,
            "没有 %s 的解码器（当前支持：%s）"
            % (arch or "(未知)", ", ".join(sorted(set(supported)))))


def backend(arch: str):
    """取 (解码函数, 线性扫描函数)。不支持的架构直接抛错，不兜底。"""
    got = ARCH_BACKEND.get(arch)
    if got is None:
        raise UnsupportedArch(arch, list(ARCH_BACKEND.keys()))
    return got


def arch_label(arch: str, bits: int) -> str:
    """架构显示名；arch 自带位数时不再重复拼接（避免 'x86-64-64'）。"""
    s = str(arch)
    return s if str(bits) in s else f"{s}-{bits}"


# ---------------------------------------------------------------- 代码区选择

MAX_REGION = 64 * 1024 * 1024     # 单个代码区最多处理 64MB


def code_regions(ident: dict) -> list[dict]:
    """
    从识别结果里挑出可执行代码区。统一成：
        {name, file_off, size, vma, arch, bits, exec}
    """
    fmt = ident.get("format")
    det = ident.get("detail") or {}
    arch, bits = normalize_arch(ident)
    out: list[dict] = []

    def add(name, file_off, size, vma, is_exec=True):
        if size <= 0 or file_off < 0:
            return
        out.append({"name": name, "file_off": file_off,
                    "size": min(size, MAX_REGION), "vma": vma,
                    "arch": arch, "bits": bits, "exec": is_exec})

    if fmt == "pe":
        base = det.get("image_base") or 0
        for s in det.get("sections", []):
            chars = " ".join(s.get("chars", [])).upper()
            if "EXECUTE" in chars or "CODE" in chars:
                add(s.get("name", "?"), s.get("raw_offset", -1),
                    s.get("raw_size", 0), base + s.get("virtual_address", 0))
    elif fmt == "elf":
        for s in det.get("sections", []):
            flags = s.get("flags", 0)
            if flags & 0x4 or s.get("name") == ".text":      # SHF_EXECINSTR
                add(s.get("name", "?"), s.get("offset", -1),
                    s.get("size", 0), s.get("addr", 0))
        if not out:
            for sg in det.get("segments", []):
                if sg.get("type") == "LOAD":
                    add("LOAD", sg.get("offset", -1), sg.get("file_size", 0),
                        sg.get("vaddr", 0))
    elif fmt == "macho":
        for seg in det.get("segments", []) or []:
            for s in seg.get("sections", []) or []:
                add(s.get("name", "?"), s.get("offset", -1),
                    s.get("size", 0), s.get("addr", 0))
            if not seg.get("sections"):
                add(seg.get("name", "?"), seg.get("fileoff", -1),
                    seg.get("filesize", 0), seg.get("vmaddr", 0))
    else:
        # 裸二进制：整块按代码处理（用户可用 --base 指定装载地址）
        add("raw", 0, ident.get("size") or 0, ident.get("base_vma") or 0)

    out.sort(key=lambda r: -r["size"])
    return out


def entry_points(ident: dict) -> list[int]:
    """取入口点 VMA 列表（PE 的 AddressOfEntryPoint / ELF 的 e_entry）。"""
    det = ident.get("detail") or {}
    eps = []
    if ident.get("format") == "pe":
        rva = det.get("entry_rva")
        base = det.get("image_base")
        if rva and base:
            eps.append(base + rva)
    elif ident.get("format") == "elf":
        e = det.get("entry")
        if e:
            eps.append(e)
    return eps


def resolve_iat(ident: dict) -> dict[int, str]:
    """
    IAT 槽位 VMA -> "dll!Func"。有了它才能把 call [0x140012345]
    还原成 "kernel32!CreateFileW" —— 语义分析的地基。

    目前只覆盖 PE（ELF 的 PLT/GOT 绑定需在运行时解析，静态映射不可靠，
    不做猜测）。拿不到时返回空字典，调用方应降级处理而不是编造名字。

    延迟导入（delay-load，.didat）一并纳入 —— 这类调用在静态导入表里查不到，
    漏掉它们会让"这个函数调了什么"的答案缺一大块。
    """
    det = ident.get("detail") or {}
    out: dict[int, str] = {}
    if ident.get("format") != "pe":
        return out
    base = det.get("image_base") or 0
    if not base:
        return out
    for key in ("imports", "delay_imports"):
        for m in det.get(key, []) or []:
            dll = m.get("dll") or "?"
            for fn in m.get("functions", []) or []:
                rva = fn.get("iat_rva")
                if rva:
                    out.setdefault(base + rva, f"{dll}!{fn.get('name')}")
    return out


def symbols_from(ident: dict) -> dict[int, str]:
    """尽量从符号表/导出表拿函数名 -> {VMA: 名字}。拿不到就返回空。"""
    det = ident.get("detail") or {}
    out: dict[int, str] = {}
    if ident.get("format") == "pe":
        base = det.get("image_base") or 0
        # export_syms 是 [{name, ordinal, rva}]（带地址的导出符号表）；
        # exports 只是名字列表，两者形状不同，别混用。
        for e in det.get("export_syms", []) or []:
            if isinstance(e, dict) and e.get("rva") and e.get("name"):
                out[base + e["rva"]] = e["name"]
    return out


# ---------------------------------------------------------------- 对外入口

def disasm_file(path: str, ident: dict | None = None, region: str | None = None,
                base_vma: int | None = None, offset: int = 0,
                length: int = 65536, max_insns: int = 20000) -> dict:
    """
    反汇编一段代码。默认取最大的可执行区的前 length 字节。
    """
    if ident is None:
        ident = identify(path)
    regions = code_regions(ident)
    if not regions:
        return {"ok": False, "error": "未找到可执行代码区", "format": ident.get("format")}

    r = regions[0]
    if region:
        for cand in regions:
            if cand["name"].lower() == region.lower():
                r = cand
                break
    vma_base = base_vma if base_vma is not None else r["vma"]
    start = r["file_off"] + offset
    size = min(length, max(0, r["size"] - offset))

    with Reader(path) as rd:
        code = rd.read(start, size)
    if not code:
        return {"ok": False, "error": "读取代码区失败（偏移越界或节为空）"}

    try:
        dec, lin = backend(r["arch"])
    except UnsupportedArch as e:
        # 明确失败，而不是拿 x86 解码器糊一份看起来对的输出。
        return {"ok": False, "error": str(e),
                "unsupported_arch": True, "arch": r["arch"],
                "reason": "该架构没有反汇编器，不会拿 x86 码器代替而产生错误指令"}
    insns = lin(code, vma_base, r["bits"], max_insns)
    return {
        "ok": True,
        "path": path,
        "region": r["name"],
        "arch": arch_label(r["arch"], r["bits"]),
        "base_vma": hex(vma_base),
        "file_offset": start,
        "bytes": len(code),
        "insn_count": len(insns),
        "invalid_count": sum(1 for i in insns if i.mnem == "(bad)"),
        "insns": [i.to_dict() for i in insns],
    }


def analyze_file(path: str, ident: dict | None = None,
                 region: str | None = None,
                 max_insns: int = 300000,
                 max_functions: int = 20000) -> dict:
    """
    完整代码分析：函数识别 + 指纹 + 交叉引用统计。
    """
    if ident is None:
        ident = identify(path)
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

    # 只支持 x86 后端做函数识别（ARM 的 CFG 语义尚未接入）
    if r["arch"] not in ("x86", "x86-64"):
        try:
            dec, lin = backend(r["arch"])
        except UnsupportedArch as e:
            return {"ok": False, "error": str(e),
                    "unsupported_arch": True, "arch": r["arch"],
                    "reason": "该架构没有反汇编器，不拿 x86 码器代替"}
        insns = lin(code, r["vma"], r["bits"], min(max_insns, 20000))
        return {
            "ok": True, "arch": arch_label(r["arch"], r["bits"]),
            "region": r["name"], "base_vma": hex(r["vma"]),
            "note": f"{r['arch']} 暂未接入函数识别/CFG，仅做线性反汇编",
            "insn_count": len(insns),
            "insns": [i.to_dict() for i in insns][:2000],
        }

    from lib_code import CodeIndex, analyze as _analyze
    idx = CodeIndex(code, base_vma=r["vma"], bits=r["bits"],
                    arch=r["arch"], max_insns=max_insns)
    res = _analyze(idx, seeds=entry_points(ident),
                   symbols=symbols_from(ident))
    res.update({"ok": True, "region": r["name"], "path": path,
                "format": ident.get("format"),
                "entry_points": [hex(e) for e in entry_points(ident)]})
    res["_idx"] = idx          # 供 cfg 子命令复用（不进 JSON）
    return res


def cfg_of(path: str, ident: dict | None = None, target: str = "",
           max_insns: int = 300000) -> dict:
    """取单个函数的 CFG。target 为十六进制地址（带或不带 0x）。"""
    res = analyze_file(path, ident=ident, max_insns=max_insns)
    if not res.get("ok"):
        return res
    idx = res.pop("_idx", None)
    if idx is None:
        return {"ok": False, "error": "该架构暂不支持 CFG"}

    from lib_code import build_cfg
    try:
        want = int(target.replace("0x", "").replace("0X", "") or "0", 16)
    except ValueError:
        return {"ok": False, "error": f"地址格式错误: {target}"}

    funcs = idx and _rebuild_funcs(idx, res)
    if not funcs:
        return {"ok": False, "error": "未识别出函数"}
    hit = None
    for f in funcs:
        if f["start_vma"] == want or f["name"] == target:
            hit = f
            break
    if hit is None:
        # 退化为"包含该地址"的函数
        for f in funcs:
            if f["start_vma"] <= want < f["end_vma"]:
                hit = f
                break
    if hit is None:
        return {"ok": False, "error": f"未找到地址 {target} 对应的函数",
                "hint": f"共识别 {len(funcs)} 个函数"}

    cfg = build_cfg(idx, hit["_offs"])
    cfg.update({"ok": True, "function": hit["name"],
                "start_vma": hex(hit["start_vma"]),
                "end_vma": hex(hit["end_vma"]),
                "block_count": len(cfg["nodes"]),
                "edge_count": len(cfg["edges"])})
    return cfg


def _rebuild_funcs(idx, res) -> list[dict]:
    """analyze() 为了 JSON 化把地址转成了字符串，这里还原出可用的函数列表。"""
    from lib_code import find_functions
    return find_functions(idx, seeds=[], symbols={})
