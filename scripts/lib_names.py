"""lib_names.py —— 符号恢复与还原（零第三方依赖）

对标顶尖工具链里「省事层」的核心：**能不能不逆，直接拿到名字？**

覆盖三条符号富矿：

1. **修饰名 demangle** —— Itanium C++ / MSVC / Rust legacy / Rust v0 四种方言。
   引擎在 `lib_symbols.py`（已有，3000+ 行）。本模块把它接到分析流水线上，
   从 PE 导出表 / 导入表、ELF 符号表里批量还原。

2. **Go pclntab 恢复** —— Go 二进制被 strip 后仍保留 `.gopclntab`（或 `.data` 里的
   魔数表），函数名与源码路径完整可恢复。这是投入产出比最高的一条：
   一条命令换来成千上万个真实函数名，且**不需要模型**。

3. **调用约定装饰清理** —— `_printf@8` / `@foo@4` / `__imp_x` 一类 C 装饰。

设计原则（与全项目一致）：
- 只读，不写目标文件。
- 任何失败都要留下可观察的 `warnings`，不静默返回空集。
- 每条符号带 `source`（哪个表来的）与 `confidence`，便于上层判断可信度。
"""

from __future__ import annotations

import struct

from lib_symbols import clean_symbol, demangle, detect_dialect

# ================================================================ Go pclntab

# Go 1.2–1.15 与 1.16–1.17 用 0xfffffffb / 0xfffffffa；
# Go 1.18–1.19 用 0xfffffff0；Go 1.20+ 起改为 0xfffffff1。
_GOMAGIC_VARIANTS = {
    0xFFFFFFF1: {"label": "Go 1.20+", "ptr_size": "arch", "version_key": "1.20+"},
    0xFFFFFFF0: {"label": "Go 1.18–1.19", "ptr_size": "arch", "version_key": "1.18-1.19"},
    0xFFFFFFFA: {"label": "Go 1.16–1.17", "ptr_size": "arch", "version_key": "1.16-1.17"},
    0xFFFFFFFB: {"label": "Go 1.2–1.15", "ptr_size": 4, "version_key": "<=1.15"},
}

# pclntab 头部各版本字段排布（偏移以魔数为基准，单位字节）
# Go 1.20+ (magic 0xfffffff1):
#   +0  magic(u32) +4  pad(u16) +6  minLC(u8) +7  ptrSize(u8)
#   +8  nfunc(int)  +16 nfiles(uint)  +24 textStart(uintptr)
#   +32 funcnameOffset(uintptr) +40 cuOffset +48 filetabOffset
#   +56 pctabOffset +64 pclnOffset
_PCLN_120 = {
    "nfunc": 8, "nfiles": 16, "text_start": 24,
    "funcname_off": 32, "cu_off": 40, "filetab_off": 48,
    "pctab_off": 56, "pcln_off": 64,
}


def _u32(b: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, off)[0]


def _ptr(b: bytes, off: int, size: int) -> int:
    if off < 0 or off + size > len(b):
        return 0
    if size == 8:
        return struct.unpack_from("<Q", b, off)[0]
    return struct.unpack_from("<I", b, off)[0]


def _cstr_at(b: bytes, off: int, limit: int = 4096) -> str:
    """从字节串里读一个 NUL 结尾字符串；越界返回空串。"""
    if off < 0 or off >= len(b):
        return ""
    end = b.find(b"\x00", off)
    if end < 0:
        end = min(len(b), off + limit)
    raw = b[off:end][:limit]
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def find_pclntab(reader, size: int, scan_limit: int = 32 * 1024 * 1024,
                 validate: bool = True):
    """在整个文件里扫 pclntab 魔数，返回**通过校验**的候选列表。

    不做节名假设 —— Go 被 strip 或加壳后节名会变，但魔数一定在。
    `reader` 是 lib_formats.Reader（有 .read(off, n)）。

    **为什么必须校验**：4 字节魔数（`fb ff ff ff` 等）在正常代码里会偶然出现
    ——本机实测 notepad.exe 上就有 3 处这种巧合（都是 x86 指令字节），
    它们不是 pclntab。若不校验，每次分析普通 PE 都会吐出"发现 Go 表但解析失败"
    的假警告，把所有真信号淹掉。因此这里要求头部字段自洽：
    指针大小/指令对齐合法、nfunc 在合理区间、关键偏移非零且指向文件内。
    """
    cands = []
    step = 1 << 20
    overlap = 64
    scanned = 0
    while scanned < min(size, scan_limit):
        n = min(step + overlap, min(size, scan_limit) - scanned)
        if n <= 0:
            break
        chunk = reader.read(scanned, n)
        if not chunk:
            break
        for magic in _GOMAGIC_VARIANTS:
            m = struct.pack("<I", magic)
            start = 0
            while True:
                p = chunk.find(m, start)
                if p < 0:
                    break
                abs_off = scanned + p
                if not validate or _looks_like_pclntab(chunk, p, magic, abs_off):
                    cands.append(abs_off)
                start = p + 1
        scanned += step
    # 去重 + 限流（避免误报把结果撑爆）
    out = []
    seen = set()
    for c in sorted(cands):
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
        if len(out) >= 64:
            break
    return out


def _looks_like_pclntab(chunk: bytes, p: int, magic: int, abs_off: int) -> bool:
    """头部自洽性校验：挡掉"代码里恰好出现魔数"的假阳性。"""
    if magic == 0xFFFFFFF1:
        if p + 72 > len(chunk):
            return False
        min_lc = chunk[p + 6]
        ptr_size = chunk[p + 7]
        if min_lc not in (1, 2, 4) or ptr_size not in (4, 8):
            return False
        nfunc = _ptr(chunk, p + _PCLN_120["nfunc"], ptr_size)
        fn_off = _ptr(chunk, p + _PCLN_120["funcname_off"], ptr_size)
        pcln_off = _ptr(chunk, p + _PCLN_120["pcln_off"], ptr_size)
        # nfunc 是函数个数：真实 Go 程序从几百到几十万，绝不是 0 或天文数字。
        # 下界取 4 而不是 10 —— 保留极小程序/测试样本的可解析性，
        # 同时 4 个函数 + 后续偏移自洽仍足以排除"代码里偶现魔数"。
        if not (4 <= nfunc <= 3_000_000):
            return False
        if fn_off == 0 or pcln_off == 0:
            return False
        # 两个偏移都应落在 pclntab 自身范围内，且 pclnOff > funcnameOff（后者更靠前）
        if fn_off >= pcln_off:
            return False
        if pcln_off > 64 * 1024 * 1024:
            return False
        # 函数表必须能容下 nfunc 个 2*ptrSize 的表项
        if pcln_off + nfunc * ptr_size * 2 > 256 * 1024 * 1024:
            return False
        # funcnametab 起点应落在一个合理的可读位置（相对 pclntab 基址）
        if fn_off >= len(chunk) - p:
            # 允许跨 chunk 边界，只要求不是离谱的大
            if fn_off > 64 * 1024 * 1024:
                return False
        return True
    # 老版本布局暂不解析：不做头部校验（避免对不支持的版本误报）
    return False


def _parse_pclntab_120(blob: bytes, base_off: int, ptr_size: int, budget: int = 20000):
    """解析一个 Go 1.20+ 的 pclntab。blob 是从 base_off 起读到的一块（含足量尾部）。"""
    h = _PCLN_120
    nfunc = _ptr(blob, h["nfunc"], ptr_size)
    text_start = _ptr(blob, h["text_start"], ptr_size)
    funcname_off = _ptr(blob, h["funcname_off"], ptr_size)
    pcln_off = _ptr(blob, h["pcln_off"], ptr_size)

    if not (0 < nfunc < 5_000_000):
        return None, "nfunc 异常（%d）" % nfunc
    if funcname_off == 0 or pcln_off == 0:
        return None, "funcnameOffset/pclnOffset 为 0（版本或布局不符）"
    # 这些是相对 pclntab 基址的偏移
    if funcname_off + base_off >= len(blob) + base_off:
        pass  # 下面按 blob 内相对位置取，越界会被 _cstr_at 挡住

    fnames_base = funcname_off  # 相对 blob 起点（blob 起点 == pclntab 起点）
    ftab_abs = pcln_off

    funcs = []
    truncated = False
    for i in range(nfunc):
        if len(funcs) >= budget:
            truncated = True
            break
        ent = ftab_abs + i * (ptr_size * 2)
        entry = _ptr(blob, ent, ptr_size)
        foff = _ptr(blob, ent + ptr_size, ptr_size)
        if entry == 0:
            # textStart 之后不会存在"地址 0 的函数"，这是无效表项
            continue
        # 注意：**foff == 0 是合法值** —— 它是 funcnametab 里第一个名字的偏移。
        # 曾经这里写成 `foff == 0: continue`，导致每个 Go 二进制的第一个
        # 函数名永远丢失（合成用例当场抓到）。判据应该是"名字能不能读出来"，
        # 而不是"偏移是不是 0"。
        if foff < 0 or fnames_base + int(foff) >= len(blob):
            continue
        # _func.nameOff 是指向 funcnametab 的偏移
        name = _cstr_at(blob, fnames_base + int(foff), 512)
        if not name:
            continue
        # 过滤掉明显不是函数名的（Go 函数名总含 `.` 或 `/`）
        if "." not in name and "/" not in name:
            continue
        funcs.append({
            "name": name,
            "entry": int(entry),
            "entry_offset": int(entry) - int(text_start) if text_start else None,
        })
    if not funcs:
        return None, "按该布局解析出 0 个函数（nfunc=%d）" % nfunc
    return {"functions": funcs, "count": len(funcs),
            "text_start": int(text_start), "nfunc_declared": int(nfunc),
            "truncated": truncated,
            "layout": "go1.20+"}, None


def recover_go_symbols(reader, size: int, scan_limit: int = 32 * 1024 * 1024):
    """尝试从二进制里恢复 Go 函数名。

    返回 (result, warnings)。result 为 None 表示不是 Go 或解析失败。
    **绝不会静默空手而归** —— 失败必须给出 warnings。
    """
    warnings = []
    cands = find_pclntab(reader, size, scan_limit=scan_limit)
    if not cands:
        return None, []  # 不是 Go，不算 "失败"，不产生噪声警告

    # 逐个候选试；取解析出函数最多的那个
    best = None
    for cand in cands[:16]:
        hdr = reader.read(cand, 128)
        if len(hdr) < 72:
            continue
        magic = _u32(hdr, 0)
        info = _GOMAGIC_VARIANTS.get(magic)
        if not info:
            continue
        ptr_size = hdr[7] if magic == 0xFFFFFFF1 else 8
        if ptr_size not in (4, 8):
            ptr_size = 8
        # 读一整块做解析：pclntab 本身可能几 MB
        span = min(size - cand, 16 * 1024 * 1024)
        blob = reader.read(cand, span)
        if len(blob) < 128:
            continue

        if magic == 0xFFFFFFF1:
            res, err = _parse_pclntab_120(blob, cand, ptr_size)
            if res is None:
                # 头部过了校验但解析仍失败 —— 这是真异常，要说出来
                warnings.append("pclntab@0x%x（%s）解析失败：%s"
                                % (cand, info["label"], err))
                continue
            res["pclntab_offset"] = cand
            res["go_version_hint"] = info["label"]
            if best is None or res["count"] > best["count"]:
                best = res
        else:
            # 老版本布局：只记一条，不刷屏。空手而归必须可区分。
            warnings.append(
                "pclntab@0x%x 是 %s 布局（非 1.20+），当前仅支持 1.20+ 解析；"
                "函数名未恢复" % (cand, info["label"]))
            break

    if best is None:
        if not warnings:
            warnings.append("发现 %d 个 pclntab 候选但全部解析失败" % len(cands))
        return None, warnings
    return best, warnings


# ================================================================ 符号表聚合


def _norm(s: str) -> str:
    return s.strip() if isinstance(s, str) else ""


def collect_symbols(ident: dict, limit: int = 20000):
    """从 identify() 的结果里收集所有原始（修饰）名字，去重后返回。

    **只收集，不还原** —— 还原是下一步的事，这样两者可分别测试。
    """
    det = (ident or {}).get("detail") or {}
    out = []
    seen = set()

    def _add(name, source):
        name = _norm(name)
        if not name or name in seen:
            return
        seen.add(name)
        out.append({"name": name, "source": source})

    # PE 导出
    for e in det.get("export_syms") or []:
        if isinstance(e, dict):
            _add(e.get("name"), "pe-export")
    # PE 导入
    for mod in det.get("imports") or []:
        if not isinstance(mod, dict):
            continue
        dll = mod.get("dll") or "?"
        for fn in mod.get("functions") or []:
            if isinstance(fn, dict):
                nm = fn.get("name")
                if nm:
                    _add(nm, "pe-import:%s" % dll)
    # ELF 符号表
    for s in det.get("symbols") or []:
        _add(s, "elf-symbol")
    # Mach-O 符号
    for s in det.get("macho_symbols") or []:
        _add(s, "macho-symbol")

    return out[:limit]


def annotate_symbols(entries, limit: int = 20000):
    """给每条符号加 dialect / demangled / changed 三个字段。

    `changed=False` 表示 demangle 没改变它 —— 上层据此可只展示"真的被还原了"的。
    """
    out = []
    stats = {}
    for e in entries[:limit]:
        raw = e.get("name") or ""
        dm = demangle(raw)
        dialect = detect_dialect(raw)
        changed = (dm != raw)
        stats[dialect] = stats.get(dialect, 0) + 1
        out.append({
            "raw": raw,
            "demangled": dm,
            "dialect": dialect,
            "changed": changed,
            "source": e.get("source") or "",
        })
    return out, stats


def recover_symbols(ident: dict, want_demangle: bool = True,
                    want_go: bool = True, path: str | None = None,
                    limit: int = 20000):
    """一站式符号恢复。返回 (result_dict, warnings)。

    result_dict 恒有：`symbols` / `stats` / `counts` / `ok`。
    warnings 非空时必须透出给用户 —— 空结果与"恢复失败"必须可区分。
    """
    warnings = []
    entries = collect_symbols(ident, limit=limit)

    syms, stats = annotate_symbols(entries, limit=limit) if want_demangle else (
        [{"raw": e["name"], "demangled": e["name"], "dialect": "plain",
          "changed": False, "source": e["source"]} for e in entries], {})

    renamed = sum(1 for s in syms if s["changed"])

    go = None
    if want_go:
        go_err = None
        if path:
            try:
                from lib_formats import Reader
                r = Reader(path)
                size = r.size
                go, go_warn = recover_go_symbols(r, size)
                warnings.extend(go_warn)
            except Exception as ex:
                go_err = "%s: %s" % (type(ex).__name__, ex)
        else:
            go_err = "未提供文件路径，跳过 pclntab 扫描"
        if go_err:
            warnings.append("Go 符号恢复未执行：" + go_err)

    res = {
        "ok": True,
        "symbols": syms,
        "stats": stats,
        "counts": {
            "total": len(syms),
            "demangled_changed": renamed,
            "go_functions": (go or {}).get("count", 0),
        },
        "go": go,
        "warnings": warnings,
    }
    if not syms:
        res["empty"] = True
        res["reason"] = "该目标的符号表为空（可能已 strip，或格式未提供符号）"
    return res, warnings
