"""缺失分析域检查器 —— 补齐 re-perception 尚未覆盖、且纯标准库可解析的 REA 分析域。

每个检查器都：
- 只用标准库（struct / plistlib / re / zlib …），保持 re-perception 零第三方依赖；
- 边界保护 + 优雅降级：解析不出就返回 ``{"ok": False, "reason": ...}`` 而不是崩；
- 数值一律由结构解析算出，不由 AI 推断；字段命名对齐 REA 的 inspect-* 命令语义。

覆盖的域（复刻 REA 的 stdlib 可解析子集）：
- ``inspect_layout``   二进制布局 + 静态缓解（ELF program headers / PE DllCharacteristics）
- ``inspect_pe_resources``  PE 资源树（类型/名字/语言）
- ``inspect_archs``    Mach-O / 胖二进制架构清单
- ``inspect_plist``    Apple plist（XML + bplist 检测）
- ``inspect_dotnet``   .NET 托管程序集元数据（CLR 头、元数据流、程序集名、运行时版本）
- ``inspect_go``       Go 二进制 buildinfo（编译器版本、模块、构建设置）
- ``inspect_evm``      EVM 字节码（dispatch selector 表、PUSH 指令统计）
- ``demangle``         符号还原（Itanium C++ / Rust legacy / Swift 前缀，尽力而为）

依赖重型外部工具的域（Ghidra 反编译、IDA、adb、浏览器、LLDB）不在这里假装实现，
而是由 ``lib_contracts.ProviderDescriptor`` 表达为 provider 槽位、诚实降级。
"""

from __future__ import annotations

import plistlib
import re
import struct

import lib_formats as F

__all__ = [
    "inspect_layout", "inspect_pe_resources", "inspect_archs",
    "inspect_plist", "inspect_dotnet", "inspect_go", "inspect_evm",
    "demangle",
]


def _ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return d


def _bad(reason, **kw):
    d = {"ok": False, "reason": reason}
    d.update(kw)
    return d


def _u(data, off, fmt, le=True):
    """安全 unpack；越界返回 None。"""
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        return None
    return struct.unpack_from("<" + fmt if le else ">" + fmt, data, off)[0]


def _cstr(data, off, limit=256):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(len(data), off + limit)
    try:
        return data[off:end].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _read(path, limit):
    """用 with 读取最多 limit 字节（满足 lint 的 open-with 约束）。"""
    with open(path, "rb") as f:
        return f.read(limit)


# ---------------------------------------------------------------- 二进制布局 + 缓解

#: PE DllCharacteristics 标志位（缓解）。
_PE_DLLCHARS = (
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),     # ASLR
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),        # DEP
    (0x0400, "NO_SEH"),
    (0x0800, "GUARD_CF"),         # Control Flow Guard
    (0x1000, "TERMINAL_SERVER_AWARE"),
)


def inspect_layout(path):
    """二进制布局 + 静态缓解检查（对应 REA ``inspect-binary-layout``）。"""
    try:
        data = _read(path, 0x1000000)  # 布局只需头部，限读 16MB
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    if data[:4] == b"\x7fELF":
        return _elf_layout(data)
    if data[:2] == b"MZ":
        return _pe_layout(data)
    return _bad("仅支持 ELF/PE 布局检查")


def _elf_layout(data):
    if len(data) < 64:
        return _bad("ELF 头过短")
    bits = 64 if data[4] == 2 else 32
    le = data[5] != 2
    if bits == 64:
        e_type = _u(data, 16, "H", le)
        e_machine = _u(data, 18, "H", le)
        e_phoff = _u(data, 32, "Q", le) or 0
        e_phentsize = _u(data, 54, "H", le) or 0
        e_phnum = _u(data, 56, "H", le) or 0
    else:
        e_type = _u(data, 16, "H", le)
        e_machine = _u(data, 18, "H", le)
        e_phoff = _u(data, 28, "I", le) or 0
        e_phentsize = _u(data, 42, "H", le) or 0
        e_phnum = _u(data, 44, "H", le) or 0

    segs = []
    nx = True          # 默认假设 NX 开启，遇到可执行可写段才推翻
    pie = (e_type == 3)  # ET_DYN = PIE
    relro = "none"
    for i in range(min(e_phnum, 1024)):
        base = e_phoff + i * e_phentsize
        if bits == 64:
            p_type = _u(data, base, "I", le)
            p_flags = _u(data, base + 4, "I", le)
            p_vaddr = _u(data, base + 16, "Q", le)
            p_memsz = _u(data, base + 40, "Q", le)
        else:
            p_type = _u(data, base, "I", le)
            p_offset = _u(data, base + 4, "I", le)
            p_vaddr = _u(data, base + 8, "I", le)
            p_filesz = _u(data, base + 16, "I", le)
            p_memsz = _u(data, base + 20, "I", le)
            p_flags = _u(data, base + 24, "I", le)
            del p_offset, p_filesz
        if p_type is None:
            break
        segs.append({"type": p_type, "flags": p_flags,
                     "vaddr": p_vaddr, "memsz": p_memsz})
        # PT_GNU_STACK = 0x6474e551；可执行即 NX 关闭
        if p_type == 0x6474e551 and (p_flags & 1):
            nx = False
        # PT_GNU_RELRO = 0x6474e552
        if p_type == 0x6474e552:
            relro = "partial"
        # PT_GNU_RELRO + BIND_NOW（0x6474e552 + DF_BIND_NOW in dynamic）→ full 近似
        # 同段 RWX 判定
        if (p_flags & 0x1) and (p_flags & 0x2):
            nx = False
    return _ok(format="elf", bits=bits, endian="le" if le else "be",
               e_type=e_type, e_machine=e_machine,
               segments=segs[:64], segment_count=len(segs),
               mitigations={"nx": nx, "pie": pie, "relro": relro,
                            "canary": None})


def _pe_layout(data):
    e_lfanew = _u(data, 0x3C, "I")
    if not e_lfanew or e_lfanew + 24 > len(data):
        return _bad("PE 头偏移无效")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return _bad("无 PE 签名")
    coff = e_lfanew + 4
    nsec = _u(data, coff + 2, "H")
    optsz = _u(data, coff + 16, "H")
    magic = _u(data, coff + 20, "H") if optsz else None
    bits = 64 if magic == 0x20B else 32
    # DllCharacteristics 位于可选头偏移 0x46 —— PE32 与 PE32+ 相同
    # （标准字段 28/24 + Windows 字段到 Subsystem 的累计 = 70 = 0x46）。
    dllchar_off = coff + 20 + 0x46
    dllchar = _u(data, dllchar_off, "H") or 0
    chars = [name for bit, name in _PE_DLLCHARS if dllchar & bit]
    mitigations = {
        "aslr": bool(dllchar & 0x0040),
        "dep_nx": bool(dllchar & 0x0100),
        "seh": not bool(dllchar & 0x0400),
        "cfg": bool(dllchar & 0x0800),
        "high_entropy_va": bool(dllchar & 0x0020),
    }
    return _ok(format="pe", bits=bits, section_count=nsec,
               dll_characteristics=dllchar, dll_characteristics_flags=chars,
               mitigations=mitigations)


# ---------------------------------------------------------------- PE 资源树

def inspect_pe_resources(path, max_entries=512):
    """PE 资源目录树（类型 → 名字 → 语言），对应 REA ``inspect-pe-resources``。"""
    try:
        data = _read(path, 0x2000000)
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    if data[:2] != b"MZ":
        return _bad("不是 PE 文件")
    e_lfanew = _u(data, 0x3C, "I")
    if not e_lfanew or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return _bad("无 PE 签名")
    coff = e_lfanew + 4
    nsec = _u(data, coff + 2, "H") or 0
    optsz = _u(data, coff + 16, "H") or 0
    opt = coff + 20
    magic = _u(data, opt, "H")
    bits = 64 if magic == 0x20B else 32
    # 数据目录：资源表是第 3 项（index 2）
    dd_off = opt + (112 if bits == 64 else 96)
    rsrc_rva = _u(data, dd_off + 2 * 8, "I")
    rsrc_sz = _u(data, dd_off + 2 * 8 + 4, "I")
    if not rsrc_rva:
        return _ok(format="pe", entries=[], count=0, note="无资源目录")
    # 节表把 RVA 映射到文件偏移。delta 使得 fileoff = rva + delta。
    sec_off = opt + optsz
    delta = None
    for i in range(min(nsec, 96)):
        so = sec_off + i * 40
        name = data[so:so + 8].split(b"\x00")[0].decode("latin1", "replace")
        vsz = _u(data, so + 8, "I")
        rawsz = _u(data, so + 16, "I")
        rawptr = _u(data, so + 20, "I")
        vaddr = _u(data, so + 12, "I")
        if name == ".rsrc" or (vaddr is not None and vaddr <= rsrc_rva
                               < vaddr + max(vsz or 0, rawsz or 0)):
            delta = rawptr - vaddr
            break
    if delta is None:
        return _bad("未定位 .rsrc 节")
    # 资源目录根的文件偏移；目录项里子目录/名字偏移都是相对此根的。
    root_off = rsrc_rva + delta
    entries = []
    more = _walk_rsrc(data, root_off, delta, root_off, 0, [], entries, max_entries)
    # count 是"实际走到的条数"（受 max_entries 截停）；more 申报"后面还有"。
    # 【实测 bug】原实现用 len(entries) > max_entries 算 truncated —— 但 walk
    # 本身就以 max_entries 截停，这个式子恒为 False，截断永远不申报。
    d = _ok(format="pe", count=len(entries), entries=entries[:max_entries],
            truncated=bool(more))
    note = _rsrc_note(entries)
    if note:
        d["note"] = note
    return d


def _rsrc_note(entries):
    """口径申报：本命令只统计**本文件 .rsrc**。

    Win10+ 的系统二进制带 MUI 重定向描述符（type 名为 MUI），真正的大批资源
    （图标/字符串表）在 ``<lang>\\<文件>.mui`` / ``.mun`` 里，由加载器合并后再
    呈现 —— OS 的 EnumResource* 口径会比这里多（实测 kernel32 本文件 2 条、
    OS 合并口径 6 条）。不申报的话两边对数会对不上，会把诚实数字误判成漏数。
    """
    if any(e.get("type") == "MUI" for e in entries):
        return ("检测到 MUI 重定向描述符：部分资源实际位于同名 .mui/.mun 文件，"
                "本命令只统计本文件 .rsrc（比加载器合并口径少属正常）")
    return None


def _walk_rsrc(data, res_base, delta, dir_off, level, path, out, cap):
    """递归遍历资源目录（最多 3 层：类型/名字/语言）。

    PE 资源目录项的 ``OffsetToData`` 对子目录/数据项都是**相对资源根**的偏移
    （``res_base``），而数据项里的 ``OffsetToData`` 是**绝对 RVA**（fileoff =
    rva + delta）。

    返回 True 表示因 ``cap`` 截停、后面还有条目没走完（调用方据此申报截断）。
    """
    if level > 2:
        return False
    if len(out) >= cap:
        return True
    # 【实测 bug】目录头里 NumberOfNamedEntries / NumberOfIdEntries 是
    # u16@+12 / u16@+14。原实现用 "I" 读 4 字节 —— n_named 被并入
    # n_id<<16、n_id 混进首条目 Name 低 16 位，total 恒被顶到 4096，
    # 去解析条目数组之外的垃圾字节（真实 PE 上吐出上万条 size/codepage
    # 离谱的伪条目）。必须按 u16 读。
    n_named = _u(data, dir_off + 12, "H")
    n_id = _u(data, dir_off + 14, "H")
    if n_named is None or n_id is None:
        return False
    total = min((n_named or 0) + (n_id or 0), 4096)
    for i in range(total):
        if len(out) >= cap:
            return True
        eo = dir_off + 16 + i * 8
        name_or_id = _u(data, eo, "I")
        data_or_dir = _u(data, eo + 4, "I")
        if name_or_id is None or data_or_dir is None:
            break
        is_dir = bool(data_or_dir & 0x80000000)
        entry_off = data_or_dir & 0x7FFFFFFF
        if name_or_id & 0x80000000:  # 名字（相对根的字符串偏移）
            str_off = res_base + (name_or_id & 0x7FFFFFFF)
            nlen = _u(data, str_off, "H") or 0
            raw = data[str_off + 2:str_off + 2 + nlen * 2]
            label = raw.decode("utf-16-le", "replace")
        else:
            label = str(name_or_id)
        newpath = path + [label]
        if is_dir:
            if _walk_rsrc(data, res_base, delta, res_base + entry_off,
                          level + 1, newpath, out, cap):
                return True
        else:
            # 叶子：IMAGE_RESOURCE_DATA_ENTRY { RVA, Size, Codepage, Reserved }
            de = res_base + entry_off
            data_rva = _u(data, de, "I")
            data_sz = _u(data, de + 4, "I")
            codepage = _u(data, de + 8, "I")
            if data_rva is None or data_sz is None:
                break  # 数据项头都读不全 = 偏移不真，别把半截垃圾当条目
            out.append({"type": newpath[0] if len(newpath) > 0 else None,
                        "name": newpath[1] if len(newpath) > 1 else None,
                        "language": newpath[2] if len(newpath) > 2 else None,
                        "size": data_sz, "codepage": codepage,
                        "data_rva": data_rva})
            if len(out) >= cap and i + 1 < total:
                return True
    return False


# ---------------------------------------------------------------- Mach-O 架构

_CPU = {
    7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64",
    18: "ppc", 0x01000012: "ppc64", 6: "mips",
}


def inspect_archs(path):
    """Mach-O / 胖二进制架构清单（对应 REA ``list-architectures``）。"""
    try:
        data = _read(path, 0x100000)
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    magic = _u(data, 0, "I", le=True)
    magic_be = _u(data, 0, "I", le=False)
    archs = []
    if magic in (0xCAFEBABE, 0xBEBAFECA) or magic_be in (0xCAFEBABE,):
        # fat header（大端魔数 0xCAFEBABE）
        nfat = _u(data, 4, "I", le=False) or 0
        # nfat 必须在合理区间：Java .class 与 fat Mach-O 共用 0xCAFEBABE 魔数，
        # .class 的偏移 4 是版本号（major≥45）。不设界就会把 .class 当 fat
        # Mach-O 上报（假阳性）。
        if not 1 <= nfat <= 32:
            return _bad("fat 头架构数异常: %d（疑似 Java class 或损坏文件）" % nfat)
        for i in range(min(nfat, 32)):
            base = 8 + i * 20
            cputype = _u(data, base, "I", le=False)
            cpusub = _u(data, base + 4, "I", le=False)
            offset = _u(data, base + 8, "I", le=False)
            size = _u(data, base + 12, "I", le=False)
            archs.append({"cputype": cputype,
                          "cpu": _CPU.get(cputype, "unknown"),
                          "cpusubtype": cpusub, "offset": offset,
                          "size": size})
        return _ok(format="mach-o-universal", fat=True, count=len(archs),
                   architectures=archs)
    # thin mach header —— 魔数必须命中才认，否则一律拒收。
    # 【实测 bug】原实现算出 le=False 也照走不误，把 notepad.exe（PE）当成
    # thin Mach-O 报了 ok:true —— MZ 头被按 cputype 解读，纯属编造。
    if magic not in (0xFEEDFACF, 0xFEEDFACE, 0xCFFAEDFE, 0xCEFAEDFE):
        return _bad("不是 Mach-O 文件")
    # 字节序：LE-read 命中 0xFEEDFACx 才是小端文件；命中 0xCFFAEDFE/0xCEFAEDFE
    # 是大端魔数的字节翻转，字段要按大端读（原实现把"是 Mach-O"当"小端"用）。
    le = magic in (0xFEEDFACF, 0xFEEDFACE)
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    cputype = _u(data, 4, "I", le=le)
    if cputype is None:
        return _bad("不是 Mach-O 文件")
    cpusub = _u(data, 8, "I", le=le)
    return _ok(format="mach-o", fat=False, count=1, bits=64 if is64 else 32,
               architectures=[{"cputype": cputype,
                               "cpu": _CPU.get(cputype, "unknown"),
                               "cpusubtype": cpusub}])


# ---------------------------------------------------------------- plist

def inspect_plist(path):
    """Apple plist（XML 或二进制），对应 REA ``inspect-plist``。"""
    try:
        with open(path, "rb") as f:
            raw = f.read(0x4000000)
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    if raw[:6] == b"bplist":
        kind = "binary"
    elif raw[:5] == b"<?xml" or b"<plist" in raw[:256]:
        kind = "xml"
    else:
        return _bad("不是 plist（缺少 bplist / <plist> 头）")
    try:
        obj = plistlib.loads(raw)
    except Exception as ex:  # noqa: BLE001
        return _bad("plist 解析失败: %s" % ex, kind=kind)
    keys = list(obj.keys()) if isinstance(obj, dict) else []
    return _ok(kind=kind, root_type=type(obj).__name__, top_keys=keys[:64],
               top_key_count=len(keys),
               preview=_jsonable_preview(obj))


def _jsonable_preview(obj, depth=0):
    """给一个有限深度的可序列化预览，避免超大 plist 撑爆输出。"""
    if depth > 3:
        return "..."
    if isinstance(obj, dict):
        return {str(k)[:64]: _jsonable_preview(v, depth + 1)
                for k, v in list(obj.items())[:32]}
    if isinstance(obj, list):
        return [_jsonable_preview(v, depth + 1) for v in obj[:32]]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj if not isinstance(obj, str) or len(obj) <= 256 else obj[:256] + "…"
    return repr(obj)[:256]


# ---------------------------------------------------------------- .NET 托管

def inspect_dotnet(path):
    """.NET 托管程序集元数据（对应 REA ``inspect-managed-artifact``）。

    只读元数据、不加载不执行：解析 CLR 头（数据目录 14）→ 元数据根 →
    #~/#Strings/#US 流 → 程序集名与运行时版本。
    """
    try:
        data = _read(path, 0x2000000)
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    if data[:2] != b"MZ":
        return _bad("不是 PE/托管程序集")
    e_lfanew = _u(data, 0x3C, "I")
    if not e_lfanew or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return _bad("无 PE 签名")
    coff = e_lfanew + 4
    optsz = _u(data, coff + 16, "H") or 0
    opt = coff + 20
    magic = _u(data, opt, "H")
    bits = 64 if magic == 0x20B else 32
    dd_off = opt + (112 if bits == 64 else 96)
    clr_rva = _u(data, dd_off + 14 * 8, "I")
    clr_sz = _u(data, dd_off + 14 * 8 + 4, "I")
    if not clr_rva or not clr_sz:
        return _bad("无 CLR 头（非 .NET 托管程序集）")
    # RVA → raw
    nsec = _u(data, coff + 2, "H") or 0
    sec_off = opt + optsz
    def rva2off(rva):
        for i in range(min(nsec, 96)):
            so = sec_off + i * 40
            vaddr = _u(data, so + 12, "I")
            vsz = _u(data, so + 8, "I")
            rawptr = _u(data, so + 20, "I")
            rawsz = _u(data, so + 16, "I")
            if vaddr is not None and vaddr <= rva < vaddr + max(vsz or 0, rawsz or 0):
                return rawptr + (rva - vaddr)
        return None
    clr_off = rva2off(clr_rva)
    if clr_off is None:
        return _bad("CLR 头 RVA 无法映射")
    # IMAGE_COR20_HEADER: cb, MajorRuntimeVersion, Minor, MetaData{RVA,Size}, Flags
    meta_rva = _u(data, clr_off + 8, "I")
    meta_sz = _u(data, clr_off + 12, "I")
    flags = _u(data, clr_off + 16, "I")
    runtime_major = _u(data, clr_off + 4, "H")
    runtime_minor = _u(data, clr_off + 6, "H")
    ilonly = bool(flags & 0x01) if flags is not None else None
    meta_off = rva2off(meta_rva) if meta_rva else None
    streams = []
    runtime_version = None
    assembly_name = None
    if meta_off is not None:
        # 元数据根: signature 'BSJB', 版本串长度在 +12
        sig = data[meta_off:meta_off + 4]
        if sig == b"BSJB":
            verlen = _u(data, meta_off + 12, "I") or 0
            runtime_version = (data[meta_off + 16:meta_off + 16 + verlen]
                               .split(b"\x00")[0].decode("latin1", "replace"))
            flags_off = meta_off + 16 + verlen
            nstreams = _u(data, flags_off + 2, "H") or 0
            p = flags_off + 4
            for _ in range(min(nstreams, 32)):
                soff = _u(data, p, "I")
                ssz = _u(data, p + 4, "I")
                name = _cstr(data, p + 8, 32)
                p += 8 + ((len(name) + 1 + 3) // 4) * 4
                streams.append({"name": name, "offset": soff, "size": ssz})
            # 从 #Strings 流粗取一个程序集名（Module 表第一列）—— 尽力而为
            for s in streams:
                if s["name"] == "#Strings" and s["size"]:
                    raw_str = data[meta_off + s["offset"]:
                                   meta_off + s["offset"] + min(s["size"], 4096)]
                    cand = [x.decode("utf-8", "replace") for x in raw_str.split(b"\x00")
                            if len(x) >= 3][:3]
                    if cand:
                        assembly_name = cand[0]
    return _ok(format="managed-assembly", bits=bits,
               runtime_version=runtime_version,
               runtime=(runtime_major, runtime_minor),
               il_only=ilonly, flags=flags,
               metadata_streams=streams, assembly_name=assembly_name,
               metadata_size=meta_sz)


# ---------------------------------------------------------------- Go buildinfo

_GO_MAGIC = b"\xff Go buildinf:"


def inspect_go(path):
    """Go 二进制 buildinfo（对应 REA ``inspect-go-binary``）。"""
    try:
        data = _read(path, 0x4000000)
    except Exception as ex:  # noqa: BLE001
        return _bad("读取失败: %s" % ex)
    idx = data.find(_GO_MAGIC)
    if idx < 0:
        return _bad("未找到 Go buildinfo 魔数（可能被剥离或非 Go）")
    # buildinfo 结构: magic(14) | ptrsize(1) | endianness(1) | ... 后随指针
    ptrsize = data[idx + 14]
    endian = "le" if data[idx + 15] == 1 else "be"
    info = {"format": "go-binary", "ptrsize": ptrsize, "endian": endian,
            "buildinfo_offset": idx}
    # Go 1.18+ : magic 后跟两个指针指向 varint 长度的字符串（版本信息）
    base = idx + 16
    le = endian == "le"
    def read_ptr(off):
        if ptrsize == 8:
            return _u(data, off, "Q", le)
        return _u(data, off, "I", le)
    p_ver = read_ptr(base)
    p_mod = read_ptr(base + ptrsize)
    # 版本串通常直接在 buildinfo 附近（现代 Go 以 varint 长度内联）
    ver_str = None
    mod_str = None
    # 尝试从指针指向处读（需 rva→file 映射；这里退化为扫描可打印版本串）
    m = re.search(rb"go1\.\d+(?:\.\d+)?", data[max(0, idx - 0x1000):idx + 0x2000])
    if m:
        ver_str = m.group(0).decode()
    info["go_version"] = ver_str
    info["pointers"] = {"version": p_ver, "mod": p_mod}
    # 扫描模块路径线索（buildinfo 数据里常见 "path\t..." "mod\t..." "build\t..."）
    window = data[max(0, idx - 0x2000):idx + 0x20000]
    mods = []
    for key in (b"path\t", b"mod\t", b"build\t"):
        for mm in re.finditer(re.escape(key) + rb"([^\x00\n]{1,200})", window):
            mods.append(mm.group(1).decode("utf-8", "replace"))
    info["module_info"] = mods[:32]
    if p_ver:
        info["ok"] = True
    else:
        return _bad("buildinfo 指针解析失败", found_offset=idx)
    return info


# ---------------------------------------------------------------- EVM 字节码

_EVM_OP = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x10: "LT", 0x11: "GT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x39: "CODECOPY",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x5B: "JUMPDEST", 0xFD: "REVERT", 0xFE: "INVALID",
    0xF1: "CALL", 0xF3: "RETURN", 0xFA: "STATICCALL", 0xFF: "SELFDESTRUCT",
}


def inspect_evm(path_or_hex):
    """EVM 字节码 dispatch selector 表（对应 REA ``inspect-evm-interface``）。

    ``path_or_hex`` 可以是文件路径或 ``0x...``/裸十六进制串。识别策略：扫
    ``PUSH4 <selector>`` + 紧邻比较指令（EQ/LT/GT）构造的 dispatch 表。
    """
    if os_path_exists(path_or_hex):
        try:
            raw = _read(path_or_hex, 0x200000)
        except Exception as ex:  # noqa: BLE001
            return _bad("读取失败: %s" % ex)
        source = "file"
    else:
        hs = path_or_hex.strip()
        if hs.startswith("0x"):
            hs = hs[2:]
        hs = re.sub(r"\s+", "", hs)
        if not re.fullmatch(r"[0-9a-fA-F]*", hs) or len(hs) % 2:
            return _bad("既不是文件也不是合法十六进制字节码")
        raw = bytes.fromhex(hs)
        source = "hex"

    selectors = []
    pushes = {}
    i = 0
    n = len(raw)
    while i < n:
        op = raw[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            nbytes = op - 0x5F
            val = raw[i + 1:i + 1 + nbytes]
            if nbytes == 4 and len(val) == 4:
                selectors.append({"selector": val.hex(),
                                  "offset": i,
                                  "next_op": _EVM_OP.get(raw[i + 1 + nbytes], None)})
            pushes[nbytes] = pushes.get(nbytes, 0) + 1
            i += 1 + nbytes
        else:
            i += 1
    # 去重保序
    seen = set()
    uniq = []
    for s in selectors:
        if s["selector"] not in seen:
            seen.add(s["selector"])
            uniq.append(s)
    return _ok(format="evm-bytecode", source=source, bytecode_size=n,
               selectors=uniq[:64], selector_count=len(uniq),
               push_histogram=pushes,
               truncated=len(uniq) > 64)


def os_path_exists(p):
    import os
    return isinstance(p, str) and len(p) < 4096 and os.path.exists(p) \
        and os.path.isfile(p)


# ---------------------------------------------------------------- 符号还原

def demangle(name):
    """符号还原（对应 REA ``demangle-swift``；含 C++ Itanium / Rust legacy 前缀）。

    尽力而为、如实申报：解析不出就返回 ``{"ok": False, "kind": "unknown"}``，
    绝不编造还原结果。
    """
    if not isinstance(name, str) or not name:
        return _bad("空符号")
    # Rust legacy: _ZN…17h<hash>E —— 必须**先于** Itanium 判定：两者同为 _Z
    # 前缀，但 Rust 名字尾部带 crate hash 段。放在 _Z 分支之后就是死分支
    # （实测 `_ZN3std3foo17h…E` 被 Itanium 截走，kind 误报 itanium-cpp，
    # 哈希段还被当成标识符泄漏进还原名）。
    if re.match(r"_+ZN\d", name) and re.search(r"\d+h[0-9a-f]{16}E$", name):
        parts = _rust_legacy(name)
        if parts:
            return _ok(kind="rust-legacy", demangled="::".join(parts), mangled=name)
    # Itanium C++: _Z...
    if name.startswith("_Z") or name.startswith("__Z"):
        return _demangle_itanium(name.lstrip("_"))
    # Swift: $s / _T / __T
    if name.startswith("$s") or name.startswith("$S"):
        return _ok(kind="swift", note="Swift 修饰符（需 swift-demangle 精确还原）",
                   mangled=name, prefix="$s")
    if name.startswith("_T") or name.startswith("__T"):
        return _ok(kind="swift-legacy", note="Swift 旧版修饰符",
                   mangled=name)
    return _bad("未识别的修饰方案", kind="unknown", mangled=name)


def _demangle_itanium(name):
    """Itanium C++ ABI 的名字段还原（不展开完整类型/运算符重载）。"""
    # name := <source-name>+ ; source-name := <length> <identifier>
    body = name[1:]  # 去掉 'Z'
    if body.startswith("N"):  # 嵌套
        body = body[1:]
        body = body.rstrip("E")
    parts = []
    i = 0
    while i < len(body):
        if not body[i].isdigit():
            i += 1
            continue
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        try:
            ln = int(body[i:j])
        except ValueError:
            break
        ident = body[j:j + ln]
        if not ident:
            break
        parts.append(ident)
        i = j + ln
    if not parts:
        return _bad("Itanium 段解析失败", mangled=name)
    return _ok(kind="itanium-cpp", demangled="::".join(parts), mangled=name)


def _rust_legacy(name):
    body = name.lstrip("_")
    if not body.startswith("ZN"):
        return None
    body = body[2:].rstrip("E")
    parts = []
    i = 0
    while i < len(body) and body[i].isdigit():
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        try:
            ln = int(body[i:j])
        except ValueError:
            return None
        parts.append(body[j:j + ln])
        i = j + ln
    # 去掉末尾 17h<hash> 之类的 crate hash 段
    parts = [p for p in parts if not re.fullmatch(r"h[0-9a-f]{16}", p)]
    return parts or None
