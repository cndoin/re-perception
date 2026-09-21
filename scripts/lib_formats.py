# -*- coding: utf-8 -*-
"""
lib_formats.py —— 二进制/文件格式的识别与结构解析

设计约束（这三条决定了整个技能包的稳定性与性能）：
  1. 零第三方依赖：只用 Python 标准库，任何机器 clone 下来就能跑。
  2. 绝不因畸形输入崩溃：每个解析器内部 try/except，失败时返回
     {"parse_ok": False, "errors": [...]}，调用方永远拿得到结构化结果。
  3. 内存有界：结构解析只做定点 seek+read，不做整体读入；超过
     MAX_PARSE_SIZE（默认 256MB）的文件只做流式扫描，不进结构解析。

输出约定：所有函数返回纯 JSON 可序列化对象（dict/list/str/int/float/bool/None）。
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
from datetime import datetime, timezone

# ---------------------------------------------------------------- 常量

READ_CHUNK = 1 << 20            # 1MB，流式扫描块大小
MAX_PARSE_SIZE = 256 * 1024 * 1024   # 超过此大小不做结构解析（固件/磁盘镜像保护）
MAX_READ_FOR_ENTROPY = 8 * 1024 * 1024  # 单个节计算熵时最多读 8MB
MAX_ENTROPY_TOTAL = 64 * 1024 * 1024    # 单次解析里「所有节算熵」合计最多读 64MB
                                        # （单节上限挡不住放大：ELF 可声明 4096 个节、
                                        #   Mach-O 可声明 1024×64 个节，逐个读 8MB 就是
                                        #   几十 GB 的 I/O —— 病态文件能把这个工具挂死）

# ---------------------------------------------------------------- 读文件封装


class Reader:
    """带边界保护的随机读封装。文件不存在/不可读在构造时抛错。"""

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        if os.path.isdir(path):
            raise IsADirectoryError(path)
        self.size = os.path.getsize(path)
        # 不放在 with 里是故意的：句柄要活过构造函数。用 try 兜住构造期
        # 的异常（如权限/句柄耗尽/设备文件），避免半构造对象泄漏句柄。
        try:
            self._f = open(path, "rb")  # lint:ok 句柄需活过构造函数，失败已在下面包成 OSError
        except Exception as e:
            raise OSError("无法打开 %s：%s: %s" % (path, type(e).__name__, e)) from e

    def read(self, off: int, n: int) -> bytes:
        """定点读；越界自动截断，返回空字节串而不抛异常。"""
        if off < 0 or n <= 0:
            return b""
        if off >= self.size:
            return b""
        self._f.seek(off)
        return self._f.read(min(n, self.size - off))

    def iter_chunks(self, chunk: int = READ_CHUNK, start: int = 0, end: int | None = None):
        """流式遍历 [start, end)，产出 (offset, bytes)，内存恒定。"""
        end = self.size if end is None else min(end, self.size)
        pos = max(0, start)
        self._f.seek(pos)
        while pos < end:
            data = self._f.read(min(chunk, end - pos))
            if not data:
                break
            yield pos, data
            pos += len(data)

    def close(self):
        # 必须幂等且不抛：__exit__ / 重复调用 / 析构都会走到这里。
        # 关闭失败时没有可用的补救手段，再抛只会掩盖真实异常。
        try:
            self._f.close()
        except Exception:  # lint:ok 幂等 close，失败已无可补救
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def hashes(path: str, chunk: int = READ_CHUNK) -> dict:
    """流式计算 md5/sha1/sha256，支持超大文件（内存恒定）。"""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            total += len(b)
            md5.update(b)
            sha1.update(b)
            sha256.update(b)
    return {
        "size": total,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """香农熵（0–8）。空数据返回 0.0。用查表累加，比逐字节 log2 快一个量级。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


# ---------------------------------------------------------------- 魔数库

MAGICS: list[dict] = [
    # ---- 可执行文件 ----
    {"key": "pe",      "label": "PE 可执行文件 (Windows)",   "sig": b"MZ",                  "off": 0, "cat": "exec"},
    {"key": "elf",     "label": "ELF 可执行文件 (Linux/Unix)", "sig": b"\x7fELF",           "off": 0, "cat": "exec"},
    {"key": "macho64", "label": "Mach-O 64 位 (macOS/iOS)",  "sig": b"\xcf\xfa\xed\xfe",    "off": 0, "cat": "exec"},
    {"key": "macho32", "label": "Mach-O 32 位 (macOS/iOS)",  "sig": b"\xce\xfa\xed\xfe",    "off": 0, "cat": "exec"},
    {"key": "macho64be", "label": "Mach-O 64 位大端",         "sig": b"\xfe\xed\xfa\xcf",    "off": 0, "cat": "exec"},
    {"key": "macho32be", "label": "Mach-O 32 位大端",         "sig": b"\xfe\xed\xfa\xce",    "off": 0, "cat": "exec"},
    {"key": "fat",     "label": "Mach-O 胖二进制 (多架构)",   "sig": b"\xca\xfe\xba\xbe",    "off": 0, "cat": "exec"},
    {"key": "dex035",  "label": "DEX 035 (Android)",          "sig": b"dex\n035\x00",        "off": 0, "cat": "exec"},
    {"key": "dex037",  "label": "DEX 037 (Android 7+)",       "sig": b"dex\n037\x00",        "off": 0, "cat": "exec"},
    {"key": "dex038",  "label": "DEX 038 (Android 8+)",       "sig": b"dex\n038\x00",        "off": 0, "cat": "exec"},
    {"key": "dex039",  "label": "DEX 039 (Android 9+)",       "sig": b"dex\n039\x00",        "off": 0, "cat": "exec"},
    {"key": "wasm",    "label": "WebAssembly 模块",           "sig": b"\x00asm",             "off": 0, "cat": "exec"},
    {"key": "class",   "label": "Java .class 字节码",         "sig": b"\xca\xfe\xba\xbe",    "off": 0, "cat": "exec"},
    {"key": "ar",      "label": "ar 静态库 / deb",            "sig": b"!<arch>\n",           "off": 0, "cat": "archive"},

    # ---- 归档 / 打包 ----
    {"key": "zip",     "label": "ZIP 归档 (APK/JAR/docx/whl)", "sig": b"PK\x03\x04",         "off": 0, "cat": "archive"},
    {"key": "gzip",    "label": "gzip 压缩",                  "sig": b"\x1f\x8b",            "off": 0, "cat": "archive"},
    {"key": "bzip2",   "label": "bzip2 压缩",                 "sig": b"BZh",                 "off": 0, "cat": "archive"},
    {"key": "xz",      "label": "xz 压缩",                    "sig": b"\xfd7zXZ\x00",        "off": 0, "cat": "archive"},
    {"key": "zstd",    "label": "zstd 压缩",                  "sig": b"\x28\xb5\x2f\xfd",    "off": 0, "cat": "archive"},
    {"key": "lz4",     "label": "lz4 压缩",                   "sig": b"\x04\x22\x4d\x18",    "off": 0, "cat": "archive"},
    {"key": "sevenz",  "label": "7z 归档",                    "sig": b"7z\xbc\xaf\x27\x1c",  "off": 0, "cat": "archive"},
    {"key": "rar",     "label": "RAR 归档",                   "sig": b"Rar!\x1a\x07",        "off": 0, "cat": "archive"},
    {"key": "tar",     "label": "tar 归档",                   "sig": b"ustar",               "off": 257, "cat": "archive"},
    {"key": "cab",     "label": "Microsoft CAB",              "sig": b"MSCF",                "off": 0, "cat": "archive"},
    {"key": "ole2",    "label": "OLE2 复合文档 (doc/xls/msi)", "sig": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "off": 0, "cat": "archive"},

    # ---- 固件 / 文件系统 ----
    {"key": "squashfs", "label": "SquashFS 文件系统",         "sig": b"hsqs",                "off": 0, "cat": "fs"},
    {"key": "squashfs", "label": "SquashFS 文件系统(大端)",    "sig": b"sqsh",                "off": 0, "cat": "fs"},
    {"key": "cramfs",  "label": "CramFS 文件系统",            "sig": b"\x45\x3d\xcd\x28",    "off": 0, "cat": "fs"},
    {"key": "cramfsbe", "label": "CramFS 文件系统(大端)",      "sig": b"\x28\xcd\x3d\x45",    "off": 0, "cat": "fs"},
    {"key": "jffs2",   "label": "JFFS2 文件系统",             "sig": b"\x19\x85",            "off": 0, "cat": "fs"},
    {"key": "jffs2be", "label": "JFFS2 文件系统(大端)",        "sig": b"\x85\x19",            "off": 0, "cat": "fs"},
    {"key": "romfs",   "label": "romfs 文件系统",             "sig": b"-rom1fs-",            "off": 0, "cat": "fs"},
    {"key": "ubifs",   "label": "UBIFS 文件系统",             "sig": b"\x31\x18\x10\x06",    "off": 0, "cat": "fs"},
    {"key": "uimage",  "label": "U-Boot uImage 镜像",         "sig": b"\x27\x05\x19\x56",    "off": 0, "cat": "fw"},
    {"key": "androidboot", "label": "Android boot.img",       "sig": b"ANDROID!",            "off": 0, "cat": "fw"},
    {"key": "dtb",     "label": "设备树 Blob (DTB)",          "sig": b"\xd0\x0d\xfe\xed",    "off": 0, "cat": "fw"},
    {"key": "trx",     "label": "TRX 固件容器 (路由器)",       "sig": b"HDR0",                "off": 0, "cat": "fw"},

    # ---- 数据 / 文档 ----
    {"key": "sqlite",  "label": "SQLite 数据库",              "sig": b"SQLite format 3\x00", "off": 0, "cat": "data"},
    {"key": "pdf",     "label": "PDF 文档",                   "sig": b"%PDF",                "off": 0, "cat": "doc"},
    {"key": "png",     "label": "PNG 图片",                   "sig": b"\x89PNG\r\n\x1a\n",   "off": 0, "cat": "image"},
    {"key": "jpeg",    "label": "JPEG 图片",                  "sig": b"\xff\xd8\xff",        "off": 0, "cat": "image"},
    {"key": "gif",     "label": "GIF 图片",                   "sig": b"GIF8",                "off": 0, "cat": "image"},
    {"key": "webp",    "label": "WebP 图片",                  "sig": b"RIFF",                "off": 0, "cat": "image"},
    {"key": "pem",     "label": "PEM 证书/密钥",              "sig": b"-----BEGIN",          "off": 0, "cat": "data"},
    {"key": "pcap",    "label": "pcap 抓包",                  "sig": b"\xd4\xc3\xb2\xa1",    "off": 0, "cat": "data"},
    {"key": "pcapbe",  "label": "pcap 抓包(大端)",            "sig": b"\xa1\xb2\xc3\xd4",    "off": 0, "cat": "data"},
    {"key": "pcapng",  "label": "pcapng 抓包",                "sig": b"\x0a\x0d\x0d\x0a",    "off": 0, "cat": "data"},
]

# pyc 魔数表：key 为「惯例编号」（raw magic & 0xFFFF）
# 标注 verified=True 的为本机实测确认，其余为公开资料参考值。
PYC_MAGIC: dict[int, tuple] = {
    62211: ("2.7", False),
    3394:  ("3.7", False),
    3413:  ("3.8", False),
    3425:  ("3.9", False),
    3439:  ("3.10", True),   # GitHub Actions 实机验证
    3495:  ("3.11", False),
    3531:  ("3.12", False),
    3571:  ("3.13", True),   # 已实测
    3627:  ("3.14", True),   # 已实测
}

# PE Machine 类型
PE_MACHINE = {
    0x014C: ("x86", 32), 0x8664: ("x86-64", 64), 0x01C0: ("ARM", 32),
    0x01C4: ("ARMNT", 32), 0xAA64: ("ARM64", 64), 0x0200: ("IA64", 64),
    0x01C2: ("Thumb", 32), 0x5032: ("RISC-V", 32), 0x5064: ("RISC-V", 64),
    0x5128: ("RISC-V", 128), 0x6232: ("LoongArch", 32), 0x6264: ("LoongArch", 64),
    0x0EBC: ("EBC", 64), 0x0166: ("MIPS", 32), 0x0266: ("MIPS64", 64),
    0x0184: ("Alpha AXP", 64), 0x01F0: ("PowerPC", 32), 0x01F1: ("PowerPC FP", 32),
}

PE_SUBSYSTEM = {
    0: "Unknown", 1: "Native(驱动)", 2: "GUI", 3: "CUI(控制台)", 5: "OS/2 CUI",
    7: "POSIX CUI", 9: "WinCE GUI", 10: "EFI Application", 11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver", 13: "EFI ROM", 14: "XBOX", 16: "Windows Boot Application",
}

PE_DLLCHARS = [
    (0x0020, "HIGH_ENTROPY_VA"), (0x0040, "ASLR(DYNAMIC_BASE)"), (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"), (0x0200, "NO_ISOLATION"), (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"), (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF(控制流防护)"), (0x8000, "TERMINAL_SERVER_AWARE"),
]

PE_SECTION_CHARS = [
    (0x00000020, "CODE"), (0x00000040, "INITIALIZED_DATA"), (0x00000080, "UNINITIALIZED_DATA"),
    (0x02000000, "DISCARDABLE"), (0x10000000, "SHARED"), (0x20000000, "EXECUTE"),
    (0x40000000, "READ"), (0x80000000, "WRITE"),
]

# 已知壳/打包器的节名特征（公开资料常见特征，需结合熵与导入数综合判断）
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".aspackdata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".petite": "Petite", "petite": "Petite", ".RLPack": "RLPack", ".packed": "RLPack",
    "Themida": "Themida", ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".ccg": "CCG Packer", ".MEW": "MEW", "MEW": "MEW", "FSG!": "FSG",
    ".fsg": "FSG", "kkrunchy": "kkrunchy", ".perplex": "Perplex",
    ".ccdboom": "CExe", ".crunch!": "Crunch", ".sexe": "SEXE",
    ".spack": "Simple Pack", ".svkp": "SVKP", "WWPACK": "WWPack",
    ".boom": "Telock", ".rlp": "RLPack", ".ImportAd": "Import Address Hiding",
    ".enigma": "Enigma", ".enigmar": "Enigma", ".perplex": "Perplex",
}

# ELF
ELF_CLASS = {1: 32, 2: 64}
ELF_DATA = {1: "little", 2: "big"}
ELF_OSABI = {0: "System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux", 6: "Solaris",
             7: "AIX", 8: "IRIX", 9: "FreeBSD", 12: "OpenBSD", 13: "NetBSD"}
ELF_TYPE = {0: "NONE", 1: "REL(可重定位)", 2: "EXEC(可执行)", 3: "DYN(共享对象/PIE)", 4: "CORE"}
ELF_MACHINE = {
    0: "None", 3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS",
    10: "MIPS(LE)", 20: "PowerPC", 21: "PowerPC64", 22: "S390", 15: "PA-RISC",
    2: "SPARC", 43: "SPARC v9", 243: "RISC-V", 258: "LoongArch",
    0x5448: "Fujitsu FR-V", 50: "IA-64", 106: "Blackfin", 140: "TI C6000",
    220: "Z80", 94: "ARC", 195: "ARC64", 224: "AMDGPU", 247: "BPF",
}
SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
       6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
       14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
       18: "SYMTAB_SHNDX", 0x6FFFFFFD: "GNU_VERDEF", 0x6FFFFFFE: "GNU_VERNEED",
       0x6FFFFFFF: "GNU_VERSYM"}
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB",
      6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK",
      0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY"}
DT = {0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH", 5: "STRTAB",
      6: "SYMTAB", 7: "RELA", 10: "RELASZ", 11: "RELAENT", 14: "SONAME", 15: "RPATH",
      17: "REL", 20: "PLTREL", 23: "JMPREL", 25: "INIT_ARRAY", 26: "FINI_ARRAY",
      29: "RUNPATH", 30: "FLAGS", 0x6FFFFFFB: "FLAGS_1", 0x6FFFFFF0: "VERSYM",
      0x6FFFFFFE: "VERNEED", 0x6FFFFFFD: "VERDEF", 0x6FFFFFF9: "RELACOUNT",
      0x6FFFFFFA: "RELCOUNT", 21: "DEBUG"}

# Mach-O
MH_FILETYPE = {1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE", 5: "PRELOAD",
               6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE", 9: "DYLIB_STUB",
               10: "DSYM", 11: "KEXT_BUNDLE", 12: "FILESET", 13: "GPU_EXECUTE",
               14: "GPU_DYLIB"}
MH_CPU = {7: ("x86", 32), 0x01000007: ("x86-64", 64), 12: ("ARM", 32),
          0x0100000C: ("ARM64", 64), 0x0200000C: ("ARM64_32", 32),
          0x0000000D: ("MC98000", 32), 18: ("PowerPC", 32),
          0x01000012: ("PowerPC64", 64), 0x02000012: ("PowerPC64", 64)}
LC_NAMES = {0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB",
            0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_WEAK_DYLIB", 0x12: "LC_SUB_FRAMEWORK",
            0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE",
            0x19: "LC_SEGMENT_64", 0x21: "LC_ENCRYPTION_INFO", 0x2C: "LC_ENCRYPTION_INFO_64",
            0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS",
            0x2F: "LC_VERSION_MIN_TVOS", 0x30: "LC_VERSION_MIN_WATCHOS",
            0x32: "LC_BUILD_VERSION", 0x26: "LC_FUNCTION_STARTS",
            0x80000028: "LC_MAIN", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
            0x80000035: "LC_DYLD_EXPORTS_TRIE", 0x1F: "LC_REEXPORT_DYLIB",
            0x20: "LC_LAZY_LOAD_DYLIB", 0x2: "LC_SYMTAB"}

# Android 加固厂商特征（公开资料常见文件名，命中仅作线索，需结合其它证据）
APK_PACKERS = [
    ("libjiagu.so", "360 加固"), ("libjiagu_64.so", "360 加固"), ("libjiagu_x86.so", "360 加固"),
    ("libdexjni.so", "腾讯乐固(Legu)"), ("libdexhelper.so", "腾讯乐固(Legu)"),
    ("libexec.so", "梆梆加固(Bangcle)"), ("libexecmain.so", "梆梆加固(Bangcle)"),
    ("libsecexe.so", "梆梆加固(Bangcle)"), ("libsecmain.so", "梆梆加固(Bangcle)"),
    ("libDexHelper.so", "梆梆加固(Bangcle)"), ("libsecshell.so", "阿里聚安全"),
    ("libSecShell.so", "阿里聚安全"), ("libmobisec.so", "阿里聚安全"),
    ("libkwscmm.so", "爱加密(ijiami)"), ("libkwslinker.so", "爱加密(ijiami)"),
    ("libijiami.so", "爱加密(ijiami)"), ("libddog.so", "通付盾"),
    ("libnagapt.so", "娜迦(Naga)"), ("libnaga.so", "娜迦(Naga)"),
    ("libbaiduprotect.so", "百度加固"), ("libapkprotect.so", "APKProtect"),
    ("libtup.so", "腾讯御安全"), ("libtosprotection.so", "腾讯御安全"),
    ("libx3g.so", "几维安全"), ("libvmp.so", "几维安全"), ("libdprotect.so", "数字联盟"),
]

# WASM section id
WASM_SECTIONS = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
                 5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
                 10: "code", 11: "data", 12: "datacount"}


# ---------------------------------------------------------------- 小工具

def _u(spec: str, data: bytes, off: int = 0):
    """struct.unpack_from，越界返回 None。"""
    try:
        return struct.unpack_from(spec, data, off)
    except Exception:
        return None


def _cstr(data: bytes, off: int = 0, limit: int | None = 256) -> str:
    """读 NUL 结尾字符串（off 默认 0，便于直接传整块数据）。

    参数
    ----
    off   : 在 data 内的起始偏移
    limit : 搜索 NUL 的**硬上限**（不是"读满再看 NUL"）。传 None 表示
            搜到 data 末尾为止 —— 读符号名时应传 None 或 _MAX_SYMBOL_LEN。

    注意 limit 是**硬上限**，不是"最多读这么多字节再找 NUL"。对导出/导入
    名这类可能极长的字符串，调用方必须显式给足 limit，否则会被静默截断。
    实测教训（两次踩坑，第二次才是真因）：
      1. 三处符号名读取原来写成 `r.read(off, 256)`，读取量就不够；
      2. 改成 `r.read(off, _MAX_SYMBOL_LEN)` 后**仍然**截到 256 ——
         因为 `_cstr` 自己的 `limit` 参数默认值就是 256，读取量放大
         但 limit 没跟着传，等于没改。
    所以正确写法是两处都要给够：`_cstr(r.read(off, N), 0, N)`。
    实测证据（BingOnlineServices.dll，导出名 #114）：
        _cstr(r.read(no, 65536), 0)        -> len=256   ← 截断
        _cstr(r.read(no, 65536), 0, 65536) -> len=446   ← 正确
    MSVC 模板链动辄 400-4000 字符，截断后得到的残名既解不出也无法与
    dbghelp 对照，会伪造出一批"解不开"的假 bug。
    """
    hi = len(data) if limit is None else min(off + limit, len(data))
    end = data.find(b"\x00", off, hi)
    if end < 0:
        end = hi
    return data[off:end].decode("utf-8", "replace")


# 符号名（导出名/导入名/字符串表项）的最大长度。
# 必须显著大于 256：MSVC 修饰名在真实二进制里经常超过 1000 字符，
# 截断后得到的假符号既解不出也无法与 dbghelp 对照。
_MAX_SYMBOL_LEN = 65536


def uleb128(data: bytes, off: int) -> tuple[int, int]:
    """DEX/WASM 用的无符号 LEB128。返回 (值, 新偏移)。"""
    result = 0
    shift = 0
    while off < len(data):
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            break
    return result, off


def _flags(mask: int, table) -> list[str]:
    return [name for bit, name in table if mask & bit]


def _ts(ts: int) -> str | None:
    try:
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return None


# ---------------------------------------------------------------- 顶层识别


def identify(path: str, deep: bool = True) -> dict:
    """
    识别文件类型。返回结构化结果，任何异常都被兜住。

    deep=True 时会进一步做结构解析（PE/ELF/Mach-O/DEX/ZIP/pyc/WASM/SQLite）。
    """
    out: dict = {
        "path": path,
        "exists": os.path.exists(path),
        "dirname": os.path.dirname(os.path.abspath(path)) if path else "",
        "basename": os.path.basename(path),
        "ext": os.path.splitext(path)[1].lower(),
        "format": "unknown",
        "label": "未知格式",
        "category": "unknown",
        "arch": None,
        "bits": None,
        "endian": None,
        "confidence": "low",
        "candidates": [],
        "magic_hex": "",
        "magic_ascii": "",
        "notes": [],
        "errors": [],
    }
    try:
        r = Reader(path)
    except Exception as e:
        out["errors"].append(f"无法读取：{type(e).__name__}: {e}")
        return out
    with r:
        out["size"] = r.size
        head = r.read(0, 4096)
        out["magic_hex"] = head[:16].hex()
        out["magic_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in head[:16])

        # 1) 魔数匹配
        cands = []
        for m in MAGICS:
            if len(head) < m["off"] + len(m["sig"]):
                continue
            if head[m["off"]:m["off"] + len(m["sig"])] == m["sig"]:
                cands.append({**m, "confidence": "high" if len(m["sig"]) >= 4 else "medium"})

        # 2) 歧义消解：0xCAFEBABE 同时是 Java class 与 Mach-O fat
        if cands and cands[0]["sig"] == b"\xca\xfe\xba\xbe":
            cls = _looks_like_java_class(head)
            if cls:
                out["format"], out["label"] = "class", "Java .class 字节码"
                out["category"] = "exec"
                out["confidence"] = "high"
                cands = [c for c in cands if c["key"] != "fat"] + [
                    {"key": "class", "label": "Java .class 字节码", "cat": "exec", "confidence": "high"}]
            else:
                out["format"], out["label"] = "fat", "Mach-O 胖二进制 (多架构)"
                out["category"] = "exec"
                out["confidence"] = "high"

        # 3) MZ 需要二次确认（PE 签名），否则可能是 DOS 程序或其他
        elif cands and cands[0]["key"] == "pe":
            v = _u("<I", head, 0x3C)
            ok = False
            if v:
                lf = v[0]
                if 0 < lf < r.size - 64:
                    ok = r.read(lf, 4) == b"PE\x00\x00"
            if ok:
                out["format"], out["label"], out["category"] = "pe", "PE 可执行文件 (Windows)", "exec"
                out["confidence"] = "high"
            else:
                out["format"], out["label"] = "mz", "DOS MZ 可执行（无 PE 签名）"
                out["category"] = "exec"
                out["confidence"] = "medium"
                out["notes"].append("有 MZ 头但无 PE 签名：可能是 DOS 程序、损坏文件或被截断")

        elif cands:
            best = cands[0]
            out["format"], out["label"], out["category"] = best["key"], best["label"], best["cat"]
            out["confidence"] = best.get("confidence", "high")

        # 4) 无魔数：pyc / 脚本 / 文本 / 纯二进制
        else:
            kind = _classify_no_magic(path, r, head)
            out.update(kind)

        out["candidates"] = [
            {"key": c.get("key", c.get("format")), "label": c.get("label", ""),
             "confidence": c.get("confidence", "")} for c in cands[:8]
        ]

        # 5) 深度解析
        if deep and out["format"] != "unknown":
            if r.size > MAX_PARSE_SIZE:
                out["notes"].append(
                    f"文件 {r.size / 1048576:.1f}MB 超过结构解析上限 "
                    f"{MAX_PARSE_SIZE // 1048576}MB，仅做流式分析（用 --max-parse-size 调整）")
            else:
                try:
                    detail = parse_detail(r, out["format"])
                except Exception as e:  # 兜底：解析炸了也不能让命令崩
                    detail = {"parse_ok": False, "errors": [f"{type(e).__name__}: {e}"]}
                out["detail"] = detail
                # 用解析结果回填架构等字段
                for k in ("arch", "bits", "endian"):
                    if detail.get(k) and not out.get(k):
                        out[k] = detail[k]
        return out


def _looks_like_java_class(head: bytes) -> bool:
    """0xCAFEBABE 歧义消解：Java class 的 magic 后跟 minor/major 版本。"""
    v = _u(">HH", head, 4)
    if not v:
        return False
    minor, major = v
    # Java major 版本从 45(JDK1.1) 到 70+；Mach-O fat 的 nfat_arch 通常很小且第 8 字节后是 cputype
    if 45 <= major <= 100 and minor <= 0xFFFF:
        # 再验证：constant_pool_count 必须 >= 1
        cp = _u(">H", head, 8)
        if cp and cp[0] >= 1:
            return True
    return False


def _classify_no_magic(path: str, r: Reader, head: bytes) -> dict:
    """无魔数时的兜底分类：pyc / 脚本 / 文本 / 未知二进制。"""
    res = {"format": "unknown", "label": "未知二进制", "category": "data", "confidence": "low"}

    # pyc：前 4 字节是 magic，第 5-8 字节是 bit field，通常高 27 位为 0
    if len(head) >= 16:
        raw = int.from_bytes(head[:4], "little", signed=False)
        conv = raw & 0xFFFF
        bitfield = int.from_bytes(head[4:8], "little")
        if conv in PYC_MAGIC and bitfield <= 0x0F:
            ver, verified = PYC_MAGIC[conv]
            res.update({"format": "pyc", "label": f"Python 字节码 (.pyc, 推定 {ver})",
                        "category": "exec", "confidence": "high" if verified else "medium"})
            return res

    # shebang
    if head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0].decode("utf-8", "replace")[:80]
        lang = "未知"
        for k, v in (("python", "Python"), ("node", "Node.js"), ("sh", "Shell"),
                     ("bash", "Bash"), ("perl", "Perl"), ("ruby", "Ruby"),
                     ("php", "PHP"), ("lua", "Lua")):
            if k in line:
                lang = v
                break
        return {"format": "script", "label": f"脚本 ({lang})", "category": "script",
                "confidence": "high", "shebang": line}

    # 文本检测
    sample = head[:1024]
    if sample:
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / len(sample)
        if ratio > 0.95:
            text = head[:2048].decode("utf-8", "replace")
            fmt, label = "text", "纯文本"
            low = text[:400].lstrip().lower()
            if low.startswith("{") or low.startswith("["):
                fmt, label = "json", "JSON 文本"
            elif low.startswith("<?xml") or low.startswith("<"):
                fmt, label = "xml", "XML/HTML"
            elif "<?php" in text[:200]:
                fmt, label = "php", "PHP 源码"
            elif re.search(r"\b(function|=>|const |let |var |require\(|module\.exports)\b", text[:2000]):
                fmt, label = "js", "JavaScript 源码"
            elif re.search(r"^\s*(import |def |class |from )", text[:2000], re.M):
                fmt, label = "python_src", "Python 源码"
            return {"format": fmt, "label": label, "category": "text", "confidence": "medium"}
        if ratio > 0.7:
            return {"format": "text", "label": "文本（含少量二进制）", "category": "text",
                    "confidence": "low"}
    return res


def parse_detail(r: Reader, fmt: str) -> dict:
    """按格式分派到具体解析器。"""
    table = {
        "pe": parse_pe, "elf": parse_elf, "macho64": parse_macho, "macho32": parse_macho,
        "macho64be": parse_macho, "macho32be": parse_macho, "fat": parse_macho,
        "dex035": parse_dex, "dex037": parse_dex, "dex038": parse_dex, "dex039": parse_dex,
        "zip": parse_zip, "pyc": parse_pyc, "wasm": parse_wasm,
        "sqlite": parse_sqlite, "class": parse_javaclass,
    }
    fn = table.get(fmt)
    if not fn:
        return {"parse_ok": True, "parser": None, "note": "该格式暂无深度解析器"}
    return fn(r)


# ---------------------------------------------------------------- PE


def parse_pe(r: Reader) -> dict:
    d: dict = {"parser": "pe", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 0x400)
        e_lfanew = _u("<I", head, 0x3C)[0]
        pe = r.read(e_lfanew, 24)
        if pe[:4] != b"PE\x00\x00":
            d["errors"].append("PE 签名缺失")
            return d
        machine, nsec, tds, _, _, size_opt, chars = struct.unpack_from("<HHIIIHH", pe, 4)
        opt_start = e_lfanew + 24
        opt = r.read(opt_start, max(size_opt, 1024))
        magic = _u("<H", opt, 0)[0]
        is64 = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            d["errors"].append(f"未知 Optional Header 魔数 0x{magic:X}")
            return d

        # 逐字段按偏移读取（比一次性 unpack 更抗版本差异，也不会因字段数写错而崩）
        # 布局：0 Magic 2/3 LinkerVer 4 SizeOfCode 8 SizeOfInitData 12 SizeOfUninitData
        #      16 AddressOfEntryPoint 20 BaseOfCode
        #      PE32+ : 24 ImageBase(Q) 32 SectAlign 36 FileAlign 40..51 版本号
        #              52 Win32Ver 56 SizeOfImage 60 SizeOfHeaders 64 CheckSum
        #              68 Subsystem 70 DllChars ... 108 NumRvaAndSizes 112 DataDir
        #      PE32  : 24 ImageBase(I) 28 SectAlign 32 FileAlign 36..47 版本号
        #              48 Win32Ver 52 SizeOfImage 56 SizeOfHeaders 60 CheckSum
        #              64 Subsystem 66 DllChars ... 88 NumRvaAndSizes 92 DataDir
        entry = _u("<I", opt, 16)[0]
        imagebase = _u("<Q" if is64 else "<I", opt, 24)[0]
        o = 32 if is64 else 28
        sect_align = _u("<I", opt, o)[0]
        file_align = _u("<I", opt, o + 4)[0]
        o = 56 if is64 else 52
        size_image = _u("<I", opt, o)[0]
        size_headers = _u("<I", opt, o + 4)[0]
        checksum = _u("<I", opt, o + 8)[0]
        o = 68 if is64 else 64
        subsystem = _u("<H", opt, o)[0]
        dllchars = _u("<H", opt, o + 2)[0]
        nrva_off = 108 if is64 else 88
        dd_off = 112 if is64 else 92
        nrva = _u("<I", opt, nrva_off)
        nrva = min(nrva[0], 16) if nrva else 16

        dirs = []
        for i in range(nrva):
            v = _u("<II", opt, dd_off + i * 8)
            dirs.append({"index": i, "rva": v[0], "size": v[1]} if v else
                        {"index": i, "rva": 0, "size": 0})

        # .NET 判定须在加壳线索之前算出来：托管程序集没有原生导入表，
        # 后文的启发式要用它来避免误报。
        is_dotnet = len(dirs) > 14 and dirs[14]["rva"] != 0

        # 节表
        sec_off = opt_start + size_opt
        sections = []
        for i in range(min(nsec, 96)):
            raw = r.read(sec_off + i * 40, 40)
            if len(raw) < 40:
                break
            name = raw[:8].rstrip(b"\x00").decode("utf-8", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
            schars = struct.unpack_from("<I", raw, 36)[0]
            ent = 0.0
            if rawsize and rawptr < r.size:
                ent = shannon_entropy(r.read(rawptr, min(rawsize, MAX_READ_FOR_ENTROPY)))
            sections.append({
                "name": name, "virtual_size": vsize, "virtual_address": vaddr,
                "raw_size": rawsize, "raw_offset": rawptr,
                "entropy": ent, "chars": _flags(schars, PE_SECTION_CHARS),
            })

        def rva2off(rva: int) -> int | None:
            for s in sections:
                if s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
                    return s["raw_offset"] + (rva - s["virtual_address"])
            return None

        # 导入表
        imports = []
        imp_dir = dirs[1] if len(dirs) > 1 else {"rva": 0, "size": 0}
        func_total = 0
        if imp_dir["rva"]:
            off = rva2off(imp_dir["rva"])
            if off:
                for i in range(128):          # 最多 128 个 DLL，防死循环
                    raw = r.read(off + i * 20, 20)
                    if len(raw) < 20 or raw == b"\x00" * 20:
                        break
                    int_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", raw, 0)
                    noff = rva2off(name_rva)
                    if not noff:
                        continue
                    dll = _cstr(r.read(noff, 128))
                    funcs = []
                    if int_rva:
                        toff = rva2off(int_rva)
                        if toff:
                            step = 8 if is64 else 4
                            for j in range(2048):
                                fraw = r.read(toff + j * step, step)
                                if len(fraw) < step:
                                    break
                                val = int.from_bytes(fraw, "little")
                                if val == 0:
                                    break
                                # IAT 槽位 RVA：编译器生成的 call [rip+x] / jmp [x]
                                # 引用的正是这个槽位地址，靠它才能把调用目标
                                # 还原成 "kernel32!CreateFileW" 这样的名字
                                slot = (iat_rva + j * step) if iat_rva else None
                                if val & (1 << (63 if is64 else 31)):
                                    funcs.append({"name": f"ordinal#{val & 0xFFFF}",
                                                  "ordinal": True, "iat_rva": slot})
                                else:
                                    noff2 = rva2off(val)
                                    if noff2:
                                        nm = _cstr(r.read(noff2 + 2, _MAX_SYMBOL_LEN),
                                                   0, _MAX_SYMBOL_LEN)
                                        if nm:
                                            funcs.append({"name": nm, "ordinal": False,
                                                          "iat_rva": slot})
                                if len(funcs) >= 512:
                                    break
                    func_total += len(funcs)
                    imports.append({"dll": dll, "count": len(funcs), "functions": funcs,
                                    "iat_rva": iat_rva})
                    if func_total >= 8192:
                        break

        # 延迟导入表（Delay Import，数据目录 13）
        # 逆向意义很大：delay-load 的 DLL **不在静态导入表里**，静态扫一眼会漏掉
        # 大量真实 API 调用（实机验证：notepad.exe 有 33 处 call 指向 .didat 槽位，
        # 不解析就全是"未知调用"）。结构与普通导入表同构：INT 给名字、IAT 给槽位。
        delay_imports = []
        if len(dirs) > 13 and dirs[13].get("rva"):
            doff = rva2off(dirs[13]["rva"])
            if doff:
                for i in range(64):               # 最多 64 个描述符，防死循环
                    raw = r.read(doff + i * 32, 32)
                    if len(raw) < 32 or raw == b"\x00" * 32:
                        break
                    # 注意：别用 _ts 当变量名 —— 模块里的 _ts 是时间戳格式化函数，
                    # 同名覆盖会让后面 compile_time 处报 "'int' object is not callable"
                    (attrs, dname_rva, _mh, iat_rva, int_rva,
                     _biat, _uilt, _dstamp) = struct.unpack_from("<IIIIIIII", raw, 0)
                    # attrs bit0 = RvaBased。旧式链接器不置位时字段是 VA，
                    # 要减掉 imagebase 才是 RVA。
                    fix = 0 if (attrs & 1) else imagebase
                    dname_rva -= fix
                    iat_rva -= fix
                    int_rva -= fix
                    dnoff = rva2off(dname_rva) if dname_rva else None
                    if not dnoff:
                        continue
                    dll = _cstr(r.read(dnoff, 128))
                    funcs = []
                    if int_rva:
                        toff = rva2off(int_rva)
                        if toff:
                            step = 8 if is64 else 4
                            for j in range(2048):
                                fraw = r.read(toff + j * step, step)
                                if len(fraw) < step:
                                    break
                                val = int.from_bytes(fraw, "little")
                                if val == 0:
                                    break
                                slot = (iat_rva + j * step) if iat_rva else None
                                if val & (1 << (63 if is64 else 31)):
                                    funcs.append({"name": f"ordinal#{val & 0xFFFF}",
                                                  "ordinal": True, "iat_rva": slot})
                                else:
                                    vrva = val - fix
                                    noff2 = rva2off(vrva) if vrva else None
                                    if noff2:
                                        nm = _cstr(r.read(noff2 + 2, _MAX_SYMBOL_LEN),
                                                   0, _MAX_SYMBOL_LEN)
                                        if nm:
                                            funcs.append({"name": nm, "ordinal": False,
                                                          "iat_rva": slot})
                                if len(funcs) >= 512:
                                    break
                    if funcs:
                        delay_imports.append({"dll": dll, "count": len(funcs),
                                              "functions": funcs, "iat_rva": iat_rva})

        # 导出表
        # 单独兜底：任何一个目录解析炸了都不该让整个 PE 结构解析归零。
        # （导出表/资源表是畸形样本里最容易越界的两处。）
        exports = []
        export_syms = []      # [{name, ordinal, rva}] —— 供函数命名用
        exp_dir = dirs[0] if dirs else {"rva": 0, "size": 0}
        if exp_dir["rva"]:
            try:
              off = rva2off(exp_dir["rva"])
              if off:
                # IMAGE_EXPORT_DIRECTORY 共 40 字节，字段布局（winnt.h）：
                #   DWORD Characteristics; DWORD TimeDateStamp;
                #   WORD  MajorVersion;  WORD  MinorVersion;
                #   DWORD Name; DWORD Base; DWORD NumberOfFunctions;
                #   DWORD NumberOfNames; DWORD AddressOfFunctions;
                #   DWORD AddressOfNames; DWORD AddressOfNameOrdinals;
                #
                # 【关键 bug 修复】旧代码用 "<IIIIIIIIIII"（11 个 DWORD = 44 字节）
                # 解这个结构，把两个 WORD 当成一个 DWORD 吃掉了。表面看前几个
                # 字段还对（Characteristics / TimeDateStamp 恰好连续），但从
                # MajorVersion 起整体错位 4 字节，于是 NumberOfNames、EAT、NPT、
                # 序号表 rva 全部指向垃圾 —— AddressOfNames 会落到 .text 里，
                # 读出来的"符号名"是机器码字节（实测 AdmTmpl.dll 读到 3494 条
                # 假符号，真值只有 4 条，如 'H\x83cP'）。这直接污染了整个
                # 符号语料与函数命名。
                # 正确解包：III + HH + 6I = 40 字节。
                raw = r.read(off, 40)
                if len(raw) >= 40:
                    (_flags_, _tds_, _mj, _mn, name_rva, ordinal_base, addr_cnt,
                     name_cnt, _eat, npt_rva, _ot) = struct.unpack_from("<IIIHHIIIIII", raw, 0)
                    # 导出表三张表：EAT(地址) / NamePointer(名字) / Ordinal(序号)。
                    # 只有把名字和地址对上，才能把 DLL 的导出函数标出真实名字 ——
                    # 这是分析 DLL 时**唯一免费可得的符号**，不能浪费。
                    # 【已修 bug】旧实现只收名字不收地址，而 lib_disasm.symbols_from
                    # 却按 {rva,name} 字典在用，两边形状对不上直接 AttributeError。
                    eat_off = rva2off(_eat)
                    npt = rva2off(npt_rva)
                    ot_off = rva2off(_ot)
                    addr_by_ord: dict[int, int] = {}
                    if eat_off:
                        for i in range(min(addr_cnt, 8192)):
                            v = _u("<I", r.read(eat_off + i * 4, 4), 0)
                            if v and v[0]:
                                addr_by_ord[ordinal_base + i] = v[0]
                    if npt:
                        for i in range(min(name_cnt, 8192)):
                            nr = _u("<I", r.read(npt + i * 4, 4), 0)
                            if not nr or not nr[0]:
                                continue
                            so = rva2off(nr[0])
                            if not so:
                                continue
                            nm = _cstr(r.read(so, _MAX_SYMBOL_LEN),
                                       0, _MAX_SYMBOL_LEN)
                            if not nm:
                                continue
                            exports.append(nm)
                            ordi = _u("<H", r.read(ot_off + i * 2, 2), 0) if ot_off else None
                            o = (ordi[0] if ordi else ordinal_base + i)
                            export_syms.append({"name": nm, "ordinal": o,
                                                "rva": addr_by_ord.get(o)})
                    ename_off = rva2off(name_rva)
                    d["export_name"] = _cstr(r.read(ename_off, 128), 0) if ename_off else None
                    d["export_count"] = addr_cnt
            except Exception as e:
                d["errors"].append(f"导出表解析失败：{type(e).__name__}: {e}")

        # 调试目录 → PDB 路径（泄露源码目录结构）
        pdb = None
        if len(dirs) > 6 and dirs[6]["rva"]:
            off = rva2off(dirs[6]["rva"])
            if off:
                for i in range(8):
                    raw = r.read(off + i * 28, 28)
                    if len(raw) < 28:
                        break
                    _c, _t, _mj, _mn, typ, sz, addr, ptr = struct.unpack_from("<IIHHIIII", raw, 0)
                    if typ == 2 and ptr and ptr < r.size:   # IMAGE_DEBUG_TYPE_CODEVIEW
                        blob = r.read(ptr, min(sz, 1024))
                        if blob[:4] == b"RSDS":
                            pdb = _cstr(blob[24:])
                            break
                        if blob[:4] == b"NB10":
                            pdb = _cstr(blob[16:])
                            break

        # 资源表（三层树，带访问集防环）
        resources = []
        if len(dirs) > 2 and dirs[2]["rva"]:
            base = rva2off(dirs[2]["rva"])
            if base:
                seen = set()
                try:
                    n_named, n_id = struct.unpack_from("<HH", r.read(base + 12, 4), 0)
                    total = min(n_named + n_id, 64)
                    for i in range(total):
                        ent = r.read(base + 16 + i * 8, 8)
                        if len(ent) < 8:
                            break
                        rid, offdata = struct.unpack_from("<II", ent, 0)
                        sub = base + (offdata & 0x7FFFFFFF)
                        if sub in seen:
                            continue
                        seen.add(sub)
                        n2, i2 = struct.unpack_from("<HH", r.read(sub + 12, 4), 0)
                        cnt = 0
                        for j in range(min(n2 + i2, 256)):
                            e2 = r.read(sub + 16 + j * 8, 8)
                            if len(e2) < 8:
                                break
                            _r2, o2 = struct.unpack_from("<II", e2, 0)
                            lvl3 = sub + (o2 & 0x7FFFFFFF)
                            n3, i3 = struct.unpack_from("<HH", r.read(lvl3 + 12, 4), 0)
                            for k in range(min(n3 + i3, 16)):
                                e3 = r.read(lvl3 + 16 + k * 8, 8)
                                if len(e3) < 8:
                                    break
                                _r3, o3 = struct.unpack_from("<II", e3, 0)
                                dataoff = rva2off(o3)
                                if dataoff:
                                    sz = _u("<I", r.read(dataoff, 4), 0)
                                    cnt += 1
                                    resources.append({
                                        "type_id": rid, "size": sz[0] if sz else 0,
                                    })
                        resources.append({"type_id": rid, "entries": cnt})
                except Exception as e:
                    d["errors"].append(f"资源解析中断：{type(e).__name__}")

        # Rich 头（MSVC 编译器指纹）
        rich = None
        try:
            scan_end = min(e_lfanew, 0x800)
            blob = r.read(0, scan_end)
            idx = blob.rfind(b"Rich")
            if idx > 0 and idx + 8 <= len(blob):
                xor = int.from_bytes(blob[idx + 4:idx + 8], "little")
                dans = bytes(b ^ (xor >> (8 * i) & 0xFF) for i, b in enumerate(b"DanS"))
                entries = []
                p = idx - 8
                while p >= 0x80 and len(entries) < 64:
                    chunk = blob[p:p + 8]
                    if len(chunk) < 8:
                        break
                    if chunk[:4] == dans:      # 起始标记 DanS（被 XOR 掩盖）
                        break
                    comp = int.from_bytes(chunk[0:4], "little") ^ xor
                    cnt = int.from_bytes(chunk[4:8], "little") ^ xor
                    entries.append({"comp_id": f"0x{comp:08X}", "count": cnt})
                    p -= 8
                if entries:
                    entries.reverse()          # 还原为「先出现 → 后出现」的原始顺序
                    rich = {"xor_key": f"0x{xor:08X}", "entry_count": len(entries),
                            "entries": entries[:24],
                            "note": "comp_id 需对照 MSVC 编译器 ID 表解读；这里只给原始值，不做猜测"}
        except Exception as e:
            # Rich 头是可选信息（老 PE 根本没有）。解析失败时不能静默 —— 但要
            # 保留"没有 Rich 头"与"有但读坏了"的区别，避免把失败当成功。
            rich = {"_error": f"{type(e).__name__}: {e}"}

        # 覆盖层（overlay）：安装包 / 加壳的常见迹象
        max_end = max([s["raw_offset"] + s["raw_size"] for s in sections], default=0)
        overlay = max(0, r.size - max_end)

        # 加壳启发式
        signals = []
        for s in sections:
            if s["name"] in PACKER_SECTIONS:
                signals.append(f"节名 {s['name']} 命中 {PACKER_SECTIONS[s['name']]}")
            if s["entropy"] >= 7.0 and s["raw_size"] > 4096:
                signals.append(f"节 {s['name']} 熵 {s['entropy']:.2f}（高，疑似压缩/加密）")
        ep_sec = None
        for s in sections:
            if s["virtual_address"] <= entry < s["virtual_address"] + max(s["virtual_size"], 1):
                ep_sec = s["name"]
        if ep_sec and sections and ep_sec == sections[-1]["name"] and len(sections) > 1:
            signals.append(f"入口点位于最后一个节 {ep_sec}（壳的典型特征）")
        if len(imports) <= 3 and r.size > 100 * 1024 and not is_dotnet:
            signals.append(f"导入表极小（{len(imports)} 个模块）但文件较大，疑似壳/静态链接")
        if overlay > r.size * 0.3 and overlay > 64 * 1024:
            signals.append(f"存在 {overlay / 1024:.0f}KB 覆盖层（>30%，常见于安装包/附加数据）")
        if not imports and not is_dotnet:
            # .NET 程序集本来就没有原生导入表（只有一条 mscoree.dll 的间接跳转），
            # 因此托管程序不把「无导入表」当作加壳信号，否则必然误报。
            signals.append("无导入表（可能手动解析 API / 加壳 / 驱动）")

        arch, bits = PE_MACHINE.get(machine, (f"unknown(0x{machine:X})", None))
        file_kind = "exe"
        if chars & 0x2000:
            file_kind = "dll"
        if chars & 0x1000:
            file_kind = "sys(驱动)"
        if is_dotnet:
            file_kind = ".NET 程序集"

        d.update({
            "parse_ok": True,
            "machine": f"0x{machine:X}", "arch": arch, "bits": bits, "endian": "little",
            "pe32plus": is64, "file_kind": file_kind, "subsystem": PE_SUBSYSTEM.get(subsystem, str(subsystem)),
            "is_dotnet": is_dotnet,
            "entry_rva": entry, "image_base": imagebase,
            "section_alignment": sect_align, "file_alignment": file_align,
            "size_of_image": size_image, "size_of_headers": size_headers,
            "checksum": checksum,
            "compile_time": _ts(tds), "compile_timestamp": tds,
            "dll_characteristics": _flags(dllchars, PE_DLLCHARS),
            "characteristics": f"0x{chars:X}",
            "sections": sections,
            "imports": imports, "import_module_count": len(imports),
            "import_function_count": func_total,
            "delay_imports": delay_imports,
            "delay_import_function_count": sum(m["count"] for m in delay_imports),
            "has_delay_import": bool(delay_imports),
            "exports": exports[:512],
            "export_syms": export_syms[:4096],
            "pdb_path": pdb,
            "resource_count": len(resources),
            "resources_sample": resources[:40],
            "has_tls": bool(len(dirs) > 9 and dirs[9]["rva"]),
            "has_reloc": bool(len(dirs) > 5 and dirs[5]["rva"]),
            "cert_size": dirs[4]["size"] if len(dirs) > 4 else 0,
            "rich_header": rich,
            "overlay_size": overlay,
            "packer_signals": signals,
            "packer_suspected": len(signals) > 0,
        })
        if is_dotnet:
            d["notes"] = [".NET 程序集：元数据完整，dnSpy/ILSpy 可近乎还原源码（NativeAOT 除外）"]
        return d
    except Exception as e:
        import os as _os
        if _os.environ.get("RE_DEBUG_TRACE"):
            import traceback as _tb
            _tb.print_exc()
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- ELF


def parse_elf(r: Reader) -> dict:
    d: dict = {"parser": "elf", "parse_ok": False, "errors": []}
    try:
        ident = r.read(0, 16)
        if ident[:4] != b"\x7fELF":
            d["errors"].append("ELF 魔数缺失")
            return d
        ei_class, ei_data = ident[4], ident[5]
        bits = ELF_CLASS.get(ei_class, 32)
        en = "<" if ei_data == 1 else ">"
        hdr = r.read(0, 64 if bits == 64 else 52)
        # ELF 头（e_ident 之后）：e_type e_machine e_version e_entry e_phoff e_shoff
        #   e_flags e_ehsize e_phentsize e_phnum e_shentsize e_shnum e_shstrndx —— 共 13 个字段
        if bits == 64:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
             _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack_from(en + "HHIQQQIHHHHHH", hdr, 16)
        else:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
             _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack_from(en + "HHIIIIIHHHHHH", hdr, 16)

        # 段（Program Header，执行视图）
        segments = []
        if e_phoff and e_phnum and e_phnum < 512:
            for i in range(e_phnum):
                raw = r.read(e_phoff + i * e_phentsize, 56)
                if len(raw) < (56 if bits == 64 else 32):
                    break
                if bits == 64:
                    p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from(en + "IIQQQQQQ", raw, 0)
                else:
                    p_type, p_off, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = struct.unpack_from(en + "IIIIIIII", raw, 0)
                segments.append({"type": PT.get(p_type, hex(p_type)), "offset": p_off,
                                 "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz,
                                 "flags": "".join([c for c, b in (("R", 4), ("W", 2), ("X", 1)) if p_flags & b])})

        # 节（Section Header，链接视图）——加壳样本常被抹掉
        sections = []
        shstr = b""
        if e_shoff and e_shnum and e_shnum < 4096:
            entsize = e_shentsize or (64 if bits == 64 else 40)
            raw_secs = []
            for i in range(e_shnum):
                raw = r.read(e_shoff + i * entsize, 64)
                if len(raw) < (64 if bits == 64 else 40):
                    break
                if bits == 64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info, _al, sh_ent = struct.unpack_from(en + "IIQQQQIIQQ", raw, 0)
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info, _al, sh_ent = struct.unpack_from(en + "IIIIIIIIII", raw, 0)
                raw_secs.append({"name_off": sh_name, "type": SHT.get(sh_type, hex(sh_type)),
                                 "flags": sh_flags, "addr": sh_addr, "offset": sh_off,
                                 "size": sh_size, "link": sh_link, "info": sh_info,
                                 "entsize": sh_ent})
            if 0 <= e_shstrndx < len(raw_secs):
                st = raw_secs[e_shstrndx]
                shstr = r.read(st["offset"], min(st["size"], 1 << 20))
            ent_budget = MAX_ENTROPY_TOTAL
            ent_skipped = 0
            for s in raw_secs:
                nm = _cstr(shstr, s["name_off"]) if shstr else ""
                ent = 0.0
                if s["size"] and s["offset"] and s["type"] not in ("NOBITS", "NULL"):
                    take = min(s["size"], MAX_READ_FOR_ENTROPY)
                    if ent_budget >= take:
                        ent_budget -= take
                        ent = shannon_entropy(r.read(s["offset"], take))
                    else:
                        # 预算耗尽就不再读。这里**不能**留 0.0：0.0 会被
                        # 下游读成"这一节是常量字节"，那是另一个假结论。
                        # None 才是"没算"，并在 notes 里交代。
                        ent = None
                        ent_skipped += 1
                sections.append({k: v for k, v in s.items() if k != "name_off"} | {"name": nm, "entropy": ent})
            if ent_skipped:
                d["notes"].append(
                    f"节熵合计读取超过 {MAX_ENTROPY_TOTAL // 1048576}MB 预算，"
                    f"剩余 {ent_skipped} 个节的熵未计算（字段为 null，不是 0）")

        # 动态段
        needed, soname, rpath, runpath, flags1 = [], None, None, None, 0
        dynsym_off = dynsym_size = dynsym_ent = strtab_off = strtab_size = None
        for s in sections:
            if s["type"] == "DYNAMIC":
                off, sz = s["offset"], min(s["size"], 1 << 20)
                blob = r.read(off, sz)
                ent = 16 if bits == 64 else 8
                for i in range(len(blob) // ent):
                    if bits == 64:
                        tag, val = struct.unpack_from(en + "QQ", blob, i * ent)
                    else:
                        tag, val = struct.unpack_from(en + "II", blob, i * ent)
                    if tag == 0:
                        break
                    if tag == 1:
                        needed.append(val)
                    elif tag == 14:
                        soname = val
                    elif tag == 15:
                        rpath = val
                    elif tag == 29:
                        runpath = val
                    elif tag == 0x6FFFFFFB:
                        flags1 = val
            if s["type"] == "DYNSYM":
                dynsym_off, dynsym_size, dynsym_ent = s["offset"], s["size"], s["entsize"] or (24 if bits == 64 else 16)
                if 0 <= s["link"] < len(sections):
                    strtab_off = sections[s["link"]]["offset"]
                    strtab_size = sections[s["link"]]["size"]

        # 解析 strtab 以还原 DT_NEEDED 与符号名
        strtab = r.read(strtab_off or 0, min(strtab_size or 0, 1 << 20)) if strtab_off else b""
        needed_names = [_cstr(strtab, v) for v in needed if v < len(strtab)] if strtab else []
        soname = _cstr(strtab, soname) if (soname is not None and strtab) else None
        rpath = _cstr(strtab, rpath) if (rpath is not None and strtab) else None
        runpath = _cstr(strtab, runpath) if (runpath is not None and strtab) else None

        symbols = []
        sym_names = set()
        if dynsym_off and dynsym_ent:
            n = min(dynsym_size // dynsym_ent, 20000)
            blob = r.read(dynsym_off, min(dynsym_size, n * dynsym_ent))
            for i in range(n):
                if bits == 64:
                    st_name = struct.unpack_from(en + "I", blob, i * dynsym_ent)[0]
                else:
                    st_name = struct.unpack_from(en + "I", blob, i * dynsym_ent)[0]
                if st_name and st_name < len(strtab):
                    nm = _cstr(strtab, st_name)
                    if nm:
                        sym_names.add(nm)
        symbols = sorted(sym_names)[:2000]

        interp = None
        for s in segments:
            if s["type"] == "INTERP":
                interp = _cstr(r.read(s["offset"], min(s["filesz"], 256)))
                break

        # checksec
        nx = all(not ("X" in s["flags"]) for s in segments if s["type"] == "GNU_STACK") and any(
            s["type"] == "GNU_STACK" for s in segments)
        pie = e_type == 3
        relro = "none"
        for s in segments:
            if s["type"] == "GNU_RELRO":
                relro = "full" if (flags1 & 0x8 or flags1 & 0x1) else "partial"
        canary = any(n in sym_names for n in ("__stack_chk_fail", "__stack_smash_handler"))
        fortify = any(n.startswith("__") and n.endswith("_chk") for n in sym_names)

        # 语言运行时指纹
        sec_names = {s["name"] for s in sections}
        lang_hints = []
        if "runtime.main" in sym_names or any(n.startswith("go.") for n in sym_names) or ".gopclntab" in sec_names:
            lang_hints.append("Go（函数名与类型元数据完整保留，pclntab 是符号金矿）")
        if any(n.startswith("_ZN") or n.startswith("_ZN4core") for n in sym_names) or \
           "rust_eh_personality" in sym_names or ".rs" in " ".join(symbols[:200]):
            lang_hints.append("Rust（panic 消息泄露源码路径；rustfilt 可还原符号）")
        if any(n.startswith("_Z") for n in sym_names):
            lang_hints.append("C++（RTTI/vtable 可辅助识别）")
        go_ver = None
        if ".go.buildinfo" in sec_names:
            bi = [s for s in sections if s["name"] == ".go.buildinfo"][0]
            blob = r.read(bi["offset"], min(bi["size"], 4096))
            m = re.search(rb"go1\.\d+(\.\d+)?", blob)
            if m:
                go_ver = m.group(0).decode()

        d.update({
            "parse_ok": True,
            "arch": ELF_MACHINE.get(e_machine, f"unknown({e_machine})"),
            "bits": bits, "endian": ELF_DATA.get(ei_data, "?"),
            "osabi": ELF_OSABI.get(ident[7], f"unknown({ident[7]})"),
            "elf_type": ELF_TYPE.get(e_type, str(e_type)),
            "entry": e_entry, "is_pie": pie,
            "interpreter": interp,
            "needed": needed_names, "soname": soname, "rpath": rpath, "runpath": runpath,
            "is_static": not needed_names and not interp,
            "segments": segments[:64],
            "sections": sections[:128],
            "section_count": len(sections),
            "has_symtab": any(s["type"] == "SYMTAB" for s in sections),
            "stripped": not any(s["type"] == "SYMTAB" for s in sections),
            "dynamic_symbols_sample": symbols[:200],
            "dynamic_symbol_count": len(sym_names),
            "checksec": {"RELRO": relro, "Canary": bool(canary), "NX": bool(nx), "PIE": pie,
                         "RPATH": rpath or runpath or None, "FORTIFY": bool(fortify)},
            "lang_hints": lang_hints,
            "go_version": go_ver,
            "packer_signals": (
                ["节头表缺失/被抹（常见于加壳）"] if not sections else []
            ) + ([f"节 {s['name']} 熵 {s['entropy']:.2f} 偏高，疑似加密/压缩"
                  # None 表示"预算耗尽没算"，按 0 处理（不加壳信号），
                  # 但绝不能让 None 进 :.2f 格式化 —— 那会直接抛 TypeError。
                  for s in sections if (s.get("entropy") or 0) >= 7.0 and s.get("size", 0) > 4096]),
        })
        d["packer_suspected"] = bool(d["packer_signals"])
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- Mach-O


def parse_macho(r: Reader) -> dict:
    d: dict = {"parser": "macho", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 32)
        magic = int.from_bytes(head[:4], "big")
        fat = magic in (0xCAFEBABE, 0xCAFEBABF, 0xBEBAFECA)
        archs = []
        targets: list[tuple[int, str]] = []   # (基准偏移, 说明)

        if fat:
            nfat = int.from_bytes(head[4:8], "big")
            is64_fat = magic == 0xCAFEBABF
            for i in range(min(nfat, 32)):
                ent = r.read(8 + i * (32 if is64_fat else 20), 32 if is64_fat else 20)
                if len(ent) < (32 if is64_fat else 20):
                    break
                if is64_fat:
                    cputype, cpusub, off, size, _al, _res = struct.unpack_from(">iiQQII", ent, 0)
                else:
                    cputype, cpusub, off, size, _al = struct.unpack_from(">iiIII", ent, 0)
                name, _b = MH_CPU.get(cputype, (f"unknown(0x{cputype:X})", None))
                archs.append({"cpu": name, "subtype": cpusub, "offset": off, "size": size})
                targets.append((off, name))
            d["fat"] = True
            d["archs"] = archs
        else:
            targets.append((0, "single"))

        parsed = []
        for base, label in targets[:8]:
            try:
                parsed.append(_parse_macho_single(r, base, label))
            except Exception as e:
                parsed.append({"cpu": label, "errors": [f"{type(e).__name__}: {e}"]})

        d["parse_ok"] = any(p.get("parse_ok") for p in parsed)
        d["slices"] = parsed
        first = parsed[0] if parsed else {}
        for k in ("arch", "bits", "endian", "filetype", "dylibs", "symbols_sample",
                  "encrypted", "cryptid", "uuid", "sections", "entry_point",
                  "min_os", "platform", "has_code_signature", "symbol_count"):
            if k in first:
                d[k] = first[k]
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


def _parse_macho_single(r: Reader, base: int, label: str) -> dict:
    out: dict = {"cpu": label, "parse_ok": False, "errors": []}
    hdr = r.read(base, 32)
    magic = int.from_bytes(hdr[:4], "big")
    if magic == 0xFEEDFACF:
        en, is64 = ">", True        # 大端存储（PowerPC 时代）
    elif magic == 0xFEEDFACE:
        en, is64 = ">", False
    elif magic == 0xCFFAEDFE:
        en, is64 = "<", True        # 小端（Intel/ARM）
    elif magic == 0xCEFAEDFE:
        en, is64 = "<", False
    else:
        out["errors"].append(f"未知 Mach-O 魔数 0x{magic:08X}")
        return out
    cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(en + "iiIIII", hdr, 4)
    hdrsize = 32 if is64 else 28
    arch, bits = MH_CPU.get(cputype, (f"unknown(0x{cputype:X})", 64 if is64 else 32))

    sections, dylibs, rpaths = [], [], []
    ent_budget = MAX_ENTROPY_TOTAL      # 所有节算熵的合计预算（见常量处说明）
    encrypted, cryptid, uuid, entry, min_os, platform = False, None, None, None, None, None
    signed, chained = False, False
    nsyms, symoff, stroff, strsize = 0, 0, 0, 0

    off = base + hdrsize
    for i in range(min(ncmds, 1024)):
        lc = r.read(off, 8)
        if len(lc) < 8:
            break
        cmd, cmdsize = struct.unpack_from(en + "II", lc, 0)
        if cmdsize < 8 or cmdsize > 64 * 1024 * 1024:
            break
        body = r.read(off, min(cmdsize, 4096))
        if cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
            if cmd == 0x19:
                segname = body[8:24].rstrip(b"\x00").decode("utf-8", "replace")
                _va, _vs, fileoff, filesize, _mp, _ip, nsects, _fl = struct.unpack_from(en + "QQQQiiII", body, 24)
                sect_size = 80
                sect_off = 72
            else:
                segname = body[8:24].rstrip(b"\x00").decode("utf-8", "replace")
                _va, _vs, fileoff, filesize, _mp, _ip, nsects, _fl = struct.unpack_from(en + "IIIIiiII", body, 24)
                sect_size = 68
                sect_off = 56
            for j in range(min(nsects, 64)):
                sb = body[sect_off + j * sect_size: sect_off + (j + 1) * sect_size]
                if len(sb) < sect_size:
                    break
                sname = sb[:16].rstrip(b"\x00").decode("utf-8", "replace")
                sgname = sb[16:32].rstrip(b"\x00").decode("utf-8", "replace")
                if is64:
                    _addr, ssize, soff = struct.unpack_from(en + "QQI", sb, 32)
                else:
                    _addr, ssize, soff = struct.unpack_from(en + "III", sb, 32)
                ent = 0.0
                if soff and ssize and soff < r.size:
                    take = min(ssize, MAX_READ_FOR_ENTROPY)
                    if ent_budget >= take:
                        ent_budget -= take
                        ent = shannon_entropy(r.read(soff, take))
                    else:
                        # 同 ELF：预算耗尽时置 None，不能留 0.0
                        # （0.0 会被读成"这节是常量字节"）。
                        ent = None
                sections.append({"seg": sgname, "name": sname, "size": ssize,
                                 "offset": soff, "entropy": ent})
        elif cmd in (0xC, 0xD, 0x1F, 0x20, 0x12):  # 依赖库
            noff = struct.unpack_from(en + "I", body, 8)[0] if len(body) >= 12 else 0
            if noff < len(body):
                nm = _cstr(body, noff, min(cmdsize, 512))
                if cmd == 0xD:
                    out["id_dylib"] = nm
                else:
                    dylibs.append(nm)
        elif cmd == 0x8000001C:  # LC_RPATH
            noff = struct.unpack_from(en + "I", body, 8)[0] if len(body) >= 12 else 0
            if noff < len(body):
                rpaths.append(_cstr(body, noff, min(cmdsize, 512)))
        elif cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from(en + "IIII", body, 8)
        elif cmd in (0x21, 0x2C):  # LC_ENCRYPTION_INFO(_64)
            _co, _cs, cryptid = struct.unpack_from(en + "III", body, 8)
            encrypted = cryptid != 0
        elif cmd == 0x1B:  # LC_UUID
            uuid = body[8:24].hex()
        elif cmd == 0x80000028:  # LC_MAIN
            entry = struct.unpack_from(en + "Q", body, 8)[0]
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            signed = True
        elif cmd == 0x80000034:
            chained = True
        elif cmd == 0x32:  # LC_BUILD_VERSION
            platform, minos, sdk, _nt = struct.unpack_from(en + "IIII", body, 8)
            min_os = f"{minos >> 16}.{(minos >> 8) & 0xFF}.{minos & 0xFF}"
        elif cmd in (0x24, 0x25, 0x2F, 0x30):
            v1, v2, v3 = struct.unpack_from(en + "III", body, 8)
            min_os = f"{v1 >> 16}.{(v1 >> 8) & 0xFF}.{v1 & 0xFF}"
        off += cmdsize

    symbols = []
    if nsyms and symoff:
        n = min(nsyms, 20000)
        blob = r.read(symoff, min(n * (16 if is64 else 12), 8 * 1024 * 1024))
        strs = r.read(stroff, min(strsize, 4 * 1024 * 1024)) if stroff else b""
        step = 16 if is64 else 12
        names = set()
        for i in range(min(n, len(blob) // step)):
            n_strx = struct.unpack_from(en + "I", blob, i * step)[0]
            if n_strx and n_strx < len(strs):
                nm = _cstr(strs, n_strx)
                if nm:
                    names.add(nm)
        symbols = sorted(names)[:500]

    out.update({
        "parse_ok": True, "arch": arch, "bits": bits,
        "endian": "little" if en == "<" else "big",
        "filetype": MH_FILETYPE.get(filetype, str(filetype)),
        "load_command_count": ncmds,
        "dylibs": dylibs, "rpaths": rpaths,
        "sections": sections[:96],
        "symbols_sample": symbols[:200], "symbol_count": len(symbols),
        "encrypted": encrypted, "cryptid": cryptid, "uuid": uuid,
        "entry_point": entry, "min_os": min_os, "platform": platform,
        "has_code_signature": signed, "uses_chained_fixups": chained,
    })
    return out


# ---------------------------------------------------------------- DEX


def parse_dex(r: Reader) -> dict:
    d: dict = {"parser": "dex", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 112)
        if not head.startswith(b"dex\n"):
            d["errors"].append("DEX 魔数缺失")
            return d
        ver = head[4:7].decode("ascii", "replace")
        # DEX 头布局（小端，固定 0x70 字节）：
        #   0  magic(8)  8  checksum  12  signature(20)  32  file_size
        #   36 header_size  40 endian_tag  44 link_size  48 link_off
        #   52 map_off   56 string_ids_size  60 string_ids_off
        #   64 type_ids_size  68 type_ids_off  72 proto_ids_size  76 proto_ids_off
        #   80 field_ids_size 84 field_ids_off 88 method_ids_size 92 method_ids_off
        #   96 class_defs_size 100 class_defs_off 104 data_size 108 data_off
        (file_size, header_size, endian_tag, _link_size, _link_off, _map_off,
         str_cnt, str_off, type_cnt, type_off, proto_cnt, proto_off,
         field_cnt, field_off, method_cnt, method_off, class_cnt, class_off,
         data_size, data_off) = struct.unpack_from(
            "<IIIIIIIIIIIIIIIIIIII", head, 32)

        # 字符串池
        strings = []
        if str_off and str_cnt:
            ids = r.read(str_off, min(str_cnt * 4, 8 * 1024 * 1024))
            for i in range(min(str_cnt, 3000)):
                if i * 4 + 4 > len(ids):
                    break
                so = struct.unpack_from("<I", ids, i * 4)[0]
                if so >= r.size:
                    continue
                blob = r.read(so, 512)
                if not blob:
                    continue
                _ln, p = uleb128(blob, 0)
                strings.append(blob[p:p + min(_ln, 400)].decode("utf-8", "replace"))

        # 类型描述符 → 类名
        types = []
        if type_off and type_cnt:
            ids = r.read(type_off, min(type_cnt * 4, 4 * 1024 * 1024))
            tstr = []
            for i in range(min(type_cnt, 2000)):
                if i * 4 + 4 > len(ids):
                    break
                di = struct.unpack_from("<I", ids, i * 4)[0]
                if di < len(strings):
                    tstr.append(strings[di])
            types = [t for t in tstr if t.startswith("L")][:800]

        d.update({
            "parse_ok": True,
            "dex_version": f"0{ver}",
            "file_size": file_size, "header_size": header_size,
            "endian_tag": hex(endian_tag),
            "string_count": str_cnt, "type_count": type_cnt,
            "method_count": method_cnt, "class_count": class_cnt,
            "strings_sample": strings[:400],
            "classes_sample": types[:200],
        })
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- ZIP / APK / JAR


def parse_zip(r: Reader) -> dict:
    d: dict = {"parser": "zip", "parse_ok": False, "errors": []}
    try:
        # 定位 EOCD（End Of Central Directory）
        tail_len = min(r.size, 65557)
        tail = r.read(r.size - tail_len, tail_len)
        eocd = tail.rfind(b"PK\x05\x06")
        entries: list[dict] = []
        comment = ""
        if eocd >= 0:
            blob = tail[eocd:]
            if len(blob) >= 22:
                _disk, _cd_disk, _n_disk, total, cd_size, cd_off, cmt_len = struct.unpack_from("<HHHHIIH", blob, 4)
                if cmt_len:
                    comment = blob[22:22 + cmt_len].decode("utf-8", "replace")[:200]
                d["eocd"] = {"total_entries": total, "cd_offset": cd_off, "cd_size": cd_size}
                pos = cd_off
                for i in range(min(total, 8000)):
                    raw = r.read(pos, 46)
                    if len(raw) < 46 or raw[:4] != b"PK\x01\x02":
                        break
                    (_vm, _vn, _fl, method, _t, _d, crc, csize, usize,
                     nlen, elen, clen, _dk, _ia, _ea, lho) = struct.unpack_from("<HHHHHHIIIHHHHHII", raw, 4)
                    name = r.read(pos + 46, nlen).decode("utf-8", "replace")
                    entries.append({"name": name, "method": method, "crc": crc,
                                    "compressed": csize, "uncompressed": usize})
                    pos += 46 + nlen + elen + clen
                    if len(entries) >= 8000:
                        break

        names = [e["name"] for e in entries]
        lname = {n.lower(): n for n in names}
        sub = "zip"
        if "AndroidManifest.xml" in names:
            sub = "apk"
        elif "META-INF/MANIFEST.MF" in names:
            sub = "jar"
        elif any(n.endswith(".whl") or "WHEEL" in n for n in names):
            sub = "wheel"
        elif any(n == "[Content_Types].xml" for n in names):
            sub = "ooxml(docx/xlsx/pptx)"
        elif any(n.endswith(".dex") for n in names):
            sub = "apk(?)"

        out: dict = {
            "parse_ok": True, "subtype": sub, "entry_count": len(entries),
            "zip_comment": comment or None,
            "entries_sample": entries[:200],
        }

        # 目录结构统计
        prefixes: dict[str, int] = {}
        for n in names:
            top = n.split("/")[0] if "/" in n else "(root)"
            prefixes[top] = prefixes.get(top, 0) + 1
        out["top_level"] = dict(sorted(prefixes.items(), key=lambda kv: -kv[1])[:30])

        if sub == "apk":
            apk: dict = {}
            dexes = [n for n in names if n.endswith(".dex")]
            apk["dex_files"] = dexes
            apk["dex_total_size"] = sum(e["uncompressed"] for e in entries if e["name"].endswith(".dex"))
            abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and len(n.split("/")) > 2})
            apk["abis"] = abis
            apk["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")][:80]
            apk["assets"] = [n for n in names if n.startswith("assets/")][:80]
            apk["has_resources_arsc"] = "resources.arsc" in names
            apk["signature_files"] = [n for n in names if n.startswith("META-INF/")][:20]
            # 加固特征
            hit = []
            for n in names:
                b = os.path.basename(n)
                for marker, vendor in APK_PACKERS:
                    if b == marker or b.startswith(marker.replace(".so", "")):
                        hit.append({"file": n, "vendor": vendor})
            apk["packer_hits"] = hit
            # 抽取型加固：主 dex 很小 + assets 里有大文件
            main_dex = [e for e in entries if e["name"] == "classes.dex"]
            big_assets = [e for e in entries if e["name"].startswith("assets/") and e["uncompressed"] > 200 * 1024]
            if main_dex and main_dex[0]["uncompressed"] < 100 * 1024 and big_assets:
                apk["packer_heuristic"] = (
                    f"classes.dex 仅 {main_dex[0]['uncompressed']}B，而 assets 内有 "
                    f"{len(big_assets)} 个 >200KB 文件 → 疑似抽取型加固（DEX 被加密后运行时还原）")
            apk["packer_suspected"] = bool(hit) or "packer_heuristic" in apk
            # AndroidManifest.xml 字符串池：权限与组件名（尽力而为，失败不影响其它字段）
            if "AndroidManifest.xml" in names:
                try:
                    apk["manifest_strings"] = _axml_strings(r)
                except Exception as e:
                    apk["manifest_errors"] = f"{type(e).__name__}: {e}"
            out["apk"] = apk
        elif sub == "jar":
            classes = [n for n in names if n.endswith(".class")]
            out["jar"] = {"class_count": len(classes),
                          "classes_sample": classes[:60],
                          "has_pom": any(n.startswith("META-INF/maven") for n in names),
                          "main_class": _jar_main_class(r, entries, lname)}
        return out
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


def _jar_main_class(r: Reader, entries: list[dict], lname: dict) -> str | None:
    name = lname.get("meta-inf/manifest.mf")
    if not name:
        return None
    # 本地文件头：签名 4 + 版本 2 + flags 2 + method 2 + time 2 + date 2 + crc 4 + csize 4 + usize 4 + nlen 2 + elen 2
    # 这里直接用中央目录无法拿到 lho，改为扫描前 1MB 找 PK\x03\x04
    blob = r.read(0, min(r.size, 1 << 20))
    idx = 0
    while True:
        i = blob.find(b"PK\x03\x04", idx)
        if i < 0:
            break
        nlen, elen = struct.unpack_from("<HH", blob, i + 26)
        nm = blob[i + 30: i + 30 + nlen].decode("utf-8", "replace")
        if nm.lower() == "meta-inf/manifest.mf":
            csize = struct.unpack_from("<I", blob, i + 18)[0]
            data_off = i + 30 + nlen + elen
            raw = r.read(data_off, min(csize, 65536))
            try:
                txt = _inflate_if_needed(raw)
            except Exception:
                txt = raw.decode("utf-8", "replace")
            m = re.search(r"Main-Class:\s*(\S+)", txt)
            if m:
                return m.group(1)
        idx = i + 4
    return None


def _inflate_if_needed(raw: bytes) -> str:
    import zlib
    try:
        return zlib.decompress(raw, -15).decode("utf-8", "replace")
    except Exception:
        try:
            return zlib.decompress(raw).decode("utf-8", "replace")
        except Exception:
            return raw.decode("utf-8", "replace")


def _axml_strings(r: Reader) -> dict:
    """
    尽力而为的 AXML 字符串池抽取：只取字符串池里的字符串，然后按正则筛出
    权限、组件名、包名等。不解析 XML 树，因此不受 AXML 版本差异影响。

    解压失败时不静默继续：defused 的压缩数据交给 _axml_pool 只会产出
    看起来"正常"的垃圾串，属于「失败被上报为成功」。这里把失败写进
    返回值，让上层能看见。
    """
    # 扫描窗口上限 1 MB：AXML 的中央目录通常在前部，但**不保证**。
    # 被截断时必须显式记账（truncated_scan），否则「找不到 AndroidManifest」
    # 会退化成「这个 APK 没有权限」，属于最危险的静默失败。
    scan_cap = 1 << 20
    truncated_scan = r.size > scan_cap
    blob = r.read(0, min(r.size, scan_cap))
    idx = 0
    pool = []
    note = None
    found_manifest = False
    while True:
        i = blob.find(b"PK\x03\x04", idx)
        if i < 0:
            break
        nlen, elen = struct.unpack_from("<HH", blob, i + 26)
        nm = blob[i + 30: i + 30 + nlen].decode("utf-8", "replace")
        if nm == "AndroidManifest.xml":
            found_manifest = True
            csize = struct.unpack_from("<I", blob, i + 18)[0]
            method = struct.unpack_from("<H", blob, i + 8)[0]
            data_off = i + 30 + nlen + elen
            raw = r.read(data_off, min(csize, 1 << 22))
            if method == 8:
                try:
                    import zlib
                except ImportError as e:  # pragma: no cover - zlib 属标准库
                    return {"_error": "zlib unavailable: %s" % e}
                try:
                    raw = zlib.decompress(raw, -15)
                except Exception as e:
                    # 关键：不要 pass。压缩数据直接喂给 _axml_pool 会产出垃圾串，
                    # 而且 pool 非空时旧代码还会伪装成功。这里立即返回错误。
                    return {"_error": "AndroidManifest.xml inflate failed: %s: %s"
                                     % (type(e).__name__, e)}
            elif method != 0:
                note = "AndroidManifest.xml stored with unsupported method %d" % method
            pool = _axml_pool(raw)
            break
        idx = i + 4
    if truncated_scan and not found_manifest:
        # 窗口被截断且窗口内没找到 manifest —— 无法判定，必须说出来。
        return {"_error": "扫描窗口 %d 字节内未找到 AndroidManifest.xml，"
                          "但文件共 %d 字节（已截断）。可能是中央目录位于 "
                          "1MB 之后，也可能是该文件不是 APK。"
                          % (scan_cap, r.size)}
    if not pool:
        if note:
            return {"_note": note}
        return {}
    perms = sorted({s for s in pool if s.startswith("android.permission.")})
    pkg = sorted({s for s in pool if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}", s) and "." in s})
    res = {"permissions": perms[:80], "package_like": pkg[:40], "pool_size": len(pool)}
    if note:
        res["_note"] = note
    return res


def _axml_pool(data: bytes) -> list[str]:
    """解析 AXML 的 RES_STRING_POOL_TYPE(0x0001) 块。"""
    out: list[str] = []
    if len(data) < 8:
        return out
    pos = 0
    while pos + 8 <= len(data):
        typ, hdr, size = struct.unpack_from("<HHI", data, pos)
        if size < 8 or pos + size > len(data):
            break
        if typ == 0x0001:
            cnt, scnt, flags, strstart, stylesstart = struct.unpack_from("<IIIII", data, pos + 8)
            utf8 = bool(flags & 0x100)
            offs = pos + hdr
            for i in range(min(cnt, 20000)):
                o = struct.unpack_from("<I", data, offs + i * 4)[0] if offs + i * 4 + 4 <= len(data) else None
                if o is None:
                    break
                base = pos + strstart + o
                if base + 2 > len(data):
                    continue
                if utf8:
                    # UTF-8：长度是变长的（可能 1 或 2 字节），这里用 16bit 头 + UTF-8 长度
                    try:
                        ln = data[base]
                        if ln & 0x80:
                            ln = ((ln & 0x7F) << 8) | data[base + 1]
                            p = base + 2
                        else:
                            p = base + 1
                        out.append(data[p:p + ln].decode("utf-8", "replace"))
                    except Exception:
                        continue
                else:
                    ln = struct.unpack_from("<H", data, base)[0]
                    if ln > 4096:
                        continue
                    try:
                        out.append(data[base + 2: base + 2 + ln * 2].decode("utf-16-le", "replace"))
                    except Exception:  # lint:ok 同上：单条坏串跳过并已 replace 兜底
                        continue
            break
        pos += size if size >= 8 else 8
    return out


# ---------------------------------------------------------------- pyc


def parse_pyc(r: Reader) -> dict:
    d: dict = {"parser": "pyc", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 16)
        raw = int.from_bytes(head[:4], "little")
        conv = raw & 0xFFFF
        ver, verified = PYC_MAGIC.get(conv, (None, False))
        bitfield = int.from_bytes(head[4:8], "little")
        hash_based = bool(bitfield & 0x1)
        checked_hash = bool(bitfield & 0x2)
        src_hash = None
        mtime = None
        src_size = None
        if hash_based:
            src_hash = head[8:16].hex()
        else:
            mtime = _ts(int.from_bytes(head[8:12], "little"))
            src_size = int.from_bytes(head[12:16], "little")
        d.update({
            "parse_ok": True,
            "magic_raw": f"0x{raw:08X}", "magic_conventional": conv,
            "python_version": ver, "version_verified_locally": verified,
            "header_layout": "3.7+ (16 字节)",
            "hash_based": hash_based, "checked_hash": checked_hash,
            "source_mtime": mtime, "source_size": src_size, "source_hash": src_hash,
            "note": ("版本为推定值：本机仅实测确认 3.13/3.14，其余取自公开魔数表"
                     if ver and not verified else (None if ver else
                     f"未知魔数 {conv}，可能不是 pyc 或来自未收录的 Python 版本")),
        })
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- WASM


def parse_wasm(r: Reader) -> dict:
    d: dict = {"parser": "wasm", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 8)
        if head[:4] != b"\x00asm":
            d["errors"].append("WASM 魔数缺失")
            return d
        version = int.from_bytes(head[4:8], "little")
        blob = r.read(0, min(r.size, 32 * 1024 * 1024))
        pos = 8
        secs, imports, exports = [], [], []
        while pos + 1 <= len(blob):
            sid = blob[pos]
            pos += 1
            size, pos = uleb128(blob, pos)
            if size <= 0 or pos + size > len(blob):
                secs.append({"id": sid, "name": WASM_SECTIONS.get(sid, "?"), "size": size})
                break
            body = blob[pos:pos + size]
            secs.append({"id": sid, "name": WASM_SECTIONS.get(sid, "?"), "size": size})
            if sid == 2:  # import
                cnt, p = uleb128(body, 0)
                for _ in range(min(cnt, 2000)):
                    mod_len, p = uleb128(body, p)
                    mod = body[p:p + mod_len].decode("utf-8", "replace")
                    p += mod_len
                    f_len, p = uleb128(body, p)
                    field = body[p:p + f_len].decode("utf-8", "replace")
                    p += f_len
                    kind = body[p] if p < len(body) else 0
                    p += 1
                    imports.append({"module": mod, "field": field, "kind": kind})
                    if p >= len(body):
                        break
            elif sid == 7:  # export
                cnt, p = uleb128(body, 0)
                for _ in range(min(cnt, 2000)):
                    n_len, p = uleb128(body, p)
                    nm = body[p:p + n_len].decode("utf-8", "replace")
                    p += n_len
                    kind = body[p] if p < len(body) else 0
                    p += 1
                    _idx, p = uleb128(body, p)
                    exports.append({"name": nm, "kind": {0: "func", 1: "table", 2: "mem", 3: "global"}.get(kind, kind)})
                    if p >= len(body):
                        break
            pos += size
        d.update({"parse_ok": True, "wasm_version": version, "sections": secs[:32],
                  "imports": imports[:200], "exports": exports[:200],
                  "import_count": len(imports), "export_count": len(exports)})
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- SQLite


def parse_sqlite(r: Reader) -> dict:
    d: dict = {"parser": "sqlite", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 100)
        page_size = struct.unpack_from(">H", head, 16)[0]
        if page_size == 1:
            page_size = 65536
        write_ver, read_ver = head[18], head[19]
        reserved = head[20]
        file_change = struct.unpack_from(">I", head, 24)[0]
        db_size_pages = struct.unpack_from(">I", head, 28)[0]
        freelist = struct.unpack_from(">I", head, 32)[0]
        schema_cookie = struct.unpack_from(">I", head, 40)[0]
        text_enc = struct.unpack_from(">I", head, 56)[0]
        enc = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(text_enc, "UTF-8")
        d.update({
            "parse_ok": True,
            "page_size": page_size, "page_count": db_size_pages,
            "size_on_disk_matches": (db_size_pages * page_size == r.size) if page_size else False,
            "write_version": write_ver, "read_version": read_ver,
            "text_encoding": enc, "schema_cookie": schema_cookie,
            "freelist_pages": freelist, "change_counter": file_change,
            "journal_mode": {1: "legacy", 2: "WAL"}.get(read_ver, "delete/other"),
        })
        # 用标准库 sqlite3 只读打开取 schema（这是最可靠的做法）
        try:
            import sqlite3
            uri = "file:" + r.path.replace("\\", "/").replace("?", "%3f").replace("#", "%23") + "?mode=ro"
            con = sqlite3.connect(uri, uri=True, timeout=2)
            cur = con.cursor()
            rows = cur.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            tables = [n for t, n in rows if t == "table"]
            counts = {}
            for t in tables[:20]:
                try:
                    counts[t] = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except Exception:
                    counts[t] = None
            d["objects"] = [{"type": t, "name": n} for t, n in rows[:300]]
            d["table_count"] = len(tables)
            d["index_count"] = sum(1 for t, _ in rows if t == "index")
            d["view_count"] = sum(1 for t, _ in rows if t == "view")
            d["trigger_count"] = sum(1 for t, _ in rows if t == "trigger")
            d["row_counts"] = counts
            con.close()
        except Exception as e:
            d["errors"].append(f"sqlite3 读取 schema 失败（文件可能损坏或被占用）：{type(e).__name__}")
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d


# ---------------------------------------------------------------- Java class


def parse_javaclass(r: Reader) -> dict:
    d: dict = {"parser": "class", "parse_ok": False, "errors": []}
    try:
        head = r.read(0, 10)
        minor, major = struct.unpack_from(">HH", head, 4)
        cp_count = struct.unpack_from(">H", head, 8)[0]
        ver_map = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6",
                   51: "7", 52: "8", 53: "9", 54: "10", 55: "11", 56: "12",
                   57: "13", 58: "14", 59: "15", 60: "16", 61: "17", 62: "18",
                   63: "19", 64: "20", 65: "21", 66: "22", 67: "23", 68: "24"}
        d.update({
            "parse_ok": True, "major": major, "minor": minor,
            "java_version": ver_map.get(major, f">24 (major {major})"),
            "constant_pool_count": cp_count,
            "access_flags": struct.unpack_from(">H", head, 0)[0] if len(head) >= 4 else None,
        })
        return d
    except Exception as e:
        d["errors"].append(f"{type(e).__name__}: {e}")
        return d
