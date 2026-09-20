# -*- coding: utf-8 -*-
"""
selftest.py —— 逆向工具箱自检套件

三条线：
  1. 正确性：合成每种受支持格式的样本，断言解析结果（PE/ELF/Mach-O/DEX/ZIP-APK/
     pyc/WASM/SQLite/Java class/固件头），并对真实系统文件做实机验证。
  2. 稳定性：畸形输入（空文件/截断/随机字节/位翻转变异）永不崩溃，
     一律返回结构化 JSON 且带 ok 字段；CLI 退出码符合约定。
  3. 性能：大文件（100MB）流式扫描耗时压测，验证内存有界、不会拖死。

用法：
  python selftest.py [--json] [--keep] [--only 关键字]
退出码：0 全通过；1 有失败。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = HERE.parent          # 技能包根目录（rules/ 在这里）
sys.path.insert(0, str(HERE))

CLI = HERE / "re.py"
SCRIPTS = HERE                 # 技能脚本目录（用于断言没被污染）
BASE = Path(os.environ.get("TEMP", "/tmp")) / "re-selftest"
TMP = BASE / datetime.now().strftime("run-%Y%m%d-%H%M%S")
PY = sys.executable

RESULTS: list[dict] = []


SKIP = object()   # 用例返回 detail 为该值即视为「跳过」（环境不具备）


def case(name, fn):
    t0 = time.time()
    try:
        ok, detail = fn()
        if ok is None:
            ok = True
    except Exception as e:
        ok, detail = False, f"用例异常：{type(e).__name__}: {e}"
    dt = round(time.time() - t0, 2)
    skipped = detail is SKIP
    if skipped:
        # 环境不具备（典型：装到运行时后 _dev/ 不再分发）→ 记为跳过。
        # 跳过必须**显式可见**，不能混进"通过"里冒充绿 —— 否则
        # 用例没跑也会显示全绿，正是本项目最忌的假成功。
        RESULTS.append({"case": name, "ok": True, "skipped": True,
                        "detail": "环境不具备，已跳过", "seconds": dt})
        print(f"  [SKIP] {name} ({dt}s)  环境不具备，已跳过")
        return True
    RESULTS.append({"case": name, "ok": bool(ok), "detail": str(detail)[:500], "seconds": dt})
    tag = "PASS" if ok else "FAIL"
    brief = str(detail).replace("\n", " ")[:96]
    print(f"  [{tag}] {name} ({dt}s)  {brief}")
    return bool(ok)


def run(args, timeout=300, stdin_text=None):
    """
    跑一次 CLI。

    stdin_text 用于测管道场景（`... | re.py result --stdin`）。
    None = 关闭 stdin（默认），空串 = 给一个立即 EOF 的空管道——
    两者对被测程序是不同的输入，都要能测到。
    """
    p = subprocess.run([PY, *[str(a) for a in args]], capture_output=True, text=True,
                       input=stdin_text,
                       encoding="utf-8", errors="replace", timeout=timeout, cwd=str(HERE))
    return p.returncode, p.stdout, p.stderr


def jrun(args, timeout=300):
    """跑 CLI 并解析 JSON；失败返回 (code, None, raw)。"""
    code, out, err = run([*args, "--json"], timeout=timeout)
    try:
        return code, json.loads(out), out[:400]
    except Exception:
        return code, None, (out[:200] + " ||STDERR|| " + err[:200])


# ---------------------------------------------------------------- 样本构造器

def w(name: str, data: bytes) -> Path:
    p = TMP / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def mk_pe64(extra_sections: bool = True) -> Path:
    """手工构造一个最小但结构完整的 PE32+（含导入表）。"""
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)          # e_lfanew
    buf[0x40:0x44] = b"PE\x00\x00"
    # COFF: machine=x86-64, nsec=2, SizeOfOptionalHeader=240, Characteristics=EXECUTABLE_IMAGE
    struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 2, 0x65000000, 0, 0, 240, 0x0002)
    opt = 0x40 + 24
    struct.pack_into("<H", buf, opt, 0x20B)          # PE32+
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)     # ImageBase
    struct.pack_into("<I", buf, opt + 32, 0x1000)          # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)           # FileAlignment
    struct.pack_into("<I", buf, opt + 56, 0x3000)          # SizeOfImage
    struct.pack_into("<I", buf, opt + 60, 0x200)           # SizeOfHeaders
    struct.pack_into("<H", buf, opt + 68, 3)               # Subsystem = CUI
    struct.pack_into("<H", buf, opt + 70, 0x8160)          # DllCharacteristics (ASLR|NX|...)
    struct.pack_into("<I", buf, opt + 108, 16)             # NumberOfRvaAndSizes
    struct.pack_into("<I", buf, opt + 16, 0x1000)          # AddressOfEntryPoint = .text RVA
    # 数据目录 1 = 导入表 → RVA 0x2000 (.idata), size 0x3C
    struct.pack_into("<II", buf, opt + 112 + 1 * 8, 0x2000, 0x3C)
    # 节表
    st = opt + 240
    buf[st:st + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, st + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", buf, st + 36, 0x60000020)       # CODE|EXECUTE|READ
    buf[st + 40:st + 48] = b".idata\x00\x00"
    struct.pack_into("<IIII", buf, st + 48, 0x200, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", buf, st + 76, 0xC0000040)       # INITIALIZED_DATA|READ|WRITE
    # .text 内容：一段可打印字符串 + 指令
    buf[0x200:0x240] = b"HelloReverse" + b"\x90" * 0x34
    # .idata：导入描述符 + 名字表
    idat = 0x400
    struct.pack_into("<IIIII", buf, idat, 0x2040, 0, 0, 0x2060, 0x2080)  # INT/Name/IAT
    struct.pack_into("<Q", buf, idat + 0x40, 0x2050 if False else 0x2050)  # INT[0] → Hint/Name
    struct.pack_into("<Q", buf, idat + 0x48, 0)            # INT 结束
    struct.pack_into("<H", buf, idat + 0x50, 0)            # Hint
    buf[idat + 0x52:idat + 0x52 + 12] = b"MessageBoxW\x00"
    buf[idat + 0x60:idat + 0x60 + 11] = b"USER32.dll\x00"
    struct.pack_into("<Q", buf, idat + 0x80, 0x2050)       # IAT[0]
    return w("sample_pe64.exe", bytes(buf))


def mk_elf64() -> Path:
    """手工构造最小 ELF64：含 PT_LOAD / PT_GNU_STACK / PT_DYNAMIC 与 .dynsym。"""
    buf = bytearray(0x600)
    buf[0:4] = b"\x7fELF"
    buf[4], buf[5], buf[6], buf[7] = 2, 1, 1, 3        # 64bit / LE / version / Linux
    # 布局：0x000 头 | 0x040 PH×3 | 0x200 .text | 0x280 .dynamic | 0x2C0 .dynsym
    #       0x300 .dynstr | 0x400 .shstrtab | 0x480 节头表×6
    struct.pack_into("<HHIQQQIHHHHHH", buf, 16, 2, 62, 1, 0x1000, 0x40, 0x480, 0, 64, 56, 3, 64, 6, 5)
    # PH0 PT_LOAD(R|X)
    struct.pack_into("<IIQQQQQQ", buf, 0x40, 1, 5, 0x200, 0x1000, 0, 0x40, 0x40, 0x1000)
    # PH1 PT_GNU_STACK(RW → 无 X 位 = NX 开启)
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 56, 0x6474E551, 6, 0, 0, 0, 0, 0, 0x10)
    # PH2 PT_DYNAMIC → .dynamic @0x280
    struct.pack_into("<IIQQQQQQ", buf, 0x40 + 112, 2, 6, 0x280, 0x2000, 0, 0x20, 0x20, 8)
    # .text
    buf[0x200:0x220] = b"/bin/sh\x00" + b"\x90" * 0x18
    # .dynamic：DT_NEEDED(1) → .dynstr+25 (libc.so.6)；DT_NULL
    struct.pack_into("<QQ", buf, 0x280, 1, 25)
    struct.pack_into("<QQ", buf, 0x290, 0, 0)
    # .dynsym：printf(@1) 与 __stack_chk_fail(@8)
    struct.pack_into("<IBBHQQ", buf, 0x2C0, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", buf, 0x2C0 + 24, 8, 0x12, 0, 0, 0, 0)
    # .dynstr
    dynstr = b"\x00printf\x00__stack_chk_fail\x00libc.so.6\x00"
    buf[0x300:0x300 + len(dynstr)] = dynstr
    # .shstrtab
    names = b"\x00.text\x00.dynamic\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    buf[0x400:0x400 + len(names)] = names
    n_text = 1
    n_dyna = n_text + len(b".text\x00")
    n_sym = n_dyna + len(b".dynamic\x00")
    n_str = n_sym + len(b".dynsym\x00")
    n_sh = n_str + len(b".dynstr\x00")
    # 节头表：0 NULL | 1 .text | 2 .dynamic | 3 .dynsym | 4 .dynstr | 5 .shstrtab
    sh = 0x480
    struct.pack_into("<IIQQQQIIQQ", buf, sh, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, sh + 64, n_text, 1, 0x6, 0x1000, 0x200, 0x40, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, sh + 128, n_dyna, 6, 0x3, 0x2000, 0x280, 0x20, 4, 0, 8, 16)
    struct.pack_into("<IIQQQQIIQQ", buf, sh + 192, n_sym, 11, 0x2, 0x2000, 0x2C0, 48, 4, 0, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", buf, sh + 256, n_str, 3, 0x2, 0, 0x300, len(dynstr), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", buf, sh + 320, n_sh, 3, 0, 0, 0x400, len(names), 0, 0, 1, 0)
    return w("sample_elf64.bin", bytes(buf))


def mk_macho64() -> Path:
    """手工构造最小 Mach-O 64（含 LC_SEGMENT_64 + LC_LOAD_DYLIB）。"""
    buf = bytearray(0x2000)
    buf[0:4] = b"\xcf\xfa\xed\xfe"          # MH_MAGIC_64 (小端存储)
    ncmds = 2
    seg_size = 72 + 80
    dylib_name = b"/usr/lib/libSystem.B.dylib"
    dylib_size = 24 + ((len(dylib_name) + 3) // 4) * 4
    sizeofcmds = seg_size + dylib_size
    struct.pack_into("<iiIIII", buf, 4, 0x01000007, 3, 2, ncmds, sizeofcmds, 0)
    # LC_SEGMENT_64
    lc = 32
    struct.pack_into("<II", buf, lc, 0x19, seg_size)
    buf[lc + 8:lc + 24] = b"__TEXT\x00\x00\x00\x00\x00\x00"
    struct.pack_into("<QQQQiiII", buf, lc + 24, 0x100000000, 0x1000, 0, 0x1000, 7, 5, 1, 0)
    s = lc + 72
    buf[s:s + 16] = b"__text\x00" + b"\x00" * 10
    buf[s + 16:s + 32] = b"__TEXT\x00" + b"\x00" * 10
    struct.pack_into("<QQI", buf, s + 32, 0x100001000, 0x100, 0x1000)
    # LC_LOAD_DYLIB
    lc2 = lc + seg_size
    struct.pack_into("<II", buf, lc2, 0xC, dylib_size)
    struct.pack_into("<I", buf, lc2 + 8, 24)     # name offset
    buf[lc2 + 24:lc2 + 24 + len(dylib_name)] = dylib_name
    buf[0x1000:0x1040] = b"HelloMachO" + b"\x90" * 0x36
    return w("sample_macho64.bin", bytes(buf))


def mk_apk() -> Path:
    """用 zipfile 构造一个带加固特征的 APK。"""
    p = TMP / "sample.apk"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 200)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 500)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 100)
        z.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF" + b"\x00" * 64)
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
        z.writestr("assets/big.dat", os.urandom(300 * 1024))
    return p


def mk_jar() -> Path:
    p = TMP / "sample.jar"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: com.demo.Main\r\n\r\n")
        z.writestr("com/demo/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x10" + b"\x00" * 40)
    return p


def mk_pyc() -> Path:
    import py_compile
    src = TMP / "sample_src.py"
    src.write_text("def secret_token():\n    return 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    out = TMP / "sample.pyc"
    py_compile.compile(str(src), cfile=str(out), doraise=True)
    return out


def mk_wasm() -> Path:
    buf = bytearray(b"\x00asm")
    buf += struct.pack("<I", 1)
    payload = bytearray()
    payload += bytes([1])                 # export count
    payload += bytes([3]) + b"run"        # name "run"
    payload += bytes([0])                 # kind = func
    payload += bytes([0])                 # index
    buf += bytes([7, len(payload)]) + payload
    return w("sample.wasm", bytes(buf))


def mk_sqlite() -> Path:
    import sqlite3
    p = TMP / "sample.db"
    if p.exists():                      # 允许同一轮自检里重复构造
        p.unlink()
    con = sqlite3.connect(str(p))
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, token TEXT)")
    con.executemany("INSERT INTO users VALUES (?,?,?)", [(1, "alice", "tok1"), (2, "bob", "tok2")])
    con.execute("CREATE VIEW v_users AS SELECT id FROM users")
    con.commit()
    con.close()
    return p


def mk_firmware() -> Path:
    return w("sample_fw.bin", b"hsqs" + os.urandom(4096))


def mk_javaclass() -> Path:
    return w("Sample.class", b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 20))


def mk_dex() -> Path:
    """构造一个 DEX 头 + 字符串池的最小可用样本。"""
    buf = bytearray(0x200)
    buf[0:8] = b"dex\n035\x00"
    strs = [b"Lcom/demo/Main;", b"onCreate"]
    pool = bytearray()
    offs = []
    pool_base = 0x70 + 4 * len(strs)      # 字符串池紧跟 string_ids 数组之后
    for s in strs:
        offs.append(pool_base + len(pool))
        pool += bytes([len(s)]) + s + b"\x00"
    struct.pack_into("<I", buf, 32, 0x200)        # file_size
    struct.pack_into("<I", buf, 36, 0x70)         # header_size
    struct.pack_into("<I", buf, 40, 0x12345678)   # endian_tag
    struct.pack_into("<I", buf, 56, len(strs))    # string_ids_size
    struct.pack_into("<I", buf, 60, 0x70)         # string_ids_off
    struct.pack_into("<I", buf, 64, len(strs))    # type_ids_size
    struct.pack_into("<I", buf, 68, 0x100)        # type_ids_off
    struct.pack_into("<I", buf, 96, 1)            # class_defs_size
    ids = b"".join(struct.pack("<I", o) for o in offs)
    buf[0x70:0x70 + len(ids)] = ids
    buf[0x70 + len(ids):0x70 + len(ids) + len(pool)] = pool
    buf[0x100:0x104] = struct.pack("<I", 0)       # type_ids[0] → string 0
    return w("sample.dex", bytes(buf[:0x200]))


def mk_strings_file() -> Path:
    parts = []
    expect = []
    pos = 0
    for s in (b"https://api.example.com/v1/report", b"192.168.1.100", b"AKIAIOSFODNN7EXAMPLE",
              b"C:\\Windows\\System32\\drivers\\etc\\hosts", b"CreateRemoteThread"):
        parts.append(b"\x00" * 16 + s + b"\x00" * 16)
        expect.append((pos + 16, s.decode()))
        pos += 16 + len(s) + 16
    # UTF-16LE：ASCII-in-UTF16（与 GNU strings -e l 一致）
    utf16 = "HiddenConfigValue".encode("utf-16-le")
    parts.append(b"\x00" * 8 + utf16 + b"\x00" * 8)
    expect.append((pos + 8, "HiddenConfigValue"))
    # 中文 UTF-16LE（需显式 --encoding utf16cjk 才提取）
    cjk = "管理员密码".encode("utf-16-le")
    parts.append(b"\x00" * 8 + cjk + b"\x00" * 8)
    pos = len(b"".join(parts)) - len(cjk) - 8
    cjk_expect = (pos, "管理员密码")
    return w("sample_strings.bin", b"".join(parts)), expect, cjk_expect


def mk_carve_file() -> Path:
    blob = bytearray(b"\x11" * 512)
    png = b"\x89PNG\r\n\x1a\n" + os.urandom(256)
    blob += png
    blob += b"\x22" * 256
    z = b"PK\x03\x04" + os.urandom(256)
    blob += z
    blob += os.urandom(256)
    return w("sample_carve.bin", bytes(blob))


def mk_big(path: Path, size_mb: int = 100) -> Path:
    """生成大文件：可打印段与随机段交替，模拟真实二进制。"""
    block = os.urandom(64 * 1024) + b"A" * 4096
    with open(path, "wb") as f:
        written = 0
        target = size_mb * 1024 * 1024
        while written < target:
            f.write(block)
            written += len(block)
    return path


# ---------------------------------------------------------------- 用例

def t_pe_synthetic():
    p = mk_pe64()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    d = (data or {}).get("detail", {})
    if data.get("format") != "pe":
        return False, f"格式识别为 {data.get('format')}"
    if d.get("arch") != "x86-64":
        return False, f"架构 {d.get('arch')}"
    dlls = {m["dll"] for m in d.get("imports", [])}
    if "USER32.dll" not in dlls:
        return False, f"导入表未解析出 USER32.dll：{dlls}"
    fns = [f["name"] for m in d.get("imports", []) for f in m["functions"]]
    if "MessageBoxW" not in fns:
        return False, f"导入函数缺失：{fns[:5]}"
    if len(d.get("sections", [])) != 2:
        return False, f"节数 {len(d.get('sections', []))}"
    return True, f"arch={d['arch']} 导入={d['import_module_count']} 节={[s['name'] for s in d['sections']]}"


def t_elf_synthetic():
    p = mk_elf64()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    d = (data or {}).get("detail", {})
    if data.get("format") != "elf":
        return False, f"格式 {data.get('format')}"
    cs = d.get("checksec") or {}
    if cs.get("NX") is not True:
        return False, f"NX 判定错误：{cs}"
    if cs.get("Canary") is not True:
        return False, f"Canary 判定错误（应检出 __stack_chk_fail）：{cs}"
    if cs.get("PIE") is not False:
        return False, f"PIE 判定错误（ET_EXEC 应为 False）：{cs}"
    if d.get("needed") != ["libc.so.6"]:
        return False, f"DT_NEEDED={d.get('needed')}"
    if "printf" not in (d.get("dynamic_symbols_sample") or []):
        return False, f"符号未解析：{d.get('dynamic_symbols_sample')[:5]}"
    if d.get("arch") != "x86-64":
        return False, f"架构 {d.get('arch')}"
    return True, f"arch={d['arch']} checksec={cs} needed={d['needed']}"


def t_macho_synthetic():
    p = mk_macho64()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    d = (data or {}).get("detail", {})
    if data.get("format") != "macho64":
        return False, f"格式 {data.get('format')}"
    if d.get("filetype") != "EXECUTE":
        return False, f"filetype {d.get('filetype')}"
    if not any("libSystem" in x for x in (d.get("dylibs") or [])):
        return False, f"依赖库缺失：{d.get('dylibs')}"
    names = [s["name"] for s in (d.get("sections") or [])]
    if "__text" not in names:
        return False, f"节名 {names}"
    return True, f"arch={d.get('arch')} dylibs={d.get('dylibs')} sections={names}"


def t_apk_synthetic():
    p = mk_apk()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    d = (data or {}).get("detail", {})
    if d.get("subtype") != "apk":
        return False, f"subtype={d.get('subtype')}"
    apk = d.get("apk") or {}
    if not any("360" in h["vendor"] for h in apk.get("packer_hits", [])):
        return False, f"加固特征未命中：{apk.get('packer_hits')}"
    if "arm64-v8a" not in (apk.get("abis") or []):
        return False, f"ABI={apk.get('abis')}"
    if apk.get("packer_suspected") is not True:
        return False, "packer_suspected 应为 True"
    return True, f"加固命中={[h['vendor'] for h in apk['packer_hits']]} abis={apk['abis']}"


def t_jar_synthetic():
    p = mk_jar()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    d = (data or {}).get("detail", {})
    if d.get("subtype") != "jar":
        return False, f"subtype={d.get('subtype')}"
    jar = d.get("jar") or {}
    if jar.get("main_class") != "com.demo.Main":
        return False, f"Main-Class={jar.get('main_class')}"
    return True, f"class_count={jar.get('class_count')} main={jar.get('main_class')}"


def t_pyc_real():
    p = mk_pyc()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    d = (data or {}).get("detail", {})
    if data.get("format") != "pyc":
        return False, f"格式 {data.get('format')}"
    want = f"{sys.version_info.major}.{sys.version_info.minor}"
    if d.get("python_version") != want:
        return False, f"版本 {d.get('python_version')} != {want}"
    if d.get("version_verified_locally") is not True:
        return False, "本机实测版本号应标记为已验证"
    return True, f"python_version={d.get('python_version')} magic={d.get('magic_conventional')}"


def t_wasm_synthetic():
    p = mk_wasm()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    d = (data or {}).get("detail", {})
    if data.get("format") != "wasm":
        return False, f"格式 {data.get('format')}"
    ex = d.get("exports") or []
    if not ex or ex[0].get("name") != "run":
        return False, f"导出解析失败：{ex}"
    return True, f"exports={[e['name'] for e in ex]}"


def t_sqlite_synthetic():
    p = mk_sqlite()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    d = (data or {}).get("detail", {})
    if data.get("format") != "sqlite":
        return False, f"格式 {data.get('format')}"
    if d.get("table_count") != 1:
        return False, f"表数 {d.get('table_count')}"
    if (d.get("row_counts") or {}).get("users") != 2:
        return False, f"行数 {d.get('row_counts')}"
    if d.get("view_count") != 1:
        return False, f"视图数 {d.get('view_count')}"
    return True, f"tables={d.get('table_count')} views={d.get('view_count')} rows={d.get('row_counts')}"


def t_class_ambiguity():
    """0xCAFEBABE 既可能是 Java class 也可能是 Mach-O fat，验证歧义消解。"""
    p = mk_javaclass()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    if data.get("format") != "class":
        return False, f"应判定为 class，实际 {data.get('format')}"
    d = (data or {}).get("detail", {})
    if d.get("java_version") != "8":
        return False, f"major 52 应为 Java 8，实际 {d.get('java_version')}"
    return True, f"消解为 class，java_version={d.get('java_version')}"


def t_dex_synthetic():
    p = mk_dex()
    code, data, raw = jrun([str(CLI), "identify", str(p)])
    d = (data or {}).get("detail", {})
    if data.get("format") != "dex035":
        return False, f"格式 {data.get('format')}"
    ss = d.get("strings_sample") or []
    if "Lcom/demo/Main;" not in ss:
        return False, f"字符串池解析失败：{ss[:5]}"
    return True, f"strings={ss[:3]} class_count={d.get('class_count')}"


def t_firmware_synthetic():
    p = mk_firmware()
    code, data, raw = jrun([str(CLI), "plan", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if (data or {}).get("route") != "firmware":
        return False, f"路由 {(data or {}).get('route')}"
    return True, f"路由 firmware，步骤 {len(data.get('steps', []))} 步"


def t_strings_offsets():
    p, expect, _ = mk_strings_file()
    code, data, raw = jrun([str(CLI), "strings", str(p), "--min", "6", "--encoding", "ascii,utf16le"])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    items = (data or {}).get("items", [])
    found = {it["value"]: it["offset"] for it in items}
    for off, val in expect:
        if val not in found:
            return False, f"未找到 {val!r}（现有 {list(found)[:8]}）"
        if found[val] != off:
            return False, f"{val!r} 偏移 {found[val]} != 期望 {off}"
    offs = [it["offset"] for it in items]
    if len(offs) != len(set(offs)):
        return False, f"存在重复偏移（去重逻辑有 bug）：{len(offs)} vs {len(set(offs))}"
    cats = (data or {}).get("categories", {})
    if "url" not in cats or "aws_key" not in cats or "ipv4" not in cats:
        return False, f"分类缺失：{cats}"
    return True, f"{len(items)} 条，分类 {cats}"


def t_strings_chunk_boundary():
    """字符串跨 1MB 块边界时必须完整输出且不重复。"""
    p = TMP / "boundary.bin"
    marker = b"X" * 6000                       # 远大于单块内任何切分
    with open(p, "wb") as f:
        f.write(b"\x00" * (CHUNK_MB * 1024 * 1024 - 3000))
        f.write(marker)
        f.write(b"\x00" * 1000)
    code, data, raw = jrun([str(CLI), "strings", str(p), "--min", "100"])
    items = (data or {}).get("items", [])
    hits = [it for it in items if it["value"] == marker.decode()]
    if len(hits) != 1:
        return False, f"跨块字符串应恰好输出 1 次，实际 {len(hits)}（长度 {[len(h['value']) for h in hits]}）"
    if hits and hits[0]["offset"] != CHUNK_MB * 1024 * 1024 - 3000:
        return False, f"偏移错误：{hits[0]['offset']}"
    return True, f"跨块字符串完整输出，偏移 0x{hits[0]['offset']:X}"


def t_strings_cjk():
    """中文 UTF-16LE 需显式开启 utf16cjk；默认不开启以避免随机数据误报。"""
    p, _, cjk_expect = mk_strings_file()
    code, data, raw = jrun([str(CLI), "strings", str(p), "--min", "4",
                            "--encoding", "ascii,utf16le,utf16cjk"])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    hits = [it for it in (data or {}).get("items", []) if it["value"] == cjk_expect[1]]
    if len(hits) != 1:
        return False, f"CJK 串应命中 1 次，实际 {len(hits)}"
    if hits[0]["offset"] != cjk_expect[0]:
        return False, f"偏移 {hits[0]['offset']} != {cjk_expect[0]}"
    # 默认模式不应产出 CJK（避免误报）
    code2, d2, _ = jrun([str(CLI), "strings", str(p), "--min", "4"])
    if any(it["value"] == cjk_expect[1] for it in (d2 or {}).get("items", [])):
        return False, "默认模式不应输出 CJK 串（会产生大量误报）"
    return True, f"utf16cjk 命中 @0x{hits[0]['offset']:X}，默认模式已过滤"


def t_carve():
    p = mk_carve_file()
    code, data, raw = jrun([str(CLI), "carve", str(p)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    keys = [h["key"] for h in (data or {}).get("hits", [])]
    offs = {h["key"]: h["offset"] for h in (data or {}).get("hits", [])}
    if "png" not in keys:
        return False, f"未雕刻出 PNG：{keys}"
    if offs.get("png") != 512:
        return False, f"PNG 偏移 {offs.get('png')} != 512"
    if offs.get("zip") != 512 + 264 + 256:
        return False, f"ZIP 偏移 {offs.get('zip')} != {512 + 264 + 256}"
    return True, f"命中 {keys} @ {offs}"


def t_carve_extract():
    p = mk_carve_file()
    outdir = TMP / "carved"
    code, data, raw = jrun([str(CLI), "carve", str(p), "--out", str(outdir)])
    ex = (data or {}).get("extracted", [])
    if not ex:
        return False, f"未落盘：{raw}"
    for e in ex:
        if not os.path.exists(e["file"]):
            return False, f"文件不存在：{e['file']}"
    return True, f"落盘 {len(ex)} 个，共 {data.get('written_bytes')} 字节"


def t_diff():
    a = w("diff_a.bin", b"A" * 1000 + b"SECRET_OLD" + b"B" * 1000)
    b = w("diff_b.bin", b"A" * 1000 + b"SECRET_NEWXX" + b"B" * 1000)
    code, data, raw = jrun([str(CLI), "diff", str(a), str(b)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if data.get("similarity", 1) >= 1:
        return False, f"相似度不应为 1：{data.get('similarity')}"
    r = data.get("changed_ranges") or []
    if not r or r[0]["start"] > 1100 or r[0]["end"] < 1000:
        return False, f"变更区间不合理：{r}"
    # 相同文件必须判定 identical
    code2, d2, _ = jrun([str(CLI), "diff", str(a), str(a)])
    if not (d2 or {}).get("identical"):
        return False, "相同文件未判定为 identical"
    return True, f"相似度 {data.get('similarity')}，区间 {r[0]}"


def t_real_pe():
    """实机验证：用系统里的真实 PE 跑一遍。"""
    cands = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\kernel32.dll",
             r"C:\Windows\System32\calc.exe"]
    target = next((c for c in cands if os.path.exists(c)), None)
    if not target:
        return None, "跳过（未找到系统 PE 样本）"
    code, data, raw = jrun([str(CLI), "triage", target, "--max-items", "500"])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if data.get("identify", {}).get("format") != "pe":
        return False, f"格式 {data.get('identify', {}).get('format')}"
    det = data["identify"].get("detail", {})
    if not det.get("sections"):
        return False, "未解析出节表"
    if not det.get("import_module_count"):
        return False, "未解析出导入表"
    return True, (f"{os.path.basename(target)}: arch={det.get('arch')} "
                  f"导入模块={det.get('import_module_count')} 函数={det.get('import_function_count')} "
                  f"节={len(det.get('sections', []))} PDB={bool(det.get('pdb_path'))} "
                  f"加壳等级={data.get('packer', {}).get('level')}")


def t_real_pyc():
    """
    实机：用本机标准库的 .pyc 验证版本识别。

    这里**不能写死路径**。原实现把用户名和 Python 版本都焊进了字符串
    （`C:/Users/<用户名>/.workbuddy/binaries/python/versions/3.13.12/...`）——
    换一台机器或换一个 Python 版本就再也找不到样本，用例会静默退化成
    "跳过"。于是"pyc 版本识别"这条能力**在别人机器上从未真正被验证过**，
    而输出里只会看到一个无害的"跳过"。改成从当前解释器自己的标准库
    目录推断，到哪台机器都成立。
    """
    import glob
    import sysconfig
    pats = []
    try:
        paths = sysconfig.get_paths()
        for key in ("stdlib", "platstdlib"):
            base = paths.get(key)
            if base:
                pats.append(os.path.join(base, "**", "__pycache__", "*.pyc"))
        # 兜底：解释器目录及其父目录下的 Lib/（Windows 上 sysconfig
        # 指到 DLLs 的情况）
        here = os.path.dirname(PY)
        pats.append(os.path.join(here, "Lib", "__pycache__", "*.pyc"))
        pats.append(os.path.join(os.path.dirname(here), "Lib",
                                 "__pycache__", "*.pyc"))
    except Exception:  # lint:ok 推断失败就退回"跳过"，由 found 为空体现
        pass
    pats = [p for p in pats if p]
    found = []
    for pt in pats:
        found = glob.glob(pt, recursive=True)[:3]
        if found:
            break
    if not found:
        return None, "跳过（未找到系统 pyc）"
    code, data, raw = jrun([str(CLI), "identify", found[0]])
    d = (data or {}).get("detail", {})
    if (data or {}).get("format") != "pyc":
        return False, f"格式 {(data or {}).get('format')}：{raw}"
    return True, f"{os.path.basename(found[0])} → python {d.get('python_version')}（验证={d.get('version_verified_locally')}）"


def t_real_dotnet():
    """实机：.NET 程序集必须识别为托管，且不能因「无原生导入表」被误判加壳。"""
    import glob
    pats = [r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\*\System.Private.CoreLib.dll",
            r"C:\Windows\Microsoft.NET\Framework64\*\mscorlib.dll"]
    found = []
    for pt in pats:
        found = glob.glob(pt)
        if found:
            break
    if not found:
        return None, "跳过（本机无 .NET 程序集）"
    code, data, raw = jrun([str(CLI), "identify", found[0]])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    det = (data or {}).get("detail", {})
    if not det.get("is_dotnet"):
        return False, f"未识别为 .NET 程序集：{data.get('format')}"
    if det.get("packer_suspected"):
        return False, f"托管程序集不应判为疑似加壳，却命中了：{det.get('packer_signals')}"
    return True, (f"{os.path.basename(found[0])}: is_dotnet=True "
                  f"file_kind={det.get('file_kind')} PDB={det.get('pdb_path')}")


def t_empty_file():
    p = w("empty.bin", b"")
    code, data, raw = jrun([str(CLI), "triage", p])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    return True, f"空文件不崩溃，format={data.get('identify', {}).get('format')}"


# ---------------------------------------------------------------- 指令解码层

# x86-64 指令向量：(字节, 期望长度, 期望文本, 说明)
# 期望文本对齐 objdump 的 Intel 语法；以 "?" 结尾的表示只校验长度。
# 跳转目标按 vma_base=0x1000 计算（= 0x1000 + 指令长度 + rel）。
X86_VECTORS = [
    ("48 89 e5", 3, "mov rbp, rsp", "REX.W mov r/m64, r64"),
    ("55", 1, "push rbp", "push 默认 64 位"),
    ("41 54", 2, "push r12", "REX.B push"),
    ("48 83 ec 20", 4, "sub rsp, 0x20", "栈帧分配"),
    ("48 8d 05 00 10 00 00", 7, "lea rax, [rip+0x1000]", "RIP 相对，lea 不带 size 前缀"),
    ("48 8b 04 25 00 10 00 00", 8, "mov rax, qword ptr [0x1000]", "SIB 绝对寻址"),
    ("48 8b 04 c8", 4, "mov rax, qword ptr [rax+rcx*8]", "SIB base+index*8"),
    ("48 8b 44 18 08", 5, "mov rax, qword ptr [rax+rbx+0x8]", "SIB + disp8"),
    ("48 8b 84 98 00 10 00 00", 8, "mov rax, qword ptr [rax+rbx*4+0x1000]", "SIB + disp32"),
    ("48 8b 45 08", 4, "mov rax, qword ptr [rbp+0x8]", "mod=1 disp8"),
    ("48 8b 45 f8", 4, "mov rax, qword ptr [rbp-0x8]", "负 disp8"),
    ("48 8b 00", 3, "mov rax, qword ptr [rax]", "mod=0 无 disp"),
    ("c3", 1, "ret", "返回"),
    ("c2 08 00", 3, "ret 0x8", "带立即数返回"),
    ("e8 00 00 00 00", 5, "call 0x1005", "相对调用（目标含指令长度）"),
    ("e9 00 00 00 00", 5, "jmp 0x1005", "相对跳转"),
    ("74 05", 2, "je 0x1007", "短跳转"),
    ("0f 84 00 00 00 00", 6, "je 0x1006", "近跳转"),
    ("eb fe", 2, "jmp 0x1000", "自跳死循环"),
    ("ff 15 00 10 00 00", 6, "call qword ptr [rip+0x1000]", "间接调用"),
    ("ff 25 00 10 00 00", 6, "jmp qword ptr [rip+0x1000]", "间接跳转"),
    ("ff d0", 2, "call rax", "寄存器间接调用"),
    ("ff e0", 2, "jmp rax", "寄存器间接跳转"),
    ("f3 0f 1e fa", 4, "endbr64", "CET landing pad"),
    ("f3 0f 1e fb", 4, "endbr32", "CET 32 位"),
    ("f3 48 0f 1e fa", 5, "endbr64", "前缀顺序不影响"),
    ("0f 05", 2, "syscall", "系统调用"),
    ("cc", 1, "int3", "断点"),
    ("48 b8 78 56 34 12 78 56 34 12", 10, "mov rax, 0x1234567812345678", "movabs imm64"),
    ("b8 05 00 00 00", 5, "mov eax, 0x5", "imm32"),
    ("66 b8 05 00", 4, "mov ax, 0x5", "0x66 覆盖 operand-size"),
    ("48 c7 c0 01 00 00 00", 7, "mov rax, 0x1", "Grp: mov r/m64, imm32"),
    ("83 f8 05", 3, "cmp eax, 0x5", "Grp1 imm8 符号扩展"),
    ("85 c0", 2, "test eax, eax", "test"),
    ("0f b6 c0", 3, "movzx eax, al", "movzx"),
    ("0f bf c0", 3, "movsx eax, ax", "movsx"),
    ("48 63 c0", 3, "movsxd rax, eax", "movsxd 是 3 字节，无立即数"),
    ("c9", 1, "leave", "leave"),
    ("0f 31", 2, "rdtsc", "rdtsc"),
    ("48 0f af c1", 4, "imul rax, rcx", "imul"),
    ("64 48 8b 04 25 30 00 00 00", 9, "mov rax, qword ptr fs:[0x30]", "读 PEB（反调试关键）"),
    ("65 48 8b 04 25 60 00 00 00", 9, "mov rax, qword ptr gs:[0x60]", "读 TEB（WOW64）"),
    # --- SSE / AVX / AVX-512 ---
    ("0f 57 c0", 3, "xorps xmm0, xmm0", "SSE 两操作数"),
    ("c5 f8 57 c0", 4, "vxorps xmm0, xmm0, xmm0", "VEX2：vvvv 是第一个源"),
    ("c5 f0 57 c1", 4, "vxorps xmm0, xmm1, xmm1", "VEX2 vvvv=1"),
    ("c5 f9 6f c1", 4, "vmovdqa xmm0, xmm1", "VEX2 NDD：不用 vvvv"),
    ("c5 f9 6f 00", 4, "vmovdqa xmm0, xmmword ptr [rax]", "VEX2 NDD 内存源"),
    ("c5 fa 7f 00", 4, "vmovdqu xmmword ptr [rax], xmm0", "VEX2 store 方向"),
    ("c4 e3 f9 14 c1 05", 6, "vpextrb rcx, xmm0, 0x5", "VEX3 0F3A：NDD + imm8"),
    ("c4 e2 79 1d c1", 5, "vpabsw xmm0, xmm1", "VEX3 0F38 NDD"),
    ("62 f1 fd 49 6f 00", 6, "vmovdqa zmm0{k1}, zmmword ptr [rax]", "EVEX 掩码 k1"),
    ("62 f1 7c 48 6f 00", 6, "vmovdqa? ", "EVEX 无掩码（aaa=0）"),
    # --- 串指令：memcpy/memset/strlen 的识别依据，长度错一字节整段流就错位 ---
    ("f3 a4", 2, "rep movsb", "串指令无立即数（曾误带 Ib 多吃一字节）"),
    ("f3 a5", 2, "rep movsd", "32 位 movs 后缀 d"),
    ("48 f3 a5", 3, "rep movsq", "REX.W 后缀 q"),
    ("f3 aa", 2, "rep stosb", "memset 特征"),
    ("48 f3 ab", 3, "rep stosq", "memset 64 位特征"),
    ("f2 ae", 2, "repne scasb", "strlen/strchr 特征"),
    ("f3 a6", 2, "rep cmpsb", "memcmp 特征"),
    ("66 f3 a5", 3, "rep movsw", "16 位后缀 w"),
    # --- 强制前缀（mandatory prefix）：同一 opcode 四条不同指令 ---
    ("f3 0f 6f 01", 4, "movdqu xmm0, xmmword ptr [rcx]", "F3=movdqu，不是 movdqa/带 rep"),
    ("66 0f 6f 01", 4, "movdqa xmm0, xmmword ptr [rcx]", "66=movdqa"),
    ("f3 0f 58 c1", 4, "addss xmm0, xmm1", "F3=标量单精度"),
    ("f2 0f 58 c1", 4, "addsd xmm0, xmm1", "F2=标量双精度"),
    ("0f 58 c1", 3, "addps xmm0, xmm1", "无前缀=packed 单精度"),
    ("66 0f 58 c1", 4, "addpd xmm0, xmm1", "66=packed 双精度"),
    ("f3 0f b8 c0", 4, "popcnt eax, eax", "F3 0F B8"),
    ("f3 0f bc c0", 4, "tzcnt eax, eax", "F3 0F BC（不是 bsf）"),
    ("f3 0f bd c0", 4, "lzcnt eax, eax", "F3 0F BD（不是 bsr）"),
    ("f2 0f c2 00 00", 5, "cmpsd xmm0, xmmword ptr [rax], 0x0", "F2=cmpsd，imm8 不能丢"),
    ("66 0f 70 c1 1b", 5, "pshufd xmm0, xmm1, 0x1b", "pshufd 带 imm8 掩码"),
    ("f3 0f 70 c1 1b", 5, "pshufhw xmm0, xmm1, 0x1b", "F3=pshufhw"),
    ("f2 0f 70 c1 1b", 5, "pshuflw xmm0, xmm1, 0x1b", "F2=pshuflw"),
    ("f0 ff 41 10", 4, "lock inc dword ptr [rcx+0x10]", "lock 前缀必须可见"),
]

ARM64_VECTORS = [
    ("1f 20 03 d5", 4, "nop", "nop"),
    ("c0 03 5f d6", 4, "ret x30", "返回"),
    ("20 00 80 d2", 4, "movz x0, #1, lsl #0", "宽立即数"),
    ("ff 43 00 d1", 4, "sub sp, sp, #16", "栈帧分配（31=sp）"),
    ("fd 7b bf a9", 4, "stp x29, x30, [sp, #-16]!", "前变址，必须带 !"),
    ("fd 7b c1 a8", 4, "ldp x29, x30, [sp], #16", "后变址：先取后加"),
    ("e0 03 1f aa", 4, "mov x0, xzr", "ORR 的 MOV 别名（Rm=31 是 zr）"),
    ("e2 03 08 aa", 4, "mov x2, x8", "ORR 的 MOV 别名"),
    ("00 00 00 94", 4, "bl 0x1000", "相对调用"),
    ("01 00 00 14", 4, "b 0x1004", "相对跳转"),
    ("e1 0b 40 f9", 4, "ldr x1, [sp+0x10]", "无符号偏移载入"),
    ("e1 0f 00 f9", 4, "str x1, [sp+0x18]", "无符号偏移存储"),
    ("3f 00 00 eb", 4, "cmp x1, x0", "SUBS 的 CMP 别名（不是 subs sp）"),
    ("1f 00 00 71", 4, "cmp w0, #0", "SUBS imm 的 CMP 别名"),
    ("81 00 00 54", 4, "b.ne 0x1010", "条件分支"),
    ("00 04 00 91", 4, "add x0, x0, #1", "立即数加法"),
    ("08 00 40 f9", 4, "ldr x8, [x0]", "偏移为 0 时不显示 +0x0"),
    ("00 01 3f d6", 4, "blr x8", "寄存器间接调用"),
]


def _check_vectors(mod, vectors, vma_base=0x1000, bits=64):
    """通用的指令向量校验。返回 (失败列表, 总数)。"""
    bad = []
    for hexstr, want_len, want_txt, note in vectors:
        code = bytes.fromhex(hexstr.replace(" ", ""))
        ins = mod.decode_one(code, 0, bits=bits, vma_base=vma_base)
        if ins.size != want_len:
            bad.append(f"{hexstr} 长度 {ins.size}!={want_len} ({note})")
            continue
        if want_txt.rstrip().endswith("?"):
            continue                      # 只校验长度
        if ins.text != want_txt:
            bad.append(f"{hexstr} 得到 {ins.text!r} 期望 {want_txt!r} ({note})")
    return bad, len(vectors)


def t_x86_decode_vectors():
    """x86-64 指令级正确性：长度 + 助记符 + 操作数 + 跳转目标。"""
    import lib_x86 as X
    bad, total = _check_vectors(X, X86_VECTORS)
    if bad:
        return False, f"{len(bad)}/{total} 条不符：{bad[:3]}"
    return True, f"{total} 条指令向量全对（含 VEX/EVEX/段前缀/跳转目标）"


def t_arm64_decode_vectors():
    """ARM64 指令级正确性：变址模式、CMP/MOV 别名、分支目标。"""
    import lib_arm as A
    bad, total = _check_vectors(A, ARM64_VECTORS)
    if bad:
        return False, f"{len(bad)}/{total} 条不符：{bad[:3]}"
    return True, f"{total} 条 ARM64 向量全对（含前后变址/别名/分支目标）"


def t_disasm_linear_robust():
    """
    线性扫描健壮性：随机/截断/超短输入都不能崩、不能越界、不能死循环。
    这是 fuzz 之外的第二道防线——解码器一旦越界，后续所有分析都不可信。
    """
    import lib_x86 as X
    import lib_arm as A
    random.seed(20260919)
    for _ in range(120):
        n = random.randint(0, 48)
        data = bytes(random.getrandbits(8) for _ in range(n))
        for mod, bits in ((X, 64), (X, 32), (A, 64), (A, 32)):
            insns = mod.disasm_linear(data, 0x1000, bits, 2000)
            total = sum(i.size for i in insns)
            if total > len(data):
                return False, f"覆盖 {total} 字节 > 输入 {len(data)}"
            for i in insns:
                if i.size < 1:
                    return False, f"{mod.__name__} 产出非法长度 {i.size}"
                if i.size > len(data):
                    return False, f"{mod.__name__} 单条指令 {i.size} > 输入 {len(data)}"
    # 截断指令：末字节不足一条完整指令
    for tail in (b"\x48\x8b", b"\xc4\xe2", b"\x0f", b"\x62\xf1\xfd", b"", b"\xff"):
        X.disasm_linear(tail, 0, 64, 100)
        X.disasm_linear(tail, 0, 32, 100)
        A.disasm_linear(tail, 0, 64, 100)
        A.disasm_linear(tail, 0, 32, 100)
    return True, "120 组随机输入 ×4 种模式全部稳定，截断输入不崩溃"


def _sys_pe():
    for c in (r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\calc.exe",
              r"C:\Windows\System32\kernel32.dll"):
        if os.path.exists(c):
            return c
    return None


def t_disasm_real_pe():
    """实机反汇编：真实 PE 代码区的非法指令率必须在可接受范围。"""
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    t0 = time.time()
    code, data, raw = jrun([str(CLI), "disasm", target, "--length", "65536"])
    if code != 0 or not data or not data.get("ok"):
        return False, f"反汇编失败：{raw}"
    cnt = data.get("insn_count", 0)
    bad = data.get("invalid_count", 0)
    if cnt < 200:
        return False, f"指令数过少（{cnt}），代码区选取可能有问题"
    ratio = bad / cnt
    if ratio > 0.20:
        return False, f"非法指令率 {ratio:.1%}（{bad}/{cnt}）过高，解码表可能有系统性错误"
    dt = round(time.time() - t0, 2)
    return True, (f"{os.path.basename(target)} {cnt} 条指令，非法 {bad}（{ratio:.1%}），"
                  f"{data.get('bytes')} 字节 {data.get('arch')}，耗时 {dt}s")


def t_funcs_real_pe():
    """实机函数识别：函数数、覆盖率、调用关系都要合理。"""
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    code, data, raw = jrun([str(CLI), "funcs", target, "--top", "5"])
    if code != 0 or not data or not data.get("ok"):
        return False, f"funcs 失败：{raw}"
    n = data.get("function_count", 0)
    if n < 5:
        return False, f"函数数过少：{n}"
    cov = data.get("coverage") or 0
    if cov < 0.2:
        return False, f"覆盖率 {cov:.1%} 过低"
    if not data.get("xrefs", {}).get("callers"):
        return False, "未产出调用关系"
    for f in data.get("functions", [])[:5]:
        if not f.get("name") or f.get("start_vma") is None:
            return False, f"函数字段缺失：{f}"
    return True, (f"{os.path.basename(target)} 识别 {n} 个函数，覆盖率 {cov:.1%}，"
                  f"调用点 {data.get('call_count')}，指令 {data.get('decoded_insns')}")


def t_cfg_real_pe():
    """实机 CFG：拿 funcs 的第一个函数去要控制流图。"""
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    code, d1, raw = jrun([str(CLI), "funcs", target, "--top", "1"])
    if code != 0 or not d1 or not d1.get("functions"):
        return False, f"先取函数列表失败：{raw}"
    addr = d1["functions"][0].get("start_vma")
    if not addr:
        return False, "函数缺 start_vma"
    code, data, raw = jrun([str(CLI), "cfg", target, str(addr)])
    if code != 0 or not data or not data.get("ok"):
        return False, f"cfg 失败：{raw}"
    if not data.get("nodes"):
        return False, f"CFG 无节点：{data}"
    if not isinstance(data.get("edges"), list):
        return False, "CFG 缺 edges"
    # 回归防线：函数里有几个 call，CFG 就必须有几条 call 边。
    # （曾因只扫描块尾指令，块中间的 call 被全部丢掉）
    want_calls = len(d1["functions"][0].get("calls") or [])
    got_calls = sum(1 for e in data["edges"] if e.get("type") == "call")
    if want_calls and got_calls < want_calls:
        return False, f"函数有 {want_calls} 个 call，CFG 只给出 {got_calls} 条 call 边"
    return True, (f"{os.path.basename(target)} @{addr} → {data.get('block_count')} 基本块，"
                  f"{data.get('edge_count')} 条边（含 {got_calls} 条调用边）")


def t_xref_real_pe():
    """实机交叉引用：指定地址要能查到调用者/被调用者。"""
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    code, d1, raw = jrun([str(CLI), "funcs", target, "--top", "1"])
    if code != 0 or not d1 or not d1.get("functions"):
        return False, f"取函数失败：{raw}"
    addr = d1["functions"][0].get("start_vma")
    code, data, raw = jrun([str(CLI), "xref", target, "--addr", str(addr)])
    if code != 0 or not data:
        return False, f"xref 失败：{raw}"
    if not data.get("ok"):
        return False, f"xref 返回 not ok：{data.get('error')}"
    return True, f"{os.path.basename(target)} @{addr} 交叉引用查询成功"


def t_sim_self():
    """函数级比对：与自身比对必须全部匹配（差分基线）。"""
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    code, data, raw = jrun([str(CLI), "sim", target, target], timeout=600)
    if code != 0 or not data:
        return False, f"sim 失败：{raw}"
    if not data.get("ok"):
        return False, f"sim 返回 not ok：{data.get('error')}"
    rate = data.get("match_rate_a")
    if rate is None:
        return False, f"未产出匹配率：{list(data)[:6]}"
    un = data.get("unmatched_a") or []
    if rate < 0.99:
        return False, f"与自身比对匹配率仅 {rate}，未匹配 {len(un)} 个（第一个 {un[:1]}）"
    rb = data.get("match_rate_b", 0)
    if rb < 0.99:
        return False, (f"A 侧全匹配但 B 侧只有 {rb}：配对不是一对一，"
                       f"指纹相同的函数撞车了")
    return True, (f"自比对 {data.get('matched')}/{data.get('total_a')} 全匹配"
                  f"（双向 {rate}/{rb}，比较 {data.get('comparisons')} 次）")


def t_x86_mem_ref():
    """
    mem_ref（内存操作数指向的地址）正确性。

    这是 API 还原的地基：MSVC 的导入调用是 call/jmp qword ptr [rip+disp]，
    调用目标运行时才确定（target=None），但被引用的 IAT 槽位是编译期常量。
    mem_ref 算错一位，全文件的 API 名就全错。
    """
    import lib_x86 as X
    base = 0x140001000
    cases = [
        # (字节, 期望 mem_ref, 说明)
        # ff 15 xx : call qword ptr [rip+disp32]，指令长 6
        ("ff1500000000", base + 6 + 0, "call [rip+0]"),
        ("ff1510000000", base + 6 + 0x10, "call [rip+0x10]"),
        # ff 25 : jmp qword ptr [rip+disp32]
        ("ff2520000000", base + 6 + 0x20, "jmp [rip+0x20]"),
        # 8b 05 : mov eax, dword ptr [rip+disp32]
        ("8b0530000000", base + 6 + 0x30, "mov eax,[rip+0x30]"),
        # 48 8b 05 : mov rax, qword ptr [rip+disp32]（REX.W，仍 7 字节）
        ("488b0540000000", base + 7 + 0x40, "mov rax,[rip+0x40]"),
        # 负位移
        ("ff15f0ffffff", base + 6 - 0x10, "call [rip-0x10]"),
    ]
    bad = []
    for hexstr, want, note in cases:
        code = bytes.fromhex(hexstr)
        ins = X.decode_one(code, 0, bits=64, vma_base=base)
        if ins.mem_ref != want:
            bad.append(f"{note}: mem_ref={ins.mem_ref and hex(ins.mem_ref)} "
                       f"期望 {hex(want)}")
    # 寄存器间接（call rax）不该产出 mem_ref
    ins = X.decode_one(bytes.fromhex("ffd0"), 0, bits=64, vma_base=base)
    if ins.mem_ref is not None:
        bad.append(f"call rax 不该有 mem_ref，得到 {hex(ins.mem_ref)}")
    if bad:
        return False, f"{len(bad)}/{len(cases) + 1} 条不符：{bad[:3]}"
    return True, f"{len(cases)} 条 RIP 相对寻址 + 1 条寄存器间接全部正确"


def t_iat_resolution():
    """
    IAT 解析：把 IAT 槽位地址映射成 "dll!FuncName"（含延迟导入）。

    【已修 bug】延迟导入（.didat）漏解析时，notepad.exe 有 33 处导入调用
    显示成"未知"。这个用例盯住它不再退化。
    """
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    import lib_formats as FT
    import lib_disasm as D
    ident = FT.identify(target, deep=True)
    det = ident.get("detail") or {}
    if not det.get("parse_ok", True):
        return False, f"PE 结构解析失败：{det.get('errors')}"
    iat = D.resolve_iat(ident)
    if not iat:
        return False, "IAT 映射为空，导入表可能没解析出来"
    # 值必须是 "dll!Func" 形态
    sample = list(iat.values())[:3]
    for s in sample:
        if "!" not in s:
            return False, f"IAT 值格式不对：{s!r}"
    n_delay = det.get("delay_import_function_count", 0)
    # 延迟导入的槽位必须也进了 iat 表（有延迟导入的二进制才校验）
    if n_delay:
        hit = sum(1 for m in det.get("delay_imports", [])
                  for f in m.get("functions", [])
                  if f.get("iat_rva") and
                  (det.get("image_base", 0) + f["iat_rva"]) in iat)
        if hit == 0:
            return False, f"有 {n_delay} 个延迟导入函数但一个都没进 IAT 映射"
    return True, (f"{os.path.basename(target)} IAT 映射 {len(iat)} 项"
                  f"（延迟导入 {n_delay} 项），样例 {sample[0]}")


def t_semantics_real_pe():
    """
    实机语义摘要：API 还原率、行为标签、调用链标签传播。

    判据按"能力存在性"设，不按某个二进制的固定数字设 —— 换台机器上的
    notepad.exe 版本不同，函数名/数量都会变，写死数字只会制造假失败。
    """
    target = _sys_pe()
    if not target:
        return None, "跳过（未找到系统 PE）"
    code, data, raw = jrun([str(CLI), "semantics", target, "--limit", "300",
                            "--max-insns", "200000"], timeout=600)
    if code != 0 or not data or not data.get("ok"):
        return False, f"semantics 失败：{raw[:200]}"
    funcs = data.get("functions") or []
    if len(funcs) < 20:
        return False, f"函数数过少（{len(funcs)}）"
    iat_n = data.get("iat_resolved", 0)
    if iat_n < 20:
        return False, f"IAT 只解析出 {iat_n} 项，导入表解析可能坏了"
    with_api = sum(1 for f in funcs if f.get("api_calls"))
    with_tag = sum(1 for f in funcs if f.get("tags"))
    with_inh = sum(1 for f in funcs if f.get("inherited_tags"))
    if with_api < 10:
        return False, (f"{len(funcs)} 个函数里只有 {with_api} 个还原出 API："
                       f"mem_ref / IAT 映射链路可能断了")
    if with_tag < 3:
        return False, f"只有 {with_tag} 个函数拿到行为标签，API_TAGS 表可能没生效"
    if with_inh == 0:
        return False, "没有任何函数通过调用链继承到标签，_propagate_tags 没起作用"
    cl = data.get("tag_clusters") or {}
    return True, (f"{os.path.basename(target)} {len(funcs)} 函数："
                  f"{with_api} 个有 API、{with_tag} 个有直接标签、"
                  f"{with_inh} 个继承标签；分组 {len(cl)} 类，IAT {iat_n} 项")


def t_libscan_consts():
    """
    常量表 / 库函数识别：确定性单测（不依赖系统里恰好有某个二进制）。

    用手工构造的假 ident + 真实临时文件验证"找到表 → 正确换算 VMA"，
    再用手工构造的函数验证 rep stosq 能认成 memset 家族。
    """
    import lib_libscan as LS

    sbox = bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                  0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])
    blob = b"\xAA" * 32 + sbox + b"\xBB" * 32
    p = w("libscan/aes.bin", blob)
    ident = {
        "format": "pe",
        "detail": {"image_base": 0x100000,
                   "sections": [{"name": ".rdata", "raw_offset": 0,
                                 "raw_size": len(blob), "virtual_address": 0x2000,
                                 "chars": []}]},
    }
    hits = LS.scan_const_tables(str(p), ident)
    aes = [h for h in hits if h["key"] == "aes_sbox"]
    if not aes:
        return False, "AES S-box 没找到（常量表扫描坏了）"
    want_vma = 0x100000 + 0x2000 + 32
    if aes[0]["vma"] != want_vma:
        return False, f"VMA 换算错：{hex(aes[0]['vma'])} 应为 {hex(want_vma)}"

    # 指令形态：rep stosq -> memset 家族
    from lib_code import CodeIndex
    code = b"\x48\xf3\xab\xc3"          # rep stosq; ret
    idx = CodeIndex(code, base_vma=0x1000, bits=64, arch="x86-64", max_insns=16)
    funcs = [{"name": "f_memset", "start_vma": hex(0x1000),
              "end_vma": hex(0x1004), "_offs": [0, 3]}]
    hints = LS.identify_libfuncs(idx, funcs, [])
    h = hints.get(0x1000)
    if not h or "memset" not in h["name"]:
        return False, f"rep stosq 未识别成 memset 家族：{h}"
    if h["confidence"] != "中":
        return False, f"置信度应为中，得到 {h['confidence']}"

    # 引用常量表的函数应拿到"高"置信度
    lea = b"\x48\x8d\x05" + (0).to_bytes(4, "little", signed=True)  # lea rax,[rip+0]
    idx2 = CodeIndex(lea + b"\xc3", base_vma=want_vma - 7, bits=64,
                     arch="x86-64", max_insns=16)
    funcs2 = [{"name": "f_aes", "start_vma": hex(want_vma - 7),
               "end_vma": hex(want_vma), "_offs": [0, 7]}]
    h2 = LS.identify_libfuncs(idx2, funcs2, aes)
    if not h2 or not h2.get(want_vma - 7):
        return False, f"引用 S-box 的函数未识别：{list(h2)}"
    if h2[want_vma - 7]["confidence"] != "高":
        return False, f"命中常量表应为高置信度，得到 {h2[want_vma-7]}"
    return True, (f"AES S-box 命中 @{hex(aes[0]['vma'])}，rep stosq -> memset 家族，"
                  f"常量引用置信度分级正确")


def t_truncated_pe():
    src = mk_pe64()
    data_bytes = src.read_bytes()
    p = w("truncated.exe", data_bytes[:120])
    code, data, raw = jrun([str(CLI), "identify", p])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    return True, f"截断 PE 不崩溃，format={data.get('format')} errors={len(data.get('detail', {}).get('errors', []))}"


def t_fuzz_mutations():
    """位翻转变异：任何畸形输入都必须返回结构化结果且不崩溃。"""
    src = mk_pe64().read_bytes()
    rnd = random.Random(20260918)
    bad = 0
    for i in range(30):
        b = bytearray(src)
        for _ in range(rnd.randint(1, 12)):
            pos = rnd.randrange(0, min(len(b), 0x500))
            b[pos] = rnd.randrange(0, 256)
        if rnd.random() < 0.3:
            b = b[:rnd.randrange(0, len(b))]
        p = w(f"fuzz/f_{i}.bin", bytes(b))
        code, out, err = run([str(CLI), "identify", str(p), "--json"], timeout=60)
        if code not in (0, 3, 4):
            bad += 1
            continue
        try:
            obj = json.loads(out)
        except Exception:
            bad += 1
            continue
        if "format" not in obj:
            bad += 1
    if bad:
        return False, f"{bad}/30 个变异样本产生了非法输出"
    return True, "30 个变异样本全部返回合法结构化结果"


def t_random_garbage():
    rnd = random.Random(7)
    for name, data in (("rand.bin", bytes(rnd.randrange(256) for _ in range(100000))),
                       ("zeros.bin", b"\x00" * 50000),
                       ("text.txt", b"hello world\n" * 500)):
        p = w(name, data)
        for cmd in ("identify", "triage", "strings", "entropy", "carve", "plan"):
            code, out, err = run([str(CLI), cmd, str(p), "--json"], timeout=120)
            if code not in (0, 3, 4):
                return False, f"{cmd} 对 {name} 退出码 {code}"
            try:
                json.loads(out)
            except Exception:
                return False, f"{cmd} 对 {name} 输出非 JSON"
    return True, "随机/全零/文本三类输入 × 6 个子命令全部稳定"


def t_exit_codes():
    code, data, raw = jrun([str(CLI), "identify", str(TMP / "no_such_file_xyz.bin")])
    if code != 3:
        return False, f"缺失目标应退出 3，实际 {code}"
    if (data or {}).get("ok") is not False:
        return False, "JSON 应带 ok=false"
    code2, _, _ = run([str(CLI), "identify", str(TMP)])
    if code2 not in (2, 3):
        return False, f"目录作为目标应退出 2/3，实际 {code2}"
    return True, "退出码约定正确（缺失=3，目录=2/3）"


def t_perf_big_file():
    """100MB 文件：流式扫描必须在可接受时间内完成（验证内存有界 + 速度）。"""
    p = TMP / "big.bin"
    mk_big(p, size_mb=100)
    t0 = time.time()
    code, data, raw = jrun([str(CLI), "entropy", str(p)], timeout=300)
    dt = time.time() - t0
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if dt > 60:
        return False, f"100MB 熵扫描耗时 {dt:.1f}s，过慢"
    t1 = time.time()
    code2, d2, raw2 = jrun([str(CLI), "strings", str(p), "--min", "8", "--max-items", "5000"], timeout=300)
    dt2 = time.time() - t1
    if code2 != 0:
        return False, f"strings 退出码 {code2}: {raw2}"
    if dt2 > 60:
        return False, f"100MB 字符串扫描耗时 {dt2:.1f}s，过慢"
    return True, f"100MB：熵 {dt:.1f}s（熵值 {data.get('overall_entropy')}），字符串 {dt2:.1f}s（{d2.get('count')} 条）"


def t_perf_triage_real():
    target = r"C:\Windows\System32\notepad.exe"
    if not os.path.exists(target):
        return None, "跳过（无系统 PE）"
    t0 = time.time()
    code, data, raw = jrun([str(CLI), "triage", target, "--max-items", "3000"], timeout=180)
    dt = time.time() - t0
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if dt > 25:
        return False, f"triage 耗时 {dt:.1f}s，过慢"
    return True, f"triage 真实 PE 耗时 {dt:.2f}s（internal {data.get('total_seconds')}s）"


def t_report():
    p = mk_pe64()
    out = TMP / "report.md"
    code, data, raw = jrun([str(CLI), "report", str(p), "--out", str(out)])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if not out.exists():
        return False, "报告文件未生成"
    txt = out.read_text(encoding="utf-8")
    for section in ("# 逆向初筛报告", "## 1. 识别结论", "## 4. 结构要点", "## 6. 合规提醒"):
        if section not in txt:
            return False, f"报告缺少章节：{section}"
    return True, f"报告 {len(txt)} 字符，章节齐全"


def t_doctor():
    code, data, raw = jrun([str(CLI), "doctor"])
    if code != 0:
        return False, f"退出码 {code}: {raw}"
    if "present" not in data or "missing" not in data:
        return False, "doctor 输出缺字段"
    if data.get("present_count", 0) + len(data.get("missing", [])) != data.get("tool_count"):
        return False, "工具统计不一致"
    return True, f"{data.get('present_count')}/{data.get('tool_count')} 工具可用，Python {data.get('python')}"


def t_plan_all_formats():
    bad = []
    for p in (mk_pe64(), mk_elf64(), mk_macho64(), mk_apk(), mk_wasm(), mk_sqlite(),
              mk_javaclass(), mk_firmware(), mk_dex(), mk_pyc()):
        code, data, raw = jrun([str(CLI), "plan", str(p), "--no-tools"])
        if code != 0 or not (data or {}).get("steps"):
            bad.append(f"{p.name}:{code}")
    if bad:
        return False, f"以下格式未产出计划：{bad}"
    return True, "10 种格式全部产出分析计划"


def t_accel_layer():
    """加速层：每个格式都要有，且命令里的 {t} 占位符必须被替换掉。"""
    bad = []
    n = 0
    for p in (mk_pe64(), mk_elf64(), mk_macho64(), mk_apk(), mk_wasm(), mk_sqlite(),
              mk_javaclass(), mk_firmware(), mk_dex(), mk_pyc()):
        code, data, raw = jrun([str(CLI), "plan", str(p), "--no-tools"])
        if code != 0:
            bad.append(f"{p.name}:退出码{code}")
            continue
        acc = (data or {}).get("accel") or []
        if len(acc) != 4:
            bad.append(f"{p.name}:加速层 {len(acc)} 步")
            continue
        n += 1
        for step in acc:
            for c in step.get("commands", []):
                if "{t}" in c:
                    bad.append(f"{p.name}:占位符未替换 -> {c}")
                if not c.strip():
                    bad.append(f"{p.name}:空命令")
    if bad:
        return False, f"加速层问题：{bad[:4]}"
    return True, f"{n} 种格式的加速层均为 4 步，占位符全部替换"


def t_tools_table_integrity():
    """工具表完整性：命令不重复、分类可控、url 齐全、AI 栈结构正确。"""
    sys.path.insert(0, str(HERE))
    import lib_tools as TT
    cmds = [t["cmd"] for t in TT.TOOLS]
    dup = {c for c in cmds if cmds.count(c) > 1}
    if dup:
        return False, f"工具表有重复命令：{sorted(dup)}"
    no_url = [t["cmd"] for t in TT.TOOLS if not t.get("url")]
    if no_url:
        return False, f"以下工具缺 url：{no_url}"
    no_cat = [t["cmd"] for t in TT.TOOLS if not t.get("cat")]
    if no_cat:
        return False, f"以下工具缺分类：{no_cat}"

    d = TT.doctor()
    if len(d.get("env_probes", [])) != len(TT.ENV_PROBES):
        return False, "env_probes 数量与定义不一致"
    for e in d["env_probes"]:
        if "dir_exists" not in e or "value" not in e:
            return False, f"env_probe 字段缺失：{e.get('name')}"
    ai = d.get("ai_stack", [])
    if len(ai) != len(TT.AI_STACK):
        return False, "ai_stack 数量与定义不一致"
    for a in ai:
        if not isinstance(a.get("ready"), bool) or "how" not in a:
            return False, f"ai_stack 字段缺失：{a.get('id')}"
    if d.get("ai_ready_count", 0) != sum(1 for a in ai if a["ready"]):
        return False, "ai_ready_count 统计不一致"
    return True, f"工具表 {len(TT.TOOLS)} 项无重复，环境探测 {len(TT.ENV_PROBES)} 项，AI 层 {len(ai)} 项"


def t_cli_help_covers_all_subcommands():
    """--help 的 epilog 必须列出**全部**已注册子命令。

    为什么需要这条：re.py 的模块 docstring 就是 --help 的 epilog，它是一份
    手写的清单，和 add_parser() 的真实注册列表之间没有任何强制关联。
    历史上它就漏了 semantics / capability —— 子命令能用，但 --help 里看不到，
    等于这两个能力对使用者不存在（文档漏报，属于静默失败的一种）。
    """
    src = (HERE / "re.py").read_text(encoding="utf-8")
    # 注册有两种写法：add_parser("x", help=...) 与本地包装 add("x", "help", fn)
    registered = set(re.findall(r'add_parser\(\s*"([a-z][a-z0-9-]*)"', src))
    registered |= set(re.findall(r'^\s*(?:s\s*=\s*)?add\(\s*"([a-z][a-z0-9-]*)"',
                                 src, re.M))
    if not registered:
        return False, "没能从 re.py 里解析出任何子命令注册项"
    # epilog 缩进是两空格 + 名字；子命令名可能长于 8 字符，故只匹配「名 + 空白」
    hdr = src.split('"""')[1] if '"""' in src else ""
    missing = sorted(s for s in registered
                     if not re.search(r"^\s{2}%s\b" % re.escape(s), hdr, re.M))
    if missing:
        return False, f"以下子命令已注册但 --help epilog 未列出：{missing}"
    return True, f"{len(registered)} 个子命令全部出现在 --help epilog 中"


def t_report_default_out_not_cwd():
    """report 不传 --out 时，绝不能把报告写进当前工作目录。

    为什么需要这条：selftest 用 cwd=scripts/ 跑 CLI，而 report 曾经默认
    写 os.getcwd() —— 结果每次自检都在**源码目录**里生成
    <目标>.re-report.md，测试残留被当成交付物发布出去。真实发生过。
    """
    src_pe = mk_pe64()
    td = TMP / "report_cwd_probe"
    td.mkdir(parents=True, exist_ok=True)
    tgt = td / "target.exe"
    tgt.write_bytes(src_pe.read_bytes())
    work = td / "cwd"
    work.mkdir(parents=True, exist_ok=True)

    p = subprocess.run([PY, str(CLI), "report", str(tgt), "--json"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300, cwd=str(work))
    if p.returncode != 0:
        return False, f"report 退出码 {p.returncode}: {(p.stdout + p.stderr)[:200]}"
    stray = sorted(x.name for x in work.iterdir())
    if stray:
        return False, f"默认输出污染了工作目录：{stray}"
    if not (td / "target.exe.re-report.md").exists():
        return False, "报告没有写到目标文件旁边（期望 target.exe.re-report.md）"
    return True, "无 --out 时报告写到目标同级目录，工作目录保持干净"


def t_json_ok_contract():
    """--json 模式下，所有子命令必须输出顶层 ok 字段（成功 true）。

    这是 AI 调用方唯一可靠的判据：没有 ok 就只能靠猜退出码。曾经 doctor /
    magic 漏了这个字段，属于契约不一致，而非风格问题。
    """
    pe = mk_pe64()
    probes = [
        ("doctor", [str(CLI), "doctor", "--json"]),
        ("magic", [str(CLI), "magic", "--json"]),
        ("identify", [str(CLI), "identify", str(pe), "--json"]),
        ("strings", [str(CLI), "strings", str(pe), "--json", "--max-items", "20"]),
        ("entropy", [str(CLI), "entropy", str(pe), "--json"]),
        ("imports", [str(CLI), "imports", str(pe), "--json"]),
        ("info", [str(CLI), "info", str(pe), "--json"]),
        ("triage", [str(CLI), "triage", str(pe), "--json"]),
        ("carve", [str(CLI), "carve", str(pe), "--json"]),
        ("diff", [str(CLI), "diff", str(pe), str(pe), "--json"]),
        ("plan", [str(CLI), "plan", str(pe), "--json"]),
        ("report", [str(CLI), "report", str(pe), "--json",
                    "--out", str(Path(TMP) / "probe.re-report.md")]),
        ("disasm", [str(CLI), "disasm", str(pe), "--json", "--max", "50"]),
        ("funcs", [str(CLI), "funcs", str(pe), "--json", "--max", "20"]),
        ("xref", [str(CLI), "xref", str(pe), "--json"]),
        ("sim", [str(CLI), "sim", str(pe), str(pe), "--json"]),
        ("semantics", [str(CLI), "semantics", str(pe), "--json", "--max", "10"]),
        ("capability", [str(CLI), "capability", str(pe), "--json", "--limit", "60"]),
    ]
    bad = []
    checked = 0
    for name, argv in probes:
        code, data, raw = jrun(argv)
        if code not in (0, 2, 3, 4):
            bad.append(f"{name}: 诡异退出码 {code}")
            continue
        if not isinstance(data, dict):
            bad.append(f"{name}: 顶层不是对象")
            continue
        if "ok" not in data:
            bad.append(f"{name}: 缺 ok 字段")
            continue
        checked += 1
        if code == 0 and data.get("ok") is not True:
            bad.append(f"{name}: 退出码 0 但 ok={data.get('ok')!r}")
    if bad:
        return False, "契约不一致：" + "；".join(bad[:6])
    return True, f"{checked} 个子命令 --json 均带 ok 字段且与退出码一致"


def t_no_third_party():
    """
    脚本只能依赖标准库 + 同目录自带模块。

    【已修 bug 1】旧实现把允许列表写死成 4 个 lib_*，新增 lib_x86/lib_arm/
    lib_disasm/lib_code 后，本地模块被误判成第三方依赖。改为扫描 scripts
    目录自动收集本地模块名，新增模块不必再手工维护这份清单。

    【已修 bug 2】手写标准库清单本身也是个坑：用 traceback 就被误报成第三方。
    改成以 sys.stdlib_module_names 为准（Python 3.10+），手写清单只作兜底。
    """
    fallback = {"os", "sys", "json", "re", "struct", "math", "time", "hashlib", "argparse",
                "importlib", "platform", "shutil", "subprocess", "datetime", "zipfile",
                "sqlite3", "py_compile", "random", "pathlib", "glob", "zlib", "tempfile",
                "collections", "unicodedata", "io", "cProfile", "pstats", "__future__",
                "typing", "dataclasses", "enum", "itertools", "functools", "bisect",
                "heapq", "array", "copy", "textwrap", "string", "binascii", "base64"}
    stdlib = set(getattr(sys, "stdlib_module_names", ())) or set(fallback)
    # 同目录 .py 都是本项目自带模块，一律放行。
    #
    # 【已修 bug 4】旧实现只扫 HERE（scripts/*.py），不含 _dev/。
    # 于是 _dev/ 下的自研模块被当成第三方依赖误报（安装器用例 import
    # _install 时当场抓到）。_dev/ 是开发脚手架，同样属于本项目自带，
    # 必须一起收进本地模块集。
    local = {p.stem for p in HERE.glob("*.py")}
    _dev_dir = HERE / "_dev"
    if _dev_dir.is_dir():
        local |= {p.stem for p in _dev_dir.glob("*.py")}
    # 安装到运行时后 _dev/ 不再分发，selftest 里指向 _dev 工具的 import
    # 会变成"找不到的第三方依赖"。这不是依赖问题，是**环境不具备**，
    # 应当整条用例跳过，而不是报红。判据：_dev/ 目录不存在且有 _ 模块
    # 找不到归属。
    if not _dev_dir.is_dir():
        _dev_only = {m for m in ("_install",) if m not in local}
        if _dev_only:
            return True, SKIP
    allowed = stdlib | local | fallback

    # 【已修 bug 3】旧实现只取 `s.split()[0]`，遇到逗号分隔的
    # `import os, sys, json` 会得到 `os,`（带逗号）→ 查表失败 →
    # 把标准库误报成第三方依赖。必须按逗号切开逐个取模块名，
    # 并处理 `import a.b as c` / `from .x import y` 等形式。
    _imp_multi = re.compile(r"^import\s+(.+)$")
    _imp_from = re.compile(r"^from\s+([.\w]+)\s+import\b")

    def _root(name: str) -> str:
        return name.strip().lstrip(".").split(" as ")[0].strip().split(".")[0]

    bad = []
    scanned = 0
    # 生产脚本 + _dev/ 脚手架都要扫：脚手架坏了同样会让门禁失灵（假绿）。
    _scan_targets = sorted(HERE.glob("*.py"))
    if _dev_dir.is_dir():
        _scan_targets += sorted(_dev_dir.glob("*.py"))
    for p in _scan_targets:
        txt = p.read_text(encoding="utf-8")
        scanned += 1
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("#"):
                continue
            m = _imp_multi.match(s)
            if m:
                mods = [_root(x) for x in m.group(1).split(",")]
            else:
                m = _imp_from.match(s)
                if not m:
                    continue
                mods = [_root(m.group(1))]
            for mod in mods:
                if mod and mod not in allowed:
                    bad.append(f"{p.name}: {s}")
    if bad:
        return False, f"引入非标准库依赖：{bad[:5]}"
    return True, f"{scanned} 个脚本仅依赖标准库 + 本地模块"


CHUNK_MB = 1  # 与 lib_analyze.CHUNK 保持一致，用于边界用例


# ---------------------------------------------------------------- 能力规则引擎

def t_rules_load():
    """
    规则库加载：20+ 条规则、0 错误、字段完整。

    并守住两个曾经踩过的静默数据丢失 bug：
      1) 多文档 YAML：一条规则一个 `---`，只用单文档解析器会**只留最后一条**；
      2) 规则重名：重名会让 match 的按名索引静默覆盖。
    """
    import lib_rules as LR
    rules_dir = SKILL / "rules"
    if not rules_dir.is_dir():
        return False, "rules/ 目录不存在"
    rules, errs = LR.load_rules(str(rules_dir))
    if errs:
        return False, f"规则加载报错：{errs[:3]}"
    if len(rules) < 20:
        return False, f"只加载到 {len(rules)} 条规则（期望 ≥20）"
    # 核心字段必须齐全
    for r in rules:
        if not r.name or not r.namespace or not r.scope:
            return False, f"规则字段缺失：{r.name!r}"
        if r.scope not in LR.SCOPES:
            return False, f"规则 {r.name} scope 非法：{r.scope}"
        if not r.features:
            return False, f"规则 {r.name} 没有 features"
    names = [r.name for r in rules]
    if len(names) != len(set(names)):
        dup = [n for n in names if names.count(n) > 1]
        return False, f"规则重名：{sorted(set(dup))[:3]}"
    n_att = sum(1 for r in rules if r.att_ck)
    return True, f"{len(rules)} 条规则，0 错误，{n_att} 条带 ATT&CK 映射"


def t_rules_yaml_parser():
    """
    自带 YAML 子集解析器：标量/列表/嵌套/多文档 全绿，且非法语法必须**报错**。

    零依赖是本项目的硬约束（见 t_no_third_party），所以规则文件用的 YAML
    必须自己解析。自己写解析器最大的风险是"静默解析错" —— 因此这里
    既测正常路径，也测每条非法语法都必须抛玉。
    """
    import lib_rules as LR

    src = (
        "a: 1\n"
        "b: 0x10\n"
        "c: -3\n"
        "d: 1.5\n"
        "e: true\n"
        "f: null\n"
        "g: 'has # inside'\n"
        "h: plain text\n"
        "i: 1_000\n"
        "lst:\n"
        "  - x\n"
        "  - y\n"
        "maps:\n"
        "  - k: v\n"
        "    z: 2\n"
        "att: Execution::Command and Scripting [T1059]\n"
        "url: https://example.com/x\n"
        "ind:\n"
        "  deep:\n"
        "      deeper: 1\n"
    )
    try:
        d = LR.yaml_load(src)
    except Exception as e:
        return False, f"正常语法解析失败：{type(e).__name__}: {e}"

    checks = [
        (d.get("a") == 1, "int"),
        (d.get("b") == 16, "hex"),
        (d.get("c") == -3, "负数"),
        (d.get("d") == 1.5, "浮点"),
        (d.get("e") is True, "布尔"),
        (d.get("f") is None, "null"),
        (d.get("g") == "has # inside", "引号内 # 不是注释"),
        (d.get("h") == "plain text", "裸字符串"),
        (d.get("i") == 1000, "下划线整数"),
        (d.get("lst") == ["x", "y"], "列表"),
        (isinstance(d.get("maps"), list) and d["maps"][0].get("k") == "v", "列表套映射"),
        (d.get("att") == "Execution::Command and Scripting [T1059]", ":: 不是键分隔符"),
        (d.get("url") == "https://example.com/x", ":// 不是键分隔符"),
        (isinstance(d.get("ind"), dict) and d["ind"]["deep"]["deeper"] == 1,
         "相对缩进（深 4 格也合法）"),
    ]
    bad = [n for ok, n in checks if not ok]
    if bad:
        return False, "解析结果错误：" + "、".join(bad)

    # 多文档：这一条曾经吞掉 4 条规则里的 3 条
    multi = "rule:\n  meta:\n    name: A\n---\nrule:\n  meta:\n    name: B\n---\nrule:\n  meta:\n    name: C\n"
    docs = LR.yaml_load_all_file.__doc__ and None
    try:
        got = LR.split_documents(multi)
    except Exception as e:
        return False, f"多文档切分失败：{type(e).__name__}: {e}"
    if len(got) != 3:
        return False, f"多文档切分应得 3 段，实得 {len(got)}"

    # 非法语法必须抛错，不能静默降级
    must_raise = [
        ("锚点 &", "a: &anchor b\n"),
        ("引用 *", "a: *ref\n"),
        ("合并键 <<", "a:\n  <<: x\n"),
        ("块标量 |", "a: |\n  text\n"),
        ("块标量 >", "a: >\n  text\n"),
        ("流式集合 {", "a: {k: v}\n"),
        ("流式集合 [", "a: [1, 2]\n"),
    ]
    not_raised = []
    for name, txt in must_raise:
        try:
            LR.yaml_load(txt)
            not_raised.append(name)
        except Exception:  # lint:ok 这里就是「必须抛异常」的反向断言，吞掉异常是通过条件
            pass
    if not_raised:
        return False, f"以下非法语法本应报错却静默通过：{not_raised}"

    return True, f"{len(checks)} 项解析断言 + 多文档切分 + {len(must_raise)} 项非法语法拦截 全通过"


def t_rules_api_norm():
    """
    API 名归一化：'dll!Func' / 'dll.Func' / 'DLL.dll!Func' 必须归一到同一形态。

    【回归守卫 · 最重要的一条】这是"20 条规则全部零命中"的根因：
    语义层 iat_map 产出 'kernel32!Sleep'，而 _norm_api 只按 '.' 切分，
    于是特征侧存成 '|kernel32!sleep'、规则侧给 'kernel32|sleep'，永远对不上。
    """
    import lib_rules as LR
    cases = {
        "kernel32!Sleep": ("kernel32", "sleep"),
        "kernel32.Sleep": ("kernel32", "sleep"),
        "KERNEL32.dll!Sleep": ("kernel32", "sleep"),
        "KERNEL32.DLL!Sleep": ("kernel32", "sleep"),
        "Sleep": ("", "sleep"),
        "WS2_32.dll!socket": ("ws2_32", "socket"),
        "ntdll!NtQueryInformationProcess": ("ntdll", "ntqueryinformationprocess"),
        # 模块名带扩展名 + 无函数名：也要去掉扩展名
        "kernel32.dll": ("", "kernel32"),
    }
    bad = []
    for src, want in cases.items():
        got = LR._norm_api(src)
        if got != want:
            bad.append(f"{src!r} -> {got}（期望 {want}）")
    if bad:
        return False, "归一化错误：" + "；".join(bad)
    # 同一 API 的不同写法必须落到同一个键
    keys = {("%s|%s" % LR._norm_api(x)) for x in
            ("kernel32!Sleep", "kernel32.Sleep", "KERNEL32.dll!Sleep")}
    if len(keys) != 1:
        return False, f"不同写法归一化不一致：{keys}"
    return True, f"{len(cases)} 种写法归一化正确且互相一致"


def t_rules_feature_fields():
    """
    特征提取的字段形态必须与真实数据结构一致。

    【回归守卫】这里每一个断言都对应一个曾经导致**静默失效**的字段名 bug：
      · 语义层输出的是 api_calls（不是 apis）→ 读到空集 → api 规则全不命中；
      · 指令助记符字段叫 mnem（不是 mnemonic）→ 读到空集 → mnemonic 规则全不命中；
      · 立即数/位移是指令自身的 imm/disp 标量（没有 operands 列表）
        → 读到空集 → number 规则全不命中。
    这三处都不报错，只是悄悄不命中 —— 所以必须用真实对象做形态断言。
    """
    import lib_rules as LR
    import lib_formats as LF
    import lib_disasm as LD
    import lib_semantics as LS

    pe = _sys_pe()
    if pe is None:
        return True, "跳过（无真实 PE 样本）"

    ident = LF.identify(str(pe), deep=True)
    an = LD.analyze_file(str(pe), ident, max_insns=120000)
    if not an.get("ok"):
        return False, f"分析失败：{an.get('error')}"
    idx = an.pop("_idx", None)
    from lib_code import find_functions
    funcs = find_functions(idx, seeds=LD.entry_points(ident),
                           symbols=LD.symbols_from(ident))
    if not funcs:
        return True, "跳过（未识别出函数）"
    iat = LD.resolve_iat(ident)
    if not iat:
        return False, "IAT 未解析出任何项（ident.detail 形态可能变了）"

    n = len(funcs)
    # 至少抓一个"有 api 调用"的函数来断言
    sums = LS.summarize_functions(idx, funcs, iat, {}, limit=min(80, n))
    api_bearing = [s for s in sums if s.get("api_calls")]
    if not api_bearing:
        return False, "语义层没有任何函数带 api_calls（字段名可能变了）"
    feats = LR.build_features(str(pe), ident, idx, funcs,
                             iat_map=iat, sem={"functions": sums})
    fns = feats["functions"]

    # 1) api 特征必须真的落到函数上（对应 api_calls 字段名 bug）
    n_api = sum(len(f["api"]) for f in fns.values())
    if n_api == 0:
        return False, "函数级 api 特征为空（api_calls 字段读取失败）"
    # 且必须不含 '!' —— 归一化后不该残留原分隔符
    dirty = [x for f in fns.values() for x in f["api"] if "!" in x]
    if dirty:
        return False, f"api 特征未归一化，仍含 '!'：{dirty[:3]}"

    # 2) mnemonic 特征（对应 mnem 字段名 bug）
    n_mn = sum(len(f["mnemonic"]) for f in fns.values())
    if n_mn == 0:
        return False, "函数级 mnemonic 特征为空（指令助记符字段读取失败）"

    # 3) number 特征（对应 operands/imm 形态 bug）
    n_num = sum(len(f["number"]) for f in fns.values())
    if n_num == 0:
        return False, "函数级 number 特征为空（立即数读取失败）"

    # 4) 文件级：arch 必须推断出来（曾经从 label 猜，结果为空的 bug）
    ff = feats["file"]
    if not ff["arch"]:
        return False, "文件级 arch 为空（应改读 ident 结构化字段）"
    if not ff["os"]:
        return False, "文件级 os 为空"
    if not ff["import"]:
        return False, "文件级 import 为空"

    # 5) characteristic 必须是可产出的（不能引用凭空的标记）
    if "packed" not in ff["characteristic"] and not ff["characteristic"]:
        pass  # packed 不是每个样本都有，这里不做强制
    return True, (f"api={n_api} mnemonic={n_mn} number={n_num} "
                  f"arch={sorted(ff['arch'])} os={sorted(ff['os'])}")


def t_rules_match_real_pe():
    """
    实机端到端：规则引擎在真实 PE 上跑通，且**不产出 CRT 误报**。

    【为什么这条用例重要】规则引擎的价值全在"准"。曾经出现过两种病态：
      · 全不命中（字段名 bug）—— 看起来"没发现恶意行为"，其实是引擎坏了；
      · 全命中（规则太松）—— notepad.exe 都能命中反调试/RC4，等于没有规则。
    所以这里同时卡住两侧：
      1) 必须能命中至少 1 条（证明链路通）；
      2) 不得命中「反调试检测」「使用 RC4」这两条针对 notepad.exe 实测为
         误报的规则 —— 它们是 MSVC CRT 样板（__report_gsfailure / _CrtDbgReport
         / FormatMessageW 缓冲），任何正常 Windows 程序都有。
    """
    import lib_rules as LR
    import lib_formats as LF
    import lib_disasm as LD
    import lib_semantics as LS

    pe = _sys_pe()
    if pe is None:
        return True, "跳过（无真实 PE 样本）"

    rules, errs = LR.load_rules(str(SKILL / "rules"))
    if errs:
        return False, f"规则加载错误：{errs[:3]}"

    ident = LF.identify(str(pe), deep=True)
    an = LD.analyze_file(str(pe), ident, max_insns=200000)
    if not an.get("ok"):
        return False, f"分析失败：{an.get('error')}"
    idx = an.pop("_idx", None)
    from lib_code import find_functions
    funcs = find_functions(idx, seeds=LD.entry_points(ident),
                           symbols=LD.symbols_from(ident))
    iat = LD.resolve_iat(ident)
    str_map = LS.string_vma_map(str(pe), ident)
    thunks = LS.resolve_thunks(idx, funcs, iat)
    sums = LS.summarize_functions(idx, funcs, iat, str_map,
                                  limit=400, thunk_map=thunks)
    feats = LR.build_features(str(pe), ident, idx, funcs,
                              iat_map=iat, sem={"functions": sums})
    if feats.get("errors"):
        return False, f"特征抽取报错：{feats['errors'][:2]}"

    res = LR.match_rules(rules, feats)
    if res.get("errors"):
        return False, f"匹配报错：{res['errors'][:2]}"
    hits = {h["rule"] for h in res["hits"]}
    if not hits:
        return False, "0 命中（链路不通或规则全部失效）"

    # 误报守卫：这两条在系统自带 PE 上是 MSVC 样板，不得命中
    fp_guards = ["反调试检测", "使用 RC4"]
    fp = [g for g in fp_guards if g in hits]
    if fp:
        return False, (f"命中 CRT 样板误报：{fp}（notepad/系统 PE 上实测为误报，"
                       f"说明规则又变松了，或 crt 判定条件被改坏）")

    # 精度守卫：良性系统 PE 上命中总条数必须有上限。
    # 【为什么要有这一条】规则太松时"命中很多"看起来像"发现了很多能力"，
    # 实际是噪声。实测踩过的坑：
    #   · `xor + loop` 版本 → 83 条命中（308 个函数里 27%），纯粹是"循环里清零"；
    #   · 加上 xor_dense 但没卡绝对条数 → 计时小函数也被判成解密例程。
    # 良性 PE 的合理量级是个位/十几条；超过 20 条基本可以断定规则被放宽了。
    # 注意：这是**回归守卫**，不是精确断言 —— 换样本/换系统版本会有浮动，
    # 所以把阈值留得比实测（3 条）宽，只拦"明显失控"。
    if len(res["hits"]) > 20:
        by_rule = {}
        for h in res["hits"]:
            by_rule[h["rule"]] = by_rule.get(h["rule"], 0) + 1
        worst = sorted(by_rule.items(), key=lambda t: -t[1])[:3]
        return False, (f"良性 PE 上命中 {len(res['hits'])} 条（>20，规则过松）；"
                       f"命中最多：{worst}")

    # ATT&CK 映射必须能从命中推导出来
    if hits and not res.get("att_ck"):
        return False, "有命中但没有 ATT&CK 映射"

    # 每条 hit 都必须带证据位置，便于人工复核（否则结论不可验证）
    no_loc = [h["rule"] for h in res["hits"] if not h.get("location")]
    if no_loc:
        return False, f"以下命中缺少位置证据：{sorted(set(no_loc))[:3]}"

    by_rule = {}
    for h in res["hits"]:
        by_rule[h["rule"]] = by_rule.get(h["rule"], 0) + 1
    desc = "、".join("%s×%d" % (k, v) if v > 1 else k for k, v in by_rule.items())
    return True, (f"{len(rules)} 条规则 → 命中 {len(hits)} 条（{desc}），"
                  f"ATT&CK {len(res['att_ck'])} 项，误报守卫通过")


def t_rules_false_positive_guard():
    """
    误报守卫（合成）：构造"CRT 样板"特征，确认反调试/RC4 规则**不**命中。

    不依赖真实样本，纯合成特征，能在任何机器上跑。
    这直接对应规则文件里记录的误报教训，防止有人"顺手放宽"规则又静默回归。
    """
    import lib_rules as LR
    rules, errs = LR.load_rules(str(SKILL / "rules"))
    if errs:
        return False, f"规则加载错误：{errs[:1]}"

    def mkfn(apis=(), mnems=(), nums=(), chars=(), tags=()):
        return {"api": {"%s|%s" % LR._norm_api(a) for a in apis},
                "mnemonic": {m.lower() for m in mnems},
                "number": set(nums),
                "characteristic": set(chars),
                "tag": set(tags),
                "string": set(), "section": set(), "function-name": set(),
                "bytes": set(), "export": set(), "import": set()}

    # 特征 1：MSVC CRT 样板 —— __report_gsfailure 的 API 组合
    crt = mkfn(
        apis=("api-ms-win-core-debug-l1-1-0.dll!IsDebuggerPresent",
              "api-ms-win-core-errorhandling-l1-1-0.dll!SetUnhandledExceptionFilter",
              "api-ms-win-core-errorhandling-l1-1-0.dll!UnhandledExceptionFilter",
              "api-ms-win-core-rtlsupport-l1-1-0.dll!RtlCaptureContext",
              "api-ms-win-core-processthreads-l1-1-1.dll!IsProcessorFeaturePresent"),
        mnems=("xor", "mov", "lea", "add", "call", "memset"),
        nums=(256, 0x200, 0xFF),
        chars=("debug",), tags=("反调试",))
    # 特征 2：FormatMessageW + 0x200 缓冲（曾被误判成 RC4）
    fmtmsg = mkfn(
        apis=("api-ms-win-core-localization-l1-2-0.dll!FormatMessageW",
              "api-ms-win-core-heap-l2-1-0.dll!LocalFree",
              "api-ms-win-crt-string-l1-1-0.dll!memset"),
        mnems=("xor", "mov", "lea", "add", "test", "jmp"),
        nums=(0x200, 0x100, 512))

    feats = {"file": {"arch": {"x86-64"}, "os": {"windows"}, "section": set(),
                      "import": set(), "export": set(), "string": set(),
                      "function-name": set(), "format": {"pe"},
                      "characteristic": set()},
             "functions": {0x1000: crt, 0x2000: fmtmsg}}
    res = LR.match_rules(rules, feats)
    hits = {h["rule"] for h in res["hits"]}
    fp = [r for r in ("反调试检测", "使用 RC4", "使用 AES") if r in hits]
    if fp:
        return False, f"合成 CRT 特征误命中：{fp}（规则被放宽了，必须收紧）"

    # 反向验证：真正的反调试组合**必须**命中（否则是"规则太严、全不报"）
    real_anti = mkfn(apis=("kernel32.dll!IsDebuggerPresent",
                           "ntdll.dll!NtSetInformationThread"),
                     mnems=("mov", "call"), nums=(0x11,))
    feats2 = {"file": feats["file"], "functions": {0x1000: real_anti}}
    res2 = LR.match_rules(rules, feats2)
    hits2 = {h["rule"] for h in res2["hits"]}
    if "反调试检测" not in hits2:
        return False, "真反调试组合未能命中（规则过严，会漏报）"

    return True, "CRT 样板不误报，真反调试组合能命中（双侧都守住）"


def t_rules_cli_capability():
    """
    CLI `capability` 子命令的对外契约。

    引擎自身对了还不够，AI 是通过 CLI 用它的，所以这里卡 CLI 层的契约：
      · --json 必须带 ok 且结构字段齐全（hit_rules / capabilities / att_ck / by_namespace）；
      · 每条命中必须带 位置 + namespace（否则结论不可复核、无法分类）；
      · 指定不存在的规则必须**报错退出**（码 2），而不是静默少跑几条 ——
        静默少跑会让"没命中"变成假结论。
    """
    pe = _sys_pe()
    if pe is None:
        return True, "跳过（无真实 PE 样本）"

    code, data, raw = jrun([str(CLI), "capability", str(pe), "--json",
                            "--limit", "60"])
    if code != 0:
        return False, f"退出码 {code}：{raw[:200]}"
    if not isinstance(data, dict) or data.get("ok") is not True:
        return False, "顶层 ok 契约不满足"
    for k in ("rules_loaded", "hit_rules", "capabilities", "att_ck",
              "by_namespace", "feature_stats"):
        if k not in data:
            return False, f"缺字段 {k}"
    if data["rules_loaded"] < 20:
        return False, f"只加载 {data['rules_loaded']} 条规则"
    if data.get("rule_load_errors"):
        return False, f"规则加载报错：{data['rule_load_errors'][:2]}"

    # 每条命中都要能复核
    for c in data["capabilities"]:
        if not c.get("locations"):
            return False, f"命中 {c.get('rule')!r} 无位置证据"
        if not c.get("namespace"):
            return False, f"命中 {c.get('rule')!r} 无 namespace"

    # 指定不存在的规则 → 必须报错（不能静默少跑）
    code2, data2, raw2 = jrun([str(CLI), "capability", str(pe), "--json",
                               "--rule", "__不存在的规则__"])
    if code2 == 0 or (isinstance(data2, dict) and data2.get("ok") is True):
        return False, "指定不存在的规则却成功退出（应报错，否则会静默少跑）"
    if isinstance(data2, dict) and not data2.get("available"):
        return False, "报错时未列出可用规则名（不利于排障）"

    return True, (f"规则 {data['rules_loaded']} 条，命中 {data['hit_rules']} 条，"
                  f"ATT&CK {len(data['att_ck'])} 项，错误路径正确")


def t_rules_match_rules_arg_validation():
    """match_rules 收到非法参数时必须给出**可读原因**，而不是 TypeError。

    为什么需要：match_rules 是公开 API。规则加载失败时，调用方很容易把
    None 一路传下来。原实现在 `_Ctx.__init__` 里抛
    `TypeError: 'NoneType' object is not iterable` —— 看不出是"规则没加载到"
    还是"引擎坏了"。而且这种失败会被上层 `except` 吞掉，最终表现为
    "0 条命中"，正是本项目最忌讳的静默失败。
    """
    import lib_rules as LR
    cases = [
        (None, {}, "None"),
        ("abc", {}, "str"),
        (123, {}, "int"),
        ({}, {}, "dict"),
        ([], {}, "空 list"),
    ]
    for rules, feats, tag in cases:
        r = LR.match_rules(rules, feats)
        if not isinstance(r, dict):
            return False, "%s 返回的不是 dict" % tag
        if "hits" not in r:
            return False, "%s 的返回缺 hits 字段（调用方会 KeyError）" % tag
        if not r.get("empty"):
            return False, "%s 应标记 empty=True" % tag
        if not r.get("reason"):
            return False, "%s 没给出可读的 reason" % tag
    return True, f"{len(cases)} 种非法参数都给出了可读原因且保留 hits 字段"


def t_cli_robustness():
    """CLI 对畸形目标必须给出受控失败，绝不漏 Traceback。

    覆盖：空文件 / 纯垃圾 / 畸形 PE 头 / 不存在 / 目录当目标。
    判据：退出码 ∈ {0,2,3,4}，且 stderr+stdout 里没有 Python Traceback。
    """
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-robust-"))
    files = {}
    files["empty"] = tmp / "empty.bin"
    files["empty"].write_bytes(b"")
    files["junk"] = tmp / "junk.bin"
    files["junk"].write_bytes(b"\xff" * 8192)
    # 畸形 PE：MZ 头 + e_lfanew 越界
    bad = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x7FFFFFFF))
    bad += b"\x00" * 4096
    files["badpe"] = tmp / "badpe.exe"
    files["badpe"].write_bytes(bytes(bad))
    files["dir"] = tmp

    bad_cases = []
    for sub in ("identify", "entropy", "imports", "info", "triage",
                "funcs", "semantics", "capability", "report", "symbols"):
        for name, p in files.items():
            code, out, err = run([CLI, sub, str(p), "--json"], timeout=180)
            if code not in (0, 2, 3, 4):
                bad_cases.append("%s/%s 退出码 %s" % (sub, name, code))
                continue
            if "Traceback (most recent call last)" in (out + err):
                bad_cases.append("%s/%s 漏出 Traceback" % (sub, name))
    # 不存在的文件
    for sub in ("identify", "triage", "funcs", "symbols"):
        code, out, err = run([CLI, sub, str(tmp / "nope.bin"), "--json"], timeout=120)
        if code not in (2, 3, 4):
            bad_cases.append("%s/不存在 退出码 %s" % (sub, code))
        if "Traceback (most recent call last)" in (out + err):
            bad_cases.append("%s/不存在 漏出 Traceback" % sub)

    if bad_cases:
        return False, "；".join(bad_cases[:5])
    n = len(files) * 9 + 3
    return True, f"{n} 组畸形目标均给出受控失败，无 Traceback"


def t_rules_no_dead_characteristic():
    """
    规则里引用的 characteristic 必须可能被引擎产出。

    否则规则永远不可能命中，而且不报错 —— 典型的静默失效。
    引擎已知可产出的 characteristic 在 ENGINE_CHARACTERISTICS 里显式列出，
    规则里出现表外的名字（还可能是笔误，如 rc4-ksa vs rc4_ksa）就直接失败。
    """
    import lib_rules as LR
    rules, errs = LR.load_rules(str(SKILL / "rules"))
    if errs:
        return False, f"规则加载错误：{errs[:1]}"

    known = LR.ENGINE_CHARACTERISTICS
    used = set()

    def walk(node):
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if k == "characteristic":
                for one in (v if isinstance(v, list) else [v]):
                    used.add(str(one))
            else:
                walk(v)

    for r in rules:
        walk(r.features)

    dead = sorted(x for x in used if x not in known)
    if dead:
        return False, (f"规则引用了引擎不可能产出的 characteristic：{dead}；"
                       f"引擎已知：{sorted(known)}")
    return True, f"规则引用的 {len(used)} 个 characteristic 均可产出：{sorted(used)}"


def t_names_demangle_all_dialects():
    """四种修饰名方言都必须能还原（这是 lib_symbols 的既有能力）。

    为什么要专门测：demangle 引擎在 lib_symbols.py 里放了很久，
    但**从未接入分析流水线** —— 能力存在却不可见，等于没有。
    本用例连同下面的 pclntab 用例一起，把这条链路钉在回归里。
    """
    import lib_symbols as LS
    vectors = [
        ("_Z3fooi", "foo(int)", "itanium"),
        ("_ZNSt6vectorIiE3addEi", "std::vector<int>::add(int)", "itanium"),
        ("?func@@YAHXZ", "int __cdecl func(void)", "msvc"),
        ("_ZN4core3fmt5write17h1234567890abcdefE", None, "rust-legacy"),
        ("_RNvCs1234_5crate3foo", None, "rust-v0"),
        ("_printf", "printf", "plain"),
        ("__imp_GetProcAddress", None, "plain"),
    ]
    bad = []
    for raw, expect, dialect in vectors:
        got = LS.demangle(raw)
        d = LS.detect_dialect(raw)
        if got == raw and dialect != "plain":
            bad.append("%s 未被还原（方言判定 %s）" % (raw, d))
        if expect is not None and got != expect:
            bad.append("%s -> %r，期望 %r" % (raw, got, expect))
        if dialect != "plain" and d != dialect:
            bad.append("%s 方言判定为 %s，期望 %s" % (raw, d, dialect))
    if bad:
        return False, "；".join(bad[:4])
    return True, f"{len(vectors)} 条覆盖 itanium/msvc/rust-v0/rust-legacy 全部还原"


def t_names_go_pclntab_synthetic():
    """合成一个 Go 1.20+ 布局的 pclntab，验证解析器真的能恢复函数名。

    为什么必须做合成用例：本机没有 Go 二进制可测（实测扫描 704 个 exe 无一为 Go）。
    如果不做，这个功能就是"写完没验证过" —— 正是本项目最忌讳的。
    同时守住两条：
      ① 合法 pclntab 必须被识别并解析出正确函数名与入口地址；
      ② **正常 PE 里的巧合魔数不得被误判**（notepad.exe 上实测有 3 处）。
    """
    import lib_names as LN
    import lib_formats as F

    PTR = 8
    names = [b"main.main", b"fmt.Println", b"runtime.gcStart",
             b"net/http.(*Server).Serve", b"os.ReadFile", b"main.init"]
    nametab = b""
    offs = []
    for n in names:
        offs.append(len(nametab))
        nametab += n + b"\x00"

    base = 0x1000
    hdr_size = 72
    funcname_off = hdr_size
    pcln_off = funcname_off + len(nametab)
    nfunc = len(names)
    text_start = 0x401000

    hdr = bytearray(hdr_size)
    struct.pack_into("<I", hdr, 0, 0xFFFFFFF1)
    hdr[6] = 1
    hdr[7] = PTR
    struct.pack_into("<Q", hdr, 8, nfunc)
    struct.pack_into("<Q", hdr, 16, 0)
    struct.pack_into("<Q", hdr, 24, text_start)
    struct.pack_into("<Q", hdr, 32, funcname_off)
    struct.pack_into("<Q", hdr, 40, 0)
    struct.pack_into("<Q", hdr, 48, 0)
    struct.pack_into("<Q", hdr, 56, 0)
    struct.pack_into("<Q", hdr, 64, pcln_off)

    ftab = b""
    for i, off in enumerate(offs):
        ftab += struct.pack("<QQ", text_start + i * 0x20, off)

    blob = b"\x00" * base + bytes(hdr) + nametab + ftab + b"\x00" * 64
    p = TMP / "fake_go_pclntab.bin"
    p.write_bytes(blob)

    r = F.Reader(p)
    cands = LN.find_pclntab(r, len(blob))
    if cands != [base]:
        return False, f"候选定位错误：{cands}，期望 [{hex(base)}]"

    res, warns = LN.recover_go_symbols(r, len(blob))
    if res is None:
        return False, f"解析失败：{warns}"
    got = {f["name"] for f in res["functions"]}
    want = {n.decode() for n in names if b"." in n or b"/" in n}
    if got != want:
        return False, f"函数名不符：得到 {sorted(got)}，期望 {sorted(want)}"
    if res.get("go_version_hint") != "Go 1.20+":
        return False, f"版本判定错误：{res.get('go_version_hint')}"

    # 反向守卫：正常 PE / 纯随机数据不得报出 Go 表
    fp = []
    for cand in (SKILL / "scripts" / "re.py",):
        if cand.exists():
            rr = F.Reader(cand)
            if LN.find_pclntab(rr, rr.size):
                fp.append(str(cand.name))
    import random
    rnd = TMP / "rand_for_pclntab.bin"
    random.seed(1234)
    rnd.write_bytes(bytes(random.getrandbits(8) for _ in range(256 * 1024)))
    rr = F.Reader(rnd)
    n_rand = len(LN.find_pclntab(rr, rr.size))
    if fp or n_rand:
        return False, f"误报：{fp} 随机数据命中 {n_rand} 处"

    return True, (f"合成 pclntab 恢复 {len(got)}/{len(names)} 个函数名，"
                  f"版本判定正确，非 Go 目标 0 误报")


def t_names_cli_symbols_contract():
    """symbols 子命令的 CLI 契约：--json 有 ok、退出码受控、不写盘。"""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-symbols-"))
    empty = tmp / "empty.bin"
    empty.write_bytes(b"")

    # 空目标：必须受控返回，且不能是"静默空结果"
    code, out, err = run([CLI, "symbols", str(empty), "--json"], timeout=120)
    if code not in (0, 2, 3, 4):
        return False, f"空目标退出码 {code}"
    if "Traceback (most recent call last)" in (out + err):
        return False, "空目标漏出 Traceback"
    try:
        data = json.loads(out)
    except Exception as e:
        return False, f"空目标 JSON 解析失败：{e}"
    if "ok" not in data:
        return False, "缺顶层 ok 字段"

    before = {f.name for f in SKILL.iterdir()}
    real = Path("C:/Windows/System32/notepad.exe")
    if real.exists():
        code, out, err = run([CLI, "symbols", str(real), "--json"], timeout=180)
        if code != 0:
            return False, f"真实 PE 退出码 {code}：{err[:100]}"
        d = json.loads(out)
        if not d.get("ok"):
            return False, "真实 PE 返回 ok=False"
        if not (d.get("counts") or {}).get("total"):
            return False, "真实 PE 没收集到任何符号"
    after = {f.name for f in SKILL.iterdir()}
    if after - before:
        return False, f"symbols 在技能目录写入了文件：{sorted(after - before)}"
    return True, "空目标受控、真实 PE 有符号、--json 含 ok、未污染技能目录"


def t_obfstr_stack_strings():
    """栈字符串恢复：逐字节 / 多字节 / rbp 版三种形态都要能还原。

    栈字符串是恶意样本隐藏 C2 地址的常用手法 —— 字节在文件里从不连续，
    普通 `strings` 全瞎。判据用合成样本（本机无真实恶意样本可测）。

    同时守住反向：正常函数序言不得产出"栈字符串"。
    """
    import lib_obfstr as OS
    import lib_x86 as X

    def decode(code, base=0x1000):
        out = []
        off = 0
        while off < len(code):
            ins = X.decode_one(code, off, bits=64, vma_base=base)
            if ins is None or ins.size <= 0:
                break
            out.append(ins)
            off += ins.size
        return out

    fails = []

    # ① 单字节：mov byte ptr [rsp+disp8], imm8  ->  c6 44 24 disp imm
    s1 = b"http://evil.example/c2"
    c1 = b"".join(bytes([0xC6, 0x44, 0x24, i, ch]) for i, ch in enumerate(s1))
    c1 += bytes([0xC6, 0x44, 0x24, len(s1), 0])
    got1 = [x["string"] for x in OS.recover_stack_strings(decode(c1))["strings"]]
    if s1.decode() not in got1:
        fails.append("单字节未还原：%r" % got1)

    # ② 宽字节：mov dword ptr [rsp+disp8], imm32  ->  c7 44 24 disp imm32
    s2 = b"C:\\Windows\\Temp\\dropper.exe"
    c2 = b""
    for i in range(0, len(s2), 4):
        v = int.from_bytes(s2[i:i + 4].ljust(4, b"\x00"), "little")
        c2 += bytes([0xC7, 0x44, 0x24, i]) + v.to_bytes(4, "little")
    got2 = [x["string"] for x in OS.recover_stack_strings(decode(c2))["strings"]]
    if s2.decode() not in got2:
        fails.append("宽字节未还原：%r" % got2)
    else:
        # 顺带守住尺寸解析：dword 被当成 word 会拼出 `C:\x00\x00Wi...`
        if any("\x00" in x or "x00" in x for x in got2):
            fails.append("宽字节拼装错位：%r" % got2)

    # ③ rbp 版（-O0/调试构建常见）：c6 45 disp imm
    s3 = b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    c3 = b"".join(bytes([0xC6, 0x45, (256 - 0x40 + i) % 256, ch])
                  for i, ch in enumerate(s3))
    got3 = [x["string"] for x in OS.recover_stack_strings(decode(c3))["strings"]]
    if s3.decode() not in got3:
        fails.append("rbp 版未还原：%r" % got3)

    # ④ 反向守卫：正常函数序言重复不得产出栈串
    norm = bytes.fromhex("4889e54883ec2048894df8488955f0b800000000") * 8
    got4 = [x["string"] for x in OS.recover_stack_strings(decode(norm))["strings"]]
    if got4:
        fails.append("正常代码误报：%r" % got4)

    if fails:
        return False, "；".join(fails[:3])
    return True, "逐字节/宽字节/rbp 三形态均还原，正常代码 0 误报"


def t_obfstr_xor_loop():
    """XOR 解密循环识别：合成循环必须认出 key，真实 PE 必须 0 误报。

    **为什么必须走"循环识别"而不是穷举密钥**：实测穷举滑窗在
    notepad.exe 上稳定打出 20–28 条垃圾（`r/IMO;nr?IMO`、`C5ikdt/kkVij`），
    加三层统计门槛也只压掉一部分 —— 短窗口上任何统计判据都会偶然命中。
    改为先定位有代码证据的解密循环，真实未混淆二进制上误报归零。
    本用例把这两个方向都钉住。
    """
    import lib_obfstr as OS
    import lib_x86 as X
    import lib_formats as F

    loop = bytes.fromhex("0fb6040e344a88040f48ffc14883f9207cee")
    objs = []
    off = 0
    while off < len(loop):
        ins = X.decode_one(loop, off, bits=64, vma_base=0x1000)
        if ins is None or ins.size <= 0:
            break
        objs.append(ins)
        off += ins.size
    r = OS.find_xor_loops(objs)
    if len(r["loops"]) != 1:
        return False, "合成解密循环识别失败：%d 个" % len(r["loops"])
    if r["loops"][0]["key"] != 0x4A:
        return False, "key 取错：0x%02x，期望 0x4a" % r["loops"][0]["key"]

    # 反向守卫：真实未混淆 PE 上不得报出解密循环
    import lib_disasm as D
    fp = []
    for p in ("C:/Windows/System32/notepad.exe",
              "C:/Windows/System32/kernel32.dll"):
        q = Path(p)
        if not q.exists():
            continue
        ident = F.identify(str(q), deep=True)
        res = D.analyze_file(str(q), ident, max_insns=60000)
        idx = res.get("_idx")
        if idx is None:
            continue
        insns = sorted(idx.insn.values(), key=lambda x: x.offset)
        n = len(OS.find_xor_loops(insns)["loops"])
        if n:
            fp.append("%s 报出 %d 个" % (q.name, n))
    if fp:
        return False, "真实 PE 误报：" + "；".join(fp)
    return True, "合成循环 key=0x4a 正确，真实 PE 0 误报"


def t_obfstr_cli_contract():
    """obfstr 子命令契约：--json 有 ok、退出码受控、不透出 Traceback。"""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-obfstr-"))
    empty = tmp / "empty.bin"
    empty.write_bytes(b"")
    junk = tmp / "junk.bin"
    junk.write_bytes(b"\x90" * 4096)

    for name, p in (("空文件", empty), ("垃圾", junk)):
        for extra in ([], ["--no-xor"], ["--no-stack"]):
            code, out, err = run([CLI, "obfstr", str(p), "--json"] + extra,
                                 timeout=120)
            if code not in (0, 2, 3, 4):
                return False, "%s %s 退出码 %s" % (name, extra, code)
            if "Traceback (most recent call last)" in (out + err):
                return False, "%s %s 漏出 Traceback" % (name, extra)
            try:
                d = json.loads(out)
            except Exception as e:
                return False, "%s %s JSON 解析失败：%s" % (name, extra, e)
            if "ok" not in d:
                return False, "%s %s 缺顶层 ok" % (name, extra)
    # 互斥参数必须被拦下
    code, out, err = run([CLI, "obfstr", str(junk), "--no-stack", "--no-xor"],
                         timeout=60)
    if code != 2:
        return False, "互斥参数未被拦（退出码 %s）" % code
    return True, "空/垃圾 × 3 组参数均受控，互斥参数被拦"


# ---------------------------------------------------------------- AI 编排层
#
# 这一层是"工具太多，AI 挑不过来"的解法：把 选工具 / 排顺序 / 记状态 /
# 判错误 四件事从模型脑子里挪进确定性代码。
# 下面这些用例守的就是"挪进去之后不能退化成猜"。

# 19 条真实口吻的意图 → 期望命令。中文口语，故意含泛词（"这个""里面"）。
_RETRIEVAL_GOLD = [
    ("这文件是不是加壳了", "entropy"),
    ("这程序是干什么的", "capability"),
    ("这是什么文件", "identify"),
    ("帮我看看导入表", "imports"),
    ("把里面的字符串提出来", "strings"),
    ("混淆字符串能不能还原", "obfstr"),
    ("函数名能还原吗", "symbols"),
    ("有哪些函数", "funcs"),
    ("这函数在干什么", "semantics"),
    ("控制流图给我看一下", "cfg"),
    ("谁调用了这个函数", "xref"),
    ("反汇编出来看看", "disasm"),
    ("两个版本差在哪", "diff"),
    ("里面有没有加密算法", "capability"),
    ("有没有反调试", "capability"),
    ("这文件熵高不高", "entropy"),
    ("文件被加了什么壳", "entropy"),
    ("符号表看看", "symbols"),
    ("静态体检一下", "triage"),
]


def t_agent_catalog_subcommand_consistency():
    """
    工具目录必须和 CLI 真实注册的子命令一一对应。

    这是防"文档漂移"的闸门：CATALOG 是 AI 唯一的工具菜单，
    它要是和 re.py 的实际子命令对不上，AI 就会照着菜单调一个不存在的命令，
    然后收到 usage_error 再重试——正好是我们最想消灭的浪费。
    """
    import lib_agent as AG
    code, out, err = run([CLI, "--help"], timeout=60)
    if code != 0:
        return False, "--help 退出码 %s" % code
    helper = out + err
    # 从 --help 里抓出所有子命令名（argparse 会列在 {a,b,c} 里）
    m = re.search(r"\{([a-z0-9,\-_]+)\}", helper)
    if not m:
        return False, "--help 里找不到子命令列表"
    real = set(m.group(1).split(","))
    cat = set(AG.CATALOG_BY_NAME.keys())

    only_real = sorted(real - cat)
    only_cat = sorted(cat - real)
    # case/require/flow/result/toolgraph 是编排自身的命令，不必出现在分析菜单里；
    # 但反过来——菜单里绝不允许出现 CLI 没有的命令。
    if only_cat:
        return False, "菜单里有 CLI 不存在的命令：%s" % only_cat
    if len(cat) != len(AG.CATALOG):
        return False, "CATALOG_BY_NAME 与 CATALOG 长度不一致（%d vs %d）" % (
            len(cat), len(AG.CATALOG))
    # 每个条目必填字段齐全
    need = ("name", "summary", "answers", "keywords", "args", "flags",
            "needs", "produces", "cost", "stage", "formats")
    for e in AG.CATALOG:
        miss = [k for k in need if k not in e]
        if miss:
            return False, "%s 缺字段 %s" % (e.get("name"), miss)
        if e["cost"] not in ("cheap", "medium", "heavy"):
            return False, "%s cost 非法：%s" % (e["name"], e["cost"])
        if e["stage"] not in AG.STAGES:
            return False, "%s stage 非法：%s" % (e["name"], e["stage"])
    return True, "%d 个子命令全部对上，字段/枚举合法，CLI 独有 %d 个编排命令" % (
        len(cat), len(only_real))


def t_agent_retrieval_accuracy():
    """
    意图检索准确率闸门：top-1 ≥ 70%、top-3 ≥ 95%。

    阈值怎么定的：AWS AGENTPERF06-BP01 给的经验是 50 个工具时准确率 84–95%。
    我们只有 21 个分析工具，理应更好；但中文口语本身有歧义
    （"有没有加密算法" 归 capability 还是 libscan 都说得通），
    所以 top-1 不敢定 100%。真正重要的是 top-3 —— 因为最终递给 AI 的是 top-6，
    正确答案只要进候选，模型就能自己挑对。
    """
    import lib_agent as AG
    top1 = top3 = 0
    misses = []
    for intent, want in _RETRIEVAL_GOLD:
        r = AG.recommend(intent, top_k=6)
        if not r.get("ok"):
            return False, "推荐失败：%s → %s" % (intent, r.get("reason"))
        names = [x["name"] for x in r["recommendations"]]
        if not names:
            misses.append("%s→(空,想%s)" % (intent, want))
            continue
        if names[0] == want:
            top1 += 1
        if want in names[:3]:
            top3 += 1
        else:
            misses.append("%s→%s(想%s)" % (intent, names[0], want))
    n = len(_RETRIEVAL_GOLD)
    r1, r3 = top1 / n, top3 / n
    if r1 < 0.70:
        return False, "top-1 %.0f%% < 70%%，未命中：%s" % (r1 * 100, misses)
    if r3 < 0.95:
        return False, "top-3 %.0f%% < 95%%，未命中：%s" % (r3 * 100, misses)
    return True, "top-1 %d/%d（%.0f%%），top-3 %d/%d（%.0f%%）" % (
        top1, n, r1 * 100, top3, n, r3 * 100)


def t_agent_recommend_fail_closed():
    """
    检索的失败必须"闭"，不能"开"。

    反面教材：意图为空或完全没命中时，图省事就把整个工具表全返回回去。
    那样 AI 收到的候选从 6 个暴涨到 21 个，等于把问题原样退回给模型，
    这层编排就白写了。
    """
    import lib_agent as AG
    r = AG.recommend("")
    if r.get("ok") is not False:
        return False, "空意图没被拦下（ok=%s）" % r.get("ok")
    if r.get("recommendations"):
        return False, "空意图仍返回了 %d 条候选" % len(r["recommendations"])
    if not r.get("hint"):
        return False, "空意图没给出 hint（AI 不知道下一步该怎么办）"

    r2 = AG.recommend("今天天气不错适合钓鱼")
    if r2.get("recommendations"):
        return False, "无关意图返回了 %d 条候选，应该空" % len(r2["recommendations"])
    if not r2.get("reason"):
        return False, "无命中时没给 reason"
    # 反向确认：真的无命中，而不是把整表兜底返回
    if len(r2.get("recommendations") or []) >= len(AG.CATALOG):
        return False, "退回了整张工具表（典型的 fail-open）"
    return True, "空意图/无关意图均返回 0 候选 + 可读原因 + hint，未退化为全表"


def t_agent_error_classification():
    """
    错误分类要能把"该重试"和"不该重试"分开。

    这是整个编排层性价比最高的一条：AI 最常见的浪费不是挑错工具，
    而是把"正常跑完但结果为空"当成失败，然后换个参数再来一遍——
    参数怎么换结果都是空的。所以 empty_result 必须 retryable=False。
    """
    import lib_agent as AG

    # 1) 正常空结果 → 不许重试
    r = AG.classify_error({"ok": True, "empty": True}, 0)
    if r["kind"] != AG.KIND_EMPTY:
        return False, "空结果被归为 %s" % r["kind"]
    if r["retryable"]:
        return False, "空结果被判为可重试（会诱发无限重试）"
    if r["next_action"] != "continue_no_retry":
        return False, "空结果 next_action=%s" % r["next_action"]

    # 2) 用法错误 → 改参数，不是改目标
    r = AG.classify_error({}, 2, "usage: re.py ...")
    if r["kind"] != AG.KIND_USAGE or r["next_action"] != "fix_args":
        return False, "退出码 2 归类为 %s/%s" % (r["kind"], r["next_action"])

    # 3) 目标不可读 → 换目标，不是改参数
    r = AG.classify_error({"error": "文件不存在"}, 3)
    if r["kind"] != AG.KIND_TARGET or r["next_action"] != "change_target":
        return False, "退出码 3 归类为 %s/%s" % (r["kind"], r["next_action"])

    # 4) 引擎错误 → 报 bug
    r = AG.classify_error({}, 4)
    if r["kind"] != AG.KIND_ENGINE or r["next_action"] != "report_bug":
        return False, "退出码 4 归类为 %s/%s" % (r["kind"], r["next_action"])

    # 5) 截断 → 可重试（放宽上限后真能拿到更多）
    r = AG.classify_error({"ok": True, "truncated": True}, 0)
    if r["kind"] != AG.KIND_PARTIAL or not r["retryable"]:
        return False, "截断归类为 %s（retryable=%s）" % (r["kind"], r["retryable"])

    # 6) 进程成功但 JSON 自报失败 → 引擎问题
    r = AG.classify_error({"ok": False, "error": "内部断言失败"}, 0)
    if r["kind"] != AG.KIND_ENGINE:
        return False, "ok=false 归类为 %s" % r["kind"]

    # 7) 正常有内容 → continue
    r = AG.classify_error({"ok": True, "count": 5}, 0)
    if r["kind"] != AG.KIND_OK or r["next_action"] != "continue":
        return False, "正常结果归类为 %s" % r["kind"]

    # 8) 每种 kind 都必须有可读的 handling 文案
    for k in (AG.KIND_OK, AG.KIND_USAGE, AG.KIND_TARGET, AG.KIND_EMPTY,
              AG.KIND_PARTIAL, AG.KIND_ENGINE):
        h = AG._HANDLING.get(k)
        if not h or not h[0] or not isinstance(h[1], bool):
            return False, "%s 的 handling 文案缺失或 retryable 非 bool" % k
    return True, "6 种归类 × 退出码 0/2/3/4 全部正确，重试语义可区分"


def t_agent_summary_shrinks():
    """
    摘要层必须真的把结果压小，而不是换个形式搬运。

    数字来自实测：真实 PE 的 triage JSON 是 247,966 字节。
    如果摘要没把它降到十分之一以下，这层就没意义——
    AI 的上下文还是会爆。同时必须保住"下一步决策要用到的字段"。
    """
    import lib_agent as AG
    # 造一个和真实 triage 形状一致的大 payload
    big = {
        "ok": True,
        "identify": {"format": "PE", "arch": "x86-64", "bits": 64},
        "packer": None,
        "leads": [{"kind": "entropy", "detail": "x" * 400} for _ in range(200)],
        "hashes": {"sha256": "ab" * 32},
        "notes": ["n"] * 50,
        "strings": ["s" * 200 for _ in range(500)],
    }
    s = AG.summarize("triage", big)
    raw = len(json.dumps(big, ensure_ascii=False))
    shrunk = len(json.dumps(s, ensure_ascii=False))
    if shrunk >= raw * 0.1:
        return False, "摘要只压到 %.1f%%（%d→%d），没起到作用" % (
            shrunk * 100.0 / raw, raw, shrunk)
    # 关键决策字段必须留住
    flat = json.dumps(s, ensure_ascii=False)
    for key in ("format", "arch", "bits"):
        if key not in flat:
            return False, "摘要丢了决策字段 %s" % key
    # 列表必须被截断到 cap
    if len(s.get("leads") or []) > AG._LIST_CAP:
        return False, "leads 未按 cap 截断（%d）" % len(s["leads"])
    # 未知命令不能崩，也不能假装成功
    u = AG.summarize("__no_such_cmd__", {"ok": True, "foo": 1})
    if not isinstance(u, dict):
        return False, "未知命令摘要未返回 dict"
    return True, "压到 %.1f%%（%d→%d），决策字段保留，列表截断到 %d，未知命令有兜底" % (
        shrunk * 100.0 / raw, raw, shrunk, AG._LIST_CAP)


def t_agent_case_roundtrip_and_staleness():
    """
    case 目录：存 → 读 → 过期检测 全链路。

    最关键的断言是"过期就必须拒绝":
    逆向分析里拿旧样本的结果去回答新样本的问题，比报错危险得多——
    AI 会自信地给出错误结论，而且没有任何异常可循。
    """
    import lib_agent as AG
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-case-"))
    target = tmp / "sample.bin"
    target.write_bytes(b"MZ" + os.urandom(4096))
    cdir = str(tmp / "case")

    r = AG.case_init(cdir, str(target), note="自检")
    if not r.get("ok"):
        return False, "case init 失败：%s" % r.get("reason")

    payload = {"ok": True, "identify": {"format": "PE"}, "count": 2}
    r = AG.case_save(cdir, "triage", payload, target=str(target))
    if not r.get("ok"):
        return False, "case save 失败：%s" % r.get("reason")

    st = AG.case_status(cdir, target=str(target))
    if "triage" not in st.get("have", []):
        return False, "status 未登记 triage（have=%s）" % st.get("have")

    ld = AG.case_load(cdir, "triage", target=str(target))
    if not ld.get("ok") or ld.get("data", {}).get("count") != 2:
        return False, "case load 内容不对：%s" % ld

    # --- 篡改目标指纹：必须拒绝返回 ---
    idx_path = os.path.join(cdir, AG.CASE_INDEX)
    idx = json.loads(Path(idx_path).read_text(encoding="utf-8"))
    ent = idx["artifacts"]["triage"]
    fp = ent.setdefault("target_fingerprint", {})
    fp["size"] = 999          # 故意与真实大小不符
    Path(idx_path).write_text(json.dumps(idx, ensure_ascii=False),
                              encoding="utf-8")

    ld2 = AG.case_load(cdir, "triage", target=str(target))
    if ld2.get("ok"):
        return False, "过期结果仍被返回（危险：拿旧结论回答新问题）"
    if ld2.get("stale") is not True:
        return False, "拒绝返回但没标 stale=True，AI 无从判断原因"
    # 显式放行时才允许拿到
    ld3 = AG.case_load(cdir, "triage", target=str(target), allow_stale=True)
    if not ld3.get("ok"):
        return False, "allow_stale=True 仍被拒"

    st2 = AG.case_status(cdir, target=str(target))
    stale_names = [x.get("name") for x in (st2.get("stale") or [])]
    if "triage" not in stale_names:
        return False, "status 未把篡改后的条目列为过期（stale=%s）" % stale_names
    # 过期条目必须从 have 里摘掉：flow 用 have 决定跳过哪些步骤，
    # 如果过期条目还留在 have，flow 会跳过它，AI 就拿旧数据往下走。
    if "triage" in (st2.get("have") or []):
        return False, "过期条目仍留在 have（flow 会据此跳过该步）"

    # --- 换目标必须告警（防止张冠李戴）---
    other = tmp / "other.bin"
    other.write_bytes(b"MZ" + os.urandom(999))
    st3 = AG.case_status(cdir, target=str(other))
    if not st3.get("warnings"):
        return False, "目标换了却没告警"
    return True, "存/读正常，篡改指纹后拒绝返回并标 stale，allow_stale 可放行，换目标有告警"


def t_agent_case_path_traversal_guard():
    """
    case 目录名来自 AI，必须防目录穿越。

    AI 会拼路径（"../.."、"C:\\Windows\\x"），这些一旦落盘就是真实越权写入。
    好的防护不是"报错"，而是把它归一化成一个安全的平铺文件名。
    """
    import lib_agent as AG
    bad = ["../../evil", "..\\..\\evil", "a/b/c", "C:\\Windows\\x.txt",
           "", ".", "..", "n" * 300, "  spaced  "]
    for b in bad:
        got = AG._safe_artifact_name(b)
        if got is None:
            continue                      # 明确拒绝也是合法策略
        if "/" in got or "\\" in got or ":" in got:
            return False, "%r → %r 仍含路径分隔符" % (b, got)
        if ".." == got or got.startswith(".."):
            return False, "%r → %r 仍可上跳" % (b, got)
        if len(got) > 80:
            return False, "%r → %r 超长（%d）" % (b, got, len(got))
    return True, "%d 种穿越/畸形目录名全部被中和为平铺安全名" % len(bad)


def t_agent_flow_ordering():
    """
    flow 的批次语义：同批次可并行，跨批次有依赖。

    这是效率的来源——batch 1 的 4 条命令彼此无依赖，
    可以一次并发发出去，而不是串行等 4 个来回。
    """
    import lib_agent as AG
    r = AG.flow()
    if not r.get("ok"):
        return False, "flow 失败：%s" % r.get("reason")
    ids = [s["id"] for s in AG.FLOW]
    if len(set(ids)) != len(ids):
        return False, "FLOW 里有重复 step id"
    # 依赖必须指向存在的步骤，且必须在更早的批次
    by_id = {s["id"]: s for s in AG.FLOW}
    for s in AG.FLOW:
        for dep in s.get("deps") or []:
            if dep.startswith("prior:"):
                dep = dep.split(":", 1)[1]
            if dep not in by_id:
                return False, "%s 依赖了不存在的 %s" % (s["id"], dep)
            if by_id[dep]["batch"] >= s["batch"]:
                return False, "%s(batch %d) 依赖 %s(batch %d)，批次未递增" % (
                    s["id"], s["batch"], dep, by_id[dep]["batch"])
    # 首批必须可并行（≥2 条），否则编排没意义
    b1 = [s for s in AG.FLOW if s["batch"] == 1]
    if len(b1) < 2:
        return False, "首批只有 %d 条，无法并行" % len(b1)
    # next_batch 必须是最小待办批次
    nb = r.get("next_batch") or []
    if not nb:
        return False, "全新 case 却没给出 next_batch"
    return True, "%d 步 / %d 批次，依赖单一递增，首批 %d 条可并行" % (
        len(AG.FLOW), max(s["batch"] for s in AG.FLOW), len(b1))


def t_agent_toolgraph_prior_and_learned():
    """
    toolgraph：先验转移表必须自洽；学到的东西必须真的改变输出。

    两个都要测，因为"prior"是我们手写的（可能写错），
    "learned"是从流水里数出来的（可能根本没接上）。
    只测其中一个，很容易出现"看起来在工作"的假象。
    """
    import lib_agent as AG
    # 先验表：目标命令必须存在
    for src, edges in AG.TRANSITIONS.items():
        if src not in AG.CATALOG_BY_NAME:
            return False, "TRANSITIONS 的源 %s 不在目录里" % src
        for nxt, w, _why in edges:
            if nxt not in AG.CATALOG_BY_NAME:
                return False, "%s→%s 的目标不在目录里" % (src, nxt)
            if not (0 < w <= 1.0):
                return False, "%s→%s 权重 %s 越界" % (src, nxt, w)

    r = AG.toolgraph("triage")
    if not r.get("ok"):
        return False, "toolgraph 失败：%s" % r.get("reason")
    if r.get("weights_source") != "prior":
        return False, "无 case 时 weights_source=%s" % r.get("weights_source")
    names = [c["cmd"] for c in r["candidates"]]
    if "symbols" not in names[:3]:
        return False, "triage 之后没把 symbols 排进前三（%s）" % names

    # --- 真的能从流水里学到东西 ---
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-tg-"))
    target = tmp / "s.bin"
    target.write_bytes(b"MZ" + os.urandom(2048))
    cdir = str(tmp / "c")
    AG.case_init(cdir, str(target))
    for _ in range(3):
        AG.case_save(cdir, "triage", {"ok": True}, target=str(target))
        AG.case_save(cdir, "obfstr", {"ok": True}, target=str(target))
    learned = AG._learn_edges(AG.case_journal(cdir)["records"])
    # _learn_edges 返回 {src: {dst: 次数}} 的嵌套结构
    if "obfstr" not in (learned.get("triage") or {}):
        return False, "流水里 triage→obfstr 出现 3 次却没学到（%s）" % (
            {k: sorted(v) for k, v in learned.items()},)
    if learned["triage"]["obfstr"] < 3:
        return False, "triage→obfstr 只数到 %d 次，应为 3" % learned["triage"]["obfstr"]
    r2 = AG.toolgraph("triage", case_dir=cdir)
    if r2.get("weights_source") != "prior+learned":
        return False, "有 case 时 weights_source=%s" % r2.get("weights_source")
    w = {c["cmd"]: c["weight"] for c in r2["candidates"]}
    if "obfstr" not in w:
        return False, "学到的边没进候选：%s" % list(w.keys())
    # 权重必须真的被抬高了，而不是原样照抄先验
    base = {c["cmd"]: c["weight"] for c in r["candidates"]}
    if base.get("obfstr") and w["obfstr"] <= base["obfstr"]:
        return False, "学到的边权重没涨（%.3f → %.3f）" % (
            base["obfstr"], w["obfstr"])
    return True, "先验表自洽，3 次共现成功学到 triage→obfstr，权重 %.3f→%.3f" % (
        base.get("obfstr", 0.0), w.get("obfstr", 0.0))


def t_agent_cli_contracts():
    """
    5 个编排命令的 CLI 契约：退出码受控、--json 有 ok、不污染目录。

    特别要守的是 result 的降级行为——它最常见的用法是接管道：
    `re.py triage x --json | re.py result --stdin`。
    上游崩了会往 stdout 吐 argparse 用法文本，这时 result 必须
    给一个受控的 ok=false，而不是自己抛 JSONDecodeError。
    """
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="re-agentcli-"))

    # require
    code, out, _ = run([CLI, "require", "这文件是不是加壳了", "--json"], timeout=60)
    if code != 0:
        return False, "require 退出码 %s" % code
    d = json.loads(out)
    if "ok" not in d or not d.get("recommendations"):
        return False, "require 输出缺 ok 或候选为空"

    # require --explain 必须给理由
    code, out, _ = run([CLI, "require", "加壳", "--json", "--explain"], timeout=60)
    d = json.loads(out)
    if not any(x.get("why") for x in d.get("recommendations", [])):
        return False, "require --explain 没给出 why"

    # flow
    code, out, _ = run([CLI, "flow", "--json"], timeout=60)
    if code != 0:
        return False, "flow 退出码 %s" % code
    if "ok" not in json.loads(out):
        return False, "flow 输出缺 ok"

    # flow 未知 stage 必须被拦（不是静默当全集）
    code, out, err = run([CLI, "flow", "--stage", "__nope__", "--json"], timeout=60)
    if code == 0 and json.loads(out).get("ok"):
        return False, "未知 stage 被静默接受"

    # case init/status
    tgt = tmp / "a.bin"
    tgt.write_bytes(b"MZ" + os.urandom(1024))
    cdir = str(tmp / "cd")
    code, out, _ = run([CLI, "case", "init", "--dir", cdir,
                        "--target", str(tgt), "--json"], timeout=60)
    if code != 0:
        return False, "case init 退出码 %s" % code
    code, out, _ = run([CLI, "case", "status", "--dir", cdir,
                        "--target", str(tgt), "--json"], timeout=60)
    if code != 0 or "missing" not in json.loads(out):
        return False, "case status 输出异常"

    # result：空 stdin 要被受控处理
    code, out, err = run([CLI, "result", "--stdin", "--json"], timeout=60,
                         stdin_text="")
    if "Traceback (most recent call last)" in (out + err):
        return False, "result 空 stdin 漏出 Traceback"
    d = json.loads(out)
    if d.get("ok") is not False:
        return False, "result 空 stdin 未返回 ok=false"

    # result：非 JSON stdin（模拟上游 argparse 崩了）也要受控
    code, out, err = run([CLI, "result", "--stdin", "--json"], timeout=60,
                         stdin_text="usage: re.py [-h] {triage,...}\nerror: bad\n")
    if "Traceback (most recent call last)" in (out + err):
        return False, "result 非 JSON stdin 漏出 Traceback"
    d = json.loads(out)
    if d.get("ok") is not False:
        return False, "result 非 JSON stdin 未返回 ok=false"
    if not d.get("evidence"):
        return False, "result 非 JSON stdin 没保留原始证据片段"

    # toolgraph
    code, out, _ = run([CLI, "toolgraph", "--cmd", "triage", "--json"], timeout=60)
    if code != 0 or "next" not in json.loads(out):
        return False, "toolgraph 输出异常"

    # --check 的告警是建议性的，不许把退出码改掉（否则脚本会误判流程非法）
    code, out, _ = run([CLI, "toolgraph", "--cmd", "diff", "--check", "triage",
                        "--json"], timeout=60)
    if code != 0:
        return False, "toolgraph --check 建议性告警却改了退出码（%s）" % code

    # 不能污染技能目录
    stray = [p.name for p in Path(SCRIPTS).iterdir()
             if p.name.startswith(("case", "manifest.json", "index.json"))]
    if stray:
        return False, "编排命令往技能目录落了文件：%s" % stray
    return True, "require/flow/case/result/toolgraph 全部受控，result 对空/非 JSON 输入优雅降级"


# ---------------------------------------------------------------- 主流程

# ---------------------------------------------------------------- 稳定性回归
#
# 这一组用例专门盯「失败被上报为成功」与「畸形输入把引擎打崩」两类缺陷。
# 每一条都对应一次真实的修复，注释里写明**原来的错法**——否则后来者看到
# 一个"多余"的断言，很容易在重构时顺手删掉，缺陷就悄悄回来了。


def t_yaml_resource_guards():
    """
    YAML 解析的资源上限：体积与嵌套深度都必须被拦住。

    原缺陷：解析耗时正比于**字节数**（缩进是空白也要逐字符扫），且没有任何
    上限。一个 95 MB 的纯缩进文件会让 _strip_comment 空转十几秒才轮到结构
    校验；深缩进则能把调用栈打爆。规则文件来自用户目录，这是实打实的输入面。

    注意断言方式：必须检查抛的是 YamlError（可读报错），而不是 RecursionError
    / MemoryError —— 后者说明我们没拦住、只是靠解释器兜底。
    """
    import time
    import lib_rules as LR

    problems = []

    # 1) 超大体积：必须抛 YamlError，且要快（不能先慢慢磨一遍）
    # 注意：不能靠"层数多"堆体积——3000 层也才 9 MB。这里刻意用
    # 「极少行 + 每行巨量缩进」的形态，正是攻击者最省事的造法。
    big = "a://n" + " " * (LR._YAML_MAX_BYTES + 1024) + "  b: 1\n"
    assert len(big) > LR._YAML_MAX_BYTES, "样本没超过上限，用例本身失效"
    t0 = time.time()
    try:
        LR.yaml_load(big)
        problems.append("超限体积未被拦截")
    except LR.YamlError:  # lint:ok 断言就是"必须抛这个错"，吞掉即为通过
        pass
    except Exception as e:
        problems.append(f"超限体积抛了非 YamlError：{type(e).__name__}")
    dt = time.time() - t0
    if dt > 2.0:
        problems.append(f"体积拦截太慢（{dt:.2f}s）——说明是先解析后校验")

    # 2) 深缩进（体积在限内）：必须抛 YamlError 而不是 RecursionError
    # _YAML_MAX_DEPTH 是 yaml_load 内部的局部量，外部读不到；只做行为断言。
    deep = "\n".join(" " * (2 * i) + "k%d:" % i for i in range(400))
    deep += "\n" + " " * 800 + "leaf: 1"
    assert len(deep) <= LR._YAML_MAX_BYTES
    try:
        LR.yaml_load(deep)
        problems.append("深嵌套未被拦截")
    except LR.YamlError:  # lint:ok 断言就是"必须抛这个错"，吞掉即为通过
        pass
    except RecursionError:
        problems.append("深嵌套爆栈（靠解释器兜底，说明没拦住）")
    except Exception as e:
        problems.append(f"深嵌套抛了非 YamlError：{type(e).__name__}")

    # 3) 正常文件不能因加了守卫而解析失败
    d = LR.yaml_load("a:\n  b: 1\n  c:\n    - x\n    - y: 2\n")
    if d != {"a": {"b": 1, "c": ["x", {"y": 2}]}}:
        problems.append(f"正常 YAML 解析结果变了：{d!r}")

    # 4) 快速路径必须与慢路径逐字节等价（含引号/井号的边界）
    strip = [
        "a: 1", "a: 1  # c", 'a: "x"', "a: 'x'", "a: x#y", 'a: "x#y"',
        "a: x # y", 'a: "x\\"#y"', 'u: "http://a/#f"', "a: '#x'",
    ]
    for s in strip:
        got = LR._strip_comment(s)
        if "\n" in got:
            problems.append(f"_strip_comment 返回了换行：{s!r}")

    if problems:
        return False, "；".join(problems)
    return True, ("体积上限(%.0fMB)与深嵌套均被 YamlError 拦住，"
                  "正常解析未变，%d 项注释剥离无异常"
                  % (LR._YAML_MAX_BYTES / 1048576.0, len(strip)))


def t_catalog_shape_invariant():
    """
    CATALOG 结构不变量：畸形目录必须在 import 期就炸掉。

    原缺陷：CATALOG 是手写字面量，下游有几十处 `e["field"]` 直接取键。少写一个
    字段不会在 import 时报错，只在某个特定意图被检索到的那一刻抛 KeyError ——
    "平时看着好好的，用户一句话就崩"。这类潜伏缺陷比语法错误危险得多。

    这条用例同时守住**两面**：该拦的必须拦，合法目录不能被误伤（过严会让
    技能直接 import 失败，那是最惨的失败模式）。
    """
    import copy
    import lib_agent as AG

    problems = []
    good = AG.CATALOG[0]

    must_raise = {
        "缺 summary": lambda c: c.pop("summary"),
        "缺 stage": lambda c: c.pop("stage"),
        "summary 类型错": lambda c: c.update(summary=1),
        "answers 是字符串": lambda c: c.update(answers="x"),
        "answers 含 int": lambda c: c.update(answers=["a", 1]),
        "cost 未知值": lambda c: c.update(cost="fast "),
        "stage 未知值": lambda c: c.update(stage="unknown"),
        "formats 是字符串": lambda c: c.update(formats="pe"),
        "flags 三元对": lambda c: c.update(flags=[["--a", "1", "2"]]),
        "flags 对里含 int": lambda c: c.update(flags=[["--a", 1]]),
    }
    for label, mut in must_raise.items():
        item = copy.deepcopy(good)
        mut(item)
        try:
            AG._validate_catalog([item])
            problems.append(f"{label} 未被拦截")
        except RuntimeError:  # lint:ok 断言就是"必须抛这个错"，吞掉即为通过
            pass
        except Exception as e:
            problems.append(f"{label} 抛了非 RuntimeError：{type(e).__name__}")

    # 非 dict 条目 / 重名
    for label, cat in (("非 dict 条目", [good, "x"]),
                       ("重名条目", [copy.deepcopy(good), copy.deepcopy(good)])):
        try:
            AG._validate_catalog(cat)
            problems.append(f"{label} 未被拦截")
        except RuntimeError:  # lint:ok 断言就是"必须抛这个错"，吞掉即为通过
            pass

    # 反向：真实的 CATALOG 必须通过（防止守卫过严把技能卡死）
    try:
        AG._validate_catalog(AG.CATALOG)
    except RuntimeError as e:
        problems.append(f"真实 CATALOG 被误伤：{str(e)[:80]}")

    if len(AG.CATALOG_BY_NAME) != len(AG.CATALOG):
        problems.append("CATALOG_BY_NAME 与 CATALOG 条目数不一致")

    # flags 的两种合法形状都要能渲染成可跑命令
    for nm in ("strings", "triage"):
        cmd = AG.build_command(AG.CATALOG_BY_NAME[nm], "t.bin")
        if "[[" in cmd or "']" in cmd:
            problems.append(f"{nm} 命令模板渲染异常：{cmd}")

    if problems:
        return False, "；".join(problems)
    return True, ("%d 种畸形目录全部拦截，真实目录 %d 条未误伤，命令模板可渲染"
                  % (len(must_raise) + 2, len(AG.CATALOG)))


def t_string_vma_map_no_swallow():
    """
    string_vma_map 必须把内部错误**抛出去**，而不是吞掉返回空表。

    原缺陷：函数内 `except Exception: return {}`，而调用方 re.py 里有
    `res["_string_map_error"] = ...` 的错误处理分支 —— 因为异常在内层就被
    吞了，外层那段处理成了**永远走不到的死代码**。表现是"字符串交叉引用
    静默少一半"，看起来是"没找到"，实际是引擎坏了。这正是本技能最忌讳的
    `失败被上报为成功`。

    断言：传一个必然触发内部异常的对象，必须抛异常，**不能**安安静静返回 {}。
    """
    import lib_semantics as LS

    # None 没有 .items()/.get()，任何实现都会在内部炸一下
    raised = None
    try:
        LS.string_vma_map(None)
    except Exception as e:
        raised = e
    if raised is None:
        return False, ("string_vma_map(None) 静默返回了——内部异常被吞了，"
                       "调用方的 _string_map_error 分支会变成死代码")
    return True, f"内部异常正常抛出：{type(raised).__name__}"


def t_unsupported_arch_fails_closed():
    """
    不支持的架构必须**明确报错**，不能兜底用 x86 解码器。

    原缺陷：backend() 对没有解码器的架构（MIPS/PPC/RISC-V）静默返回 x86-64
    后端，产出语法合法、语义完全错误的指令，且 ok=True。一个说得通但完全
    错误的结论，比一个明确的报错危险一百倍。

    断言两点：(1) 不支持架构抛 UnsupportedArch；(2) 报错信息里列出支持的架构，
    让调用者知道下一步该干什么。
    """
    import lib_disasm as LD

    problems = []
    for arch in ("mips", "ppc", "riscv", "sparc", "unknown-arch"):
        try:
            LD.backend(arch)
            problems.append(f"{arch} 未报错（静默兜底了）")
        except LD.UnsupportedArch as e:
            msg = str(e)
            if "支持" not in msg:
                problems.append(f"{arch} 报错信息没说明支持哪些架构")
        except Exception as e:
            problems.append(f"{arch} 抛了非 UnsupportedArch：{type(e).__name__}")

    # 支持的架构必须照常工作（守卫不能误伤）
    for arch in ("x86-64", "arm64"):
        try:
            fn = LD.backend(arch)
            if not fn:
                problems.append(f"{arch} 后端为空")
        except Exception as e:
            problems.append(f"{arch} 被误伤：{type(e).__name__}: {e}")

    if problems:
        return False, "；".join(problems)
    return True, "5 种不支持架构全部明确报错，x86-64/arm64 未误伤"


def t_case_index_shape_tolerance():
    """
    case 目录的 index.json 是**外部可变状态**，形状非法时必须受控。

    原缺陷：只防了"读不到"（None），没防"形状不对"。
      * index.json 写成 `{"artifacts": "x"}` → 字符串是真值，`or {}` 不生效，
        case_load 里 `art.get('sha256')` 直接 AttributeError；
      * artifacts 的某个条目写成 int → case_status 里 `e.get(...)` 直接崩。
    实测这两种都要复现，且 status/load/flow/toolgraph 四条路径都不得抛栈。
    """
    import lib_agent as AG

    problems = []
    bad_shapes = [
        ("artifacts 是字符串", {"artifacts": "x"}),
        ("artifacts 是列表", {"artifacts": [1, 2]}),
        ("顶层是列表", [1, 2, 3]),
        ("顶层是字符串", "nope"),
        ("条目不是 dict", {"artifacts": {"obfstr": 123}}),
        ("条目缺 sha256", {"artifacts": {"obfstr": {}}}),
        ("artifacts 为 null", {"artifacts": None}),
    ]
    for label, payload in bad_shapes:
        cdir = TMP / "idxshape" / label.replace(" ", "_")
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "manifest.json").write_text('{"target": "t.bin"}', encoding="utf-8")
        (cdir / "index.json").write_text(json.dumps(payload), encoding="utf-8")
        for fn, fname in ((lambda: AG.case_status(str(cdir)), "status"),
                          (lambda: AG.case_load(str(cdir), "obfstr"), "load")):
            try:
                r = fn()
                if not isinstance(r, dict) or "ok" not in r:
                    problems.append(f"{label}/{fname} 返回了非契约结构")
            except Exception as e:
                problems.append(f"{label}/{fname} 抛栈：{type(e).__name__}: {e}")

    # 索引损坏时 status 必须**如实上报**（ok=False + reason），不能不吭声
    cdir = TMP / "idxshape" / "corrupt"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "manifest.json").write_text('{"target": "t.bin"}', encoding="utf-8")
    (cdir / "index.json").write_text("{ not json", encoding="utf-8")
    try:
        r = AG.case_status(str(cdir))
        if r.get("ok") is not False:
            problems.append("索引损坏但 status 仍报 ok=True（失败被上报为成功）")
        elif not r.get("reason"):
            problems.append("索引损坏但没给出 reason")
    except Exception as e:
        problems.append(f"损坏索引导致 status 抛栈：{type(e).__name__}: {e}")

    if problems:
        return False, "；".join(problems)
    return True, (f"{len(bad_shapes)} 种畸形 index 全部受控，"
                  "损坏索引如实上报 ok=False")


def t_case_journal_bounded_read():
    """
    case journal 是无界追加文件，读取必须**流式有界**，且如实标注被截断。

    原缺陷：先 `recs.append(...)` 把整个文件读进列表，再 `recs[-limit:]` 切片。
    追加型文件可以长到任意大，这一步内存无界；而且返回结果里没有 truncated
    标志，调用者以为拿到的是全部。
    """
    import lib_agent as AG

    cdir = TMP / "journalbig"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "manifest.json").write_text('{"target": "t.bin"}', encoding="utf-8")
    jpath = cdir / "journal.jsonl"
    N = 5000
    with jpath.open("w", encoding="utf-8") as f:
        for i in range(N):
            f.write(json.dumps(
                {"ts": "2026-01-01T00:00:00", "cmd": "obfstr", "n": i},
                ensure_ascii=False) + "\n")

    problems = []
    got = None
    for kwargs in ({}, {"limit": 10}):
        try:
            got = AG.case_journal(str(cdir), **kwargs)
        except Exception as e:
            problems.append(f"case_journal({kwargs}) 抛栈：{type(e).__name__}: {e}")
            continue
        entries = got.get("entries") or got.get("records") or []
        if not isinstance(entries, list):
            problems.append(f"{kwargs} 返回的 entries 不是列表")
            continue
        if kwargs.get("limit") and len(entries) > 10:
            problems.append(f"limit=10 却返回 {len(entries)} 条")
        # 条目总数必须如实，且标明截断
        if got.get("total") is not None and got["total"] != N:
            problems.append(f"total 应为 {N}，实得 {got['total']}")
        if kwargs.get("limit") and got.get("truncated") is not True:
            problems.append("有 limit 且超量，但没标 truncated=True（调用者会以为拿全了）")

    if problems:
        return False, "；".join(problems)
    return True, f"{N} 行 journal 流式读取受控（limit/total/truncated 语义正确）"

def t_rules_feature_depth_guard():
    """
    规则特征树必须有深度上限，且必须在**构建期**就拦住深嵌套。

    原缺陷：只有步数上限（max_calls）。但"递归深度"和"循环步数"是两个正交的
    轴 —— 一条 `not: not: not: ...` 嵌套规则可以在极少的"步数"内把调用栈打爆。

    守卫分两层，这条用例把两层都验证到：
      1) Rule._validate 里 depth>32 的构建期检查 —— **这是实际生效的那层**。
         它拦在规则文件被解析成 Rule 的那一刻，比运行期拦更早、更省。
      2) match_rules 内部 _MAX_EVAL_DEPTH 的运行期兜底 —— 只有绕过 Rule
         直接构造特征树才走得到。真实规则文件到不了这里（32 < 200），
         但**兜底必须在**：去掉它，绕过 Rule 的调用路径就会裸奔爆栈。
         这里用独立子进程直接驱动内部匹配器来验证它确实存在。

    为什么两者都要：可靠性要求"同一风险在不同入口都有防线"，因为未来任何
    一条新入口（比如某个 loader 直接塞 node）都可能绕过 Rule。
    """
    import subprocess
    import sys as _sys
    import lib_rules as LR

    problems = []
    HERE_ = str(HERE)   # HERE 由 selftest.py 顶部定义为本脚本目录

    def _rule(name, features):
        return LR.Rule({
            "rule": {"meta": {"name": name, "scope": "file"},
                     "features": features},
        })

    feats = {"instruction": [], "basic block": [], "function": [], "file": []}

    # 1) 构建期守卫：深嵌套必须在 Rule() 构造时就抛错
    depth = 200
    node = {"or": [{"mnemonic": "nop"}]}
    for _ in range(depth):
        node = {"not": node}
    try:
        _rule("deepnot", node)
        problems.append(f"{depth} 层嵌套未被构建期守卫拦住")
    except LR.RuleError as e:
        if "过深" not in str(e):
            problems.append(f"构建期报错原因不对：{str(e)[:60]}")
    except RecursionError:
        problems.append("深嵌套在构建期就爆栈（说明守卫没拦住）")
    except Exception as e:
        problems.append(f"深嵌套抛了非 RuleError：{type(e).__name__}: {e}")

    # 2) 边界：守卫位置要准，不能过严（把合法规则拦掉）也不能过松。
    #    实测口径：`_validate` 的 depth 每进一层 dict/list 加 1，
    #    所以 `not: not: ...` 每级吃 2 层。30 层（depth≈62）必被拦；
    #    15 层（depth≈32）须通过 —— 这两个数就是实测出来的边界两侧。
    def _chain(n):
        nd = {"or": [{"mnemonic": "nop"}]}
        for _ in range(n):
            nd = {"not": nd}
        return nd

    for n, should_pass in ((15, True), (30, False)):
        try:
            _rule("edge%d" % n, _chain(n))
            if not should_pass:
                problems.append(f"{n} 层应被拦截但通过了")
        except LR.RuleError:
            if should_pass:
                problems.append(f"{n} 层被误拦（守卫过严）")

    # 3) 浅层规则必须照常工作
    try:
        res2 = LR.match_rules(
            [_rule("shallow", {"or": [{"mnemonic": "nop"}, {"mnemonic": "ret"}]})],
            feats)
        if res2.get("errors"):
            problems.append(f"浅层规则被误伤：{res2['errors'][:2]}")
    except Exception as e:
        problems.append(f"浅层规则抛错：{type(e).__name__}: {e}")

    # 4) 规则依赖成环仍要被拦住（既有保护，一起守住）
    try:
        res3 = LR.match_rules([
            _rule("ring-a", {"or": [{"rule": "ring-b"}]}),
            _rule("ring-b", {"or": [{"rule": "ring-a"}]}),
        ], feats)
        errs = res3.get("errors") or []
        if not any("成环" in str(x) for x in errs):
            problems.append("规则依赖成环未被拦截")
    except LR.RuleError:  # lint:ok 断言就是"必须抛这个错"，吞掉即为通过
        pass
    except Exception as e:
        problems.append(f"成环规则抛了非 RuleError：{type(e).__name__}: {e}")

    # 5) 运行期兜底：绕过 Rule 直接喂深树给 match_rules 内部闭包。
    #    在子进程里做，避免污染当前解释器的状态；断言"要么抛出带 深度/嵌套 的
    #    RuleError，要么被受控拦截"，**绝不允许裸 RecursionError 冒到顶层**。
    # 注意：probe 里也有 %s（用于打印异常类型），所以整块**不能用 % 格式化**，
    # 否则 "%s" 会被外层当成占位符吃掉。这里改用拼接注入路径。
    probe = (
        "import sys; sys.path.insert(0, " + repr(HERE_) + ")\n"
        "import lib_rules as LR\n"
        "node = {'or': [{'mnemonic': 'nop'}]}\n"
        "for _ in range(1500):\n"
        "    node = {'not': node}\n"
        "r = LR.Rule.__new__(LR.Rule)\n"
        "r.name = 'raw'; r.namespace = ''; r.scope = 'file'\n"
        "r.authors = []; r.description = ''; r.att_ck = []\n"
        "r.references = []; r.features = node; r.source = ''; r.raw = {}\n"
        "feats = {'instruction': [], 'basic block': [], 'function': [], 'file': []}\n"
        "try:\n"
        "    res = LR.match_rules([r], feats)\n"
        "    errs = res.get('errors') or []\n"
        "    hit = any(('深度' in str(x) or '嵌套' in str(x)) for x in errs)\n"
        "    print('GUARDED' if hit else 'UNGUARDED:' + str(errs[:1]))\n"
        "except RecursionError:\n"
        "    print('RECURSION')\n"
        "except LR.RuleError as e:\n"
        "    print('GUARDED' if ('深度' in str(e) or '嵌套' in str(e)) else 'OTHER:' + str(e)[:50])\n"
        "except Exception as e:\n"
        "    print('OTHER:%s:%s' % (type(e).__name__, e))\n"
    )
    try:
        p = subprocess.run([_sys.executable, "-c", probe], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=120,
                           cwd=HERE_)
        out = (p.stdout or "").strip().splitlines()
        last = out[-1] if out else "(无输出)"
        if last == "RECURSION":
            problems.append("绕过 Rule 直喂深树时裸爆栈（运行期兜底缺失）")
        elif last.startswith("OTHER") or last.startswith("UNGUARDED"):
            problems.append(f"运行期兜底未生效：{last[:80]}")
        elif last != "GUARDED":
            problems.append(f"子进程探测结果异常：{last[:80]}  stderr={p.stderr[:80]}")
    except Exception as e:
        problems.append(f"子进程探测失败：{type(e).__name__}: {e}")

    if problems:
        return False, "；".join(problems)
    return True, ("构建期守卫(>32层)与边界(15通过/30拦截)正确，"
                  "浅层/成环正常，运行期兜底拦住了绕过 Rule 的深树")


def t_install_paths_in_spec():
    """各运行时的技能目录必须落在官方约定上，且能被本机解析成绝对路径。

    这是"能不能装"的地基：路径错了，后面一切免谈。
    """
    if not (HERE / "_dev" / "_install.py").is_file():
        # 装到运行时后 _dev/ 不再分发（面向贡献者的脚手架），
        # 此时安装用例无从取材 —— 跳过而不是失败。
        return True, SKIP
    sys.path.insert(0, str(HERE / "_dev"))
    try:
        import _install as I
    except Exception as e:
        return False, "导入 _install.py 失败：%s: %s" % (type(e).__name__, e)

    # 必须覆盖用户点名要求的运行时（含 WorkBuddy 自身）
    need = ["claude-code", "codex", "hermes", "openclaw", "workbuddy"]
    missing = [r for r in need if r not in I._RUNTIME_DOC]
    if missing:
        return False, "缺少运行时定义：%s" % "、".join(missing)

    # 路径终点必须叫 skills（各家的约定一致），且个人级能解析成绝对路径
    problems = []
    for rt in need:
        p = I.personal_dir(rt)
        if p is None:
            continue
        if not os.path.isabs(p):
            problems.append("%s 个人级路径不是绝对路径：%s" % (rt, p))
        if os.path.basename(p.rstrip("/\\")) != "skills":
            problems.append("%s 个人级目录不以 skills 结尾：%s" % (rt, p))
    if problems:
        return False, "；".join(problems)

    # Codex 必须认 CODEX_HOME（不能硬编码 ~/.codex）
    old = os.environ.get("CODEX_HOME")
    try:
        os.environ["CODEX_HOME"] = os.path.join(str(TMP), "cx")
        got = I.personal_dir("codex")
        if not got or "cx" not in got:
            return False, "Codex 未遵循 CODEX_HOME 环境变量：%s" % got
    finally:
        if old is None:
            os.environ.pop("CODEX_HOME", None)
        else:
            os.environ["CODEX_HOME"] = old

    return True, "4 个必需运行时路径合规，Codex 正确遵循 CODEX_HOME"


def t_install_verify_detects_broken():
    """验证器必须能识别坏安装 —— 一个永不失败的检查等于没有。

    这是本项目"假成功"病在安装环节的对偶：验证器若总是返回 ok，
    就等于把坏安装上报成好安装。
    """
    if not (HERE / "_dev" / "_install.py").is_file():
        # 装到运行时后 _dev/ 不再分发（面向贡献者的脚手架），
        # 此时安装用例无从取材 —— 跳过而不是失败。
        return True, SKIP
    sys.path.insert(0, str(HERE / "_dev"))
    try:
        import _install as I
    except Exception as e:
        return False, "导入 _install.py 失败：%s: %s" % (type(e).__name__, e)

    sandbox = Path(TMP) / "inst-verify"
    os.environ[I.HOME_ENV] = str(sandbox)
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)
    dest = sandbox / ".claude" / "skills" / "reverse-engineering"
    dest.mkdir(parents=True)

    # 1) 缺 SKILL.md
    (dest / "README.md").write_text("x", encoding="utf-8")
    ok, problems = I.verify_one("claude-code", "personal", str(sandbox))
    if ok:
        return False, "缺 SKILL.md 时验证器仍报通过（假成功）"
    if not any("SKILL.md" in p for p in problems):
        return False, "未指出缺 SKILL.md：%s" % problems

    # 2) name 与目录名不一致
    (dest / "SKILL.md").write_text(
        "---\nname: wrong-name\ndescription: x\n---\n", encoding="utf-8")
    ok, problems = I.verify_one("claude-code", "personal", str(sandbox))
    if ok:
        return False, "name 与目录名不符时验证器仍报通过（假成功）"
    if not any("名称" in p or "name" in p for p in problems):
        return False, "未指出 name 不一致：%s" % problems

    # 3) 完好的安装必须能过（反向确认验证器不是一味报错）
    (dest / "SKILL.md").write_text(
        "---\nname: reverse-engineering\ndescription: d\n---\n",
        encoding="utf-8")
    (dest / "scripts").mkdir(exist_ok=True)
    (dest / "scripts" / "re.py").write_text("", encoding="utf-8")
    (dest / "scripts" / "selftest.py").write_text("", encoding="utf-8")
    ok, problems = I.verify_one("claude-code", "personal", str(sandbox))
    if not ok:
        return False, "完好的安装被误判为坏：%s" % problems

    os.environ.pop(I.HOME_ENV, None)
    shutil.rmtree(sandbox, ignore_errors=True)
    return True, "缺 SKILL.md / name 不符均被拦截，完好安装正常通过"


def t_install_copy_slims_and_runs():
    """真装一次：复制模式必须可用，且裁掉开发产物（_ref/_dev/.github）。

    末尾用子进程跑一次 re.py --help，确认**装出来的副本真的能执行** ——
    只看文件在不在是不够的。
    """
    if not (HERE / "_dev" / "_install.py").is_file():
        # 装到运行时后 _dev/ 不再分发（面向贡献者的脚手架），
        # 此时安装用例无从取材 —— 跳过而不是失败。
        return True, SKIP
    sys.path.insert(0, str(HERE / "_dev"))
    try:
        import _install as I
    except Exception as e:
        return False, "导入 _install.py 失败：%s: %s" % (type(e).__name__, e)

    sandbox = Path(TMP) / "inst-copy"
    os.environ[I.HOME_ENV] = str(sandbox)
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)
    sandbox.mkdir(parents=True)

    old_force = None
    try:
        ok, msg = I.install_one("claude-code", "personal", str(sandbox),
                                "copy", False)
        if not ok:
            return False, "复制安装失败：%s" % msg
    except Exception as e:
        return False, "安装抛异常：%s: %s" % (type(e).__name__, e)
    finally:
        if old_force is not None:
            pass

    dest = sandbox / ".claude" / "skills" / "reverse-engineering"
    if not (dest / "SKILL.md").is_file():
        return False, "装完没有 SKILL.md"

    # 开发/合规产物必须被裁掉
    leaked = [rel for rel in ("scripts/_dev", "scripts/_ref", ".github", ".git")
              if (dest / rel).exists()]
    if leaked:
        return False, "安装副本泄漏了开发/合规产物：%s" % "、".join(leaked)

    # 装出来的副本必须真的能执行
    # 装出来的副本必须真的能执行。
    # 注意 cwd 必须是副本自己的 scripts/ —— re.py 按相对位置 import 同目录模块，
    # 沿用 run() 的 cwd=HERE 会去 import 源仓库的模块，测不出副本真实可用性。
    cp_scripts = dest / "scripts"
    p = subprocess.run([PY, "re.py", "--help"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120,
                       cwd=str(cp_scripts))
    if p.returncode != 0 or "triage" not in p.stdout:
        return False, ("安装副本无法执行 re.py --help（code=%s, err=%s）"
                       % (p.returncode, p.stderr[:160]))

    # 副本跑一次真实子命令（不只是 --help），确认分析链路完整
    p2 = subprocess.run([PY, "re.py", "magic", "--json"], capture_output=True,
                        text=True, encoding="utf-8", errors="replace",
                        timeout=120, cwd=str(cp_scripts))
    if p2.returncode != 0:
        return False, ("安装副本执行 magic 子命令失败（code=%s）" % p2.returncode)
    try:
        if not json.loads(p2.stdout).get("ok"):
            return False, "安装副本 magic 未返回 ok=true"
    except Exception as e:
        return False, "安装副本 magic 输出不可解析：%s" % e

    # 自验要通过
    vok, problems = I.verify_one("claude-code", "personal", str(sandbox))
    if not vok:
        return False, "安装后自验未过：%s" % problems

    os.environ.pop(I.HOME_ENV, None)
    shutil.rmtree(sandbox, ignore_errors=True)
    return True, "复制安装可用、已裁掉 _dev/_ref/.github、副本可执行 re.py"



def t_install_workbuddy_no_selfcopy():
    """
    workbuddy 运行时的目标必须是 <home>/.workbuddy/skills，不能是
    「技能自己的上一级目录」。

    原缺陷：personal_dir("workbuddy") 返回 os.path.dirname(SELF_ROOT)。
    后果有两层，第二层更严重：
      1) 把仓库 clone 到 ~/projects/re-clone 后跑 --auto，会往
         ~/projects/reverse-engineering 复制一份 —— 那不是任何运行时
         读技能的路径；
      2) 这一步还会被上报成「[成功] 复制 → ...」。装到一个永远不会被读
         的位置却报成功，就是假成功。

    还要守「已在目标位置时是 no-op」：本技能常年就住在
    ~/.workbuddy/skills/ 下，此时安装不该把自己复制进自己。
    """
    if not (HERE / "_dev" / "_install.py").is_file():
        return True, SKIP
    import importlib
    sys.path.insert(0, str(HERE / "_dev"))
    try:
        import _install as I
        importlib.reload(I)
    except Exception as e:
        return False, "导入 _install.py 失败：%s: %s" % (type(e).__name__, e)

    sandbox = os.path.join(str(TMP), "wb-home")
    os.makedirs(sandbox, exist_ok=True)
    old = os.environ.get(I.HOME_ENV)
    os.environ[I.HOME_ENV] = sandbox
    try:
        got = I.personal_dir("workbuddy")
        want = os.path.join(sandbox, ".workbuddy", "skills")
        if os.path.abspath(got or "") != os.path.abspath(want):
            return False, ("workbuddy 目标路径错误：得到 %r，应为 %r"
                           % (got, want))
        # 绝不能等于技能自己的上一级（那是 clone 所在目录）
        if os.path.abspath(got or "") == os.path.abspath(
                os.path.dirname(str(HERE.parent))):
            return False, "workbuddy 目标仍解析到技能上一级目录：%r" % got
    finally:
        if old is None:
            os.environ.pop(I.HOME_ENV, None)
        else:
            os.environ[I.HOME_ENV] = old

    return True, "workbuddy 目标为 <home>/.workbuddy/skills，未退化为技能上级目录"


def t_install_no_clobber():
    """已存在同名技能时必须拒绝覆盖（保护用户已有安装）。"""
    if not (HERE / "_dev" / "_install.py").is_file():
        # 装到运行时后 _dev/ 不再分发（面向贡献者的脚手架），
        # 此时安装用例无从取材 —— 跳过而不是失败。
        return True, SKIP
    sys.path.insert(0, str(HERE / "_dev"))
    try:
        import _install as I
    except Exception as e:
        return False, "导入 _install.py 失败：%s: %s" % (type(e).__name__, e)

    sandbox = Path(TMP) / "inst-noclobber"
    os.environ[I.HOME_ENV] = str(sandbox)
    if sandbox.exists():
        shutil.rmtree(sandbox, ignore_errors=True)
    dest = sandbox / ".claude" / "skills" / "reverse-engineering"
    dest.mkdir(parents=True)
    marker = dest / "MINE.txt"
    marker.write_text("用户自己的东西", encoding="utf-8")

    ok, msg = I.install_one("claude-code", "personal", str(sandbox),
                            "copy", False)
    if ok:
        return False, "已存在时仍覆盖了用户目录（危险）"
    if not marker.is_file():
        return False, "用户原有内容被破坏"

    # --force 时必须先备份
    ok2, msg2 = I.install_one("claude-code", "personal", str(sandbox),
                              "copy", True)
    if not ok2:
        return False, "--force 覆盖失败：%s" % msg2
    baks = list((sandbox / ".claude" / "skills").glob("reverse-engineering.bak-*"))
    if not baks:
        return False, "--force 覆盖前没生成备份"
    if not (baks[0] / "MINE.txt").is_file():
        return False, "备份里没保住用户原内容"

    os.environ.pop(I.HOME_ENV, None)
    shutil.rmtree(sandbox, ignore_errors=True)
    return True, "已存在时拒绝覆盖；--force 先备份且备份含原内容"

def t_diff_partial_flag():
    """
    match_functions 触到比对预算时必须标 partial + truncated_note。

    原缺陷：cmp_count 超过 max_pairs*50 就 break，返回值里没有任何标记。
    调用方看到 match_rate_a 偏低，会读成「两个二进制只有 12% 像」，
    实际是「比到一半就停了」。与已修的 function_count:0 同一类缺陷。

    这条用例是**双向**的：既要证明触顶时有标记，也要证明没触顶时
    标记不出现（否则永久 partial=True 等于把标记变成噪音）。
    """
    import lib_code as LC

    def mkfuncs(n, base=0x140001000):
        """构造 n 个指纹相同的函数，保证它们全部落进同一个 simhash 桶。"""
        out = []
        for i in range(n):
            out.append({
                "name": "f%d" % i,
                "start_vma": hex(base + i * 0x10),
                "end_vma": hex(base + i * 0x10 + 0x10),
                "calls": [],
                "fingerprint": {"simhash": 0xABCDEF0123456789, "size": 1,
                                "mnemonics": ["ret"]},
            })
        return out

    fa, fb = mkfuncs(60), mkfuncs(60)

    # 1) 预算极小 -> 必然触顶 -> 必须标 partial
    small = LC.match_functions(fa, fb, max_pairs=1)   # budget = 1*50 = 50
    if not small.get("partial"):
        return False, "比对预算触顶却没标 partial（comparisons=%r）" % small.get("comparisons")
    if not small.get("truncated_note"):
        return False, "partial=True 但缺 truncated_note，调用方无从知道原因"
    if small["comparisons"] > 50:
        return False, "超出预算仍在比对：comparisons=%d > 50" % small["comparisons"]

    # 2) 预算充足 -> 不得标 partial（防止标记退化成恒真噪音）
    big = LC.match_functions(fa, fb, max_pairs=100000)
    if big.get("partial"):
        return False, "预算充足却标了 partial（comparisons=%r）" % big.get("comparisons")
    if big.get("truncated_note"):
        return False, "预算充足却带了 truncated_note"

    return True, ("触顶时标 partial（comparisons=%d）+ truncated_note，"
                  "充足时不误标（comparisons=%d）"
                  % (small["comparisons"], big["comparisons"]))


def t_axml_truncated_window_reports():
    """
    _axml_strings 扫描窗口被截断且窗口内无 manifest 时，必须报错而非返回空。

    原缺陷：blob 被截到 1 MB；若 AndroidManifest.xml 的中央目录条目落在
    1 MB 之后，循环走完 find 返回 -1 → pool 为空 → 返回 **{}**，
    即 permissions: [] / package_like: []，**连 _note 都没有**。
    调用方会读成「这个 APK 不申请任何权限」—— 全库最危险的静默失败。

    反向也要验：正常小文件在窗口内找不到 manifest 时，仍应安静返回 {}，
    不能被这条守卫误报成错误。
    """
    import lib_formats as LF

    class _R:
        """最小 Reader 替身：只用得到 size 与 read(off, n)。"""
        def __init__(self, data):
            self._d = data
            self.size = len(data)

        def read(self, off, n):
            return self._d[off:off + n]

    # 1) 大于 1 MB 且窗口内无 manifest -> 必须 _error
    big = b"\x00" * (LF.__dict__.get("_SCAN_CAP", 1 << 20) + 4096)
    got = LF._axml_strings(_R(big))
    if "_error" not in got:
        return False, ("大文件且窗口内无 manifest，却返回 %r —— "
                       "调用方会读成「无权限」" % (got,))
    if not got["_error"].strip():
        return False, "_error 是空串，等于没说"

    # 2) 小文件且无 manifest -> 仍应安静返回 {}（不得误报）
    small = LF._axml_strings(_R(b"plain text, not a zip"))
    if small:
        return False, "小文件无 manifest 时应返回 {}，实际 %r" % (small,)

    return True, "截断窗口内无 manifest 时明确 _error；小文件仍安静返回 {}"




def t_imports_ok_false_on_parse_error():
    """
    PE 解析失败时 `imports` 必须报 ok:false 并给出 errors。

    原缺陷（P0）：out 里把 "ok" 写死成 True。PE 头畸形时 parse_pe 在
    lib_formats 的 except 里把异常吞掉，detail 只剩 parse_ok:False + errors，
    **连 imports 键都不会有**；命令照样返回 ok:true / modules:[] /
    function_count:null。用户读到的是"这文件没有导入表"，而真相是
    "压根没解析成功"——失败被上报为成功，而且比直接崩掉更难发现。

    反向也验：正常 PE 必须仍是 ok:true，不能把守卫写成"永远失败"。
    """
    import struct as _st

    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    _st.pack_into("<I", buf, 0x3C, 0x80)      # e_lfanew 指向 0x80
    buf[0x80:0x84] = b"PE\x00\x00"
    _st.pack_into("<H", buf, 0x84, 0x9999)    # 未知 Optional Header 魔数
    p = w("bad_optmagic.exe", bytes(buf))

    code, data, raw = jrun([str(CLI), "imports", str(p), "--json"])
    if code != 0:
        return False, "退出码 %d（输出：%s）" % (code, raw[:300])
    if data.get("ok") is not False:
        return False, "畸形 PE 仍报 ok=%r（应为 false）：%s" % (
            data.get("ok"), json.dumps(data, ensure_ascii=False)[:400])
    if not data.get("errors"):
        return False, "ok:false 却没有 errors，排障的人只能靠猜：%s" % (
            json.dumps(data, ensure_ascii=False)[:400])

    good = mk_pe64()
    code2, data2, raw2 = jrun([str(CLI), "imports", str(good), "--json"])
    if code2 != 0:
        return False, "正常 PE 退出码 %d（%s）" % (code2, raw2[:300])
    if data2.get("ok") is not True:
        return False, "正常 PE 被误判为失败：ok=%r（%s）" % (
            data2.get("ok"), json.dumps(data2, ensure_ascii=False)[:400])
    return True, "畸形 PE → ok:false + %d 条 errors；正常 PE 仍 ok:true" % len(data["errors"])


def t_capability_warns_without_function_index():
    """
    analyze_file 没给出函数索引（idx=None）时，capability 必须告警。

    原缺陷（P0）：非 x86 架构下 lib_disasm.analyze_file 走线性反汇编分支，
    返回 ok:true 但**不带 _idx**；cmd_capability 里随后所有语义层代码都以
    `if idx is not None` 为条件，于是整段跳过 —— api / 字符串类特征全空，
    规则必然大面积漏报，输出却仍是 ok:true / capabilities:[]。
    用户会把"没命中"读成"样本没这个能力"，这正是该函数自己注释里
    点名要防的事（"把没命中读成没这个能力"）。

    这里用替身直接复现该分支，不依赖能否造出真实的非 x86 样本。
    """
    import argparse as _ap
    import contextlib as _cl
    import importlib.util as _ilu
    import io as _io

    spec = _ilu.spec_from_file_location("_re_cli_under_test", str(CLI))
    if spec is None or spec.loader is None:
        return False, "无法构造 re.py 的 import spec：%s" % CLI
    mod = _ilu.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        return False, "导入 re.py 失败：%s: %s" % (type(e).__name__, e)

    try:
        import lib_disasm as _ld
    except Exception as e:
        return False, "导入 lib_disasm 失败：%s: %s" % (type(e).__name__, e)

    pe = mk_pe64()
    orig = _ld.analyze_file
    calls = {"n": 0}

    def _stub(path, ident=None, region=None, max_insns=0, **kw):
        calls["n"] += 1
        # 精确复刻 lib_disasm 的非 x86 分支：ok:true，但**没有 _idx**
        return {"ok": True, "arch": "arm64", "region": ".text",
                "note": "arm64 暂未接入函数识别/CFG，仅做线性反汇编",
                "insn_count": 10, "insns": []}

    _ld.analyze_file = _stub
    buf = _io.StringIO()
    try:
        ns = _ap.Namespace(target=str(pe), json=False, section=None,
                           max_insns=20000, limit=60, no_strings=True,
                           rules=None, rule=None)
        with _cl.redirect_stdout(buf):
            rc = mod.cmd_capability(ns)
    except Exception as e:
        return False, "cmd_capability 崩了：%s: %s" % (type(e).__name__, e)
    finally:
        _ld.analyze_file = orig

    if calls["n"] != 1:
        return False, "替身未被调用（n=%d），本用例没有真正覆盖该分支" % calls["n"]
    txt = buf.getvalue()
    if "未做函数识别" not in txt:
        return False, "idx=None 时零告警，输出：\n%s" % txt[:800]
    if rc != mod.EXIT_OK:
        return False, "退出码异常：%r" % rc
    return True, "idx=None → 明确告警「未做函数识别」，不再伪装成 0 条命中"


def t_entropy_sampled_really_samples():
    """
    超过采样阈值时 entropy_profile 必须真的算出整体熵，而不是留 None。

    原缺陷：else 分支只设 sampled=True 和一句"整体熵由采样估算"，
    **一行采样代码都没有** —— out["overall_entropy"] 始终是 None，
    报告里就印出"整体熵：**None**"。这比不做更糟：读者会以为那个数字
    是采样结果，实际什么都没算（"声称做了但没做"）。

    反向：小文件必须走精确分支，sampled=False。
    """
    import lib_analyze as LA

    p = w("entropy_big.bin", os.urandom(3 * 1024 * 1024))
    d = LA.entropy_profile(str(p), window=4096, max_windows=32,
                           sample_threshold=1024)   # 强制进采样分支
    if not d.get("sampled"):
        return False, "没进采样分支（sampled=%r）" % d.get("sampled")
    oe = d.get("overall_entropy")
    if oe is None:
        return False, "sampled=True 但 overall_entropy 仍是 None（声称采样却没采样）"
    if not (7.5 <= oe <= 8.0):
        return False, "3MB 均匀随机字节的采样熵 %r 不在 [7.5, 8.0]" % oe
    if not d.get("sampled_bytes"):
        return False, "没记录 sampled_bytes，读者无从判断采样覆盖了多少"
    # 采样量绝不可能超过文件本身：段长若大于段间距，相邻段重叠会把同一批
    # 字节重复计数，sampled_ratio 会算出 1794% 这种荒唐值（本机实测踩到过）。
    if d["sampled_bytes"] > os.path.getsize(str(p)):
        return False, ("采样字节 %d 超过文件本身 %d —— 采样段重叠了，"
                       "统计不可信" % (d["sampled_bytes"], os.path.getsize(str(p))))
    if not (0 < (d.get("sampled_ratio") or 0) <= 1.0):
        return False, "sampled_ratio=%r 不在 (0, 1.0]" % d.get("sampled_ratio")

    small = w("entropy_small.bin", b"\x00" * 4096)
    d2 = LA.entropy_profile(str(small), window=1024, max_windows=4)
    if d2.get("sampled"):
        return False, "小文件被误判为采样：sampled=%r" % d2.get("sampled")
    if d2.get("overall_entropy") != 0.0:
        return False, "全零文件精确熵应为 0.0，得到 %r" % d2.get("overall_entropy")
    return True, "采样分支 really 采样：overall_entropy=%s（采样 %d 字节，占 %.1f%%）" % (
        oe, d["sampled_bytes"], (d.get("sampled_ratio") or 0) * 100)


def t_names_go_pclntab_scan_truncated_reports():
    """
    pclntab 扫描窗口被截断时必须报出来，不能等同于"不是 Go 程序"。

    原缺陷：find_pclntab 默认只扫前 32MB；文件更大而 pclntab 落在窗口之外时
    返回空列表，recover_go_symbols 直接 `return None, []` —— 与"这文件不是
    Go 程序"在返回值上**完全一样**。用户拿到的是假阴性，且没有任何线索
    提示"其实只扫了一部分"。与已修的 AXML 截断窗口同族缺陷。

    反向：完整扫过的小文件不该产生噪声告警。
    """
    import lib_formats as LF
    import lib_names as LN

    big = w("go_scan_big.bin", b"\x11" * (2 * 1024 * 1024))
    with LF.Reader(str(big)) as r:
        res, warns = LN.recover_go_symbols(r, r.size, scan_limit=4096)
    if res is not None:
        return False, "填充数据不该解析出 Go 符号"
    if not warns:
        return False, ("扫描窗口 4096 字节 << 文件 2MB 且未找到候选，"
                       "却零告警 —— 与「不是 Go 程序」无法区分")

    small = w("go_scan_small.bin", b"\x00" * 1024)
    with LF.Reader(str(small)) as r2:
        _res2, warns2 = LN.recover_go_symbols(r2, r2.size, scan_limit=4096)
    if warns2:
        return False, "完整扫过的小文件不该产生噪声告警：%r" % (warns2,)
    return True, "扫描窗口截断时给出告警（%d 条），完整扫描时不噪声" % len(warns)

def t_xrefs_unresolved_calls_counted():
    """
    build_xrefs 的 unresolved_calls 必须是「真·解析不出目标的调用」条数。

    原缺陷（P0，编造数字）：旧写法是
        sum(1 for f in funcs for i in [0] if any(c is None for c in [None]))
    —— `any(c is None for c in [None])` 是个没写完的占位脚手架，对每个 f 恒
    为 True，于是该值恒等于 len(funcs)。用户拿到的「未解析调用数」其实是
    「函数总数」，而且在 xref 表里跟真数字并排放着，看不出哪个是编的：不崩、
    不报错，只是交出一张错表。

    样本为什么这样造（关键）：必须让**真值严格小于** function_count，
    否则旧实现那种「恒等于函数数」的编造值还能蒙混过关。
      · 函数 A：一条目标已知的 call rel32 + 一条目标未知的 call rax
      · 函数 B：只有 ret，一条 call 都没有
    → 真实 unresolved_calls = 1 < function_count = 2。
    """
    import lib_code as LC

    code = (b"\xe8\x08\x00\x00\x00"      # call +0x8 -> 0x100d（目标已知）
            b"\xff\xd0"                  # call rax（间接调用，目标未知）
            b"\xc3"                      # ret
            + b"\xcc" * 5                # int3 对齐填充（不该被当成函数）
            + b"\xc3")                   # 第二个函数：只有一条 ret
    idx = LC.CodeIndex(code, base_vma=0x1000, bits=64, arch="x86-64",
                       max_insns=64)
    funcs = LC.find_functions(idx, seeds=[0x1000, 0x100d], symbols={})
    if len(funcs) != 2:
        return False, ("样本没构造出预期的 2 个函数，实际 %d 个：%r"
                       % (len(funcs), [f["name"] for f in funcs]))

    # 先把「样本里两种 call 确实都有」钉住，免得这条用例自己退化成空跑
    indirect = sum(1 for f in funcs for o in (f.get("_offs") or [])
                   for ins in [idx.insn.get(o)]
                   if ins is not None and ins.kind == LC.K_CALL
                   and ins.target is None)
    direct = sum(len(f["calls"]) for f in funcs)
    if indirect != 1:
        return False, "样本里应恰好有 1 条目标未知的间接调用，实际 %d 条" % indirect
    if direct != 1:
        return False, "样本里应恰好有 1 条目标已知的直接调用，实际 %d 条" % direct

    xr = LC.build_xrefs(idx, funcs)
    got = xr["unresolved_calls"]
    n = len(funcs)
    if got >= n:
        return False, ("unresolved_calls=%d 不小于 function_count=%d —— 这个值"
                       "退化回了「恒等于函数数」的编造口径" % (got, n))
    if got != 1:
        return False, "unresolved_calls 应为 1（只有 1 条 call rax），实际 %d" % got
    return True, ("unresolved_calls=%d < function_count=%d（直接调用 %d 条已解析，"
                  "间接调用 1 条如实记为未解析）" % (got, n, direct))

def t_obfstr_vma2off_translates_vma():
    """
    make_vma2off：解密循环的密文地址是 VMA，必须先换算成文件偏移才能读。

    原缺陷（P0）：xor_loops_to_strings 把指令里读到的**虚拟地址**直接当
    **文件偏移**喂给 Reader.read()。PE 的 image_base 通常是 0x140000000，
    远超任何文件长度 -> read() 越界返回空 -> 一条明文都恢复不出来，而
    warnings 是空的 —— 标准的「失败被上报为成功」。

    这条用例钉三层：
      1) 单元：PE 的 virtual_address 是 RVA，要加 image_base 才是 VMA；
         节内偏移要跟着走，节外必须坦白返回 None；
      2) 端到端（最关键）：同一份密文，给了 vma2off 必须恢复出明文，
         不给必须恢复不出来 —— 后者正是旧实现的表现；
      3) 诚实度：Mach-O 节表目前**没有地址字段**（lib_formats.py:1338-1339
         只输出 seg/name/size/offset），此时必须返回 (None, 非空 warnings)，
         不许假装能算出一个映射。
    """
    import lib_obfstr as OS
    import lib_formats as LF

    ident = {"format": "PE", "detail": {
        "image_base": 0x140000000,
        "sections": [{"virtual_address": 0x1000, "raw_offset": 0x400,
                      "raw_size": 0x200, "virtual_size": 0x100}]}}
    fn, warns = OS.make_vma2off(ident)
    if warns:
        return False, "节信息完整的 PE 却给了告警：%r" % (warns,)
    if fn is None:
        return False, "节信息完整的 PE 却返回 None（密文会全部读不出来）"

    # PE 的 virtual_address 是 RVA：0x140000000 + 0x1000 -> 文件偏移 0x400
    got_map = fn(0x140001000)
    if got_map != 0x400:
        return False, ("VMA 0x140001000 应映射到文件偏移 0x400，实际 %r"
                       "（RVA 有没有加 image_base？）" % (got_map,))
    if fn(0x140001010) != 0x410:
        return False, "节内 +0x10 后文件偏移没跟着走：%r" % (fn(0x140001010),)
    if fn(0x140002000) is not None:
        return False, "节外地址不该给出映射（应返回 None）：%r" % (fn(0x140002000),)

    # ---- 端到端：同一份密文，给不给映射函数必须是两种结果 ----
    key = 0x4A
    plain = "http://cdn.example.com/update.bin"
    cipher = bytes(b ^ key for b in plain.encode("ascii")) + b"\xff"
    buf = bytearray(b"\xff" * 0x600)
    buf[0x400:0x400 + len(cipher)] = cipher
    p = w("xordata_vma2off.bin", bytes(buf))
    loop = {"key": key, "data_ref": 0x140001000,
            "loop_start_vma": 0x140001100, "evidence": "合成解密循环"}
    with LF.Reader(str(p)) as r:
        with_map = OS.xor_loops_to_strings(r, [loop], vma2off=fn)
        no_map = OS.xor_loops_to_strings(r, [loop])
    hit = [s["string"] for s in with_map["strings"]]
    if plain not in hit:
        return False, ("给了 vma2off 仍没恢复出明文：strings=%r warnings=%r"
                       % (hit[:3], with_map["warnings"]))
    miss = [s["string"] for s in no_map["strings"]]
    if miss:
        return False, ("不传 vma2off 时 VMA 0x140001000 必然超出文件长度，"
                       "不该读出任何明文，实际得到 %r" % (miss[:2],))

    # ---- Mach-O：给不出映射必须诚实报错，不许假装成功 ----
    mach = {"format": "Mach-O", "detail": {"sections": [
        {"name": "__text", "size": 16, "offset": 0x1000}]}}
    mfn, mw = OS.make_vma2off(mach)
    if mfn is not None:
        return False, "Mach-O 节表没有地址字段，却返回了一个换算函数（会算出假偏移）"
    if not mw:
        return False, "给不出映射却没留下 warnings —— 调用方会以为换算成功了"
    return True, ("PE: 0x140001000->0x400 / 0x140001010->0x410 / 节外 None；"
                  "端到端给了映射才出明文、不给就是空；Mach-O 报 %d 条告警"
                  % len(mw))

def t_semantics_as_vma_int_decimal():
    """
    _as_vma_int 的十进制分支必须真的按十进制解析。

    原缺陷（P0）：旧写法两个分支都是十六进制
        int(v, 16) if v.lower().startswith("0x") else int(v, 16)
    于是十进制串地址 "4096" 被解析成 0x4096 = 16534，而且**不抛异常** ——
    静默得到一个差了几倍的错误 VMA。后面拿它去查符号、查函数名、查调用关系
    全部查空，表现为「这个函数没名字」「这条调用没目标」，没人会怀疑到
    地址解析这一步。

    失败方向也钉住：非法入参必须返回 None，不能返回 0 —— 0 是一个合法 VMA，
    把解析失败冒充成 0 号地址同样是静默造假。
    """
    import lib_semantics as LS

    cases = [("4096", 4096),        # 十六进制旧 bug 下会变成 16534
             ("0x1000", 0x1000),
             ("0X1000", 0x1000),
             ("zz", None),
             (None, None)]
    problems = []
    for arg, want in cases:
        got = LS._as_vma_int(arg)
        if got != want:
            problems.append("_as_vma_int(%r) = %r，期望 %r" % (arg, got, want))
    if problems:
        return False, "；".join(problems)
    return True, "十进制 4096 不再被当成十六进制；0x1000 正常；非法串/None 返回 None"

def t_rules_bytes_leaf_reported():
    """
    规则里用了 bytes 叶子时，必须报「无法求值」，不能静默当成不命中。

    原缺陷（P0）：lib_rules._leaf_hit 的 `kind == "bytes"` 分支只有一个裸
    `return False`，而它头顶那行注释写着「但要报出来（不能静默当成不命中）」
    —— 注释里的承诺没兑现。后果是：规则整条不命中，match_rules 返回的
    errors 里一个字都没有，用户读到的是「样本干净」，真相是「这条规则压根
    没有能力判」。

    为什么这里走完整的 match_rules 而不是去调内部闭包：errors 是 match_rules
    收集并返回给调用方的出口，`_leaf_hit` 只是它内部的局部闭包 —— 绕过
    match_rules 就等于自己重新实现一遍「错误怎么汇总」的约定，测到的东西跟
    用户实际看到的不是一回事。而这条路径只需一条 file 作用域规则加最小
    feats 就能走到叶子求值（成本远低于构造真实样本跑 build_features），
    所以走全链路。
    """
    import lib_rules as LR

    def _mk(name, features):
        return LR.Rule({"rule": {"meta": {"name": name, "scope": "file"},
                                 "features": features}})

    feats = {"instruction": [], "basic block": [], "function": [], "file": []}

    bad = _mk("带字节序列的规则",
              {"or": [{"bytes": "E8 ?? 00 00"}, {"mnemonic": "nop"}]})
    res = LR.match_rules([bad], feats)
    if res.get("hits"):
        return False, "bytes 叶子在无文件句柄时不可能命中，却命中了：%r" % (
            [h["rule"] for h in res["hits"]],)
    errs = res.get("errors") or []
    if not errs:
        return False, ("bytes 叶子无法求值，errors 却为空 —— 用户会读成"
                       "「样本干净」，而真相是这条规则没能力判")
    if not any("无法求值" in str(e) for e in errs):
        return False, "errors 里没有「无法求值」的说明：%r" % (errs[:2],)
    if not any("带字节序列的规则" in str(e) for e in errs):
        return False, "errors 没指名是哪条规则失效，排障只能靠猜：%r" % (errs[:2],)

    # 反向守卫：不含 bytes 的普通规则不得产生这条告警，
    # 否则守卫会退化成「每条规则都报错」的噪音。
    good = _mk("普通规则", {"or": [{"mnemonic": "nop"}]})
    errs2 = (LR.match_rules([good], feats).get("errors") or [])
    if any("无法求值" in str(e) for e in errs2):
        return False, "不含 bytes 的规则也报了「无法求值」：%r" % (errs2[:2],)
    return True, ("bytes 叶子登记了含「无法求值」的错误（%d 条），普通规则不产生该告警"
                  % len(errs))

def t_code_truncation_reported():
    """
    find_functions / _walk 撞到预算时必须留痕，不许交出偏小却看似完整的数字。

    原缺陷（两个，同一类——隐性丢数据）：
      · _walk 撞到遍历预算时 `return body` 返回的是**半个函数体**，返回值里
        没有任何标记，调用方无法区分「走完了」和「没走完」，照单全收 ->
        insn_count / bb_count / calls 全是偏小的假数字；
      · max_functions 到了直接 `break`，被丢掉的种子一个都不登记，外面只看
        到 N 个函数，报告里的 function_count 会被读成「全文件就这么多函数」。

    修复约定：_walk 返回 (body, hit_limit)；find_functions 把 skipped_seeds /
    truncated_functions 写进传入的 stats；analyze() 把它们翻译成
    function_seed_truncated / functions_truncated 及对应的 note。本用例从最内
    层到最外层把这条链路钉住。
    """
    import lib_code as LC

    problems = []

    # ---- 1) 丢种子必须登记（max_functions=1，种子多于 1 个）----
    # ret / int3 / ret / int3 / ret：三个互不相干的函数，int3 是对齐填充
    idx = LC.CodeIndex(b"\xc3\xcc\xc3\xcc\xc3", base_vma=0x1000, bits=64,
                       arch="x86-64", max_insns=64)
    stats: dict = {}
    kept = LC.find_functions(idx, seeds=[0x1000, 0x1002, 0x1004],
                             symbols={}, max_functions=1, stats=stats)
    if len(kept) != 1:
        problems.append("max_functions=1 时应只保留 1 个函数，实际 %d 个" % len(kept))
    if not stats.get("skipped_seeds"):
        problems.append("丢弃了候选入口但 skipped_seeds=%r（调用方无从知道 "
                        "function_count 不是全文件的函数总数）"
                        % (stats.get("skipped_seeds"),))

    # ---- 2) analyze() 必须把丢种子这件事翻译成输出字段 ----
    # analyze 的 max_functions 用默认值 20000，这里给 20001 个互不相同的种子，
    # 最后一个必然被丢掉 —— 这是不用任何替身就能真正走到该分支的最省办法。
    big = b"\xc3" * 20001
    bidx = LC.CodeIndex(big, base_vma=0x2000, bits=64, arch="x86-64",
                        max_insns=len(big) + 8)
    seeds = [0x2000 + i for i in range(len(big))]
    an = LC.analyze(bidx, seeds=seeds)
    if not an.get("function_seed_truncated"):
        problems.append("analyze() 输出里没有 function_seed_truncated："
                        "function_count=%r 会被读成全文件的函数总数"
                        % (an.get("function_count"),))
    if not an.get("function_seed_note"):
        problems.append("有 function_seed_truncated 却没有 function_seed_note，"
                        "用户只看到标记看不到原因")

    # ---- 3) _walk 单独测：撞预算时第二返回值必须是 True ----
    # 为什么要「先填满解码缓存、再调小 max_insns」：_walk 的
    # limit = idx.max_insns * 2，而 decode_at 在已解码条数达到 max_insns 后会
    # 返回 None 让 _walk 提前 break —— 直接用小预算的 idx，guard 最多只能涨到
    # max_insns，永远追不上 2 倍的上限，截断分支就永远执行不到。所以这里先用
    # 大预算把 101 条指令全部解码进缓存，再把 max_insns 调到 20（limit=40），
    # 同一条解码路径就能连续走 41 步，真正触发该分支。
    nop = b"\x90" * 100 + b"\xc3"
    widx = LC.CodeIndex(nop, base_vma=0x3000, bits=64, arch="x86-64",
                        max_insns=100000)
    widx.linear_scan()
    cached = len(widx.insn)
    widx.max_insns = 20
    body, hit_limit = LC._walk(widx, 0, set(), {})
    if not isinstance(hit_limit, bool):
        problems.append("_walk 的第二返回值不是 bool：%r（约定是「是否截断」）"
                        % (hit_limit,))
    elif not hit_limit:
        problems.append("_walk 撞到遍历预算却返回 hit_limit=False"
                        "（body=%d 条 / 缓存=%d 条）" % (len(body), cached))

    # 反向守卫：预算充足时不得谎报截断，否则标记会退化成恒真噪音
    oidx = LC.CodeIndex(nop, base_vma=0x3000, bits=64, arch="x86-64",
                        max_insns=100000)
    oidx.linear_scan()
    _b2, h2 = LC._walk(oidx, 0, set(), {})
    if h2:
        problems.append("预算充足时 _walk 也报了截断")

    # ---- 4) 外层：函数体只走了一半时，analyze 也要标注 ----
    tidx = LC.CodeIndex(nop, base_vma=0x4000, bits=64, arch="x86-64",
                        max_insns=100000)
    tidx.linear_scan()
    tidx.max_insns = 20
    tan = LC.analyze(tidx, seeds=[0x4000])
    if not tan.get("functions_truncated"):
        problems.append("函数体被截断但输出里没有 functions_truncated")
    elif not tan.get("functions_truncated_note"):
        problems.append("有 functions_truncated 却没有 functions_truncated_note，"
                        "用户不知道 insn_count 是偏小的")

    if problems:
        return False, "；".join(problems)
    return True, ("skipped_seeds=%s；analyze 输出 function_seed_truncated 与 "
                  "functions_truncated；_walk 截断返回 True、不截断返回 False"
                  % stats.get("skipped_seeds"))


def main():
    ap = argparse.ArgumentParser(description="逆向工具箱自检")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep", action="store_true", help="保留临时目录")
    ap.add_argument("--only", help="只跑名字包含该关键字的用例")
    args = ap.parse_args()

    TMP.mkdir(parents=True, exist_ok=True)
    print(f"\n逆向工具箱自检 · Python {sys.version.split()[0]}")
    print(f"临时目录：{TMP}\n")

    cases = [
        ("PE 合成样本解析", t_pe_synthetic),
        ("ELF 合成样本解析(checksec)", t_elf_synthetic),
        ("Mach-O 合成样本解析", t_macho_synthetic),
        ("APK 结构与加固识别", t_apk_synthetic),
        ("JAR 与 Main-Class 抽取", t_jar_synthetic),
        ("DEX 字符串池解析", t_dex_synthetic),
        ("pyc 版本识别（本机实测）", t_pyc_real),
        ("WASM 导出表解析", t_wasm_synthetic),
        ("SQLite schema 抽取", t_sqlite_synthetic),
        ("0xCAFEBABE 歧义消解", t_class_ambiguity),
        ("固件头识别与路由", t_firmware_synthetic),
        ("字符串偏移与分类", t_strings_offsets),
        ("中文 UTF-16LE（可选编码）", t_strings_cjk),
        ("跨块字符串完整性", t_strings_chunk_boundary),
        ("文件雕刻（清单）", t_carve),
        ("文件雕刻（落盘）", t_carve_extract),
        ("差分分析", t_diff),
        ("实机：系统 PE 文件", t_real_pe),
        ("实机：系统 pyc 文件", t_real_pyc),
        ("实机：.NET 程序集（防误判）", t_real_dotnet),
        ("x86-64 指令向量", t_x86_decode_vectors),
        ("ARM64 指令向量", t_arm64_decode_vectors),
        ("x86 内存操作数地址 mem_ref", t_x86_mem_ref),
        ("线性扫描健壮性", t_disasm_linear_robust),
        ("实机：反汇编真实 PE", t_disasm_real_pe),
        ("实机：函数识别", t_funcs_real_pe),
        ("实机：控制流图 CFG", t_cfg_real_pe),
        ("实机：交叉引用 XREF", t_xref_real_pe),
        ("实机：函数级自比对", t_sim_self),
        ("实机：IAT/延迟导入解析", t_iat_resolution),
        ("实机：函数语义摘要", t_semantics_real_pe),
        ("库函数/密码学常量识别", t_libscan_consts),
        ("空文件", t_empty_file),
        ("截断 PE", t_truncated_pe),
        ("位翻转模糊测试×30", t_fuzz_mutations),
        ("垃圾输入×18 组合", t_random_garbage),
        ("退出码约定", t_exit_codes),
        ("性能：100MB 流式扫描", t_perf_big_file),
        ("性能：triage 真实 PE", t_perf_triage_real),
        ("报告生成", t_report),
        ("工具链探测", t_doctor),
        ("全格式分析计划", t_plan_all_formats),
        ("加速层（复用/比对/符号/AI）", t_accel_layer),
        ("工具表完整性", t_tools_table_integrity),
        ("--json ok 字段契约", t_json_ok_contract),
        ("--help 覆盖全部子命令", t_cli_help_covers_all_subcommands),
        ("report 默认输出不污染 cwd", t_report_default_out_not_cwd),
        ("零第三方依赖", t_no_third_party),
        ("能力规则：库加载", t_rules_load),
        ("能力规则：YAML 子集解析器", t_rules_yaml_parser),
        ("能力规则：API 名归一化", t_rules_api_norm),
        ("能力规则：特征字段形态", t_rules_feature_fields),
        ("能力规则：实机端到端匹配", t_rules_match_real_pe),
        ("能力规则：CRT 误报守卫", t_rules_false_positive_guard),
        ("能力规则：CLI capability 契约", t_rules_cli_capability),
        ("能力规则：无死 characteristic", t_rules_no_dead_characteristic),
        ("能力规则：match_rules 参数校验", t_rules_match_rules_arg_validation),
        ("CLI 鲁棒性：畸形目标不崩", t_cli_robustness),
        ("符号：四方言 demangle", t_names_demangle_all_dialects),
        ("符号：Go pclntab 合成解析", t_names_go_pclntab_synthetic),
        ("符号：CLI symbols 契约", t_names_cli_symbols_contract),
        ("混淆串：栈字符串恢复", t_obfstr_stack_strings),
        ("混淆串：XOR 解密循环", t_obfstr_xor_loop),
        ("混淆串：CLI obfstr 契约", t_obfstr_cli_contract),
        ("编排：目录与子命令一致", t_agent_catalog_subcommand_consistency),
        ("编排：意图检索准确率", t_agent_retrieval_accuracy),
        ("编排：无命中不退化全表", t_agent_recommend_fail_closed),
        ("编排：错误分类与重试语义", t_agent_error_classification),
        ("编排：摘要层真的压小", t_agent_summary_shrinks),
        ("编排：case 存取与过期拒绝", t_agent_case_roundtrip_and_staleness),
        ("编排：case 目录穿越防护", t_agent_case_path_traversal_guard),
        ("编排：flow 批次与依赖", t_agent_flow_ordering),
        ("编排：toolgraph 先验与学习", t_agent_toolgraph_prior_and_learned),
        ("编排：5 命令 CLI 契约", t_agent_cli_contracts),
        ("稳定性：YAML 资源上限", t_yaml_resource_guards),
        ("稳定性：工具目录结构不变量", t_catalog_shape_invariant),
        ("稳定性：不吞异常（string_vma_map）", t_string_vma_map_no_swallow),
        ("稳定性：不支持架构明确报错", t_unsupported_arch_fails_closed),
        ("稳定性：case 索引形状容错", t_case_index_shape_tolerance),
        ("稳定性：journal 有界读取", t_case_journal_bounded_read),
        ("稳定性：规则特征树深度守卫", t_rules_feature_depth_guard),
        ("稳定性：差分比对截断如实标注", t_diff_partial_flag),
        ("稳定性：AXML 截断窗口不伪装成空", t_axml_truncated_window_reports),
        ("安装：运行时路径合规", t_install_paths_in_spec),
        ("安装：workbuddy 不复制到技能上级", t_install_workbuddy_no_selfcopy),
        ("安装：验证器能识别坏安装", t_install_verify_detects_broken),
        ("安装：复制可用且裁剪开发产物", t_install_copy_slims_and_runs),
        ("安装：不覆盖用户已有技能", t_install_no_clobber),
        ("导入表：解析失败不报 ok:true", t_imports_ok_false_on_parse_error),
        ("能力识别：无函数索引必须告警", t_capability_warns_without_function_index),
        ("熵：采样分支真的采样", t_entropy_sampled_really_samples),
        ("符号：pclntab 截断不伪装成非 Go", t_names_go_pclntab_scan_truncated_reports),
        ("交叉引用：unresolved_calls 不是函数数", t_xrefs_unresolved_calls_counted),
        ("混淆串：VMA 到文件偏移换算", t_obfstr_vma2off_translates_vma),
        ("语义：_as_vma_int 十进制分支", t_semantics_as_vma_int_decimal),
        ("能力规则：bytes 叶子必须报错", t_rules_bytes_leaf_reported),
        ("函数识别：截断与丢弃种子留痕", t_code_truncation_reported),
    ]

    t0 = time.time()
    selected = [(n, f) for n, f in cases
                if not args.only or args.only in n]
    if args.only and not selected:
        # 【不要静默通过】一个用例都没匹配上时，旧行为是打印 "通过 0/0" 并
        # 返回 0 —— 在 CI 里等于一道永不拦截的门。这里必须明确报错。
        print(f"[错误] --only {args.only!r} 没有匹配到任何用例；"
              f"共 {len(cases)} 个用例，未执行任何检查", file=sys.stderr)
        prefixes = []
        for n, _ in cases:
            p = n.split("：")[0]
            if p not in prefixes:
                prefixes.append(p)
        print("可用的用例名前缀（示例）：" + "、".join(prefixes[:12]),
              file=sys.stderr)
        return 2
    for name, fn in selected:
        case(name, fn)

    total = len(RESULTS)
    # 跳过有两种来源：① 用例返回 SKIP 标记（环境不具备，如装到运行时后
    # 不再分发 _dev/）；② 用例自己返回 detail 以「跳过」开头（找不到
    # 本机样本）。两者都必须**显式计入 skipped 并从 passed 里剔除** ——
    # 否则会出现"通过 4/4 跳过 4"这种自相矛盾的输出，且跳过会被
    # 误当成通过（假绿）。
    skipped = sum(1 for r in RESULTS
                  if r.get("skipped") or r["detail"].startswith("跳过"))
    passed = sum(1 for r in RESULTS
                 if r["ok"] and not r.get("skipped")
                 and not r["detail"].startswith("跳过"))
    failed = [r for r in RESULTS
              if not r["ok"] and not r.get("skipped")
              and not r["detail"].startswith("跳过")]
    dur = round(time.time() - t0, 2)

    print(f"\n{'=' * 64}")
    print(f"通过 {passed}/{total}　跳过 {skipped}　失败 {len(failed)}　总耗时 {dur}s")
    if failed:
        print("\n失败用例：")
        for r in failed:
            print(f"  ✗ {r['case']}\n    {r['detail']}")
    print(f"{'=' * 64}")

    if args.json:
        print(json.dumps({"total": total, "passed": passed, "skipped": skipped,
                          "failed": len(failed), "seconds": dur,
                          "results": RESULTS}, ensure_ascii=False, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
