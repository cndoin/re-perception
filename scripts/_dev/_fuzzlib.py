# -*- coding: utf-8 -*-
"""库级 fuzz：直接轰解析器，绕过 CLI 的兜底逻辑（修正版）。

为什么不能只测 CLI：CLI 有一层 `except` 兜底，会把异常转成退出码 4 /
错误 JSON。这掩盖了"到底是**预期内的目标非法**，还是**我们自己写崩了**"
的区别。真正的 bug 往往藏在"畸形输入 → 内部状态不一致 → 后续代码的
假设被打破"。

判定：出现以下异常即视为**缺陷**（说明代码没考虑这种情况）：
    AttributeError, KeyError, IndexError, TypeError,
    struct.error, ZeroDivisionError, RecursionError,
    MemoryError, OverflowError, UnboundLocalError, StopIteration
允许：明确表示"目标/格式非法"的异常（解析失败语义）。

【重要】本文件的调用必须按**真实签名**来（path 而非 bytes、
idx 是索引对象而非原始字节），否则测出来的是"我调错了"而不是"代码有 bug"。
第一版就犯过这个错，把 200 多处假阳性当成缺陷 —— 记在这里防止复发。
"""
from __future__ import annotations

import os
import random
import signal
import struct
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
sys.path.insert(0, SCRIPTS)

import lib_analyze as A          # noqa: E402
import lib_code as C             # noqa: E402
import lib_disasm as D           # noqa: E402
import lib_formats as F          # noqa: E402
import lib_libscan as LS         # noqa: E402
import lib_rules as LR           # noqa: E402
import lib_semantics as S        # noqa: E402
import lib_symbols as SY         # noqa: E402
import lib_x86 as X              # noqa: E402
import lib_arm as ARM            # noqa: E402

BAD_EXC = (AttributeError, KeyError, IndexError, TypeError, struct.error,
           ZeroDivisionError, RecursionError, MemoryError, OverflowError,
           UnboundLocalError, StopIteration)

issues = []
calls = 0


def probe(label, fn, *a, **kw):
    global calls, _LAST
    calls += 1
    _LAST = label
    if calls % 50 == 0:
        print("   ... 已跑 %d 次（最后：%s）" % (calls, label[:60]), flush=True)
    try:
        fn(*a, **kw)
    except BAD_EXC as e:
        tb = traceback.format_exc().strip().splitlines()
        frames = [l.strip() for l in tb if "File " in l and "lib" in l]
        where = frames[-1] if frames else (tb[-3].strip() if len(tb) >= 3 else "")
        issues.append((label, type(e).__name__, str(e)[:120], where))
    except Exception:
        pass


_LAST = ""
SLOW = []          # 超过阈值但仍返回的调用
SLOW_LIMIT = 5.0   # 秒


def phase(name):
    print(">> %s（累计 %d 次）" % (name, calls), flush=True)


class _Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise _Timeout()


def probe_timed(label, fn, *a, **kw):
    """带墙钟上限的 probe。

    为什么需要：有些**合法**调用在坏数据上会非常慢（比如
    analyze_file 跑 200KB 重复字节要 5s+）。慢不等于 bug，但如果
    会拖到"看起来卡死"，就必须测量并记下来，否则整个压测跑不完、
    也就永远发现不了后面的问题。
    """
    global calls
    calls += 1
    if calls % 50 == 0:
        print("   ... 已跑 %d 次（最后：%s）" % (calls, label[:58]), flush=True)
    import time as _t
    t0 = _t.time()
    can_alarm = hasattr(signal, "SIGALRM")
    old = None
    if can_alarm:
        try:
            old = signal.signal(signal.SIGALRM, _alarm)
            signal.alarm(int(SLOW_LIMIT) + 1)
        except Exception:
            can_alarm = False
    try:
        fn(*a, **kw)
    except _Timeout:
        SLOW.append((label, SLOW_LIMIT + 1, "超过硬上限，已中断"))
    except BAD_EXC as e:
        tb = traceback.format_exc().strip().splitlines()
        frames = [l.strip() for l in tb if "File " in l and "lib" in l]
        where = frames[-1] if frames else (tb[-3].strip() if len(tb) >= 3 else "")
        issues.append((label, type(e).__name__, str(e)[:120], where))
    except Exception:
        pass
    finally:
        if can_alarm:
            signal.alarm(0)
            if old is not None:
                try:
                    signal.signal(signal.SIGALRM, old)
                except Exception:
                    pass
    dt = _t.time() - t0
    if dt > SLOW_LIMIT:
        SLOW.append((label, round(dt, 2), "慢"))


# ---------------------------------------------------------------- 样本落盘

def write_samples(tmp: str) -> dict[str, str]:
    """落盘成真文件 —— 接口收的是路径。"""
    T = {}

    def w(name, data: bytes) -> str:
        p = os.path.join(tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    T["空"] = w("empty.bin", b"")
    T["1 字节"] = w("one.bin", b"\x00")
    T["全 FF 4K"] = w("ff4k.bin", b"\xff" * 4096)
    T["全 00 4K"] = w("z4k.bin", b"\x00" * 4096)
    T["MZ 4K"] = w("mz4k.bin", b"MZ" + b"\x00" * 4094)
    T["MZ+垃圾"] = w("mzgarbage.bin", b"MZ" + random.Random(7).randbytes(4094))
    T["ELF 4K"] = w("elf4k.bin", b"\x7fELF" + b"\x00" * 4092)
    T["MachO 4K"] = w("macho4k.bin", b"\xcf\xfa\xed\xfe" + b"\x00" * 4092)
    T["ZIP 4K"] = w("zip4k.bin", b"PK\x03\x04" + b"\x00" * 4092)
    T["DEX 4K"] = w("dex4k.bin", b"dex\n035\x00" + b"\x00" * 4086)
    T["WASM 4K"] = w("wasm4k.bin", b"\x00asm\x01\x00\x00\x00" + b"\x00" * 4088)
    T["SQLite 4K"] = w("sqlite4k.bin", b"SQLite format 3\x00" + b"\x00" * 4080)
    T["javaclass 4K"] = w("jclass4k.bin", b"\xca\xfe\xba\xbe" + b"\x00" * 4092)
    T["pyc 4K"] = w("pyc4k.bin", b"\x00" * 16 + b"\xff" * 4080)
    T["PDF 4K"] = w("pdf4k.bin", b"%PDF-1.7\n" + b"\x00" * 4088)
    T["随机 8K"] = w("rand8k.bin", random.Random(9).randbytes(8192))
    T["超长单行"] = w("longline.bin", b"Q" * 200000)
    T["NUL 串海"] = w("manystr.bin", b"a\x00" * 30000)
    T["高熵 1M"] = w("hi_ent.bin", random.Random(3).randbytes(1 << 20))

    # ZIP 谎报尺寸（中央目录 + 本地头都极端）
    z = bytearray(b"PK\x03\x04" + b"\x00" * 4092)
    struct.pack_into("<H", z, 10, 0xFFFF)
    struct.pack_into("<I", z, 20, 0xFFFFFFFF)
    T["ZIP 谎报尺寸"] = w("zip_lie.bin", bytes(z))

    # PE：节数谎报 0xFFFF
    pe = bytearray(0x1000)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x44, 0x8664, 0xFFFF, 0, 0, 0, 240, 2)
    struct.pack_into("<H", pe, 0x40 + 24, 0x20B)
    T["PE 节数 0xFFFF"] = w("pe_nsec.bin", bytes(pe))

    # PE：节表偏移/大小全垃圾
    pe2 = bytearray(pe)
    struct.pack_into("<H", pe2, 0x46, 2)
    st = 0x40 + 24 + 240
    for i in range(2):
        pe2[st + i * 40: st + i * 40 + 8] = b".badsect"
        struct.pack_into("<IIII", pe2, st + i * 40 + 8, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF)
    T["PE 节表全垃圾"] = w("pe_badsect.bin", bytes(pe2))

    # PE：合法最小 PE，用于让 code/disasm 有真实工作
    ok = bytearray(0x800)
    ok[0:2] = b"MZ"
    struct.pack_into("<I", ok, 0x3C, 0x40)
    ok[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", ok, 0x44, 0x8664, 2, 0x65000000, 0, 0, 240, 2)
    opt = 0x40 + 24
    struct.pack_into("<H", ok, opt, 0x20B)
    struct.pack_into("<Q", ok, opt + 24, 0x140000000)
    struct.pack_into("<I", ok, opt + 32, 0x1000)
    struct.pack_into("<I", ok, opt + 36, 0x200)
    struct.pack_into("<I", ok, opt + 56, 0x3000)
    struct.pack_into("<I", ok, opt + 60, 0x200)
    struct.pack_into("<H", ok, opt + 68, 3)
    struct.pack_into("<I", ok, opt + 108, 16)
    struct.pack_into("<I", ok, opt + 16, 0x1000)
    struct.pack_into("<II", ok, opt + 112 + 8, 0x2000, 0x3C)
    st = opt + 240
    ok[st:st + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", ok, st + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", ok, st + 36, 0x60000020)
    ok[st + 40:st + 48] = b".idata\x00\x00"
    struct.pack_into("<IIII", ok, st + 48, 0x200, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", ok, st + 76, 0xC0000040)
    buf = bytearray(0x800)
    buf[0x200:0x204] = b"\x48\x31\xc0\xc3"
    T["合法 PE64"] = w("ok_pe64.exe", bytes(buf) if False else bytes(ok))
    return T


# ---------------------------------------------------------------- 各组

def fuzz_formats(T):
    for name, path in T.items():
        probe("formats.identify/%s" % name, F.identify, path)
        probe("formats.identify(deep)/%s" % name, F.identify, path, True)
        probe("formats.parse_detail/%s" % name, F.parse_detail, path)
        probe("formats.hashes/%s" % name, F.hashes, path)
        for p in (F.parse_pe, F.parse_elf, F.parse_macho, F.parse_dex,
                  F.parse_zip, F.parse_pyc, F.parse_wasm, F.parse_sqlite,
                  F.parse_javaclass):
            probe("formats.%s/%s" % (p.__name__, name), p, path)


def fuzz_analyze(T):
    for name, path in T.items():
        probe("analyze.classify/%s" % name, A.classify, path)
        probe("analyze.scan_strings/%s" % name, A.scan_strings, path)
        probe("analyze.scan_strings(pat)/%s" % name,
              A.scan_strings, path, 4, None, 200, r"[A-Z]{3,}")
        probe("analyze.scan_strings(0len)/%s" % name,
              A.scan_strings, path, 0, None, 50)
        probe("analyze.entropy_profile/%s" % name, A.entropy_profile, path)
        probe("analyze.carve/%s" % name, A.carve, path)
        for fn in (A.parse_detail if hasattr(A, "parse_detail") else A.classify,):
            pass
    # diff：同文件/不同文件
    keys = list(T)
    for k in keys[:6]:
        probe("analyze.diff_files/%s-self" % k, A.diff_files, T[k], T[k])
    for i in range(0, min(6, len(keys) - 1)):
        probe("analyze.diff_files/%s+%s" % (keys[i], keys[i + 1]),
              A.diff_files, T[keys[i]], T[keys[i + 1]])
    # 特殊参数
    okp = T["合法 PE64"]
    for w in (0, -1, 1, 10 ** 9, 2 ** 31):
        probe("analyze.entropy_profile/win=%s" % w, A.entropy_profile, okp, w)
    for ml in (0, -1, 10 ** 9):
        probe("analyze.scan_strings/minlen=%s" % ml, A.scan_strings, okp, ml)
    for mi in (0, -1, 10 ** 9):
        probe("analyze.scan_strings/maxitems=%s" % mi, A.scan_strings, okp, 4, None, mi)


def fuzz_disasms(T):
    """代码区：先建索引再交给解码器。"""
    for name, path in T.items():
        # 低层解码器直接吃 bytes
        try:
            data = open(path, "rb").read(8192)
        except Exception:
            data = b""
        probe("x86.disasm_linear/%s" % name, X.disasm_linear, data, 0, 64)
        probe("arm.disasm_linear/%s" % name, ARM.disasm_linear, data, 0, 64)
        for arch in ("x86", "x64", "arm64", "thumb", "mips", "unknown", ""):
            probe("x86.decode_one/%s/%s" % (name, arch),
                  X.decode_one, data, 0, arch)
            probe("arm.decode_one/%s/%s" % (name, arch),
                  ARM.decode_one, data, 0, arch)
        # 越界 offset
        for off in (0, len(data), len(data) * 10, -1, 10 ** 9):
            probe("x86.disasm_linear/%s/off=%s" % (name, off),
                  X.disasm_linear, data, off, 16)

        # 高层：先 identify 再 disasm/analyze/cfg
        try:
            ident = F.identify(path)
        except Exception:
            continue
        probe_timed("disasm.disasm_file/%s" % name, D.disasm_file, path)
        # 【注意】disasm_file 的位置参数顺序是
        #   (path, ident, region, base_vma, offset, length, max_insns)
        # 中间任何一项都不能传 None —— offset/base_vma 是 int 语义，
        # 传 None 会 TypeError，但那是**调用方**的错，不是库的 bug。
        # 第一版就是把 None 塞进 offset，误判成库缺陷。这里一律用合法类型。
        probe("disasm.disasm_file(max=0)/%s" % name,
              lambda p=path: D.disasm_file(p, max_insns=0))
        probe("disasm.disasm_file(max=-1)/%s" % name,
              lambda p=path: D.disasm_file(p, max_insns=-1))
        probe("disasm.disasm_file(len=1e9)/%s" % name,
              lambda p=path: D.disasm_file(p, length=10 ** 9))
        probe("disasm.disasm_file(len=0)/%s" % name,
              lambda p=path: D.disasm_file(p, length=0))
        probe("disasm.disasm_file(off=1e9)/%s" % name,
              lambda p=path: D.disasm_file(p, offset=10 ** 9))
        probe("disasm.disasm_file(off=-1)/%s" % name,
              lambda p=path: D.disasm_file(p, offset=-1))
        probe("disasm.disasm_file(region=怪)/%s" % name,
              lambda p=path: D.disasm_file(p, region="no_such_region"))
        probe("disasm.disasm_file(base=0)/%s" % name,
              lambda p=path: D.disasm_file(p, base_vma=0))
        probe("disasm.disasm_file(base=-1)/%s" % name,
              lambda p=path: D.disasm_file(p, base_vma=-1))
        probe_timed("disasm.analyze_file/%s" % name, D.analyze_file, path)
        probe("disasm.analyze_file(max_insns=0)/%s" % name,
              lambda p=path: D.analyze_file(p, max_insns=0))
        probe("disasm.analyze_file(max_functions=0)/%s" % name,
              lambda p=path: D.analyze_file(p, max_functions=0))
        probe_timed("disasm.cfg_of(0)/%s" % name, D.cfg_of, path, None, "0")
        probe_timed("disasm.cfg_of(1e9)/%s" % name, D.cfg_of, path, None, hex(10 ** 9))
        probe_timed("disasm.cfg_of(怪)/%s" % name, D.cfg_of, path, None, "zzz")
        probe_timed("disasm.cfg_of(空)/%s" % name, D.cfg_of, path, None, "")
        probe_timed("disasm.cfg_of(None)/%s" % name, D.cfg_of, path, None, None)
        # ident 层：只收 ident
        for bad_ident in (None, {}, {"format": "pe"}, {"arch": "x64"},
                          {"format": "pe", "arch": None, "bits": None},
                          {"format": "pe", "sections": None},
                          {"format": "pe", "sections": [None]}):
            probe("disasm.code_regions/%r" % (bad_ident,)[:34],
                  D.code_regions, bad_ident)
            probe("disasm.entry_points/%r" % (bad_ident,)[:34],
                  D.entry_points, bad_ident)
            probe("disasm.symbols_from/%r" % (bad_ident,)[:34],
                  D.symbols_from, bad_ident)
            probe("disasm.resolve_iat/%r" % (bad_ident,)[:34],
                  D.resolve_iat, bad_ident)
            probe("disasm.normalize_arch/%r" % (bad_ident,)[:34],
                  D.normalize_arch, bad_ident)
        for a in ("x86", "x86-64", "arm64", "thumb", "mips", "", None, 123):
            probe("disasm.backend/%r" % (a,), D.backend, a)
            probe("disasm.arch_label/%r" % (a,), D.arch_label, a, 64)
        probe("disasm.arch_label/bits=None", D.arch_label, "x86", None)


def _make_index(path):
    """按真实路径建一个 CodeIndex；不支持则返回 None。

    真实 API：CodeIndex(code_bytes, base_vma=, bits=, arch=, max_insns=)
    区域信息来自 code_regions(ident)（只收 ident，不收 path）。
    """
    from lib_code import CodeIndex
    try:
        ident = F.identify(path)
        regs = D.code_regions(ident)
        if not regs:
            return None, ident
        r = regs[0]
        with F.Reader(path) as rd:
            code = rd.read(r["file_off"], r["size"])
        if not code:
            return None, ident
        idx = CodeIndex(code, base_vma=r["vma"], bits=r["bits"],
                        arch=r["arch"])
        return idx, ident
    except Exception:
        return None, None


def fuzz_code(T):
    """函数识别 / CFG / 指纹：按真实签名喂 CodeIndex。"""
    for name, path in T.items():
        idx, ident = _make_index(path)
        if idx is None:
            continue
        probe_timed("code.analyze/%s" % name, C.analyze, idx)
        probe("code.analyze(seeds=[])/%s" % name, C.analyze, idx, [])
        probe("code.analyze(seeds=怪)/%s" % name, C.analyze, idx, [None, -1, 10 ** 9, "x"])
        probe_timed("code.find_functions/%s" % name, C.find_functions, idx)
        probe("code.find_functions(max=0)/%s" % name,
              C.find_functions, idx, None, None, 0)
        probe("code.find_functions(max=-1)/%s" % name,
              C.find_functions, idx, None, None, -1)
        probe("code.build_xrefs/%s" % name, C.build_xrefs, idx)
        probe("code.match_functions/%s" % name, C.match_functions, idx, [])
        # 指纹/相似度：喂畸形函数对象
        for v in (None, {}, {"blocks": None}, {"blocks": [None]},
                  {"insns": None}, {"vma": None}, []):
            probe("code.func_fingerprint/%r" % (v,)[:28], C.func_fingerprint, v)
            probe("code.compare_funcs/%r" % (v,)[:28], C.compare_funcs, v, v)
            probe("code.multiset_jaccard/%r" % (v,)[:28],
                  C.multiset_jaccard, v, v)
        # CFG：地址取 0 / 极大 / 负
        for tgt in (0, -1, 10 ** 9, 2 ** 63):
            probe("code.build_cfg/%s/%s" % (name, tgt), C.build_cfg, idx, tgt)


def fuzz_symbols():
    weird = [
        "", "?", "??", "?a", "?a@", "?a@@", "?a@@@", "@@@@", "???",
        "_Z", "_Z1", "_ZN", "_ZN1", "_ZN1a", "_ZN1aE", "_Z1fv" * 200,
        "?_Z1fv", "??0", "??1", "??_7", "??_7Test@@6B@", "?x@@3HA",
        "_R", "_RN", "_RNv", "_RNvC", "__ZN1a1bE" * 100,
        "a" * 10000, "?" + "a@" * 5000, "?" + "0" * 5000,
        "?f@@YAXH@Z" * 500, "?<\x00>@@",
        "??$x@H@@", "?$x@H@", "?" + "P" * 3000 + "X@@",
        "?func@ns@@@@YAXXZ" * 100, "\x00\x01\x02",
        "?" + "Y" * 2000, "?" + "?" * 2000, "?" + "@" * 2000,
        "_Z" + "N" * 5000, "?__E" * 1000, "??_7" + "X@" * 2000,
    ]
    for w in weird:
        tag = repr(w[:20])
        probe("symbols.demangle/%s" % tag, SY.demangle, w)
        probe("symbols.demangle_many/%s" % tag, SY.demangle_many, [w, w, ""])
        probe("symbols.clean_symbol/%s" % tag, SY.clean_symbol, w)
        probe("symbols.detect_dialect/%s" % tag, SY.detect_dialect, w)
    probe("symbols.demangle_many/空表", SY.demangle_many, [])
    probe("symbols.demangle_many/None", SY.demangle_many, None)


def fuzz_rules_yaml():
    bad = [
        "", "\n", "   ", "#", "a", "a:", "a: b", ": b", "- ", "-",
        "a:\n  - 1\n  - 2\n", "a:\n" * 500, "a: " + "b" * 100000,
        "&x a: b", "*x", "a: |\n  b", "a: >\n  b", "a: {b: c}",
        "a: [1,2", "a: 'unclosed", 'a: "unclosed', "---\n" * 1000,
        "a:\n" + "  b:\n" * 300 + "  1\n",
        "\t a: b", "a:: b", "a: http://x", "x: a::b::c",
        "?", "? a", "!!str a", "%YAML 1.2", "\x00\x01",
        "a: " + "\u4f60" * 5000,
        "- a\n  b: c\n" * 300,
        "a:\n  - b:\n      - c\n" * 200,
        "a: [" + "1," * 10000 + "]",     # 超长流式集合（未支持语法）
        "x: " + "! " * 10000,
        "\n".join("%d: v" % i for i in range(20000)),   # 超多键
        "a: " + "b" * 500000,
    ]
    for i, b in enumerate(bad):
        probe("rules.yaml_load/#%d" % i, LR.yaml_load, b)
        probe("rules.split_documents/#%d" % i, LR.split_documents, b)

    rule_bad = [
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n",
        "rule:\n  meta:\n    name: r\n  features: {}\n",
        "rule:\n  meta: {}\n  features:\n    and: []\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - and:\n          - and:\n              - and: []\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - not:\n          - or: []\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - match: r\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - bogus: 1\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - mnemonics: [a, b]\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - api: ''\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - count(api(kernel32!Sleep)): 1\n",
        "rule:\n  meta:\n    name: r\n  features:\n    and:\n      - " + "and:\n          - " * 80 + "api: x\n",
    ]
    import tempfile
    for i, b in enumerate(rule_bad):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         encoding="utf-8") as f:
            f.write(b)
            p = f.name
        probe("rules.load_rules/#%d" % i, LR.load_rules, p)


def fuzz_features():
    """build_features(path, ident, idx, funcs, iat_map, sem) 喂畸形结构。"""
    ident_bad = [
        {}, {"format": "pe"}, {"format": None}, {"format": 123}, {"arch": None},
        {"format": "pe", "bits": None, "sections": [None, 1, "x"]},
        {"format": "pe", "sections": [{"name": None, "entropy": None}]},
        {"format": "pe", "imports": [None, {"api": None}]},
        {"format": "pe", "exports": [None]},
    ]
    for i, ib in enumerate(ident_bad):
        probe("rules.build_features/ident#%d" % i,
              LR.build_features, None, ib, None, [], None, None)

    funcs_bad = [
        [None], [{}], [{"start_vma": None}], [{"start_vma": "zzz"}],
        [{"start_vma": 0, "_offs": None}], [{"start_vma": 0, "_offs": [10 ** 9]}],
        [{"start_vma": -1}], [{"start_vma": 0, "_offs": "notalist"}],
        [{"start_vma": 0, "name": None, "_offs": []}],
    ]
    for i, fb in enumerate(funcs_bad):
        probe("rules.build_features/funcs#%d" % i,
              LR.build_features, None, {"format": "pe"}, None, fb, None, None)

    sem_bad = [
        None, {}, {"functions": None}, {"functions": [None]},
        {"functions": [{}]}, {"functions": [{"start_vma": None}]},
        {"functions": [{"start_vma": "x", "api_calls": None}]},
        {"functions": [{"start_vma": 0, "api_calls": [None]}]},
        {"functions": [{"start_vma": 0, "api_calls": [{"api": None}]}]},
        {"functions": [{"start_vma": 0, "apis": [{"api": "k!x", "count": None}]}]},
    ]
    for i, sb in enumerate(sem_bad):
        probe("rules.build_features/sem#%d" % i,
              LR.build_features, None, {"format": "pe"}, None, [], None, sb)

    for ib in ({}, [], None, "x"):
        probe("rules.summarize/%r" % (ib,), LR.summarize, ib)
    probe("rules.match_rules/空规则", LR.match_rules, [], {})
    probe("rules.match_rules(None)", LR.match_rules, None, {})


def fuzz_libscan(T):
    """libscan：scan_const_tables(path, ident) / identify_libfuncs(idx, funcs)。"""
    for name, path in T.items():
        try:
            ident = F.identify(path)
        except Exception:
            continue
        probe("libscan.scan_const_tables/%s" % name,
              LS.scan_const_tables, path, ident)
        probe("libscan.scan_const_tables(max=0)/%s" % name,
              LS.scan_const_tables, path, ident, 0)
        for bad_ident in (None, {}, {"format": "pe"}):
            probe("libscan.scan_const_tables/badident/%s" % name,
                  LS.scan_const_tables, path, bad_ident)
        idx, _ = _make_index(path)
        if idx is not None:
            probe("libscan.identify_libfuncs/%s" % name,
                  LS.identify_libfuncs, idx, [])
            probe("libscan.identify_libfuncs(const=None)/%s" % name,
                  LS.identify_libfuncs, idx, [], None)
    for v in (None, [], {}, [None], [{}], [{"function": None}],
              [{"name": None, "hits": None}], [{"name": "x", "hits": 1}]):
        probe("libscan.summarize_hints/%r" % (v,)[:28],
              LS.summarize_hints, v)


def fuzz_semantics(T):
    """semantics：split_api 直接吃字符串；其它按签名。"""
    for v in (None, "", "!", "a!", "!b", "a!b", ".", "..", "a..b",
              "kernel32!Sleep", "KERNEL32.DLL!Sleep", "a" * 10000,
              "\x00", "!\x00!", "a!" * 5000):
        probe("semantics.split_api/%r" % (v,)[:28], S.split_api, v)
        probe("semantics.api_tag/%r" % (v,)[:28], S.api_tag, v)
        probe("semantics.is_noise_api/%r" % (v,)[:28], S.is_noise_api, v)

    for v in (None, [], {}, [None], [{}], ["a"], [{"tags": None}],
              [{"tags": ["x"]}], [{"api_calls": None}]):
        probe("semantics.cluster_by_tag/%r" % (v,)[:28], S.cluster_by_tag, v)
        probe("semantics.tag_counts/%r" % (v,)[:28], S.tag_counts, v)

    for name, path in list(T.items())[:10]:
        try:
            ident = F.identify(path)
        except Exception:
            continue
        probe("semantics.string_vma_map/%s" % name,
              S.string_vma_map, path, ident)
        probe("semantics.string_vma_map(bad ident)/%s" % name,
              S.string_vma_map, path, {"format": "pe"})
    probe("semantics.ins_at/None", S.ins_at, None, 0)
    probe("semantics.ins_at_errors/None", S.ins_at_errors, None)


def main():
    import tempfile
    tmp = tempfile.mkdtemp(prefix="re-fuzzlib-")
    T = write_samples(tmp)
    print("=" * 78)
    print("库级 fuzz：%d 类畸形样本" % len(T))
    print("=" * 78)
    phase("formats 解析层")
    fuzz_formats(T)
    phase("analyze 分析层")
    fuzz_analyze(T)
    phase("disasm 反汇编")
    fuzz_disasms(T)
    phase("code 函数识别")
    fuzz_code(T)
    phase("symbols 符号")
    fuzz_symbols()
    phase("rules YAML")
    fuzz_rules_yaml()
    phase("rules features")
    fuzz_features()
    phase("semantics 语义")
    fuzz_semantics(T)
    phase("libscan 库函数指纹")
    fuzz_libscan(T)

    print()
    print("=" * 78)
    print("共 %d 次库调用，发现 %d 处未防御异常" % (calls, len(issues)))
    print("=" * 78)
    if issues:
        # 按「库内出错位置 + 异常类型」聚合，去掉同类噪音
        agg = {}
        for label, ename, msg, where in issues:
            key = (ename, where, msg)
            agg.setdefault(key, []).append(label)
        print()
        for (ename, where, msg), labels in sorted(agg.items(),
                                                  key=lambda x: -len(x[1])):
            print("  !! %s ×%d" % (ename, len(labels)))
            print("     %s" % msg)
            print("     位置：%s" % where)
            print("     触发：%s" % ", ".join(sorted(set(labels))[:4]))
            print()

    if SLOW:
        # 慢 ≠ bug，但会拖成"看起来卡死"，必须单独列出来供评估
        print("=" * 78)
        print("慢调用（超过 %.0fs，非崩溃，但影响可用性）：%d 处"
              % (SLOW_LIMIT, len(SLOW)))
        print("=" * 78)
        agg2 = {}
        for label, dt, why in SLOW:
            # 按「函数 + 样本类别」聚合，避免同一问题刷屏
            key = label.split("/")[0] + "  [" + (
                label.split("/")[1] if "/" in label else "") + "]"
            agg2.setdefault(key, []).append(dt)
        for key, dts in sorted(agg2.items(), key=lambda x: -max(x[1])):
            print("   %-46s 最慢 %.1fs，%d 次超阈"
                  % (key[:46], max(dts), len(dts)))
        print()
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
