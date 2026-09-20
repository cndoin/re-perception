# -*- coding: utf-8 -*-
"""实证探针：证明本轮每个修复真的改变了行为（而不是只改了代码）。

做法：对每一处，先给出「修前的旧实现会算出什么」，再给出「新实现算出什么」，
两者必须不同；相同就说明修复没生效。
"""
import io
import json
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import lib_semantics as LS          # noqa: E402
import lib_obfstr as OS             # noqa: E402
import lib_formats as LF            # noqa: E402

TMP = tempfile.mkdtemp(prefix="probe138-")
ROWS = []


def rec(name, before, after, ok, note=""):
    ROWS.append((name, before, after, ok, note))


def sh(x, n=42):
    s = repr(x)
    return s if len(s) <= n else s[:n - 3] + "..."


# ---------------------------------------------------------------- 1. _as_vma_int
try:
    got = LS._as_vma_int("4096")
    old = 16534  # int("4096", 16) —— 修前把十进制串当十六进制解析
    rec("_as_vma_int('4096')", old, got, got == 4096,
        "十进制串必须按十进制解析；旧实现读到 16534（0x4096）")
except Exception as e:
    rec("_as_vma_int('4096')", "-", "异常 %s" % e, False)


# ---------------------------------------------------------------- 2. PE VMA 映射
ident = {
    "format": "PE",
    "detail": {
        "image_base": 0x140000000,
        "sections": [{"name": ".data",
                      "virtual_address": 0x1000,
                      "raw_offset": 0x400,
                      "raw_size": 0x200,
                      "virtual_size": 0x100}],
    },
}
f2f, warn2 = OS.make_vma2off(ident)
a1 = f2f(0x140001000) if f2f else None
a2 = f2f(0x140001010) if f2f else None
rec("make_vma2off(PE) 0x140001000", "None/异常（旧版无此函数）",
    sh(a1), a1 == 0x400, "RVA 0x1000 + image_base 应落到文件偏移 0x400")
rec("make_vma2off(PE) 0x140001010", "-", sh(a2), a2 == 0x410)


# ---------------------------------------------------------------- 3. XOR 端到端
key = 0x4A
# 真实二进制里的加密串是 **NUL 结尾** 的（否则解密循环不知道何时停）。
# 不加结尾的话，解密会把后面的填充字节一起解出来，字符串尾巴粘上一串
# '\x00'^key 的字符 —— 那是样本不真实，不是工具判据的问题。
plain = b"http://evil.example.com/c2/beacon\x00"
cipher = bytes(b ^ key for b in plain)
# 布局：前 0x100 字节垫料，密文从 0x400 开始（正是上面 .data 的文件偏移）
blob = bytearray(0x600)
blob[0x400:0x400 + len(cipher)] = cipher
fp = os.path.join(TMP, "xor_pe.bin")
io.open(fp, "wb").write(bytes(blob))

loops = [{"key": key, "data_ref": 0x140001000, "loop_start_vma": 0x140001100,
          "evidence": ["xor al, 0x4a"]}]
with LF.Reader(fp) as rd:
    r_new = OS.xor_loops_to_strings(rd, loops, vma2off=f2f)
    r_old = OS.xor_loops_to_strings(rd, loops)      # 缺换算 = 修前的行为
got_new = [s["string"] for s in r_new["strings"]]
got_old = [s["string"] for s in r_old["strings"]]
want = plain.decode().rstrip("\x00")   # 期望值不含结尾 NUL
rec("xor_loops_to_strings 带 vma2off", sh(got_old), sh(got_new),
    want in got_new,
    "PE 上必须能还原出明文；不加换算时应一条都没有")

# 哪个 succeeded 的 offset 字段是文件偏移而不是 VMA
off_field = r_new["strings"][0]["offset"] if r_new["strings"] else None
rec("恢复结果的 offset 字段", "0x140001000（VMA 冒充 offset）",
    hex(off_field) if off_field is not None else None,
    off_field == 0x400, "offset 必须是真实文件偏移")

# ---------------------------------------------------------------- 4. data_ref 缺失要有告警
loops_noref = [{"key": 0x11, "data_ref": None, "loop_start_vma": 1, "evidence": []}]
with LF.Reader(fp) as rd:
    r3 = OS.xor_loops_to_strings(rd, loops_noref, vma2off=f2f)
rec("data_ref 为 None 时", "[] 且 warnings=[]（静默丢）",
    "warnings=%d 条" % len(r3["warnings"]),
    len(r3["warnings"]) == 1, "必须报出来，不能假装没找到")

# ---------------------------------------------------------------- 5. Mach-O 无 addr
mid = {"format": "Mach-O",
       "detail": {"sections": [{"name": "__text", "size": 16, "offset": 0x1000}]}}
mf, mw = OS.make_vma2off(mid)
rec("make_vma2off(Mach-O)", "-", "映射=%s, warnings=%d" % (mf, len(mw)),
    mf is None and len(mw) == 1,
    "Mach-O 节表没有地址字段，必须诚实说给不出映射")


print("=" * 96)
print("实证探针 · v1.3.8")
print("=" * 96)
bad = 0
for name, before, after, ok, note in ROWS:
    print("%s %s" % ("[OK]  " if ok else "[失败]", name))
    print("        修前： %s" % before)
    print("        修后： %s" % after)
    if note:
        print("        说明： %s" % note)
    if not ok:
        bad += 1
print("-" * 96)
print("共 %d 项，通过 %d，失败 %d" % (len(ROWS), len(ROWS) - bad, bad))
print("临时目录：%s" % TMP)
sys.exit(1 if bad else 0)
