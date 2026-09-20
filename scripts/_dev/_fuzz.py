# -*- coding: utf-8 -*-
"""稳定性压测器：拿一批**恶意/畸形/极端**目标轰击每一个子命令。

设计目标（与 selftest 分工不同）：
  selftest 验"功能对不对"（黄金向量、正确性）；
  _fuzz    验"打不打得死"（崩溃、挂死、Traceback、契约违背）。

判定标准（任一条不满足即记为缺陷）：
  1. 退出码必须是 0/2/3/4 之一 —— 出现 1 或负数（=未捕获异常/信号）即缺陷。
  2. stdout **不得**出现 Python Traceback —— 说明异常没被兜住。
  3. `--json` 下 stdout 必须是可解析 JSON，且含顶层 `ok` 字段。
  4. 必须在超时内返回 —— 卡死即缺陷。
  5. 不得往当前目录/生产目录写任何文件。

用法：
    python _dev/_fuzz.py            # 跑全套
    python _dev/_fuzz.py --quick    # 只跑高价值组合
"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
SKILL = os.path.dirname(SCRIPTS)
PY = sys.executable
CLI = os.path.join(SCRIPTS, "re.py")

SUBS_NO_TARGET = ["doctor", "magic"]
SUBS_TARGET = [
    "identify", "strings", "entropy", "imports", "info", "triage", "carve",
    "plan", "report", "funcs", "xref",
]
SUBS_TARGET_BOTH = ["diff", "sim"]
SUBS_TARGET_CODE = [
    ("disasm", ["--max-insns", "200"]),
    ("cfg", []),
    ("semantics", ["--max-insns", "200"]),
    ("capability", ["--max-insns", "200"]),
]

TIMEOUT = 60
results = []


def rec(sub, target_kind, ok, detail, code=None, secs=None):
    results.append({
        "sub": sub, "kind": target_kind, "ok": bool(ok),
        "detail": str(detail)[:300], "code": code, "secs": secs,
    })


# ---------------------------------------------------------------- 样本构造

def _pe64(valid=True) -> bytes:
    """最小 PE32+。valid=False 时返回截断/畸形版本族。"""
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x44, 0x8664, 2, 0x65000000, 0, 0, 240, 0x0002)
    opt = 0x40 + 24
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<Q", buf, opt + 24, 0x140000000)
    struct.pack_into("<I", buf, opt + 32, 0x1000)
    struct.pack_into("<I", buf, opt + 36, 0x200)
    struct.pack_into("<I", buf, opt + 56, 0x3000)
    struct.pack_into("<I", buf, opt + 60, 0x200)
    struct.pack_into("<H", buf, opt + 68, 3)
    struct.pack_into("<I", buf, opt + 108, 16)
    struct.pack_into("<I", buf, opt + 16, 0x1000)
    struct.pack_into("<II", buf, opt + 112 + 1 * 8, 0x2000, 0x3C)
    st = opt + 240
    buf[st:st + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, st + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", buf, st + 36, 0x60000020)
    buf[st + 40:st + 48] = b".idata\x00\x00"
    struct.pack_into("<IIII", buf, st + 48, 0x200, 0x2000, 0x200, 0x400)
    struct.pack_into("<I", buf, st + 76, 0xC0000040)
    buf[0x200:0x200 + 10] = bytes(range(10))
    return bytes(buf)


def make_targets(tmp: str) -> dict[str, str]:
    """造一批"最能让解析器炸"的目标文件。"""
    T = {}

    def w(name, data: bytes) -> str:
        p = os.path.join(tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    T["正常 PE64"] = w("ok_pe64.exe", _pe64())
    T["空文件"] = w("empty.bin", b"")
    T["1 字节"] = w("one.bin", b"\x00")
    T["全零 64K"] = w("zeros.bin", b"\x00" * 65536)
    T["全 FF 64K"] = w("ff.bin", b"\xff" * 65536)
    T["MZ 无 PE 头"] = w("mz_only.exe", b"MZ" + b"\x00" * 0x200)
    T["MZ+e_lfanew 越界"] = w("bad_lfanew.exe",
                              b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x7FFFFFFF))
    T["PE 头截断"] = w("trunc_pe.exe", _pe64()[:0x80])
    T["节表越界"] = w("bad_sect.exe", _pe64()[:0x200] + b"\xff" * 0x200)
    T["节数谎报 0xFFFF"] = (lambda b: (struct.pack_into("<H", b, 0x46, 0xFFFF)
                                       or w("huge_nsec.exe", bytes(b))))(bytearray(_pe64()))
    T["随机 128K"] = w("rand128k.bin", random.Random(1).randbytes(131072))
    T["可打印垃圾"] = w("text.bin", b"A" * 4096 + b"\n" + b"B" * 4096)
    T["超长单行字符串"] = w("longline.bin", b"X" * 500000)
    T["超多 NUL 分隔串"] = w("manystr.bin", b"str\x00" * 20000)
    T["畸形 ELF"] = w("bad.elf", b"\x7fELF" + b"\xff" * 512)
    T["畸形 Mach-O"] = w("bad.macho", b"\xcf\xfa\xed\xfe" + b"\xff" * 512)
    T["畸形 ZIP"] = w("bad.zip", b"PK\x03\x04" + b"\xff" * 512)
    T["畸形 Java class"] = w("bad.class", b"\xca\xfe\xba\xbe" + b"\xff" * 512)
    T["畸形 PDF"] = w("bad.pdf", b"%PDF-1.7" + b"\xff" * 512)
    T["UTF-16 文本"] = w("u16.txt", ("hello 世界 " * 500).encode("utf-16-le"))
    T["高熵 1M"] = w("hi_ent.bin", random.Random(2).randbytes(1 << 20))

    # 非文件类
    T["不存在的文件"] = os.path.join(tmp, "no_such_file_xyz.bin")
    T["目录当目标"] = tmp
    T["无权限目标"] = os.path.join(tmp, "denied.bin")
    return T


# ---------------------------------------------------------------- 执行

def run_one(sub: str, argv: list, kind: str, workdir: str | None = None):
    tgt = argv[-1] if argv else ""
    full = [PY, CLI, sub, *argv, "--json"]
    t0 = time.time()
    try:
        p = subprocess.run(full, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           timeout=TIMEOUT, cwd=workdir or SCRIPTS)
    except subprocess.TimeoutExpired:
        rec(sub, kind, False, "超时 %ds（疑似挂死）" % TIMEOUT, None, TIMEOUT)
        return
    dt = round(time.time() - t0, 2)
    out, err = p.stdout or "", p.stderr or ""

    # 1) 退出码契约
    if p.returncode not in (0, 2, 3, 4):
        rec(sub, kind, False,
            "退出码 %s 违反契约(应 0/2/3/4)；stderr=%s"
            % (p.returncode, err.strip().splitlines()[-1][:150] if err.strip() else ""),
            p.returncode, dt)
        return

    # 2) 不得漏 Traceback
    if "Traceback (most recent call last)" in out or \
       "Traceback (most recent call last)" in err:
        tail = (err or out).strip().splitlines()[-1][:180]
        rec(sub, kind, False, "漏出 Python Traceback：%s" % tail, p.returncode, dt)
        return

    # 3) --json 契约
    if p.returncode == 0:
        try:
            data = json.loads(out)
        except Exception:
            rec(sub, kind, False, "返回 0 但 stdout 不是合法 JSON：%r" % out[:150],
                p.returncode, dt)
            return
        if not isinstance(data, dict) or "ok" not in data:
            rec(sub, kind, False, "JSON 缺顶层 ok 字段：%r" % out[:150],
                p.returncode, dt)
            return
    else:
        # 失败路径也要求 --json 下有 ok:false（除非是用法错误 2）
        if p.returncode in (3, 4):
            try:
                data = json.loads(out)
                if isinstance(data, dict) and data.get("ok") is not False:
                    rec(sub, kind, False,
                        "退出码 %d 但 JSON ok 不是 false" % p.returncode,
                        p.returncode, dt)
                    return
            except Exception:
                rec(sub, kind, False,
                    "退出码 %d 但 stdout 不是 JSON（AI 无法判定失败原因）" % p.returncode,
                    p.returncode, dt)
                return

    rec(sub, kind, True, "码 %d，%.2fs" % (p.returncode, dt), p.returncode, dt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()
    random.seed(args.seed)

    tmp = tempfile.mkdtemp(prefix="re-fuzz-")
    targets = make_targets(tmp)
    # 造一个"不可读"文件（Windows 上 chmod 不生效，用独占打开模拟）
    denied = targets.pop("无权限目标", None)

    kinds = list(targets.items())
    if args.quick:
        keep = ("正常 PE64", "空文件", "1 字节", "不存在的文件", "目录当目标", "MZ 无 PE 头")
        kinds = [(k, v) for k, v in kinds if k in keep]

    print("=" * 78)
    print("稳定性压测：%d 个子命令 × %d 类目标" % (len(SUBS_TARGET) + 4, len(kinds)))
    print("超时上限：%ds/次   工作目录：%s" % (TIMEOUT, SCRIPTS))
    print("=" * 78)

    # --- 无目标子命令 ---
    for sub in SUBS_NO_TARGET:
        if args.only and args.only not in sub:
            continue
        run_one(sub, [], "无目标")

    # --- 单目标子命令 ---
    for sub in SUBS_TARGET:
        if args.only and args.only not in sub:
            continue
        for kind, path in kinds:
            run_one(sub, [path], kind)

    # --- 双目标子命令 ---
    ok = targets.get("正常 PE64")
    for sub in SUBS_TARGET_BOTH:
        if args.only and args.only not in sub:
            continue
        for kind, path in kinds:
            run_one(sub, [path, path], kind)
        # 一边正常一边畸形
        if ok:
            run_one(sub, [ok, targets.get("随机 128K", ok)], "正常+随机")

    # --- 需要代码区的子命令 ---
    for sub, extra in SUBS_TARGET_CODE:
        if args.only and args.only not in sub:
            continue
        for kind, path in kinds:
            run_one(sub, [path, *extra], kind)

    # --- 缺参数（用法错误应给 2）---
    for sub in SUBS_TARGET:
        if args.only and args.only not in sub:
            continue
        run_one(sub, [], "缺目标参数")

    # --- 工作目录污染检查 ---
    before = set(os.listdir(SCRIPTS))
    run_one("report", [targets["正常 PE64"]], "污染检查", workdir=tmp)
    polluted = [f for f in set(os.listdir(SCRIPTS)) - before]
    if polluted:
        rec("report", "污染检查", False,
            "往 scripts/ 写了文件：%s" % polluted)
    else:
        rec("report", "污染检查", True, "生产目录未被污染")

    # ---------------------------------------------------------------- 报告
    bad = [r for r in results if not r["ok"]]
    print()
    print("=" * 78)
    print("共 %d 次调用，失败 %d 次" % (len(results), len(bad)))
    print("=" * 78)
    if bad:
        print()
        print("!!! 发现缺陷（按子命令分组）：")
        by_sub = {}
        for r in bad:
            by_sub.setdefault(r["sub"], []).append(r)
        for sub in sorted(by_sub):
            print()
            print("  [%s]  %d 处" % (sub, len(by_sub[sub])))
            for r in by_sub[sub]:
                print("     - [%s] %s" % (r["kind"], r["detail"]))
    print()
    print("=" * 78)
    print("合计 %d 处缺陷" % len(bad))
    print("=" * 78)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
