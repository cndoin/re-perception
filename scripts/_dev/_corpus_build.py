# -*- coding: utf-8 -*-
"""从本机 PE 里提取「干净」的 MSVC 修饰名语料。

有些 DLL 的导出表字符串表指向了 .text 之类的地方，读出来的不是符号名。
这里加一道**格式校验**：只接受满足 `[?@$_A-Za-z0-9]+` 且以 '?' 开头的，
并且 dbghelp 能解出来的。这样语料本身是可信的。
"""
import os
import re
import sys
import json
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib_formats import Reader, parse_pe

ROOTS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or ".",
    r"C:\ProgramData",
]
EXT = (".dll", ".exe", ".ocx", ".cpl", ".sys")

_OK_RE = re.compile(r"^[?@$_A-Za-z0-9]*$")

_d = ctypes.WinDLL("dbghelp").UnDecorateSymbolName
_d.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
               ctypes.c_uint32]
_d.restype = ctypes.c_uint32


def gold(s):
    buf = ctypes.create_string_buffer(16384)
    n = _d(s.encode("ascii", "replace"), buf, 16384, 0)
    return buf.value.decode("utf-8", "replace") if n else None


def main():
    keep = {}
    scanned = 0
    bad_files = 0
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d.lower() != "temp"]
            for fn in filenames:
                if not fn.lower().endswith(EXT):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(p) > 120 * 1024 * 1024:
                        continue
                    info = parse_pe(Reader(p))
                except Exception:
                    continue
                scanned += 1
                dirty = 0
                for s in (info.get("export_syms") or []):
                    nm = s["name"]
                    if not nm.startswith("?") or len(nm) < 3:
                        continue
                    if not _OK_RE.match(nm):
                        dirty += 1
                        continue
                    g = gold(nm)
                    if g is None:
                        continue
                    if nm not in keep:
                        keep[nm] = g
                if dirty:
                    bad_files += 1
            if len(keep) > 8000:
                break

    out = {"scanned": scanned, "bad_files": bad_files,
           "count": len(keep),
           "cases": [[k, keep[k]] for k in sorted(keep)]}
    with open(os.path.join(HERE, "_corpus_clean.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    print("扫描 PE 文件:", scanned, " 导出表损坏的文件:", bad_files)
    print("干净且 dbghelp 可解的 MSVC 符号:", len(keep))
    lens = sorted(len(k) for k in keep)
    if lens:
        print("长度中位数:", lens[len(lens) // 2], " 最长:", lens[-1])


if __name__ == "__main__":
    main()
