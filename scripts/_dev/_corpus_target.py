"""从指定的「高质量」DLL 里直接抽 MSVC 符号，作为快速回归语料。

比全盘扫描快得多，而且这几个文件里的 C++ 修饰名密度极高，
覆盖模板、嵌套名、thunk、异常规格、x64 __ptr64 等主要语法点。
"""
import os
import sys
import json
import ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib_formats import Reader, parse_pe

# 这些文件的导出表以真实 C++ 修饰名为主
SRCS = [
    r"C:\Windows\System32\msvcp_win.dll",
    r"C:\Windows\System32\vcruntime140.dll",
    r"C:\Windows\System32\vcruntime140_1.dll",
    r"C:\Windows\System32\msvcp140.dll",
    r"C:\Windows\System32\mfc140u.dll",
    r"C:\Windows\System32\windows.storage.dll",
    r"C:\Windows\System32\d3d11.dll",
    r"C:\Windows\System32\dwrite.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\setupapi.dll",
    r"C:\Windows\System32\WinTypes.dll",
    r"C:\Windows\System32\combase.dll",
]

_d = ctypes.WinDLL("dbghelp").UnDecorateSymbolName
_d.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
_d.restype = ctypes.c_uint32


def gold(s):
    buf = ctypes.create_string_buffer(16384)
    n = _d(s.encode("ascii", "replace"), buf, 16384, 0)
    return buf.value.decode("utf-8", "replace") if n else None


def main():
    keep = {}
    per = {}
    for p in SRCS:
        if not os.path.exists(p):
            continue
        try:
            info = parse_pe(Reader(p))
        except Exception as e:
            print("解析失败", os.path.basename(p), e)
            continue
        got = 0
        for s in (info.get("export_syms") or []):
            nm = s.get("name") or ""
            if not nm.startswith("?") or len(nm) < 5:
                continue
            g = gold(nm)
            if g is None:
                continue
            got += 1
            if nm not in keep:
                keep[nm] = g
        per[os.path.basename(p)] = got
    out = {"count": len(keep), "per_file": per,
           "cases": [[k, keep[k]] for k in sorted(keep)]}
    with open(os.path.join(HERE, "_corpus_target.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    for k, v in per.items():
        print("  %-28s %d" % (k, v))
    print("合计去重:", len(keep))


if __name__ == "__main__":
    main()
