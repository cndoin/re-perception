# -*- coding: utf-8 -*-
"""扫描本机 PE 文件的导出表，收集真实的 MSVC '?' 符号做语料。"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib_formats import Reader, parse_pe

ROOTS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or ".",
]
EXT = (".dll", ".exe", ".ocx", ".cpl", ".sys", ".efi")

msvc = set()
itanium = set()
files = []
scanned = 0
CAP_M = 60000

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
                r = Reader(p)
                info = parse_pe(r)
                syms = info.get("export_syms") or []
            except Exception:
                continue
            scanned += 1
            hit_m = [s["name"] for s in syms if s["name"].startswith("?")]
            hit_i = [s["name"] for s in syms
                     if s["name"].startswith("_Z") or s["name"].startswith("__Z")]
            if hit_m:
                files.append([p, len(hit_m), len(hit_i)])
                msvc.update(hit_m)
            if hit_i:
                itanium.update(hit_i)
        if len(msvc) > CAP_M:
            break

out = {
    "scanned": scanned,
    "files": sorted(files, key=lambda x: -x[1])[:300],
    "msvc": sorted(msvc),
    "itanium": sorted(itanium),
}
with open(os.path.join(HERE, "_corpus.json"), "w", encoding="utf-8") as f:
    json.dump(out, f)
print("scanned PE:", scanned)
print("msvc syms:", len(msvc), " itanium syms:", len(itanium))
print("top contributors:")
for p, a, b in out["files"][:20]:
    print("   %5d %5d  %s" % (a, b, p))
