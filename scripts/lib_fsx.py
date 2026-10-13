"""固件 / 嵌入文件系统扫描提取 + 系统复刻（纯标准库）。

对标 binwalk / unblob / FACT 的**静态签名扫描 + 可解尽解**子集：
- ``scan_embedded``  binwalk 式签名扫描：gzip/xz/bz2/lzma/zip/7z/tar/cpio(newc/odc)/
  SquashFS/JFFS2/cramfs/UBI/uImage/Android boot/TRX/DTB/ELF/PE/Mach-O，
  报 offset/size 估计/熵上下文。
- ``extract_embedded`` 对**标准库可解**的容器（gzip/bz2/xz/lzma/zip/tar/cpio）
  真提取；只检测不解的（SquashFS/JFFS2/cramfs/UBI）如实标
  ``extractable: false, reason: "needs_external_tool"``，不冒充。
- ``replica_manifest`` 提取树的确定性清单（sha256，字典序）；
  ``replica_build`` 复刻打包（tar，mtime=0/uid=0，字节确定性）；
  ``replica_verify`` 清单回验。这就是「复刻系统」的诚实范围：
  静态镜像层的提取与重建，运行时状态/注册表/固件签名不在范围内（如实声明）。

安全：提取走路径清洗（拒 `..`/绝对路径/盘符）+ 数量与总量上限 + zip/tar
成员大小上限，防 zip bomb。
"""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import os
import re
import struct
import tarfile
import zipfile
import zlib

__all__ = ["scan_embedded", "extract_embedded",
           "replica_manifest", "replica_build", "replica_verify"]


def _ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return d


def _bad(reason, **kw):
    d = {"ok": False, "reason": reason}
    d.update(kw)
    return d


# ---------------------------------------------------------------- 签名表
# (key, label, magic, offset, 可解, 解释器)
_SIGS = [
    ("gzip",    "gzip 压缩流",      b"\x1f\x8b\x08",            0,  True,  "gzip"),
    ("bz2",     "bzip2 压缩流",     b"BZh",                     0,  True,  "bz2"),
    ("xz",      "xz 压缩流",        b"\xfd7zXZ\x00",            0,  True,  "xz"),
    ("lzma",    "lzma 压缩流",      b"\x5d\x00\x00",            0,  True,  "lzma"),
    ("zip",     "ZIP 归档",         b"PK\x03\x04",              0,  True,  "zip"),
    ("7z",      "7z 归档",          b"7z\xbc\xaf\x27\x1c",      0,  False, None),
    ("cpio_newc", "cpio newc",      b"070701",                  0,  True,  "cpio_newc"),
    ("cpio_odc",  "cpio odc",       b"070707",                  0,  False, None),
    ("tar",       "tar 归档",       b"ustar",                   257, True, "tar"),
    ("squashfs", "SquashFS",        b"hsqs",                    0,  False, None),
    ("squashfs_be", "SquashFS(大端)", b"sqsh",                  0,  False, None),
    ("jffs2",   "JFFS2",            b"\x85\x19",                0,  False, None),
    ("jffs2_be", "JFFS2(大端)",     b"\x19\x85",                0,  False, None),
    ("cramfs",  "cramfs",           b"\x45\x3d\xcd\x28",        0,  False, None),
    ("cramfs_be", "cramfs(大端)",   b"\x28\xcd\x3d\x45",        0,  False, None),
    ("ubi",     "UBI 镜像",         b"UBI#",                    0,  False, None),
    ("uimage",  "U-Boot uImage",    b"\x27\x05\x19\x56",        0,  False, None),
    ("androidboot", "Android boot.img", b"ANDROID!",            0,  False, None),
    ("trx",     "TRX 固件",         b"HDR0",                    0,  False, None),
    ("dtb",     "设备树 DTB",       b"\xd0\x0d\xfe\xed",        0,  False, None),
    ("elf",     "ELF",              b"\x7fELF",                 0,  False, None),
    ("pe",      "PE/MZ",            b"MZ",                      0,  False, None),
    ("macho64", "Mach-O 64",        b"\xcf\xfa\xed\xfe",        0,  False, None),
    ("macho32", "Mach-O 32",        b"\xce\xfa\xed\xfe",        0,  False, None),
    ("dex",     "DEX",              b"dex\n",                   0,  False, None),
]

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = 0.0
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return round(e, 3)


def scan_embedded(path: str, max_hits: int = 200, window: int = 64 * 1024) -> dict:
    """全文件签名扫描（binwalk 风格），按 offset 排序返回。"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(min(size, 256 * 1024 * 1024))
    except OSError as e:
        return _bad("读取失败: %s" % e)

    hits = []
    for key, label, magic, off, extractable, interp in _SIGS:
        start = 0
        while len(hits) < max_hits * 4:
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            # off>0 的签名位于结构内部（如 tar 的 ustar 在 +257）：
            # 结构起点 = 魔数位置 - off（此前按魔数位置当起点，tar 永远偏 257）
            if i < off:
                continue
            struct_off = i - off
            if key == "pe":
                # MZ 需 PE 头佐证（不然命中面太大）
                if struct_off + 0x40 > len(data):
                    continue
                e_lfanew = struct.unpack_from("<I", data, struct_off + 0x3C)[0]
                if struct_off + e_lfanew + 4 > len(data) or \
                   data[struct_off + e_lfanew:struct_off + e_lfanew + 4] != b"PE\x00\x00":
                    continue
            hits.append({
                "key": key, "label": label, "offset": struct_off,
                "extractable": extractable,
                "interpreter": interp,
                "entropy_after": _entropy(data[struct_off + len(magic):
                                               struct_off + len(magic) + window]),
            })
    hits.sort(key=lambda h: h["offset"])
    hits = hits[:max_hits]
    return _ok(format="embedded-signatures", hits=hits, count=len(hits),
               file_size=size, scanned_bytes=len(data),
               truncated=len(hits) >= max_hits,
               extractable_keys=sorted({h["key"] for h in hits if h["extractable"]}),
               detected_only=sorted({h["key"] for h in hits if not h["extractable"]}),
               note="detected_only 的容器需外部工具（squashfs-tools 等），本工具不冒充提取")


# ---------------------------------------------------------------- 提取


def _safe_parts(name: str):
    parts = [p for p in name.replace("\\", "/").split("/") if p and p not in (".", "..")]
    if any(re.match(r"^[A-Za-z]:", p) for p in parts):
        return None
    return parts


def _extract_cpio_newc(blob: bytes, out_dir: str, budget: dict):
    """cpio newc 解包（TRAILER!!! 终止）。"""
    files = []
    pos = 0
    while pos + 110 <= len(blob) and budget["files"] < budget["max_files"]:
        if blob[pos:pos + 6] != b"070701":
            break
        namesize = int(blob[pos + 94:pos + 102], 16)
        filesize = int(blob[pos + 54:pos + 62], 16)
        name = blob[pos + 110:pos + 110 + namesize].rstrip(b"\x00").decode("utf-8", "replace")
        hdr_end = pos + 110 + namesize
        hdr_end = (hdr_end + 3) & ~3
        data_end = hdr_end + filesize
        if data_end > len(blob) or name == "TRAILER!!!":
            break
        parts = _safe_parts(name)
        if parts:
            dest = os.path.join(out_dir, *parts)
            os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(blob[hdr_end:data_end])
            files.append({"path": name, "size": filesize})
            budget["files"] += 1
            budget["bytes"] += filesize
        pos = (data_end + 3) & ~3
    return files


def extract_embedded(path: str, out_dir: str, max_files: int = 200,
                     max_total: int = 256 * 1024 * 1024) -> dict:
    """提取扫描到的可解容器（gzip/bz2/xz/lzma/zip/tar/cpio）。"""
    scan = scan_embedded(path, max_hits=60)
    if not scan.get("ok"):
        return scan
    try:
        with open(path, "rb") as f:
            data = f.read(min(os.path.getsize(path), 256 * 1024 * 1024))
    except OSError as e:
        return _bad("读取失败: %s" % e)

    os.makedirs(out_dir, exist_ok=True)
    budget = {"files": 0, "bytes": 0, "max_files": max_files, "max_total": max_total}
    extracted, skipped = [], []

    for h in scan["hits"]:
        if budget["files"] >= max_files or budget["bytes"] >= max_total:
            skipped.append({"offset": h["offset"], "key": h["key"], "why": "预算用尽"})
            continue
        if not h["extractable"]:
            continue
        off, key = h["offset"], h["key"]
        sub = os.path.join(out_dir, "%08x_%s" % (off, key))
        try:
            if key in ("gzip", "bz2", "xz", "lzma"):
                blob = _inflate(key, data[off:off + 64 * 1024 * 1024])
                _write_blob(sub + ".out", blob, budget)
                extracted.append({"offset": off, "key": key, "out": sub + ".out",
                                  "size": len(blob)})
            elif key == "zip":
                os.makedirs(sub, exist_ok=True)
                with zipfile.ZipFile(io.BytesIO(data[off:])) as zf:
                    for zi in zf.infolist()[:max_files]:
                        parts = _safe_parts(zi.filename)
                        if not parts or zi.is_dir() or zi.file_size > max_total:
                            continue
                        dest = os.path.join(sub, *parts)
                        os.makedirs(os.path.dirname(dest) or sub, exist_ok=True)
                        with open(dest, "wb") as f:
                            f.write(zf.read(zi))
                        budget["files"] += 1
                        budget["bytes"] += zi.file_size
                extracted.append({"offset": off, "key": key, "out": sub})
            elif key == "tar":
                os.makedirs(sub, exist_ok=True)
                with tarfile.open(fileobj=io.BytesIO(data[off:]),
                                  mode="r:") as tf:
                    for ti in tf.getmembers()[:max_files]:
                        parts = _safe_parts(ti.name)
                        if not parts or not ti.isfile() or ti.size > max_total:
                            continue
                        dest = os.path.join(sub, *parts)
                        os.makedirs(os.path.dirname(dest) or sub, exist_ok=True)
                        src = tf.extractfile(ti)
                        if src is None:
                            continue
                        with open(dest, "wb") as f:
                            f.write(src.read())
                        budget["files"] += 1
                        budget["bytes"] += ti.size
                extracted.append({"offset": off, "key": key, "out": sub})
            elif key == "cpio_newc":
                os.makedirs(sub, exist_ok=True)
                files = _extract_cpio_newc(data[off:off + 64 * 1024 * 1024], sub, budget)
                extracted.append({"offset": off, "key": key, "out": sub,
                                  "members": len(files)})
        except Exception as e:
            skipped.append({"offset": off, "key": key,
                            "why": "%s: %s" % (type(e).__name__, e)})

    return _ok(extracted=extracted, extracted_count=len(extracted), skipped=skipped,
               files=budget["files"], bytes=budget["bytes"], out_dir=out_dir)


def _inflate(key: str, chunk: bytes) -> bytes:
    """流式解压单个成员：解到流末尾即停，尾部垃圾不炸（固件里流后跟
    其它数据是常态；gzip.decompress/lzma.decompress 遇尾部垃圾直接抛）。"""
    if key == "gzip":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(chunk)
    if key == "bz2":
        d = bz2.BZ2Decompressor()
        return d.decompress(chunk)
    if key == "xz":
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        return d.decompress(chunk)
    if key == "lzma":
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        return d.decompress(chunk)
    raise ValueError("无此解压器: %s" % key)


def _write_blob(dest, blob, budget):
    if budget["bytes"] + len(blob) > budget["max_total"]:
        raise ValueError("超出提取总量上限")
    with open(dest, "wb") as f:
        f.write(blob)
    budget["files"] += 1
    budget["bytes"] += len(blob)


# ---------------------------------------------------------------- 复刻


def _walk_hash(root: str, max_files: int = 20000):
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace(os.sep, "/")
            try:
                with open(fp, "rb") as f:
                    h = hashlib.sha256(f.read()).hexdigest()
                sz = os.path.getsize(fp)
            except OSError as e:
                entries.append({"path": rel, "error": str(e)})
                continue
            entries.append({"path": rel, "size": sz, "sha256": h})
            if len(entries) >= max_files:
                return entries, True
    return entries, False


def replica_manifest(src: str, max_files: int = 20000) -> dict:
    """确定性清单：文件路径 + sha256 + 大小（字典序）。单文件或目录皆可。"""
    if os.path.isfile(src):
        with open(src, "rb") as f:
            data = f.read()
        return _ok(kind="file", path=os.path.basename(src), size=len(data),
                   sha256=hashlib.sha256(data).hexdigest(),
                   manifest=[{"path": os.path.basename(src), "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest()}])
    if not os.path.isdir(src):
        return _bad("源不存在: %s" % src)
    entries, truncated = _walk_hash(src, max_files)
    total = sum(e.get("size", 0) for e in entries)
    return _ok(kind="tree", root=src, manifest=entries, file_count=len(entries),
               total_bytes=total, truncated=truncated,
               tree_sha256=hashlib.sha256(
                   "\n".join("%s:%s" % (e["path"], e.get("sha256", "")) for e in entries)
                   .encode("utf-8")).hexdigest())


def replica_build(src: str, out_tar: str, max_files: int = 20000) -> dict:
    """复刻打包：确定性 tar（按路径排序、mtime=0、uid/gid=0、模式归一）。"""
    if not os.path.isdir(src):
        return _bad("源不是目录: %s" % src)
    entries, truncated = _walk_hash(src, max_files)
    paths = sorted(e["path"] for e in entries if "sha256" in e)
    try:
        with tarfile.open(out_tar, "w") as tf:
            for rel in paths:
                fp = os.path.join(src, rel.replace("/", os.sep))
                ti = tarfile.TarInfo(rel)
                ti.size = os.path.getsize(fp)
                ti.mtime = 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode = 0o644
                with open(fp, "rb") as f:
                    tf.addfile(ti, f)
    except OSError as e:
        return _bad("打包失败: %s" % e)
    with open(out_tar, "rb") as f:
        out_hash = hashlib.sha256(f.read()).hexdigest()
    return _ok(out=out_tar, file_count=len(paths), truncated=truncated,
               out_sha256=out_hash, out_size=os.path.getsize(out_tar),
               note="确定性 tar：同树必同哈希（mtime=0/uid=0/排序），可用于复刻对比")


def replica_verify(src: str, manifest: dict) -> dict:
    """清单回验：逐文件 sha256 对比，报 added/removed/changed。"""
    cur, _ = _walk_hash(src) if os.path.isdir(src) else ([], False)
    if manifest.get("kind") == "file" and not cur:
        with open(src, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        want = manifest.get("sha256")
        return _ok(match=(h == want), checked=1,
                   mismatch=[] if h == want else [{"path": src, "want": want, "got": h}])
    want = {e["path"]: e.get("sha256") for e in manifest.get("manifest", [])}
    got = {e["path"]: e.get("sha256") for e in cur}
    added = sorted(set(got) - set(want))
    removed = sorted(set(want) - set(got))
    changed = sorted(p for p in set(want) & set(got) if want[p] != got[p])
    return _ok(match=not (added or removed or changed), checked=len(want),
               added=added[:100], removed=removed[:100], changed=changed[:100])
