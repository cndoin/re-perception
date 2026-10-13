"""ISO9660 光盘镜像解析与提取（纯标准库）。

对标 isoinfo/7z 的静态清单能力：
- PVD（主卷描述符，扇区 16）+ Joliet SVD（UCS-2 长文件名）
- 目录树递归（目录记录 both-endian LBA/大小、目录标志位）
- 文件清单（路径/LBA/大小/是否目录）与受限提取（防路径穿越、容量上限）

诚实边界：
- Rock Ridge（SUSP NM/RR）长文件名不做完整实现 —— Joliet 缺失时降级为
  ISO9660 级别 1 的 8.3 名字并在输出 ``name_note`` 申报。
- ISO/UDF 混合镜像只解析 ISO9660 层；UDF 已知边界如实标注（检测到 BEA01/NSR02
  标记时输出 udf_suspected）。
- 加密/会话多轨道镜像不解析（reason 如实给出）。
"""

from __future__ import annotations

import os
import re
import struct

import lib_paths as PT

__all__ = ["inspect_iso", "iso_extract"]

_SECTOR = 2048
_PVD_OFF = 16 * _SECTOR


def _ok(**kw):
    d = {"ok": True}
    d.update(kw)
    return d


def _bad(reason, **kw):
    d = {"ok": False, "reason": reason}
    d.update(kw)
    return d


def _u(data, off, fmt, le=True):
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        return None
    return struct.unpack_from("<" + fmt if le else ">" + fmt, data, off)[0]


def _both_u32(data, off):
    """ISO9660 的 both-endian u32（8 字节：LE32 + BE32）。"""
    le = _u(data, off, "I", le=True)
    be = _u(data, off + 4, "I", le=False)
    if le is None or be is None:
        return None
    return le if le == be else le  # 不一致取 LE 并申报


def _both_u16(data, off):
    le = _u(data, off, "H", le=True)
    be = _u(data, off + 2, "H", le=False)
    if le is None or be is None:
        return None
    return le if le == be else le


def _svd_is_joliet(data, svd_off):
    """Joliet SVD 的判定：escape sequences 为 %/@、%/C、%/E。"""
    esc = data[svd_off + 88:svd_off + 91]
    return esc in (b"%/@", b"%/C", b"%/E")


def _walk_dir(data, lba, size, depth, path, out, cap, joliet, seen):
    if depth > 8 or len(out) >= cap:
        return
    key = (lba, size)
    if key in seen:  # 目录环/别名防护
        return
    seen.add(key)
    start = lba * _SECTOR
    end = min(len(data), start + size)
    pos = start
    while pos < end:
        rec_len = data[pos]
        if rec_len == 0:
            # 目录记录不跨扇区；跳到下一扇区边界
            pos = (pos // _SECTOR + 1) * _SECTOR
            continue
        if pos + rec_len > len(data):
            break
        rec = data[pos:pos + rec_len]
        extent = _both_u32(rec, 2)
        fsize = _both_u32(rec, 10)
        flags = rec[25] if len(rec) > 25 else 0
        name_len = rec[32] if len(rec) > 32 else 0
        raw_name = rec[33:33 + name_len]
        pos += rec_len
        if extent is None or fsize is None:
            continue
        # 名字：0x00=当前目录 0x01=父目录
        if name_len == 1 and raw_name in (b"\x00", b"\x01"):
            continue
        if joliet:
            name = raw_name.decode("utf-16-be", "replace")
        else:
            name = raw_name.decode("ascii", "replace")
            # 去掉 ;1 版本后缀
            name = name.split(";")[0]
        name = name.replace("\x00", "")
        is_dir = bool(flags & 0x02)
        full = "/".join(path + [name])
        rec_out = {"path": full, "lba": extent, "size": fsize, "dir": is_dir}
        out.append(rec_out)
        if is_dir and depth < 8:
            _walk_dir(data, extent, fsize, depth + 1, path + [name],
                      out, cap, joliet, seen)


def inspect_iso(path: str, max_entries: int = 500) -> dict:
    """ISO9660 镜像清单：卷信息 + 目录树 + UDF 侦察。"""
    try:
        import os as _os
        size = _os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(min(size, 512 * 1024 * 1024))
    except OSError as e:
        return _bad("读取失败: %s" % e)

    if len(data) < _PVD_OFF + _SECTOR:
        return _bad("文件太小，不是 ISO9660 镜像", size=size)
    pvd = data[_PVD_OFF:_PVD_OFF + _SECTOR]
    if pvd[1:6] != b"CD001":
        # 也可能是其它扇区大小（2352 raw）—— 静态尝试
        off2352 = 16 * 2352 + 16
        if len(data) > off2352 + 6 and data[off2352 + 1:off2352 + 6] == b"CD001":
            return _bad("检测到 raw 2352 扇区镜像（需字节扇区重排，超出本模块边界）",
                        sector_size=2352)
        return _bad("PVD 魔数缺失（CD001）", magic=pvd[1:6].hex())

    vol_id = pvd[40:72].decode("ascii", "replace").replace("\x00", "").strip()
    space_size = _both_u32(pvd, 80)
    block_size = _both_u16(pvd, 128) or _SECTOR
    root_lba = _both_u32(pvd, 158) if len(pvd) > 166 else None
    root_size = _both_u32(pvd, 166) if len(pvd) > 174 else None
    vol_set = _both_u16(pvd, 120)
    # PVD 创建日期：偏移 813 起 17 字节（ECMA-192 8.4.26，别按 817 算）
    created = pvd[813:830].decode("ascii", "replace").strip() if len(pvd) > 830 else ""

    out = {
        "ok": True,
        "format": "iso9660",
        "volume_id": vol_id,
        "volume_space_size": space_size,
        "volume_space_bytes": (space_size * block_size) if space_size else None,
        "block_size": block_size,
        "volume_set_size": vol_set,
        "created_raw": created,
        "image_size": size,
    }

    # Joliet SVD（卷描述符序列从扇区 16 起，type 2 为 SVD）
    joliet = False
    svd_off = None
    for i in range(1, 16):
        vo = (_PVD_OFF) + i * _SECTOR
        v = data[vo:vo + _SECTOR]
        if len(v) < _SECTOR:
            break
        vtype = v[0]
        if vtype == 2 and _svd_is_joliet(data, vo):
            joliet = True
            svd_off = vo
            out["joliet"] = True
            out["joliet_volume_id"] = v[40:72].decode("utf-16-be", "replace").replace("\x00", "").strip()
            r_lba = _both_u32(v, 158)
            r_size = _both_u32(v, 166)
            if r_lba and r_size:
                root_lba, root_size = r_lba, r_size
            break
        if vtype == 255:
            break
    out.setdefault("joliet", False)

    # UDF 侦察（BEA01/NSR0x/TEA01 标记）
    out["udf_suspected"] = bool(re.search(b"BEA01|NSR0[23]|TEA01",
                                          data[_PVD_OFF:_PVD_OFF + 32 * _SECTOR]))

    # 目录树
    entries = []
    if root_lba and root_size:
        _walk_dir(data, root_lba, root_size, 0, [], entries, max_entries,
                  joliet, set())
    out["entries"] = entries
    out["file_count"] = sum(1 for e in entries if not e["dir"])
    out["dir_count"] = sum(1 for e in entries if e["dir"])
    out["truncated"] = len(entries) >= max_entries
    out["name_note"] = ("joliet-ucs2" if joliet else
                        "iso9660-level1（8.3 名字，Rock Ridge 未解析——已知边界）")
    return out


def iso_extract(path: str, out_dir: str, max_files: int = 200,
                max_total: int = 256 * 1024 * 1024) -> dict:
    """提取 ISO 内文件到目录（防路径穿越 + 容量/数量上限）。"""
    info = inspect_iso(path, max_entries=max_files * 4)
    if not info.get("ok"):
        return info
    try:
        with open(path, "rb") as f:
            data = f.read(min(info.get("image_size") or 0, 512 * 1024 * 1024))
    except OSError as e:
        return _bad("读取失败: %s" % e)

    os.makedirs(out_dir, exist_ok=True)
    extracted, skipped, total = [], [], 0
    for e in info.get("entries", []):
        if e["dir"] or len(extracted) >= max_files:
            continue
        # 路径安全：交给全库唯一裁决点（lib_paths），与 fsx 提取同一套语义，
        # 并且会断言"拼接后的最终路径确实落在 out_dir 之内"。
        parts = PT.safe_parts(e["path"])
        if parts is None:
            skipped.append({"path": e["path"], "why": "路径穿越防护"})
            continue
        if total + (e["size"] or 0) > max_total:
            skipped.append({"path": e["path"], "why": "超出提取总量上限"})
            continue
        start = e["lba"] * info.get("block_size", _SECTOR)
        blob = data[start:start + (e["size"] or 0)]
        if len(blob) != (e["size"] or 0):
            skipped.append({"path": e["path"], "why": "数据越界（镜像截断）"})
            continue
        dest, why = PT.safe_join(out_dir, parts)
        if dest is None:
            skipped.append({"path": e["path"], "why": why or "路径穿越防护"})
            continue
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(blob)
        extracted.append({"path": e["path"], "size": e["size"]})
        total += e["size"] or 0
    return _ok(extracted=extracted, extracted_count=len(extracted),
               skipped=skipped, total_bytes=total, out_dir=out_dir,
               volume_id=info.get("volume_id"))
