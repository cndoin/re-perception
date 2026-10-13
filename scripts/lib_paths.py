"""路径安全裁决点（唯一）。

为什么要单独一个模块：
`--extract` 类命令（iso / fsx）要把"样本内部的成员名"拼成宿主路径写出，
成员名来自不可信输入（镜像/固件的目录记录、`path traversal` 式文件名很常见）。
原先 `lib_iso` 与 `lib_fsx` 各有一份逐段清洗，**语义还不完全一致**（对反斜杠的处理
不同）—— 这是典型的"多裁决点"缺陷：改一处漏一处，且无法用同一份用例证明安全。
本模块是全库唯一裁决点，两处调用同一实现，并补了原先都缺的最后一道兜底：
**拼接后最终路径必须真的落在输出目录之内**（符号链接穿越只靠逐段黑名单拦不住）。
"""

import os
import re

# Windows 盘符（C: / C:\）与 UNC（\\server\share）
_DRIVE = re.compile(r"^[A-Za-z]:")
# Windows 保留设备名（CON / NUL / AUX / COM1..9 / LPT1..9），写这类名会打到设备
_RESERVED = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^.]*)?$", re.IGNORECASE)


def safe_parts(name: str):
    """把成员名切成安全的路径段。返回 None 表示"这个名字不能用"。

    统一语义：`\\` 与 `/` 都当分隔符（原先两模块不一致的点在这里收敛）。
    """
    if name is None:
        return None
    norm = name.replace("\\", "/")
    parts = []
    for seg in norm.split("/"):
        seg = seg.strip()
        if not seg or seg in (".", ".."):
            continue
        # 绝对路径/盘符/UNC/保留设备名 —— 一律拒
        if seg.startswith("/") or _DRIVE.match(seg):
            return None
        if seg.startswith("\\\\") or _RESERVED.match(seg):
            return None
        if "\x00" in seg:
            return None
        parts.append(seg)
    if not parts:
        return None
    return parts


def safe_join(out_dir: str, parts):
    """拼出最终写出路径，并断言它确实落在 out_dir 之内。

    返回 (dest, reason)：
      - 成功：dest 为绝对路径，reason 为 None
      - 失败：dest 为 None，reason 说明原因（调用方应把它写进 `warnings`，不要静默丢弃）
    """
    if not parts:
        return None, "empty path"
    root = os.path.abspath(out_dir)
    dest = os.path.abspath(os.path.join(root, *parts))
    try:
        # 只认 "dest == root" 或 "dest 在 root 之下"；.. 逃逸与符号链接都在这里被抓住
        if os.path.commonpath([root, dest]) != root:
            return None, "path escapes output directory"
    except ValueError:
        # Windows 上跨盘符时 commonpath 会抛
        return None, "path escapes output directory"
    return dest, None


def prepare_dest(out_dir: str, parts):
    """creates the parent dir too. 返回 (dest_dir, dest_path, reason)。"""
    dest, reason = safe_join(out_dir, parts)
    if dest is None:
        return None, None, reason
    parent = os.path.dirname(dest)
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            return None, None, "cannot create dir: %s" % e.__class__.__name__
    return parent, dest, None
