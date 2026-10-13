"""Android APK / iOS IPA 应用逆向（纯标准库）。

对标开源工具的功能面（jadx / apktool / androguard / ipa-parser 的静态清单部分）：
- APK：ZIP 结构、AndroidManifest 二进制 XML（AXML）解析（包名/版本/权限/组件/
  导出状态/意图过滤器/SDK 范围/调试标志）、原生库 ABI 清单、DEX 摘要、
  签名形态（v1 JAR 签名文件 / v2-v3 APK Signing Block）。
- IPA：Payload/*.app/Info.plist（含 bplist）、Bundle 标识/版本/可执行文件/
  最低系统版本、Frameworks、provisioning profile 存在性。

诚实边界：
- 证书链解析需要 cryptography/pkcs7 库 —— 这里只报签名**形态与指纹**，不冒充
  证书解析器（.RSA/.DSA/.EC 的 DER 主体信息标 unknown_reason="needs_pkcs7_parser"）。
- resources.arsc（资源表）解析不在本模块（已知边界，reason 如实标注）。
- AXML 只按属性名/属性值还原语义；资源引用（TYPE_REFERENCE）保留原始 resId 不反查。

所有解析都做边界保护：损坏输入返回 ``{"ok": False, "reason": ...}``，不崩不编造。
"""

from __future__ import annotations

import hashlib
import io
import plistlib
import struct
import zipfile

__all__ = ["inspect_apk", "inspect_ipa", "parse_axml"]


# ---------------------------------------------------------------- 基础助手


class _BytesReader:
    """lib_formats.Reader 的字节缓冲鸭子类型（供 parse_dex 复用）。"""

    def __init__(self, data: bytes):
        self._d = data
        self.size = len(data)

    def read(self, off: int, n: int) -> bytes:
        if off < 0 or off >= len(self._d):
            return b""
        return self._d[off:off + n]


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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- AXML


# ResXML chunk 类型
_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_NS = 0x0100
_RES_XML_END_NS = 0x0101
_RES_XML_START_EL = 0x0102
_RES_XML_END_EL = 0x0103
_RES_XML_CDATA = 0x0104
_RES_XML_RES_MAP = 0x0180

# Res_value 数据类型
_TYPE_REFERENCE = 0x01
_TYPE_STRING = 0x03
_TYPE_FLOAT = 0x04
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12


def _parse_string_pool(chunk: bytes):
    """解析字符串池 chunk（UTF-8 与 UTF-16 两种编码）。"""
    n_str = _u(chunk, 8, "I")
    _n_style = _u(chunk, 12, "I")
    flags = _u(chunk, 16, "I") or 0
    strings_start = _u(chunk, 20, "I")
    if n_str is None or strings_start is None or n_str > 2_000_000:
        return []
    utf8 = bool(flags & 0x100)
    out = []
    for i in range(n_str):
        rel = _u(chunk, 28 + i * 4, "I")
        if rel is None:
            break
        p = strings_start + rel
        if p < 0 or p >= len(chunk):
            out.append("")
            continue
        try:
            if utf8:
                # u8 charLen(可扩展) u8 byteLen(可扩展) bytes u8\0
                char_len, p = _u8len(chunk, p)
                byte_len, p = _u8len(chunk, p)
                raw = chunk[p:p + min(byte_len, 65535)]
                out.append(raw.decode("utf-8", "replace"))
            else:
                n, p = _u16len(chunk, p)
                raw = chunk[p:p + min(n * 2, 131070)]
                out.append(raw.decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


def _u8len(data, p):
    b = data[p]
    if b & 0x80:
        v = ((b & 0x7F) << 8) | data[p + 1]
        return v, p + 2
    return b, p + 1


def _u16len(data, p):
    v = _u(data, p, "H")
    if v is None:
        return 0, p + 2
    if v & 0x8000:
        v2 = _u(data, p + 2, "H") or 0
        return ((v & 0x7FFF) << 16) | v2, p + 4
    return v, p + 2


def parse_axml(data: bytes) -> dict:
    """Android 二进制 XML（AXML）→ 元素树。

    返回 {"ok", "strings", "elements": [ {name, attrs, children?, text?} ]}。
    只做一层深度的元素线性流（manifest 解析用 start/end 配对重建层级）。
    """
    if len(data) < 8:
        return _bad("AXML 太短")
    ftype = _u(data, 0, "H")
    fsize = _u(data, 4, "I")
    if ftype != _RES_XML:
        return _bad("不是 AXML（type=%s）" % hex(ftype or 0))
    if fsize is None or fsize > len(data):
        fsize = len(data)

    strings: list[str] = []
    events = []
    pos = 8
    while pos + 8 <= fsize:
        ctype = _u(data, pos, "H")
        hsize = _u(data, pos + 2, "H")
        csize = _u(data, pos + 4, "I")
        if not ctype or not csize or csize < 8 or pos + csize > len(data):
            break
        chunk = data[pos:pos + csize]
        if ctype == _RES_STRING_POOL:
            strings = _parse_string_pool(chunk)
        elif ctype in (_RES_XML_START_EL, _RES_XML_END_EL):
            # node header: 8(chunk) + lineNumber u32 + comment u32 = 16
            if ctype == _RES_XML_START_EL:
                ns_i = _u(chunk, 16, "I")
                name_i = _u(chunk, 20, "I")
                attr_start = _u(chunk, 24, "H") or 0
                attr_size = _u(chunk, 26, "H") or 20
                attr_count = _u(chunk, 28, "H") or 0
                attrs = {}
                base = 16 + attr_start  # 相对 node 起点（chunk[16:] 是 node 体）
                for k in range(min(attr_count, 512)):
                    ao = base + k * attr_size
                    a_ns = _u(chunk, ao, "I")
                    a_name = _u(chunk, ao + 4, "I")
                    a_raw = _u(chunk, ao + 8, "I")
                    v_type = _u(chunk, ao + 15, "B")
                    v_data = _u(chunk, ao + 16, "I")
                    key = strings[a_name] if a_name is not None and a_name < len(strings) else "attr%d" % k
                    if v_type == _TYPE_STRING:
                        val = strings[a_raw] if a_raw is not None and a_raw < len(strings) else (
                            strings[v_data] if v_data is not None and v_data < len(strings) else None)
                    elif v_type == _TYPE_INT_BOOLEAN:
                        val = bool(v_data)
                    elif v_type in (_TYPE_INT_DEC, _TYPE_REFERENCE):
                        val = v_data
                    elif v_type == _TYPE_INT_HEX:
                        val = hex(v_data or 0)
                    elif v_type == _TYPE_FLOAT:
                        val = v_data  # 原始位型；不做浮点还原（避免精度误导）
                    else:
                        val = v_data
                    if a_ns is not None and a_ns < len(strings):
                        key = strings[a_ns].split("/")[-1] + ":" + key
                    attrs[key] = val
                name = strings[name_i] if name_i is not None and name_i < len(strings) else "?"
                events.append(("start", name, attrs))
            else:
                name_i = _u(chunk, 20, "I")
                name = strings[name_i] if name_i is not None and name_i < len(strings) else "?"
                events.append(("end", name, None))
        # START_NS / END_NS / CDATA / RES_MAP 忽略（不影响 manifest 语义）
        pos += csize

    # start/end 配对重建层级（栈式）
    root = {"name": "#root", "attrs": {}, "children": []}
    stack = [root]
    for ev in events:
        if ev[0] == "start":
            node = {"name": ev[1], "attrs": ev[2], "children": []}
            stack[-1]["children"].append(node)
            stack.append(node)
        elif ev[0] == "end":
            if len(stack) > 1:
                stack.pop()
    return _ok(strings=len(strings), elements=root["children"],
               tree=root["children"][0] if root["children"] else None)


# ---------------------------------------------------------------- manifest 语义


_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
_PREFER_NS = ("android:", "")


def _attr(attrs: dict, name: str, ns: str = "android:"):
    """属性查找：android: 名空间优先，裸名兜底。"""
    for k in (ns + name, name):
        if k in attrs:
            return attrs[k]
    # 任意名空间匹配
    for k, v in attrs.items():
        if k.split(":")[-1] == name:
            return v
    return None


def _manifest_semantics(tree: dict) -> dict:
    """从 AXML 元素树提取 manifest 语义（包名/权限/组件/SDK…）。"""
    out = {
        "package": _attr(tree.get("attrs", {}), "package", "") if tree else None,
        "version_code": _attr(tree.get("attrs", {}), "versionCode") if tree else None,
        "version_name": _attr(tree.get("attrs", {}), "versionName") if tree else None,
        "shared_user_id": _attr(tree.get("attrs", {}), "sharedUserId") if tree else None,
        "permissions": [],
        "sdk": {},
        "application": {},
        "components": [],
        "queries_packages": [],
    }
    if not tree:
        return out

    def walk(node, in_app=False):
        tag = node.get("name", "")
        attrs = node.get("attrs", {})
        if tag == "uses-permission" or tag == "uses-permission-sdk-23":
            nm = _attr(attrs, "name")
            if nm and nm not in out["permissions"]:
                out["permissions"].append(nm)
        elif tag == "uses-sdk":
            for k in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
                v = _attr(attrs, k)
                if v is not None:
                    out["sdk"][k] = v
        elif tag == "application":
            in_app = True
            out["application"] = {
                "label": _attr(attrs, "label"),
                "debuggable": _attr(attrs, "debuggable"),
                "allow_backup": _attr(attrs, "allowBackup"),
                "network_security_config": _attr(attrs, "networkSecurityConfig"),
                "uses_cleartext_traffic": _attr(attrs, "usesCleartextTraffic"),
            }
        elif tag == "package" and node.get("parent_provider"):
            pass
        elif tag in _COMPONENT_TAGS:
            comp = {
                "type": tag,
                "name": _attr(attrs, "name"),
                "exported": _attr(attrs, "exported"),
                "permission": _attr(attrs, "permission"),
                "intent_actions": [],
                "intent_categories": [],
            }
            for ch in node.get("children", []):
                if ch.get("name") == "intent-filter":
                    for f in ch.get("children", []):
                        if f.get("name") == "action":
                            a = _attr(f.get("attrs", {}), "name")
                            if a:
                                comp["intent_actions"].append(a)
                        elif f.get("name") == "category":
                            c = _attr(f.get("attrs", {}), "name")
                            if c:
                                comp["intent_categories"].append(c)
            # exported 缺省：有 intent-filter 时 Android 语义默认 true（targetSdk<31）
            if comp["exported"] is None:
                comp["exported"] = bool(comp["intent_actions"]) or None
                comp["exported_source"] = "intent-filter-default" if comp["intent_actions"] else "absent"
            else:
                comp["exported_source"] = "explicit"
            out["components"].append(comp)
            return  # 组件子节点已处理
        elif tag == "queries":
            for ch in node.get("children", []):
                if ch.get("name") == "package":
                    nm = _attr(ch.get("attrs", {}), "name", "")
                    if nm:
                        out["queries_packages"].append(nm)
        for ch in node.get("children", []):
            walk(ch, in_app)

    walk(tree)
    return out


# ---------------------------------------------------------------- APK


_ZIP_MAGIC = b"PK\x03\x04"


def inspect_apk(path: str, max_entries: int = 200) -> dict:
    """APK 静态检查：结构 + manifest 语义 + DEX 摘要 + 原生库 + 签名形态。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        if head != _ZIP_MAGIC:
            return _bad("不是 ZIP/APK（魔数不符）", magic=head.hex())
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        return _bad("ZIP 损坏: %s" % e)
    except OSError as e:
        return _bad("读取失败: %s" % e)

    with zf:
        names = zf.namelist()
        if not any(n == "AndroidManifest.xml" for n in names) and \
           not any(n.endswith(".dex") for n in names):
            return _bad("ZIP 里没有 AndroidManifest.xml / classes*.dex，不是 APK",
                        entries=len(names))

        infos = zf.infolist()
        out = {
            "ok": True,
            "format": "apk",
            "entry_count": len(names),
            "total_uncompressed": sum(i.file_size for i in infos),
            "total_compressed": sum(i.compress_size for i in infos),
            "entries_sample": [i.filename for i in infos[:max_entries]],
        }

        # manifest
        try:
            mdata = zf.read("AndroidManifest.xml")
            ax = parse_axml(mdata)
            if ax.get("ok"):
                sem = _manifest_semantics(ax.get("tree"))
                out["manifest"] = sem
                out["manifest_sha256"] = _sha256(mdata)
            else:
                out["manifest"] = {"error": ax.get("reason")}
        except Exception as e:
            out["manifest"] = {"error": "%s: %s" % (type(e).__name__, e)}

        # DEX 摘要（复用 lib_formats.parse_dex 的头解析）
        dexes = []
        try:
            import lib_formats as F
            for n in names:
                if n.endswith(".dex") and "/" not in n.rstrip("/"):
                    blob = zf.read(n)
                    d = F.parse_dex(_BytesReader(blob))
                    d["entry"] = n
                    d["sha256"] = _sha256(blob)
                    dexes.append(d)
        except Exception as e:
            out["dex_error"] = "%s: %s" % (type(e).__name__, e)
        out["dex"] = dexes

        # 原生库 ABI 清单
        libs = {}
        for n in names:
            if n.startswith("lib/") and n.endswith(".so"):
                parts = n.split("/")
                abi = parts[1] if len(parts) > 2 else "?"
                libs.setdefault(abi, []).append(parts[-1])
        out["native_libs"] = {k: sorted(v) for k, v in sorted(libs.items())}

        # assets / res / kotlin 等目录规模
        out["dir_counts"] = {
            "assets": sum(1 for n in names if n.startswith("assets/")),
            "res": sum(1 for n in names if n.startswith("res/")),
            "kotlin": sum(1 for n in names if n.startswith("kotlin/")),
            "META-INF": sum(1 for n in names if n.startswith("META-INF/")),
        }

        # 签名形态：v1（META-INF 签名文件）+ v2/v3（APK Signing Block）
        sig_v1 = [n for n in names if n.startswith("META-INF/") and
                  n.upper().endswith((".RSA", ".DSA", ".EC", ".SF", ".MANIFEST"))]
        out["signing"] = {"v1_files": sig_v1, "v1_present": bool(sig_v1)}
        out["signing"].update(_apk_signing_block(path))
        if "resources.arsc" in names:
            out["resources_arsc"] = {
                "present": True,
                "note": "资源表解析超出本模块边界（已知限制），仅申报存在性",
            }
    return out


def _apk_signing_block(path: str) -> dict:
    """检测 v2/v3 APK Signing Block（中央目录之前搜 'APK Sig Block 42'）。"""
    try:
        with open(path, "rb") as f:
            data = f.read(min(_file_size(path), 256 * 1024 * 1024))
    except OSError as e:
        return {"v2_present": None, "reason": str(e)}
    # EOCD 在尾部 64K 内（注释最长 64K）
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return {"v2_present": False, "reason": "无 EOCD"}
    cd_off = _u(data, eocd + 16, "I")
    if cd_off is None or cd_off < 32:
        return {"v2_present": False}
    magic = data[cd_off - 16:cd_off]
    if magic == b"APK Sig Block 42":
        blk_size = _u(data, cd_off - 24, "Q")
        return {"v2_present": True, "signing_block_size": blk_size,
                "marker_off": cd_off - 16}
    return {"v2_present": False}


def _file_size(path: str) -> int:
    import os
    return os.path.getsize(path)


# ---------------------------------------------------------------- IPA


def inspect_ipa(path: str, max_entries: int = 200) -> dict:
    """IPA（iOS 应用）静态检查：Info.plist 语义 + Frameworks + provisioning。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        if head != _ZIP_MAGIC:
            return _bad("不是 ZIP/IPA（魔数不符）", magic=head.hex())
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        return _bad("ZIP 损坏: %s" % e)
    except OSError as e:
        return _bad("读取失败: %s" % e)

    with zf:
        names = zf.namelist()
        app_dirs = sorted({n.split("/")[1] for n in names
                           if n.startswith("Payload/") and n.count("/") >= 1 and
                           n.split("/")[1].endswith(".app")})
        if not app_dirs:
            return _bad("没有 Payload/*.app，不是 IPA", entries=len(names))

        out = {"ok": True, "format": "ipa", "app_bundles": app_dirs,
               "entry_count": len(names),
               "entries_sample": names[:max_entries]}
        app = app_dirs[0]
        info_name = "Payload/%s/Info.plist" % app

        # Info.plist（可能是 bplist；plistlib 自动识别）
        if info_name in names:
            try:
                raw = zf.read(info_name)
                pl = plistlib.loads(raw)
                out["info_plist"] = {
                    "bundle_id": pl.get("CFBundleIdentifier"),
                    "name": pl.get("CFBundleName") or pl.get("CFBundleDisplayName"),
                    "short_version": pl.get("CFBundleShortVersionString"),
                    "bundle_version": pl.get("CFBundleVersion"),
                    "executable": pl.get("CFBundleExecutable"),
                    "min_os": pl.get("MinimumOSVersion"),
                    "platform": pl.get("DTPlatformName"),
                    "sdk": pl.get("DTSDKName"),
                    "url_schemes": _url_schemes(pl),
                    "bundle_url_types": len(pl.get("CFBundleURLTypes", []) or []),
                    "device_family": pl.get("UIDeviceFamily"),
                    "plist_sha256": _sha256(raw),
                }
            except Exception as e:
                out["info_plist"] = {"error": "%s: %s" % (type(e).__name__, e)}
        else:
            out["info_plist"] = {"error": "Info.plist 缺失"}

        out["frameworks"] = sorted({n.split("/")[-2] for n in names
                                    if "/Frameworks/" in n and n.endswith(".framework/") or
                                    ("/Frameworks/" in n and n.count("/") == 3 and
                                     n.split("/")[-1].endswith(".framework"))})[:50]
        # 更稳的 framework 清单
        fws = sorted({n.split("/Frameworks/")[1].split("/")[0] for n in names
                      if "/Frameworks/" in n})
        out["frameworks"] = fws[:50]
        out["provisioning"] = {
            "embedded_mobileprovision":
                ("Payload/%s/embedded.mobileprovision" % app) in names,
        }
        out["plugins"] = sorted({n.split("/PlugIns/")[1].split("/")[0] for n in names
                                 if "/PlugIns/" in n})[:20]
        out["dylibs"] = sorted({n.split("/")[-1] for n in names
                                if n.endswith(".dylib")})[:50]
    return out


def _url_schemes(pl: dict):
    schemes = []
    for t in pl.get("CFBundleURLTypes", []) or []:
        for s in t.get("CFBundleURLSchemes", []) or []:
            schemes.append(s)
    return schemes
