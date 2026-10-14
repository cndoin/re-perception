# -*- coding: utf-8 -*-
"""DEX 方法级接口地图（纯标准库）。

对标 androguard / jadx / dexdump 的方法级分析面，回答核心问题
「这个 APK 到底调用了什么接口、是哪段代码调的」：

- **全表解析**：string / type / proto / field / method id 表 +
  class_def → class_data（encoded_method）→ code_item，落到「类 × 方法」粒度。
- **方法级调用面**：逐方法线性扫 Dalvik 字节码，抽取 invoke-*（method_ids
  引用）、const-string、sget/iget 字段引用、const-class/new-instance 类型引用；
  调用按「应用内（DEX 自定义类）/ 外部（框架与三方库）」分类。
- **api_surface 汇总**：外部调用按 owner 类聚合（方法名 + 调用者 + 次数），
  这就是「APK 里调用了什么接口」的直接答案。
- **JNI 双向映射**：ACC_NATIVE 方法声明 ↔ lib/*.so 里的 Java_* 符号，
  报 matched / unmatched_native / orphan_symbols 三向差集（不装作能对上就对上）。
- **组件入口面**：manifest 组件类 → DEX 里是否定义 → 生命周期方法清单。
- **字符串溯源**：const-string → 归属方法，URL 用 lib_netio 的同一套正则
  （URL 判定只有一个裁决点，不做第二套实现）。

诚实边界（不冒充）：
- 不反编译、不做数据流/类型恢复（那是 IR 线的活）；这里只回答
  「谁调用了谁、用了什么串、native 边界在哪」。
- Dalvik 按官方 opcode 宽度表线性扫；遇到未知 opcode / 越界 code_off 时
  **停止该方法的扫描并如实标记 partial / error**，不猜、不跳、不吞。
- .so 符号是「符号串扫描」（dynstr 里的符号必然以明文出现），**不是完整
  dynsym 语义解析**；scan_method 字段如实标注，剥离/混淆样本扫不到就说扫不到。
- 扫描预算（max_insns）耗尽即停，truncated 标志与真实总量一起给出。
"""

from __future__ import annotations

import re
import struct
import zipfile

import lib_formats as F
import lib_netio as NET

__all__ = ["map_dex"]

# ---------------------------------------------------------------- 常量表

# Dalvik opcode → 指令宽度（16-bit code unit 数）。来源：Dalvik bytecode
# 官方 opcode 表（10x/11x/11n=1，21c/22c/23x/22t/21t/22s/22b=2，
# 31i/31c/31t/35c/3rc/30t/32x=3，45cc/4rcc=4，51l=5）。
def _build_op_len() -> list:
    w = [1] * 256
    for op in (0x02, 0x05, 0x08,                 # move/from16 家族
               0x13, 0x15, 0x16, 0x19,           # const/16、high16 家族
               0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23,
               0x29,                              # goto/16
               0x2d, 0x2e, 0x2f, 0x30, 0x31,     # cmp*
               0xfe, 0xff):
        w[op] = 2
    for op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37):   # if-eq..if-le
        w[op] = 2
    for op in range(0x38, 0x3e):                       # if-eqz..if-lez
        w[op] = 2
    for op in range(0x44, 0x6e):                       # aget/aput/iget/iput/sget/sput
        w[op] = 2
    for op in range(0x90, 0xb0):                       # binop
        w[op] = 2
    for op in range(0xd0, 0xe3):                       # binop/lit16、lit8
        w[op] = 2
    for op in (0x03, 0x06, 0x09,                       # move/16 家族
               0x14, 0x17, 0x1b,                       # const、const-wide/32、const-string/jumbo
               0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c):    # filled-new-array*、fill-array-data、goto/32、switch
        w[op] = 3
    for op in range(0x6e, 0x73):                       # invoke-kind
        w[op] = 3
    for op in range(0x74, 0x79):                       # invoke-kind/range
        w[op] = 3
    w[0xfc] = w[0xfd] = 3                              # invoke-custom(/range)
    w[0x18] = 5                                        # const-wide
    w[0xfa] = w[0xfb] = 4                              # invoke-polymorphic(/range)
    return w


_OP_LEN = _build_op_len()

_INVOKE_OPS = {
    0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct",
    0x71: "invoke-static", 0x72: "invoke-interface",
    0x74: "invoke-virtual/range", 0x75: "invoke-super/range",
    0x76: "invoke-direct/range", 0x77: "invoke-static/range",
    0x78: "invoke-interface/range",
    0xFA: "invoke-polymorphic", 0xFB: "invoke-polymorphic/range",
}
_CUSTOM_OPS = {0xFC: "invoke-custom", 0xFD: "invoke-custom/range"}

# 方法 access_flags（只列方法语义位；字段的 volatile/transient 与此不同）
_ACCESS = (
    (0x0001, "public"), (0x0002, "private"), (0x0004, "protected"),
    (0x0008, "static"), (0x0010, "final"), (0x0020, "synchronized"),
    (0x0040, "bridge"), (0x0080, "varargs"), (0x0100, "native"),
    (0x0200, "interface"), (0x0400, "abstract"), (0x0800, "strictfp"),
    (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum"),
    (0x10000, "constructor"), (0x20000, "declared-synchronized"),
)

_NO_INDEX = 0xFFFFFFFF

# 每类默认输出上限（超出计数如实报 truncated）
DEF_MAX_CLASSES = 200
DEF_MAX_METHODS = 40
DEF_MAX_INSNS = 2_000_000

# 组件生命周期方法（entry_points 用；只做「定义了没」的观测，不猜运行时行为）
_LIFECYCLE = {
    "activity": ("onCreate", "onStart", "onResume", "onPause", "onStop",
                 "onDestroy", "onNewIntent", "onActivityResult"),
    "service": ("onCreate", "onStartCommand", "onBind", "onUnbind", "onDestroy"),
    "receiver": ("onReceive",),
    "provider": ("onCreate", "query", "insert", "update", "delete", "getType"),
}


# ---------------------------------------------------------------- 基础助手


def _bad(reason, **kw):
    d = {"ok": False, "reason": reason}
    d.update(kw)
    return d


def _u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def _uleb(data, off):
    """uleb128，委托 lib_formats（判定逻辑只留一处）。"""
    return F.uleb128(data, off)


def _mutf8(raw: bytes) -> str:
    """MUTF-8 解码（DEX 字符串编码）：0xC0 0x80 是内嵌 NUL，补充平面用代理对。

    与 utf-8 的差别正是 DEX 字符串的坑：直接 bytes.decode('utf-8') 会把
    0xC0 0x80 解坏、代理对也会乱。这里按规范逐码元解，坏序列给 U+FFFD
    而不是抛异常（截断输入必须优雅）。
    """
    out = []
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0:
            break
        if b < 0x80:
            out.append(chr(b))
            i += 1
        elif (b & 0xE0) == 0xC0 and i + 1 < n:
            out.append(chr(((b & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif (b & 0xF0) == 0xE0 and i + 2 < n:
            cp = ((b & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F)
            # 高位代理 → 尝试拼低位代理（两个 3 字节序列）
            if 0xD800 <= cp <= 0xDBFF and i + 5 < n and (raw[i + 3] & 0xF0) == 0xE0:
                lo = ((raw[i + 3] & 0x0F) << 12) | ((raw[i + 4] & 0x3F) << 6) | (raw[i + 5] & 0x3F)
                if 0xDC00 <= lo <= 0xDFFF:
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                    i += 6
                    out.append(chr(cp))
                    continue
            out.append(chr(cp))
            i += 3
        else:
            out.append("�")
            i += 1
    return "".join(out)


_PRIM = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
         "I": "int", "J": "long", "F": "float", "D": "double"}


def _pretty_type(desc: str) -> str:
    """类型描述符 → 可读名：Landroid/telephony/TelephonyManager; → android.telephony.TelephonyManager"""
    arr = 0
    while desc.startswith("["):
        arr += 1
        desc = desc[1:]
    if desc.startswith("L") and desc.endswith(";"):
        base = desc[1:-1].replace("/", ".")
    else:
        base = _PRIM.get(desc, desc)
    return base + "[]" * arr


def _pretty_proto(proto: str) -> str:
    """"(ILjava/lang/String;)V" → ("int, java.lang.String", "void")"""
    if not (proto.startswith("(") and ")" in proto):
        return ("?", "?")
    args, ret = proto[1:proto.index(")")], proto[proto.index(")") + 1:]
    out, i = [], 0
    while i < len(args):
        j = i
        while j < len(args) and args[j] == "[":
            j += 1
        if j < len(args) and args[j] == "L":
            j = args.find(";", j)
            if j < 0:
                break
        j += 1
        out.append(_pretty_type(args[i:j]))
        i = j
    return (", ".join(out), _pretty_type(ret))


def _flags_names(mask: int) -> list:
    return [name for bit, name in _ACCESS if mask & bit]


def _jni_symbol(desc: str, method: str) -> str:
    """JNI 导出符号名（短名形式）：Lcom/demo/Main; + init → Java_com_demo_Main_init"""
    def esc(s):
        out = []
        for ch in s:
            if ch == "_":
                out.append("_1")
            elif ch == "/":
                out.append("_")
            elif ch == ".":
                out.append("_")
            elif ch == ";":
                out.append("_2")
            elif ch == "[":
                out.append("_3")
            elif ch.isascii() and ch.isalnum():
                out.append(ch)
            else:
                out.append("_0%04x" % ord(ch))
        return "".join(out)

    core = desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    return "Java_" + esc(core) + "_" + esc(method)


# ---------------------------------------------------------------- DEX 解析


def _parse_string_pool(data: bytes, str_off: int, str_cnt: int) -> list:
    out = []
    ids = data[str_off:str_off + str_cnt * 4]
    for i in range(str_cnt):
        so = _u32(ids, i * 4)
        if so is None or so >= len(data):
            out.append("")
            continue
        _ulen, p = _uleb(data, so)
        end = data.find(b"\x00", p)
        if end < 0:
            end = min(p + 4096, len(data))
        out.append(_mutf8(data[p:min(end, p + 4096)]))
    return out


def _parse_type_list(data: bytes, off: int) -> list:
    """type_list → type_idx 列表。"""
    if not off:
        return []
    size = _u32(data, off)
    if not size or size > 4096:
        return []
    out = []
    for i in range(size):
        v = _u16(data, off + 4 + i * 2)
        if v is None:
            break
        out.append(v)
    return out


def _walk_code(data: bytes, off: int, budget: list) -> dict:
    """线性扫一个 code_item，抽取方法调用/字符串/字段/类型引用。

    budget 是 [剩余可扫 code unit 数] 的单元素列表（跨方法共享）；
    耗尽即停并把 partial 标出来 —— 宁可少报，不可编造。
    """
    out = {"insns": 0, "calls": [], "strings": [], "fields": [], "types": [],
           "partial": False, "reason": None}
    regs = _u16(data, off)
    # code_item 头：registers u16@0 ins u16@2 outs u16@4 tries u16@6
    #               debug_off u32@8 insns_size u32@12 insns u16[]@16
    insns_size = _u32(data, off + 12)
    if regs is None or insns_size is None:
        out["partial"] = True
        out["reason"] = "code_item 头越界"
        return out
    out["registers"] = regs
    out["ins_size"] = _u16(data, off + 2)
    base = off + 16
    pos = 0
    while pos < insns_size:
        if budget[0] <= 0:
            out["partial"] = True
            out["reason"] = "insns 预算耗尽"
            break
        unit = _u16(data, base + pos * 2)
        if unit is None:
            out["partial"] = True
            out["reason"] = "insns 越界"
            break
        budget[0] -= 1
        # payload 伪指令（packed/sparse-switch、fill-array-data）
        if unit in (0x0100, 0x0200, 0x0300):
            if unit == 0x0100:
                sz = _u16(data, base + (pos + 1) * 2) or 0
                step = 4 + 2 * sz
            elif unit == 0x0200:
                sz = _u16(data, base + (pos + 1) * 2) or 0
                step = 2 + 4 * sz
            else:
                ew = _u16(data, base + (pos + 1) * 2) or 0
                sz = _u32(data, base + (pos + 2) * 2) or 0
                step = 4 + (ew * sz + 1) // 2
            pos += max(step, 1)
            continue
        op = unit & 0xFF
        width = _OP_LEN[op] if op < 256 else 1
        nxt = _u16(data, base + (pos + 1) * 2) if width >= 2 else None
        if op in _INVOKE_OPS:
            if nxt is not None:
                out["calls"].append({"op": _INVOKE_OPS[op], "method_idx": nxt})
        elif op in _CUSTOM_OPS:
            # invoke-custom 的索引是 call_site（本模块不解析 call_site 段）
            out["calls"].append({"op": _CUSTOM_OPS[op], "call_site_idx": nxt,
                                 "target": "call-site(未解析)"})
        elif op in (0x1A, 0x1B):
            if op == 0x1A:
                idx = nxt
            else:
                lo = nxt or 0
                hi = _u16(data, base + (pos + 2) * 2) or 0
                idx = lo | (hi << 16)
            if idx is not None:
                out["strings"].append(idx)
        elif 0x52 <= op <= 0x6D and nxt is not None:
            out["fields"].append(nxt)            # iget/iput/sget/sput
        elif op in (0x1C, 0x1F, 0x20, 0x22, 0x23) and nxt is not None:
            out["types"].append(nxt)             # const-class/check-cast/instance-of/new-*
        pos += width
        out["insns"] += 1
    return out


def _parse_dex_buffer(data: bytes, entry: str, max_insns: int) -> dict:
    """单个 DEX buffer → 结构化结果（类/方法/引用 + 观测计数）。"""
    res = {"entry": entry, "errors": [], "classes": [], "class_total": 0,
           "method_total": 0, "methods_with_code": 0, "insns_scanned": 0}
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        res["errors"].append("DEX 魔数缺失/文件过短")
        return res
    ver = data[4:7].decode("ascii", "replace")
    (file_size, _hdr, _endian, _ls, _lo, _mo,
     str_cnt, str_off, type_cnt, type_off, proto_cnt, proto_off,
     field_cnt, field_off, method_cnt, method_off, class_cnt, class_off,
     _ds, _do) = struct.unpack_from("<IIIIIIIIIIIIIIIIIIII", data, 32)
    res.update({"dex_version": ver, "file_size": file_size,
                "string_count": str_cnt, "type_count": type_cnt,
                "method_count": method_cnt, "class_count": class_cnt})
    # 限额保护：计数字段损坏时宁可拒解，不按坏计数跑飞
    for label, cnt, cap in (("string", str_cnt, 2_000_000), ("type", type_cnt, 1_000_000),
                            ("proto", proto_cnt, 1_000_000), ("method", method_cnt, 1_000_000),
                            ("class", class_cnt, 200_000)):
        if cnt > cap:
            res["errors"].append("%s 表计数 %d 超过上限 %d（表损坏或非 DEX）" % (label, cnt, cap))
            return res

    strings = _parse_string_pool(data, str_off, str_cnt) if str_cnt and str_off else []
    if len(strings) < str_cnt:
        res["errors"].append("字符串池部分越界（%d/%d）" % (len(strings), str_cnt))

    def s(idx, default=""):
        return strings[idx] if idx is not None and 0 <= idx < len(strings) else default

    # type_ids → 描述符
    types = []
    if type_cnt and type_off:
        ids = data[type_off:type_off + type_cnt * 4]
        for i in range(type_cnt):
            di = _u32(ids, i * 4)
            types.append(s(di))
    # proto_ids → 原型文本
    protos = []
    if proto_cnt and proto_off:
        for i in range(proto_cnt):
            base = proto_off + i * 12
            _shorty = _u32(data, base)
            ret_idx = _u32(data, base + 4)
            params_off = _u32(data, base + 8)
            pidx = _parse_type_list(data, params_off or 0)
            args = "".join(types[t] if t < len(types) else "?" for t in pidx)
            ret = types[ret_idx] if ret_idx is not None and ret_idx < len(types) else "?"
            protos.append("(" + args + ")" + ret)
    # field_ids
    fields = []
    if field_cnt and field_off:
        for i in range(field_cnt):
            base = field_off + i * 8
            cidx = _u16(data, base)
            tidx = _u16(data, base + 2)
            nidx = _u32(data, base + 4)
            fields.append(_ref(types, cidx, s(nidx), types[tidx] if tidx is not None else "?"))
    # method_ids
    methods = []
    if method_cnt and method_off:
        for i in range(method_cnt):
            base = method_off + i * 8
            cidx = _u16(data, base)
            pidx = _u16(data, base + 2)
            nidx = _u32(data, base + 4)
            owner = types[cidx] if cidx is not None and cidx < len(types) else "?"
            proto = protos[pidx] if pidx is not None and pidx < len(protos) else "?"
            methods.append({"owner": owner, "name": s(nidx), "proto": proto})
    res["methods_ref_total"] = len(methods)

    # 本 DEX 自定义类（owner 分类的裁决点：defined set）
    defined = set()
    budget = [max_insns]
    classes_out = []
    if class_cnt and class_off:
        for ci in range(class_cnt):
            base = class_off + ci * 32
            cidx = _u32(data, base)
            access = _u32(data, base + 4) or 0
            super_idx = _u32(data, base + 8)
            if_off = _u32(data, base + 12)
            src_idx = _u32(data, base + 16)
            # class_def_item: class_idx@0 access@4 super@8 interfaces@12
            #                 source_file@16 annotations@20 class_data@24
            #                 static_values@28（class_data_off 在 +24，不是 +28）
            cd_off = _u32(data, base + 24)
            desc = types[cidx] if cidx is not None and cidx < len(types) else "?"
            defined.add(desc)
            res["class_total"] += 1
            cls = {
                "descriptor": desc,
                "name": _pretty_type(desc),
                "super": (types[super_idx]
                          if super_idx not in (None, _NO_INDEX) and super_idx < len(types) else None),
                "interfaces": [types[t] for t in _parse_type_list(data, if_off or 0)
                               if t < len(types)],
                "access": _flags_names(access),
                "source_file": (s(src_idx) if src_idx not in (None, _NO_INDEX) else None),
                "methods": [],
                "errors": [],
            }
            if cd_off:
                cls.update(_parse_class_data(data, cd_off, methods, budget, res))
            else:
                cls["method_count"] = 0
            classes_out.append(cls)
    res["classes"] = classes_out
    res["defined_classes"] = defined
    # 引用表存进 res —— _aggregate 的字符串溯源（d["strings"]）和
    # 调用解析（d["method_refs"]）依赖这两张表，缺了就全是空面
    res["strings"] = strings
    res["method_refs"] = methods
    res["insns_scanned"] = max_insns - budget[0]
    return res


def _ref(types, cidx, name, type_desc):
    owner = types[cidx] if cidx is not None and cidx < len(types) else "?"
    return {"owner": owner, "name": name, "type": type_desc}


def _parse_class_data(data: bytes, off: int, methods: list,
                      budget: list, res: dict) -> dict:
    """class_data_item → 方法清单（含 code 扫描）。"""
    out = {"methods": [], "method_count": 0, "methods_truncated": False}
    try:
        p = off
        static_fields, p = _uleb(data, p)
        instance_fields, p = _uleb(data, p)
        direct_cnt, p = _uleb(data, p)
        virtual_cnt, p = _uleb(data, p)
        if any(v > 65535 for v in (static_fields, instance_fields, direct_cnt, virtual_cnt)):
            out["errors"] = ["class_data 计数异常（疑似损坏）"]
            return out
        # 字段项是变长 uleb（field_idx_diff + access_flags），逐项走不能粗跳
        for _ in range(static_fields + instance_fields):
            _diff, p = _uleb(data, p)
            _acc, p = _uleb(data, p)
        for kind, cnt in (("direct", direct_cnt), ("virtual", virtual_cnt)):
            midx = 0
            for _ in range(cnt):
                diff, p = _uleb(data, p)
                acc, p = _uleb(data, p)
                code_off, p = _uleb(data, p)
                midx += diff
                if midx >= len(methods):
                    break
                res["method_total"] += 1
                m = methods[midx]
                item = {
                    "full": "%s->%s%s" % (m["owner"], m["name"], m["proto"]),
                    "name": m["name"],
                    "owner": m["owner"],
                    "proto": m["proto"],
                    "kind": kind,
                    "access": _flags_names(acc),
                    "native": bool(acc & 0x100),
                }
                args, ret = _pretty_proto(m["proto"])
                item["pretty"] = "%s %s.%s(%s)" % (ret, _pretty_type(m["owner"]), m["name"], args)
                if code_off:
                    res["methods_with_code"] += 1
                    item["code"] = _walk_code(data, code_off, budget)
                elif item["native"]:
                    item["code"] = None
                else:
                    item["code"] = None   # abstract/接口方法
                out["methods"].append(item)
        out["method_count"] = len(out["methods"])
    except Exception as e:  # noqa: BLE001 —— 损坏输入降级为错误字段，不崩
        out["errors"] = ["class_data 解析失败：%s: %s" % (type(e).__name__, e)]
    return out


# ---------------------------------------------------------------- 汇总


def _aggregate(dexes: list, apk_info, max_classes: int, max_methods: int,
               class_filter, surface_only: bool) -> dict:
    """多 DEX 结果 → api_surface / jni / entry_points / urls 汇总。"""
    totals = {"classes": 0, "methods": 0, "methods_with_code": 0,
              "insns_scanned": 0, "external_calls": 0, "internal_calls": 0}
    surface = {}      # owner descriptor -> {"methods": {full: count}, "callers": set}
    urls = []
    seen_url = set()
    native_methods = []
    classes_out = []
    defined = set()

    for d in dexes:
        defined |= d.get("defined_classes", set())
    for d in dexes:
        totals["classes"] += d.get("class_total", 0)
        totals["methods"] += d.get("method_total", 0)
        totals["methods_with_code"] += d.get("methods_with_code", 0)
        totals["insns_scanned"] += d.get("insns_scanned", 0)

    for d in dexes:
        for cls in d.get("classes", []):
            if class_filter and class_filter.lower() not in cls["name"].lower():
                continue
            if not surface_only and len(classes_out) < max_classes:
                shown = []
                for m in cls.get("methods", [])[:max_methods]:
                    item = {k: m[k] for k in ("full", "name", "proto", "kind",
                                              "access", "native", "pretty")}
                    code = m.get("code")
                    if code:
                        calls = []
                        for c in code.get("calls", []):
                            if "method_idx" in c:
                                ref = _resolve_call(c, d)
                                calls.append(ref if isinstance(ref, dict) else {"ref": ref})
                            else:
                                calls.append({"ref": c.get("target"), "op": c["op"],
                                              "unresolved": True})
                        item["code"] = {
                            "insns": code.get("insns"),
                            "partial": code.get("partial"),
                            "reason": code.get("reason"),
                            "calls": calls[:16],
                            "call_count": len(calls),
                            "strings": [d["strings"][i] if i < len(d.get("strings", [])) else ""
                                        for i in code.get("strings", [])][:16],
                        }
                    else:
                        item["code"] = None
                    shown.append(item)
                cls_out = {k: cls[k] for k in ("descriptor", "name", "super",
                                                "interfaces", "access", "source_file")}
                cls_out["methods"] = shown
                cls_out["method_count"] = cls.get("method_count", 0)
                if cls.get("method_count", 0) > len(shown):
                    cls_out["methods_truncated"] = True
                if cls.get("errors"):
                    cls_out["errors"] = cls["errors"]
                classes_out.append(cls_out)
            # 汇总面（不受 max_classes 影响）
            for m in cls.get("methods", []):
                if m.get("native"):
                    native_methods.append(m)
                code = m.get("code")
                if not code:
                    continue
                for st in code.get("strings", []):
                    sval = d["strings"][st] if st < len(d.get("strings", [])) else ""
                    m_url = NET._RX_URL.search(sval)   # URL 判定唯一裁决点（lib_netio）
                    if m_url and m_url.group(0) not in seen_url:
                        seen_url.add(m_url.group(0))
                        urls.append({"url": m_url.group(0), "in_method": m["full"]})
                for c in code.get("calls", []):
                    if "method_idx" not in c:
                        continue
                    mi = c["method_idx"]
                    ref = d["method_refs"][mi] if mi < len(d.get("method_refs", [])) else None
                    if not ref:
                        continue
                    full = "%s->%s%s" % (ref["owner"], ref["name"], ref["proto"])
                    internal = ref["owner"] in defined
                    totals["internal_calls" if internal else "external_calls"] += 1
                    if internal:
                        continue
                    ent = surface.setdefault(ref["owner"], {"methods": {}, "callers": set()})
                    ent["methods"][full] = ent["methods"].get(full, 0) + 1
                    ent["callers"].add(m["full"])

    api_surface = []
    for owner, ent in sorted(surface.items(),
                             key=lambda kv: -sum(kv[1]["methods"].values())):
        api_surface.append({
            "owner": owner,
            "owner_pretty": _pretty_type(owner),
            "methods": [{"ref": k, "count": v}
                        for k, v in sorted(ent["methods"].items(), key=lambda kv: -kv[1])],
            "callers": sorted(ent["callers"])[:12],
            "call_count": sum(ent["methods"].values()),
        })

    out = {
        "ok": True,
        "format": "dex-map",
        "dex_files": [{k: d.get(k) for k in ("entry", "dex_version", "file_size",
                                             "class_count", "method_count", "string_count")}
                      for d in dexes],
        "totals": totals,
        "api_surface": api_surface,
        "urls": urls[:100],
        "errors": [e for d in dexes for e in d.get("errors", [])],
    }
    if not surface_only:
        out["classes"] = classes_out
        out["classes_total"] = totals["classes"]
        if totals["classes"] > len(classes_out):
            out["classes_truncated"] = True
        if totals["methods"] > sum(len(c["methods"]) for c in classes_out):
            out["methods_truncated"] = True

    # ---- JNI 双向映射 ----
    so_symbols = _collect_so_symbols(apk_info)
    matched, unmatched = [], []
    for m in native_methods:
        base = _jni_symbol(m["owner"], m["name"])
        hit = None
        for lib, syms in so_symbols.items():
            for sym in syms:
                if sym == base or sym.startswith(base + "__"):
                    hit = (lib, sym)
                    break
            if hit:
                break
        if hit:
            matched.append({"method": m["full"], "symbol": hit[1], "lib": hit[0]})
        else:
            unmatched.append({"method": m["full"], "expected_symbol": base})
    all_matched_syms = {x["symbol"] for x in matched}
    orphan = [{"lib": lib, "symbol": sym}
              for lib, syms in so_symbols.items() for sym in syms
              if sym.startswith("Java_") and sym not in all_matched_syms]
    out["jni"] = {
        "native_methods": [m["full"] for m in native_methods],
        "so_symbols": {lib: syms[:60] for lib, syms in so_symbols.items()},
        "matched": matched,
        "unmatched_native": unmatched,
        "orphan_symbols": orphan[:60],
        "scan_method": "symbol-string-scan",
        "note": "so 符号为符号串扫描（非 dynsym 语义解析），剥离样本会如实报 unmatched/orphan",
    }

    # ---- 组件入口面 ----
    out["entry_points"] = _entry_points(apk_info, defined, dexes)
    return out


def _resolve_call(c: dict, d: dict) -> dict:
    mi = c["method_idx"]
    refs = d.get("method_refs", [])
    if mi >= len(refs):
        return {"ref": "method@%d(越界)" % mi, "op": c["op"], "unresolved": True}
    r = refs[mi]
    return {"ref": "%s->%s%s" % (r["owner"], r["name"], r["proto"]),
            "owner": r["owner"], "op": c["op"]}


def _collect_so_symbols(apk_info) -> dict:
    """lib/*.so 的 Java_* 符号串扫描（定位到符号串出现处，不冒充 dynsym 解析）。"""
    out = {}
    if not apk_info:
        return out
    path = apk_info.get("path")
    if not path:
        return out
    try:
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if not (n.startswith("lib/") and n.endswith(".so")):
                    continue
                blob = zf.read(n)
                syms = sorted({m.group(0) for m in
                               re.finditer(rb"Java_[A-Za-z0-9_]{1,200}", blob)})
                if syms:
                    out[n] = [x.decode("ascii", "replace") for x in syms]
    except (zipfile.BadZipFile, OSError, KeyError):
        return out  # 无 so / 读不到 → 已收集的部分如实返回，不影响主输出
    return out


def _entry_points(apk_info, defined: set, dexes: list) -> list:
    """manifest 组件 → DEX 类定义与生命周期方法观测。"""
    if not apk_info:
        return []
    manifest = apk_info.get("manifest") or {}
    pkg = manifest.get("package") or ""
    # 每类的方法名集合（观测「定义了哪些生命周期方法」）
    names_by_class = {}
    for d in dexes:
        for cls in d.get("classes", []):
            names_by_class.setdefault(cls["descriptor"], set()).update(
                m["name"] for m in cls.get("methods", []))
    out = []
    for comp in manifest.get("components", []):
        raw = comp.get("name") or ""
        if not raw:
            continue
        if raw.startswith("."):
            full = pkg + raw
        elif "." not in raw:
            full = pkg + "." + raw
        else:
            full = raw
        desc = "L%s;" % full.replace(".", "/")
        want = _LIFECYCLE.get(comp.get("type"), ())
        have = sorted(names_by_class.get(desc, set()) & set(want))
        out.append({
            "type": comp.get("type"),
            "name": full,
            "exported": comp.get("exported"),
            "exported_source": comp.get("exported_source"),
            "intent_actions": comp.get("intent_actions", []),
            "in_dex": desc in defined,
            "lifecycle_methods": have,
        })
    return out


# ---------------------------------------------------------------- 顶层


def map_dex(path: str, max_classes: int = DEF_MAX_CLASSES,
            max_methods: int = DEF_MAX_METHODS, max_insns: int = DEF_MAX_INSNS,
            class_filter: str | None = None, surface_only: bool = False) -> dict:
    """DEX 方法级接口地图。目标可以是 .apk（合并多 classes*.dex）或裸 .dex。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError as e:
        return _bad("读取失败: %s" % e)

    apk_info = None
    dex_blobs = []
    if head.startswith(b"PK"):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                dex_names = sorted((n for n in names if re.fullmatch(r"classes\d*\.dex", n)),
                                   key=lambda n: (len(n), n))
                if not dex_names:
                    return _bad("ZIP 里没有 classes*.dex", entries=len(names))
                for n in dex_names:
                    dex_blobs.append((n, zf.read(n)))
        except (zipfile.BadZipFile, OSError) as e:
            return _bad("ZIP 损坏: %s" % e)
        import lib_apk as AK
        apk_info = AK.inspect_apk(path)
        apk_info["path"] = path
        if not apk_info.get("ok"):
            apk_info = {"path": path, "manifest": None}
    elif head.startswith(b"dex\n"):
        with open(path, "rb") as f:
            dex_blobs.append((os_basename(path), f.read()))
    else:
        return _bad("不是 DEX / APK（魔数不符）", magic=head.hex())

    if max_insns <= 0:
        max_insns = DEF_MAX_INSNS
    dexes = [_parse_dex_buffer(blob, entry, max_insns) for entry, blob in dex_blobs]
    fatal = [d for d in dexes if not d.get("class_total") and d.get("errors")]
    if len(fatal) == len(dexes):
        base = _aggregate(dexes, apk_info, max_classes, max_methods,
                          class_filter, surface_only)
        base["ok"] = False
        base["reason"] = "全部 DEX 解析失败：" + "；".join(
            e for d in fatal for e in d["errors"])[:300]
        return base
    out = _aggregate(dexes, apk_info, max_classes, max_methods,
                     class_filter, surface_only)
    out["source"] = "apk" if apk_info else "dex"
    if apk_info and apk_info.get("manifest"):
        out["package"] = (apk_info.get("manifest") or {}).get("package")
    return out


def os_basename(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
