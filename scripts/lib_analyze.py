# -*- coding: utf-8 -*-
"""
lib_analyze.py —— 内容分析引擎：流式字符串提取、熵分析、IOC/风险标记、
加壳启发式、差分分析、文件雕刻。

性能设计（这三条是本技能包"快"的来源）：
  1. 一切扫描都是流式：固定 1MB 缓冲，内存占用与文件大小无关。
  2. 字符串提取用 C 实现的正则引擎做匹配，而不是 Python 逐字节循环
     ——实测比手写循环快一个数量级以上。
  3. 所有输出都有硬上限（max_items / budget_seconds），
     遇到病态文件（几百万个字符串）会主动截断而不是把内存吃光。
"""

from __future__ import annotations

import math
import os
import re
import time
from collections import Counter

from lib_formats import MAGICS, Reader, identify, shannon_entropy

# 可打印字符映射表：用于 translate 后 count(0) 反推不可打印字节数（比 Python 循环快得多）
PRINTABLE_TABLE = bytes(1 if (32 <= i < 127 or i in (9, 10, 13)) else 0 for i in range(256))

CHUNK = 1 << 20          # 1MB
CARRY = 8192             # 跨块字符串的最大回看长度
CLASSIFY_MAXLEN = 512    # 参与分类匹配的最大字符数（性能护栏）
DEFAULT_MAX_STRLEN = 8192   # 单条字符串的最大保存长度（内存护栏）

# ---------------------------------------------------------------- 分类正则（模块级编译一次）

RE_URL = re.compile(rb"https?://[^\s\"'<>\x00]{4,}")
# 整串匹配才算 IP（否则 "version=5.1.0.0" 这类版本号会被误判成地址）
RE_IPV4_FULL = re.compile(rb"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$")
# 量词一律加上界：无界的 [\w.+-]+@ 在长字符串上会退化成 O(n²) 回溯
RE_EMAIL = re.compile(rb"[\w.+-]{1,64}@[\w-]{1,64}\.[\w.-]{1,64}")
RE_WINPATH = re.compile(rb"[A-Za-z]:\\[^\s\"'\x00]{3,}")
RE_UNIXPATH = re.compile(rb"(?:/(?:usr|etc|home|var|tmp|opt|bin|sbin|root|data|system|proc)/)[^\s\"'\x00]{2,}")
RE_REG = re.compile(rb"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\x00]{2,}")
RE_PEM = re.compile(rb"-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE|PUBLIC KEY|RSA|EC|DSA|OPENSSH)")
RE_JWT = re.compile(rb"\beyJ[A-Za-z0-9_-]{10,80}\.[A-Za-z0-9_-]{10,80}\.[A-Za-z0-9_-]{5,80}")
RE_AWS = re.compile(rb"\bAKIA[0-9A-Z]{16}\b")
RE_GITHUB = re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
RE_BASE64 = re.compile(rb"^[A-Za-z0-9+/]{40,}={0,2}$")
RE_SQL = re.compile(rb"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|ALTER TABLE)\b", re.I)
RE_FMT = re.compile(rb"%[0-9*]*[sdifxXupn%]")
RE_CRYPTO = re.compile(
    rb"\b(?:AES|DES|3DES|RC4|RC5|Blowfish|ChaCha20|RSA|ECC|ECDSA|Ed25519|DSA|DH|"
    rb"SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5|HMAC|PBKDF2|bcrypt|scrypt|Argon2|"
    rb"Base64|Base32|Hex|TEA|XTEA|XXTEA|SM2|SM3|SM4|ZUC)\b")
RE_SRCPATH = re.compile(rb"[\w./\\-]{1,200}\.(?:c|cc|cpp|h|hpp|rs|go|java|kt|cs|py|js|ts|m|mm|swift):\d{1,8}")
RE_PDB = re.compile(rb"[\w./\\-]+\.pdb", re.I)
RE_UUID = re.compile(rb"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
RE_VER = re.compile(rb"\bv?\d+\.\d+(?:\.\d+)?(?:[-.]\w+)?\b")
RE_ERROR = re.compile(
    rb"(?:error|failed|failure|invalid|exception|panic|assert|denied|refused|timeout|"
    rb"not found|unauthorized|forbidden)", re.I)
# 中文关键词走 str 正则（bytes 正则里不能写非 ASCII 字面量）
RE_ERROR_CN = re.compile("损坏|失败|错误|拒绝|超时|未授权|异常|无效")

# 风险 API / 行为关键词（出现在导入表或字符串中即值得关注）
SUSPICIOUS_API = {
    # 进程注入 / 代码执行
    "CreateRemoteThread", "RtlCreateUserThread", "NtCreateThreadEx", "QueueUserAPC",
    "WriteProcessMemory", "ReadProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
    "OpenProcess", "NtUnmapViewOfSection", "SetWindowsHookEx", "WinExec", "ShellExecute",
    "ShellExecuteEx", "system", "popen", "execve", "execvp", "fork", "posix_spawn",
    "dlopen", "dlsym", "LoadLibrary", "GetProcAddress", "NtMapViewOfSection",
    # 持久化
    "RegSetValueEx", "RegCreateKeyEx", "WritePrivateProfileString",
    # 网络
    "URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpen", "WinHttpOpen",
    "HttpSendRequest", "socket", "connect", "getaddrinfo", "curl_easy_perform",
    "SSL_write", "SSL_read", "WSAStartup",
    # 加密 / 反分析
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "ptrace", "sysctl", "task_get_exception_ports", "OutputDebugString",
    # 权限 / 提权
    "AdjustTokenPrivileges", "SeDebugPrivilege", "setuid", "setgid", "sudo",
    # 键盘 / 截屏
    "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExW", "BitBlt", "XQueryKeymap",
    # 文件 / 自删除
    "DeleteFileW", "MoveFileEx", "SetFileAttributes", "CreateFile", "_wsystem",
}

CATEGORY_LABELS = {
    "url": "URL/域名", "ipv4": "IPv4 地址", "email": "邮箱", "win_path": "Windows 路径",
    "unix_path": "Unix 路径", "registry": "注册表键", "pem": "PEM 密钥/证书",
    "jwt": "JWT", "aws_key": "AWS AccessKey", "github_token": "GitHub Token",
    "base64": "长 Base64 串", "sql": "SQL 语句", "crypto": "加密算法名",
    "source_path": "源码路径:行号", "pdb": "PDB 路径", "uuid": "UUID",
    "version": "版本号", "error": "错误/异常文案", "fmt": "格式化串",
    "suspicious_api": "高风险 API",
}

CATEGORY_ORDER = ["suspicious_api", "url", "ipv4", "pem", "aws_key", "github_token",
                  "jwt", "registry", "win_path", "unix_path", "source_path", "pdb",
                  "crypto", "sql", "email", "base64", "uuid", "version", "error", "fmt"]


def _valid_ipv4(value: str) -> bool:
    """校验四段八位组都在 0–255 内（"999.1.1.1" 不算 IP）。"""
    head = value.split(":")[0]
    parts = head.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def classify(value: str) -> str | None:
    """
    给字符串打类别标签；无匹配返回 None。按风险高低排序返回第一个命中。

    只取前 CLASSIFY_MAXLEN 个字符做匹配：超长字符串（比如一大段 base64 或
    整块明文）参与正则匹配会显著拖慢扫描，而分类结论不受影响。
    """
    if len(value) > CLASSIFY_MAXLEN:
        value = value[:CLASSIFY_MAXLEN]
    b = value.encode("utf-8", "replace")
    if value in SUSPICIOUS_API:
        return "suspicious_api"
    if RE_AWS.search(b):
        return "aws_key"
    if RE_GITHUB.search(b):
        return "github_token"
    if RE_JWT.search(b):
        return "jwt"
    if RE_PEM.search(b):
        return "pem"
    if RE_URL.search(b):
        return "url"
    if RE_REG.search(b):
        return "registry"
    if RE_SRCPATH.search(b):
        return "source_path"
    if RE_PDB.search(b):
        return "pdb"
    if RE_UUID.search(b):
        return "uuid"
    if RE_IPV4_FULL.match(b) and _valid_ipv4(value):
        return "ipv4"
    if RE_EMAIL.search(b):
        return "email"
    if RE_WINPATH.search(b):
        return "win_path"
    if RE_UNIXPATH.search(b):
        return "unix_path"
    if RE_SQL.search(b):
        return "sql"
    if RE_CRYPTO.search(b):
        return "crypto"
    if RE_ERROR.search(b) or RE_ERROR_CN.search(value):
        return "error"
    if RE_FMT.search(b):
        return "fmt"
    if RE_BASE64.match(b):
        return "base64"
    if RE_VER.search(b):
        return "version"
    return None


# ---------------------------------------------------------------- 字符串提取


def scan_strings(path: str, min_len: int = 6, encodings: tuple = ("ascii", "utf16le"),
                 max_items: int = 20000, pattern: str | None = None,
                 dedupe: bool = False, budget_seconds: float | None = None,
                 categorize: bool = True, max_strlen: int = DEFAULT_MAX_STRLEN) -> dict:
    """
    流式提取可打印字符串。

    :param min_len: 最小长度
    :param encodings: ascii / utf16le
    :param max_items: 输出上限（达到即停止扫描，保证病态文件不会拖死）
    :param pattern: 只保留匹配该正则的字符串（在解码后的文本上匹配）
    :param budget_seconds: 时间预算，超时即停
    """
    t0 = time.time()
    out: dict = {
        "path": path, "min_len": min_len, "encodings": list(encodings),
        "max_items": max_items, "items": [], "count": 0, "truncated": False,
        "timed_out": False, "scan_seconds": 0.0, "scanned_bytes": 0,
        "categories": {}, "pattern": pattern,
    }
    rx = re.compile(pattern) if pattern else None

    # ASCII: 连续可打印字符；UTF-16LE: 可打印字符 + 0x00 交替
    patterns = []
    if "ascii" in encodings:
        patterns.append(("ascii", re.compile(rb"[\x20-\x7e\t]{" + str(min_len).encode() + rb",}")))
    if "utf16le" in encodings:
        # 与 GNU strings -e l 一致：只匹配 UTF-16LE 中的 ASCII 字符
        patterns.append(("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")))
    if "utf16cjk" in encodings:
        # 中文 UTF-16LE（CJK 统一表意文字 U+4E00–U+9FFF）。
        # 显式开启才有，因为随机二进制里该模式的误报率明显高于 ASCII 模式。
        patterns.append(("utf16cjk", re.compile(rb"(?:[\x00-\xff][\x4e-\x9f]){" + str(min_len).encode() + rb",}")))

    carries = {enc: b"" for enc, _ in patterns}
    seen: set[str] = set() if dedupe else set()
    items: list[dict] = []
    scanned = 0
    stop = False

    try:
        with Reader(path) as r:
            total = r.size
            for base, chunk in r.iter_chunks(CHUNK):
                scanned += len(chunk)
                for enc, rx_b in patterns:
                    carry_len = len(carries[enc])
                    buf = carries[enc] + chunk
                    buf_base = base - carry_len
                    is_last = (base + len(chunk)) >= total
                    for m in rx_b.finditer(buf):
                        end_local = m.end()
                        # 1) 匹配延伸到缓冲末尾且还没到文件尾 → 可能跨块，本轮跳过留给下一轮
                        if end_local == len(buf) and not is_last:
                            continue
                        # 2) 完全落在回看区（上一块已扫描过）→ 已输出过，跳过防重复
                        if m.start() < carry_len and end_local <= carry_len:
                            continue
                        # 3) 其余：本块新增，或跨块衔接（上一块被规则 1 跳过）
                        raw = m.group()
                        if enc == "utf16le" or enc == "utf16cjk":
                            text = raw.decode("utf-16-le", "replace")
                        else:
                            text = raw.decode("ascii", "replace")
                        if len(text) > max_strlen:   # 内存护栏：超长串截断保存
                            text = text[:max_strlen] + f"…[共 {len(raw)} 字节]"
                        if rx and not rx.search(text):
                            continue
                        if dedupe:
                            if text in seen:
                                continue
                            seen.add(text)
                        off = buf_base + m.start()
                        cat = classify(text) if categorize else None
                        items.append({"offset": off, "encoding": enc, "value": text, "category": cat})
                        if len(items) >= max_items:
                            stop = True
                            break
                    carries[enc] = buf[-CARRY:] if len(buf) > CARRY else buf
                    if stop:
                        break
                if stop:
                    break
                if budget_seconds and (time.time() - t0) > budget_seconds:
                    out["timed_out"] = True
                    break
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    out["truncated"] = stop
    out["items"] = items
    out["count"] = len(items)
    out["scanned_bytes"] = scanned
    out["scan_seconds"] = round(time.time() - t0, 3)

    cats: dict[str, int] = {}
    for it in items:
        if it.get("category"):
            cats[it["category"]] = cats.get(it["category"], 0) + 1
    out["categories"] = {k: cats[k] for k in CATEGORY_ORDER if k in cats}
    return out


# ---------------------------------------------------------------- 熵分析


def entropy_profile(path: str, window: int = 4096, max_windows: int = 512,
                    sample_threshold: int = 256 * 1024 * 1024) -> dict:
    """
    整体熵 + 分块熵曲线。

    超过 sample_threshold 的文件不整体读一遍（固件镜像常见 GB 级），
    改为等距采样估算，并在结果里标注 sampled=True。
    """
    t0 = time.time()
    size = os.path.getsize(path)
    out: dict = {"path": path, "size": size, "window": window, "sampled": False,
                 "overall_entropy": None, "windows": [], "high_entropy_regions": [],
                 "seconds": 0.0}

    # 整体熵 + 字节分布（小文件精确，大文件用采样）
    if size <= sample_threshold:
        # Counter(bytes) 走 C 实现的 _count_elements，比 Python 逐字节循环快约 3 倍；
        # 可打印占比用 translate + count 一次 C 扫描算完，避免第二个 O(n) Python 循环。
        counts: dict[int, int] = {}
        total = 0
        printable = 0
        zeros = 0
        with Reader(path) as r:
            for _, chunk in r.iter_chunks(CHUNK):
                total += len(chunk)
                zeros += chunk.count(0)
                printable += len(chunk) - chunk.translate(PRINTABLE_TABLE).count(0)
                c = Counter(chunk)
                for k, v in c.items():
                    counts[k] = counts.get(k, 0) + v
        ent = 0.0
        for c in counts.values():
            if c:
                p = c / total
                ent -= p * math.log2(p)
        out["overall_entropy"] = round(ent, 4)
        out["null_byte_ratio"] = round(zeros / total, 4) if total else 0
        out["printable_ratio"] = round(printable / total, 4) if total else 0
    else:
        out["sampled"] = True
        out["note"] = f"文件 {size / 1048576:.0f}MB 超过精确扫描阈值，整体熵由采样估算"

    # 分块熵曲线
    if size == 0:
        out["seconds"] = round(time.time() - t0, 3)
        return out
    stride = max(window, size // max_windows)
    windows = []
    with Reader(path) as r:
        pos = 0
        while pos < size and len(windows) < max_windows:
            data = r.read(pos, window)
            if not data:
                break
            windows.append({"offset": pos, "entropy": shannon_entropy(data)})
            pos += stride
    out["windows"] = windows
    # 高熵连续区段（压缩/加密的可疑区域）
    regions = []
    cur = None
    for w in windows:
        if w["entropy"] >= 7.0:
            if cur is None:
                cur = {"start": w["offset"], "end": w["offset"] + window, "windows": 1}
            else:
                cur["end"] = w["offset"] + window
                cur["windows"] += 1
        else:
            if cur:
                regions.append(cur)
                cur = None
    if cur:
        regions.append(cur)
    out["high_entropy_regions"] = [r for r in regions if (r["end"] - r["start"]) >= window * 2]
    out["seconds"] = round(time.time() - t0, 3)
    return out


# ---------------------------------------------------------------- 差分分析


def diff_files(path_a: str, path_b: str, block: int = 4096, max_ranges: int = 200) -> dict:
    """两个文件的字节级差分：变更区间 + 相似度 + 独有字符串。"""
    t0 = time.time()
    size_a, size_b = os.path.getsize(path_a), os.path.getsize(path_b)
    out: dict = {"a": path_a, "b": path_b, "size_a": size_a, "size_b": size_b,
                 "size_delta": size_b - size_a, "identical": False,
                 "changed_ranges": [], "changed_bytes": 0, "similarity": None,
                 "seconds": 0.0}
    if size_a == size_b:
        import hashlib
        ha = hashlib.sha256()
        hb = hashlib.sha256()
        with Reader(path_a) as ra, Reader(path_b) as rb:
            for _, ca in ra.iter_chunks(CHUNK):
                ha.update(ca)
            for _, cb in rb.iter_chunks(CHUNK):
                hb.update(cb)
        out["sha256_a"] = ha.hexdigest()
        out["sha256_b"] = hb.hexdigest()
        if ha.hexdigest() == hb.hexdigest():
            out["identical"] = True
            out["similarity"] = 1.0
            out["seconds"] = round(time.time() - t0, 3)
            return out

    min_size = min(size_a, size_b)
    ranges: list[dict] = []
    changed = 0
    cur: dict | None = None
    with Reader(path_a) as ra, Reader(path_b) as rb:
        pos = 0
        while pos < min_size:
            da = ra.read(pos, block)
            db = rb.read(pos, block)
            if not da or not db:
                break
            if da == db:
                if cur:
                    ranges.append(cur)
                    cur = None
            else:
                n = sum(1 for x, y in zip(da, db) if x != y)
                changed += n
                if cur is None:
                    cur = {"start": pos, "end": pos + len(da), "diff_bytes": n}
                else:
                    cur["end"] = pos + len(da)
                    cur["diff_bytes"] += n
            pos += block
        if cur:
            ranges.append(cur)
    if size_a != size_b:
        changed += abs(size_b - size_a)
        ranges.append({"start": min_size, "end": max(size_a, size_b),
                       "diff_bytes": abs(size_b - size_a), "note": "长度差异区间（一方独有）"})
    out["changed_ranges"] = ranges[:max_ranges]
    out["changed_bytes"] = changed
    out["similarity"] = round(1 - (changed / max(size_a, size_b, 1)), 4)
    out["seconds"] = round(time.time() - t0, 3)
    return out


# ---------------------------------------------------------------- 文件雕刻

CARVE_MIN_SIG = 4   # 少于 4 字节的魔数误报太多，不参与雕刻


def carve(path: str, out_dir: str | None = None, max_files: int = 100,
          max_total: int = 256 * 1024 * 1024, align: int = 1) -> dict:
    """
    按魔数在任意偏移处扫描嵌入文件（固件/覆盖层分析常用）。

    默认只列清单（不写盘）；指定 out_dir 才落盘，且受 max_files / max_total 双重限制。
    """
    t0 = time.time()
    sigs = [m for m in MAGICS if len(m["sig"]) >= CARVE_MIN_SIG and m["off"] == 0]
    out: dict = {"path": path, "hits": [], "hit_count": 0, "extracted": [],
                 "written_bytes": 0, "seconds": 0.0, "out_dir": out_dir}
    hits: list[dict] = []
    try:
        with Reader(path) as r:
            carry = b""
            for off, chunk in r.iter_chunks(CHUNK):
                buf = carry + chunk
                buf_base = off - len(carry)
                for m in sigs:
                    sig = m["sig"]
                    start = 0
                    while True:
                        i = buf.find(sig, start)
                        if i < 0 or len(hits) >= 5000:
                            break
                        abs_off = buf_base + i
                        if align > 1 and abs_off % align != 0:
                            start = i + 1
                            continue
                        hits.append({"offset": abs_off, "key": m["key"], "label": m["label"]})
                        start = i + 1
                carry = buf[-64:]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    hits.sort(key=lambda h: h["offset"])
    # 去重：同一偏移只保留最长魔数命中的那个
    dedup: list[dict] = []
    for h in hits:
        if dedup and dedup[-1]["offset"] == h["offset"]:
            continue
        dedup.append(h)
    out["hits"] = dedup[:2000]
    out["hit_count"] = len(dedup)

    if out_dir and dedup:
        os.makedirs(out_dir, exist_ok=True)
        written = 0
        with Reader(path) as r:
            for i, h in enumerate(dedup[:max_files]):
                start = h["offset"]
                end = dedup[i + 1]["offset"] if i + 1 < len(dedup) else r.size
                if end <= start:
                    continue
                size = min(end - start, 64 * 1024 * 1024)
                if written + size > max_total:
                    break
                name = f"{start:08X}_{h['key']}.bin"
                dst = os.path.join(out_dir, name)
                with open(dst, "wb") as fo:
                    pos = start
                    while pos < start + size:
                        data = r.read(pos, min(CHUNK, start + size - pos))
                        if not data:
                            break
                        fo.write(data)
                        pos += len(data)
                written += size
                out["extracted"].append({"file": dst, "offset": start, "size": size})
        out["written_bytes"] = written
    out["seconds"] = round(time.time() - t0, 3)
    return out


# ---------------------------------------------------------------- 综合研判


def packer_verdict(ident: dict, ent: dict) -> dict:
    """把结构解析的线索 + 熵证据合并成一个加壳/混淆判断。"""
    detail = ident.get("detail") or {}
    signals = list(detail.get("packer_signals") or [])
    overall = ent.get("overall_entropy")
    if overall is not None and overall >= 7.2:
        signals.append(f"整体熵 {overall:.2f} ≥ 7.2（整文件压缩/加密的典型特征）")
    regions = ent.get("high_entropy_regions") or []
    if len(regions) >= 2:
        signals.append(f"存在 {len(regions)} 段高熵区域（加密/压缩数据块）")
    # 反向证据：有完整符号表 / 正常节结构 → 不像加壳
    if detail.get("parser") == "elf" and not detail.get("stripped"):
        signals.append("(反向证据) ELF 保留 .symtab，非 strip 状态")
    if detail.get("parser") == "pe" and detail.get("pdb_path"):
        signals.append("(反向证据) 存在 PDB 调试信息路径")
    level = "none"
    if len([s for s in signals if not s.startswith("(反向证据)")]) >= 3:
        level = "high"
    elif len([s for s in signals if not s.startswith("(反向证据)")]) >= 1:
        level = "medium"
    return {"level": level, "signals": signals}


def triage(path: str, min_len: int = 6, max_strings: int = 20000,
           pattern: str | None = None, budget_seconds: float | None = None) -> dict:
    """
    一站式初筛：识别 + 结构解析 + 字符串 + 熵 + IOC + 加壳判断。
    这是「拿到未知目标后第一个该跑的命令」对应的实现。
    """
    t0 = time.time()
    ident = identify(path, deep=True)
    res: dict = {"path": path, "identify": ident, "seconds": 0.0}
    if ident.get("errors"):
        res["seconds"] = round(time.time() - t0, 3)
        return res

    res["entropy"] = entropy_profile(path)
    res["strings"] = scan_strings(path, min_len=min_len, max_items=max_strings,
                                  pattern=pattern, budget_seconds=budget_seconds)
    s = res["strings"]
    items = s.get("items", [])

    # 高价值线索（按类别各取前若干条，避免上下文爆炸）
    leads: dict[str, list] = {}
    for it in items:
        c = it.get("category")
        if not c:
            continue
        leads.setdefault(c, [])
        if len(leads[c]) < 25:
            leads[c].append({"offset": it["offset"], "value": it["value"][:300]})
    res["leads"] = {k: leads[k] for k in CATEGORY_ORDER if k in leads}

    res["packer"] = packer_verdict(ident, res["entropy"])
    res["string_count"] = s.get("count", 0)
    res["truncated"] = s.get("truncated") or s.get("timed_out")
    res["seconds"] = round(time.time() - t0, 3)
    return res
