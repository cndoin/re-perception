"""
lib_libscan.py —— 静态链接库函数 / 密码学常量识别

逆向里最费时间的第一件事是"这函数叫什么名字"。有符号时不需要猜；没符号时，
静态链接进来的库函数（memcpy/memset/strlen/AES/CRC32/SHA…）占了相当大比例，
而它们**是可以认出来的**：

  1. 指令形态指纹：rep movsq / rep stosq / repne scasb 分别是 memcpy /
     memset / strlen 家族的标志性实现，编译器内联库函数时尤其明显。
  2. 常量表签名：AES S-box、CRC32 表、SHA-256 初始常量、Base64 字母表……
     这些是"写死在二进制里的指纹"，找到表所在的地址，再看哪个函数引用它，
     就能把 sub_140001234 认成"AES 相关"。

设计原则（和整个项目一致）：**认不出来就说认不出来**。
这里只给"家族级"结论 + 置信度 + 依据，不把猜测包装成确定结论 ——
memcpy 家族里到底是 memcpy 还是 memmove，光看 rep movs 是分不出来的。
"""

from lib_x86 import K_CALL

# ---------------------------------------------------------------- 常量表签名

# 每条签名取前 16~32 字节：足够唯一，又不至于因为编译器重排/加料而漏判。
CONST_SIGS: list[dict] = [
    {
        "key": "aes_sbox", "name": "AES S-box（正向）", "tag": "加解密",
        "sig": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                      0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
    },
    {
        "key": "rc4_ksa", "name": "RC4 KSA 初始化序列（0x00..0xFF）", "tag": "加解密",
        # RC4 的 KSA 起手就是把 S 盒填成 0x00,0x01,...,0xFF。
        # 这段 32 字节（0x00..0x1F 递增）在正常程序里几乎不会作为数据常量出现，
        # 判别力足够高，可以当作「疑似 RC4」的硬证据。
        # 之所以要把这条签名补上：规则里原本想用 mnemonic 组合去猜 RC4，
        # 结果在 notepad.exe 上误报（详见 rules/crypto.yml 的误报教训），
        # 改用常量签名才是可靠做法 —— 能签名的就不靠猜。
        "sig": bytes(range(0x00, 0x20)),
    },
    {
        "key": "aes_inv_sbox", "name": "AES 逆 S-box", "tag": "加解密",
        "sig": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                      0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
    },
    {
        "key": "crc32_table", "name": "CRC32 表", "tag": "加解密",
        "sig": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
                      0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99]),
    },
    {
        # MD5 与 SHA-1 的前 4 个初始常量完全相同，无法区分 —— 不硬猜
        "key": "md5_sha1_init", "name": "MD5/SHA-1 初始常量", "tag": "加解密",
        "sig": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
    },
    {
        "key": "sha256_init", "name": "SHA-256 初始常量", "tag": "加解密",
        "sig": bytes([0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB,
                      0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xF5, 0x4F, 0xA5]),
    },
    {
        "key": "sha512_init", "name": "SHA-512 初始常量", "tag": "加解密",
        "sig": bytes([0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A,
                      0x3B, 0xA7, 0xCA, 0x84, 0x85, 0xAE, 0x67, 0xBB]),
    },
    {
        "key": "base64", "name": "Base64 字母表", "tag": "编码",
        "sig": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[:32],
    },
    {
        "key": "base32", "name": "Base32 字母表", "tag": "编码",
        "sig": b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    },
]

# 代码里的"魔数"立即数：单个常量，不是表
MAGIC_IMMS: list[tuple[int, str, str]] = [
    (0xEDB88320, "CRC32 多项式（反射）", "加解密"),
    (0x04C11DB7, "CRC32 多项式（正规）", "加解密"),
    (0x9E3779B9, "TEA/XTEA delta", "加解密"),
    (0x9E3779B1, "xxHash/TEA 变体常量", "加解密"),
    (0x1B873593, "MurmurHash3 常量", "哈希"),
    (0xCC9E2D51, "MurmurHash3 常量", "哈希"),
    (0x85EBCA6B, "MurmurHash3 混合常量", "哈希"),
    (0xC2B2AE35, "MurmurHash3 混合常量", "哈希"),
    (0x67452301, "MD5/SHA-1 初始常量", "加解密"),
    (0x428A2F98, "SHA-256 K[0]", "加解密"),
]


def scan_const_tables(path: str, ident: dict, max_scan: int = 64 * 1024 * 1024
                      ) -> list[dict]:
    """
    在文件里搜已知常量表，返回 [{key, name, tag, offset, vma, section}]。

    只搜数据区（可执行节里的同名字节序列多半是代码巧合，噪声大）。
    命中表本身不算完 —— 关键是**谁引用了它**，见 attribute_consts。
    """
    spans = _data_spans(ident)
    if not spans:
        return []
    from lib_formats import Reader

    hits: list[dict] = []
    try:
        with Reader(path) as rd:
            size = min(rd.size, max_scan)
            for raw_off, span_size, vma in spans:
                if span_size <= 0:
                    continue
                end = min(raw_off + span_size, size)
                # 分块读，块间留重叠，避免签名跨块被切断
                chunk = 1 << 20
                overlap = 64
                off = raw_off
                while off < end:
                    n = min(chunk, end - off)
                    buf = rd.read(off, n)
                    if not buf:
                        break
                    for sg in CONST_SIGS:
                        idx = buf.find(sg["sig"])
                        if idx < 0:
                            continue
                        foff = off + idx
                        hits.append({
                            "key": sg["key"], "name": sg["name"], "tag": sg["tag"],
                            "offset": foff,
                            "vma": vma + (foff - raw_off),
                            "size": len(sg["sig"]),
                        })
                    # 必须保证 off 单调前进：块比重叠还小时 n-overlap 会让 off
                    # 倒退，直接死循环（小数据节上必现）。
                    step = n - overlap
                    if step <= 0:
                        break
                    off += step
    except Exception as e:
        # 【为什么必须上抛】旧写法是 `except Exception: return hits`，
        # 两个后果都很坏：
        #   1. 返回"部分命中"——AES/CRC32 之类的特征凭空消失，所有依赖
        #      `characteristic:` 的规则大面积漏报，而报告里毫无异常；
        #   2. lib_rules.py:726 那个 `errs_out.append("const-sigs: ...")`
        #      永远不触发，成了死代码。
        # 这里改成上抛，由调用方登记并让用户看见"扫描没跑完"。
        raise RuntimeError(
            "常量签名扫描中断（已扫到 %d 条命中，结果不完整）：%s: %s"
            % (len(hits), type(e).__name__, e)) from e
    return hits


def _data_spans(ident: dict) -> list[tuple[int, int, int]]:
    """数据节 (文件偏移, 大小, VMA)，复用 lib_semantics 的判断逻辑。"""
    try:
        from lib_semantics import _data_spans as _ds
        return _ds(ident)
    except Exception:
        return []


# ---------------------------------------------------------------- 指令形态指纹

# 串指令 -> 库函数家族。注意：只给"家族"，因为光看指令分不出具体是哪个。
STR_FAMILY: dict[str, tuple[str, str]] = {
    "movs": ("memcpy 家族", "rep movs：块复制（memcpy/memmove 内联或库实现）"),
    "stos": ("memset 家族", "rep stos：块填充（memset/ZeroMemory 内联）"),
    "scas": ("strlen/strchr 家族", "repne scas：扫描字节（strlen/strchr/strrchr）"),
    "cmps": ("memcmp 家族", "rep(e) cmps：块比较（memcmp/strcmp 内联）"),
}

# 向量化实现的 strlen/strcmp/memchr：pcmpeqb + pmovmskb + (tzcnt/not)
SIMD_CMP_MNEMS = ("pcmpeqb", "vpcmpeqb", "pcmpeqw", "vpcmpeqw",
                  "pcmpeqd", "vpcmpeqd")
SIMD_MASK_MNEMS = ("pmovmskb", "vpmovmskb")


def _func_addrs(insns: list) -> list[int]:
    """函数里引用到的所有绝对地址（用于匹配常量表）。"""
    out = []
    for ins in insns:
        if getattr(ins, "mem_ref", None) is not None:
            out.append(ins.mem_ref)
        if getattr(ins, "imm", None):
            out.append(ins.imm)
    return out


def identify_libfuncs(idx, funcs: list[dict], const_hits: list[dict] | None = None
                      ) -> dict[int, dict]:
    """
    给每个函数一个"库函数/密码学"提示。返回 {函数起始 VMA: hint}。

    hint = {"name": 家族名或常量名, "confidence": "高/中/低",
            "reason": 依据, "tag": 行为类别（可能没有）}

    置信度说明：
      高 = 命中写死的常量表（AES S-box 这类基本不可能巧合）
      中 = 命中典型指令形态（rep stosq 几乎必然是 memset 家族）
      低 = 只有弱特征（如魔数立即数，可能被误当成普通常量）
    """
    const_hits = const_hits or []
    out: dict[int, dict] = {}
    for f in funcs:
        offs = f.get("_offs") or []
        if not offs:
            continue
        from lib_semantics import ins_at
        insns = [ins_at(idx, o) for o in offs]
        insns = [i for i in insns if i is not None]
        if not insns:
            continue
        start = _as_int(f.get("start_vma"))
        if start is None:
            continue

        mnems = [i.mnem for i in insns]
        hint = None

        # 1) 常量表引用（置信度最高：写死的表不会巧合）
        if const_hits:
            addrs = _func_addrs(insns)
            for h in const_hits:
                v0, v1 = h["vma"], h["vma"] + h["size"]
                if any(v0 <= a < v1 for a in addrs):
                    hint = {"name": h["name"], "confidence": "高",
                            "reason": f"引用了 {h['name']}（@{hex(h['vma'])}）",
                            "tag": h["tag"]}
                    break

        # 2) 串指令家族
        if hint is None:
            for ins in insns:
                for base, (fam, why) in STR_FAMILY.items():
                    if ins.mnem.startswith(base) and "rep" in (ins.prefixes or []):
                        hint = {"name": fam, "confidence": "中",
                                "reason": f"{ins.text}（{why}）", "tag": None}
                        break
                if hint:
                    break

        # 3) 向量化比较族：pcmpeqb + pmovmskb（glibc/MSVC 的 strlen/strcmp）
        if hint is None:
            has_cmp = any(m in SIMD_CMP_MNEMS for m in mnems)
            has_mask = any(m in SIMD_MASK_MNEMS for m in mnems)
            if has_cmp and has_mask and len(insns) <= 80:
                hint = {"name": "向量化 strlen/strcmp/memchr 家族",
                        "confidence": "中",
                        "reason": "pcmpeqb + pmovmskb：SIMD 字节比较循环",
                        "tag": None}

        # 4) 魔数立即数（弱特征）
        if hint is None:
            for ins in insns:
                v = getattr(ins, "imm", None)
                if not v:
                    continue
                for magic, nm, tag in MAGIC_IMMS:
                    if v == magic:
                        hint = {"name": nm, "confidence": "低",
                                "reason": f"立即数 {hex(magic)} = {nm}", "tag": tag}
                        break
                if hint:
                    break

        # 5) 自旋锁/原子：lock cmpxchg 或 xadd + pause
        if hint is None:
            has_lock = any("lock" in (i.prefixes or []) for i in insns)
            has_pause = any(i.mnem == "pause" for i in insns)
            if has_lock and has_pause:
                hint = {"name": "自旋锁/原子操作", "confidence": "中",
                        "reason": "lock 前缀指令 + pause：自旋等待", "tag": None}

        if hint:
            hint["start_vma"] = hex(start)
            out[start] = hint
    return out


def _as_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v:
        try:
            return int(v, 16)
        except ValueError:
            return None
    return None


def summarize_hints(hints: dict[int, dict]) -> list[dict]:
    """把命中结果按家族聚合，给出"这个二进制用了哪些已知算法/库"的概览。"""
    agg: dict[str, dict] = {}
    for h in hints.values():
        a = agg.setdefault(h["name"], {"name": h["name"], "count": 0,
                                       "confidence": h["confidence"],
                                       "tag": h.get("tag"),
                                       "sample": h.get("start_vma")})
        a["count"] += 1
    return sorted(agg.values(), key=lambda d: -d["count"])
