"""lib_obfstr.py —— 混淆字符串静态恢复（零第三方依赖）

对标 Mandiant **FLOSS** 的核心能力。恶意软件把敏感字符串（C2 地址、
注册表键、API 名、互斥体名）藏起来，让 `strings` 看不见。常见三类：

1. **栈字符串** —— 逐字节 `mov [rsp+N], imm8` 在栈上拼串，
   字节在文件里从不连续，静态字符串扫描全瞎。
2. **宽字节栈串** —— `mov dword [rsp+N], 0x70747468`（"http" 小端）。
3. **XOR 加密串** —— 数据段里存密文，循环逐字节 XOR 单字节密钥后使用。

本模块只做**静态**恢复，不执行目标代码（只读分析原则）。
思想来自 FLOSS：**沿指令流模拟它对内存/寄存器的影响**，
而不是真的跑起来。

实测判别阈值（来自实战经验，写进代码里当常量）：
  - 连续 ≥ `MIN_SEQ` 条单字节立即数写栈，且偏移落在 `WINDOW` 字节窗口内
    —— 正常未混淆代码几乎不产生这种模式。
  - 宽字节版用 ≥ `MIN_SEQ_WIDE` 条，阈值可低些（dword 一次写 4 字节）。

设计原则（与全项目一致）：
  - 只读，不写目标文件。
  - 失败必须留 `warnings`，不静默返回空集。
  - 每条结果带 `offset`/`vma` 证据，可回 `disasm` 复核。
  - 结果带 `method`，说明是哪种技术恢复出来的。
"""

from __future__ import annotations

# ---------------------------------------------------------------- 判别阈值

MIN_SEQ = 8          # 单字节写栈：至少这么多条才算栈字符串
MIN_SEQ_WIDE = 4     # 多字节写栈：至少这么多条
WINDOW = 64          # 被写入的偏移必须落在一个 64 字节窗口内
MIN_STR = 4          # 恢复出的字符串最短长度
MAX_STR = 4096       # 单条上限，防构造数据撑爆

# 栈基址寄存器（x86-64）。rbp 版通常出现在 -O0/调试构建，rsp 版在优化后。
_STACK_REGS = ("rsp", "rbp", "esp", "ebp")

# 操作数尺寸 -> 字节数。
# 注意顺序陷阱：`"word" in "dword"` 为真 —— 如果按顺序做子串匹配，
# dword 会被误判成 word(2 字节)，栈串会被错拼成 `C:\x00\x00Wi...`。
# 必须**最长匹配优先**（下面的 _SIZE_KEYS 已按长度倒序）。
_SIZE_BYTES = {"qword": 8, "dword": 4, "word": 2, "byte": 1}
_SIZE_KEYS = ("qword", "dword", "word", "byte")


def _parse_mov_store(ins) -> dict | None:
    """判断一条指令是否是「立即数写栈」。

    命中返回 {reg, disp, size, value}；否则 None。

    识别目标形态（lib_x86 解码后 mnemonics/operands 已规范化）：
        mov byte  ptr [rsp+0x1], 0x74
        mov dword ptr [rsp+0x0], 0x70747468
        mov qword ptr [rbp-0x8], 0x5858585858585841
    """
    if ins is None or ins.mnem != "mov":
        return None
    if ins.imm is None or ins.disp is None:
        return None
    ops = ins.ops or ""
    # 必须形如 "... ptr [reg+disp], imm"  —— 目的操作数是内存
    if "ptr [" not in ops or "," not in ops:
        return None
    lhs, _, rhs = ops.partition(",")
    if "ptr [" not in lhs:
        return None
    # 右侧必须是立即数（0x... 或纯十进制）
    rhs = rhs.strip()
    if not (rhs.startswith("0x") or rhs.isdigit()):
        return None

    size = None
    for key in _SIZE_KEYS:      # 已按长度倒序：qword/dword 必须先于 word
        if key in lhs:
            size = _SIZE_BYTES[key]
            break
    if size is None:
        return None

    # 取 [reg ...] 里的基址寄存器
    try:
        inner = lhs[lhs.index("[") + 1:lhs.index("]")]
    except ValueError:
        return None
    reg = None
    for r in _STACK_REGS:
        if inner.startswith(r) or (" " + r) in inner:
            reg = r
            break
    if reg is None:
        return None
    # 必须只有基址 + 常量位移，出现 index 寄存器（如 [rsp+rax*4]）说明是数组不是栈串
    if "*" in inner:
        return None

    return {"reg": reg.replace("e", "r", 1) if reg.startswith("e") else reg,
            "disp": int(ins.disp), "size": size, "value": int(ins.imm)}


def _seq_to_bytes(entries) -> bytes:
    """把 (disp, size, value) 列表铺进一块连续缓冲，返回拼好的字节。

    按**偏移排序**而不是按指令顺序 —— 编译器可能重排写入次序。
    洞用 0 填充（会在最后被当作终止符处理，符合真实内存布局）。
    """
    lo = min(d for d, _, _ in entries)
    hi = max(d + s for d, s, _ in entries)
    if hi - lo > 4096:
        return b""
    buf = bytearray(hi - lo)
    for disp, size, value in entries:
        off = disp - lo
        for i in range(size):
            b = (value >> (8 * i)) & 0xFF
            if off + i < len(buf):
                buf[off + i] = b
    return bytes(buf)


def _extract_strings(buf: bytes, min_len: int = MIN_STR):
    """从缓冲里切出可打印字符串（NUL 或不可打印处断开）。"""
    out = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(buf):
        if 0x20 <= b < 0x7F:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((start, cur.decode("ascii", "replace")))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((start, cur.decode("ascii", "replace")))
    return out


def recover_stack_strings(insns, base_vma: int = 0, max_results: int = 200):
    """从一条指令序列里恢复栈字符串。

    `insns` 是 lib_x86.Insn 的可迭代对象（按执行顺序）。
    返回 {strings: [...], warnings: [...]}。

    算法：
      1. 扫出所有「立即数写栈」指令，按基址寄存器分组、按偏移聚类。
      2. 同一簇内条目数达到阈值 → 铺进缓冲 → 切可打印串。
      3. 一条指令同时属于两簇时，取条目更多的那个（贪心，够用）。
    """
    warnings = []
    stores = []
    for ins in insns:
        st = _parse_mov_store(ins)
        if st is None:
            continue
        st["off"] = getattr(ins, "offset", 0)
        st["vma"] = getattr(ins, "vma", base_vma + st["off"])
        stores.append(st)

    if not stores:
        return {"strings": [], "warnings": warnings, "store_count": 0}

    # 按 (寄存器, 尺寸) 分组后，在偏移轴上做聚类 —— 用一个移动窗口扫描。
    results = []
    used = [False] * len(stores)

    # 先处理所有可能的窗口起点：按偏移排序，滑动窗口取最大簇
    order = sorted(range(len(stores)), key=lambda i: (stores[i]["reg"],
                                                      stores[i]["disp"]))
    i = 0
    while i < len(order) and len(results) < max_results:
        seed = stores[order[i]]
        lo = seed["disp"]
        hi = lo + WINDOW
        cluster = [order[j] for j in range(i, len(order))
                   if stores[order[j]]["reg"] == seed["reg"]
                   and lo <= stores[order[j]]["disp"] <= hi]
        # 只保留没被用过的
        cluster = [j for j in cluster if not used[j]]
        if cluster:
            n_single = sum(1 for j in cluster if stores[j]["size"] == 1)
            n_wide = sum(1 for j in cluster if stores[j]["size"] > 1)
            # 阈值：单字节需 ≥ MIN_SEQ；含宽字节则可放宽到 MIN_SEQ_WIDE
            enough = (n_single >= MIN_SEQ) or \
                     (n_single + n_wide >= MIN_SEQ_WIDE and n_wide >= 1)
            if enough and len(cluster) >= MIN_SEQ_WIDE:
                entries = [(stores[j]["disp"], stores[j]["size"],
                            stores[j]["value"]) for j in cluster]
                buf = _seq_to_bytes(entries)
                for rel, s in _extract_strings(buf, MIN_STR):
                    if len(s) > MAX_STR:
                        continue
                    first = min((stores[j] for j in cluster),
                                key=lambda x: x["off"])
                    results.append({
                        "string": s,
                        "method": "stack-string",
                        "offset": first["off"],
                        "vma": first["vma"],
                        "store_insns": len(cluster),
                        "window": [lo, hi],
                    })
                for j in cluster:
                    used[j] = True
        i += 1

    # 去重（同串同地址只留一条）
    seen = set()
    dedup = []
    for r in results:
        k = (r["string"], r["offset"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(r)

    if dedup:
        return {"strings": dedup, "warnings": warnings,
                "store_count": len(stores)}

    return {"strings": [], "warnings": warnings, "store_count": len(stores)}


# ---------------------------------------------------------------- XOR 解密

# 密文段最短长度，太短容易偶然"解出"可打印串
_MIN_CIPHER = 6
# 单字节 XOR 的判据（实测调出来的，不是拍的）：
#
# 踩过三次坑，每次都是"以为够了"：
#   ① 只看"可打印率 ≥95%" —— 32 字节随机数据里大量 key 能到 100% 可打印，
#      300 组随机样本打出几十个假阳性。
#   ② 加"字母数字占比 ≥0.75" —— 长串能挑了，但真实 PE 上仍有 26 条垃圾，
#      因为填充区的低熵数据 XOR 后变成 `tttttttttttt`。
#   ③ 加"禁止 ≥6 个同字符连续" —— 重复串没了，但 12–14 字节的随机短串
#      仍然能过（`s.HLN:os>HLN`、`A7kifv-iiTkh`）。
#
# 根本问题：**长度不够时，任何基于统计的判据都会偶然命中**。
# 最终方案是把门槛拆成两道，一起用：
#   - 长度门槛抬高到 16：短串不判（宁可漏报）
#   - **必须有"锚点"**：真实被混淆的字符串是 URL / 路径 / 域名 / API 名 /
#     注册表键，它们一定含 `://` `\` `/` `.com` `.exe` `_` `-` 这类锚点，
#     或者含一个 ≥4 字符的纯字母单词。纯随机噪声极难同时满足。
_MIN_CIPHER = 16

_PRINT_MIN = 1.0
_ALNUM_MIN = 0.75

# 强锚点：出现任意一个就强烈提示"这是真的字符串"。
# 这些 token 的共同点是**正常编码里几乎不会偶然出现**：
#   - `://` `\\` `/`  协议与路径分隔
#   - `.exe` `.dll` `.php` 等扩展名
#   - `SOFTWARE` `CurrentVersion` 等注册表词
#   - `Mozilla` `User-Agent` `POST ` `GET ` 等网络词
_XOR_ANCHORS = (b"://", b"\\\\", b"/", b".com", b".net", b".org", b".exe",
                b".dll", b".php", b".py", b".sh", b".txt", b".dat", b".bin",
                b".bat", b".ps1", b".vbs", b".js", b".json", b".xml",
                b"http", b"cmd", b"SOFTWARE", b"SYSTEM", b"Microsoft",
                b"Windows", b"CurrentVersion", b"Run", b"User-Agent",
                b"Mozilla", b"POST ", b"GET ", b"Content-", b"reg ",
                b"Temp", b"Users", b"Program", b"AppData", b"Local",
                b"password", b"admin", b"token", b"api", b"www.", b"ftp")


def _has_anchor(txt: bytes) -> bool:
    """是否含"确定性"锚点。

    **刻意不做**"含一个 N 字符纯字母词"这种退化判据 —— 实测它在真实 PE
    上会放行 `Y\\t5zlylxl{lz`、`SF@EDRGRFRER` 这类随机噪声（28 条命中
    里有 25 条是靠退化判据进来的）。宁可漏报，也不给用户一堆看不出所以然
    的垃圾 —— 那会让真信号被淹没。
    """
    low = txt.lower()
    for a in _XOR_ANCHORS:
        if a.lower() in low:
            return True
    return False

_ALNUM = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_STRUCT = set(b" .:/\\_-?=&%@,;+~#()[]{}<>|*!'\"$^`")
# 明文里几乎不会出现的可打印字符（反引号、制表符之外的控制类）
_WEIRD = set(b"`~^|\\")

# 字符似然权重：越像自然文本（URL / 路径 / 英文词 / 常见代码）权重越高。
# 这是"英文字母频率 + 常见串字符集"的粗量化，不必精确 —— 只要能让
# 正确明文与"整体偏移几位的伪明文"拉开可见差距就够。
# 参考频率顺序：etaoinshrdlu... 元音与 t/h/e 最高；q/z/x/j 最低。
_CHAR_WEIGHT = {}
for _c, _w in (
    (b"etaoinshrdlu", 1.00), (b"ETASOINHRDLU", 0.95),
    (b"cmfwypvbgkqjxz", 0.75), (b"CMFWYPVBGKQJXZ", 0.72),
    (b"0123456789", 0.85),
    (b".:/\\_-?", 0.90),          # URL / 路径 / 文件名里的分隔符
    (b"=&%#@,;+", 0.70),
    (b"()[]{}<>|*!'\"$^`~", 0.35),
    (b" \t\n\r", 0.60),
):
    for _b in _c:
        _CHAR_WEIGHT[_b] = _w
del _c, _w, _b


def _xor_score(data: bytes, key: int):
    """用单字节 key 解 data，返回 (分数, 解出的字节)。

    分数越高越像真明文；-1 表示直接淘汰。

    为什么不能只看"可打印率"或"字母数字占比"：
      实测把 `http://malware-c2...` 用 key=0x41 加密后，key=0x43 也解出
      100% 字母数字可打印的 `jvvr8--ocnucpg...` —— 两者打分完全并列，
      于是选中错的那个（真明文被整体偏移 2）。**关键区别在字符分布**：
      明文里 `t`/`h`/`p` 高频，错解里 `v`/`r`/`8` 高频。因此打分必须
      引入**字符频率似然**，而不是只数类别。

    分数 = 字母数字占比 - 怪异字符惩罚 + 频率似然项
    """
    out = bytes(b ^ key for b in data)
    n = len(out)
    if n == 0:
        return -1.0, out
    # 硬门槛 1：全部可打印（允许 TAB/CR/LF，明文串里有）
    for b in out:
        if not (0x20 <= b < 0x7F or b in (9, 10, 13)):
            return -1.0, out
    n_alnum = sum(1 for b in out if b in _ALNUM)
    n_struct = sum(1 for b in out if b in _STRUCT)
    n_weird = sum(1 for b in out if b in _WEIRD)
    # 硬门槛 2：字母数字必须占主体
    if n_alnum / n < _ALNUM_MIN:
        return -1.0, out
    # 硬门槛 3：必须像"文本"而不是"二进制恰好可打印" —— 要有词间分隔
    if n >= 12 and n_struct == 0:
        return -1.0, out
    # 硬门槛 4：**不允许长同字符重复**。
    # 这是真实数据上最关键的一道闸。PE 的填充区/零表/常量表 XOR 之后会变成
    # `tttttttttttttt` / `llllllllll` 这种整串同一个字符 —— 它们在"可打印率"
    # 和"字母占比"上全部达标，但在真实文本里绝不可能出现。
    # 实测：不加这条，notepad.exe 上会打出 26 条垃圾。
    if _max_run(out) >= 6:
        return -1.0, out
    # 硬门槛 5：必须带"锚点"。
    # 短串上任何纯统计判据都会偶然命中（实测 12 字节随机数据能过前四道闸）。
    # 真实被混淆的内容一定是 URL/路径/域名/API 名/注册表键，
    # 它们必然含 `://`、`\`、`.exe`、或一个 ≥5 字符的纯字母词。
    if not _has_anchor(out):
        return -1.0, out
    # 频率似然：按常见程度给每个字符打分，归一化到 [0,1]
    lik = 0.0
    for b in out:
        lik += _CHAR_WEIGHT.get(b, 0.15)
    lik /= n
    # 惩罚怪异字符（反引号/波浪号/竖线在正常串里罕见）
    score = lik - 0.25 * (n_weird / n)
    return score, out


def _max_run(data: bytes) -> int:
    """最长同字节连续段长度。"""
    best = 0
    cur = 0
    prev = -1
    for b in data:
        if b == prev:
            cur += 1
        else:
            cur = 1
            prev = b
        if cur > best:
            best = cur
    return best


# ---------------------------------------------------------------- 解密循环定位
#
# **为什么不能只靠滑窗盲扫**（这是本模块最重要的一条设计教训）：
#
# 最初的实现是"在数据段上滑动窗口、对每个窗口试 255 个 key"。实测在
# notepad.exe 上稳定打出 20–28 条垃圾（`r/IMO;nr?IMO`、`C5ikdt/kkVij`），
# 在 kernel32.dll 上 20–29 条。加了三层统计门槛（可打印率 / 字母占比 /
# 禁重复）只压掉一部分，因为**短窗口上任何统计判据都会偶然命中**。
#
# FLOSS 的做法不是盲扫，而是：
#   ① 先找**解密循环**（数据段引用 + 逐字节 XOR + 写回/比较）
#   ② 只对循环真正触及的那段数据套用它推导出的 key
#
# 这样假阳性是**结构性消除**的，不靠调阈值。本模块采用同样的思路：
# 下面这个函数从指令序列里识别 XOR 解密循环，推出 (key, 数据引用)。


def find_xor_loops(insns, base_vma: int = 0, max_results: int = 50):
    """从指令序列里找单字节 XOR 解密循环，返回候选 {key, data_ref, ...}。

    识别的形态（x86-64 常见）：
        loc_loop:
            movzx eax, byte ptr [rsi+rcx]     ; 取密文字节
            xor   al, 0x4A                     ; 单字节 key
            mov   byte ptr [rdi+rcx], al       ; 写明文
            inc   rcx
            cmp   rcx, 0x20
            jl    loc_loop                    ; 向后跳 = 形成循环

    关键判据（缺一不可）：
      1. 循环体内有 `xor` 指令，且**操作数含立即数**（拿到 key）
      2. 循环体内有内存读 + 内存写（搬运密文→明文）
      3. 有向后跳转（形成循环）

    算法：**先找向后跳转**（它才定义循环），再看循环体。
    反过来的写法（从 xor 出发去猜循环边界）实测非常脆 —— 边界常常定不出来，
    于是明明是正确的解密循环也识别不到。
    """
    found = []
    if not insns:
        return {"loops": [], "warnings": []}

    insns = list(insns)
    n = len(insns)
    if n < 3:
        return {"loops": [], "warnings": []}

    # 建 vma -> 下标 映射，用于把跳转目标解析回指令下标
    by_vma = {}
    for i, ins in enumerate(insns):
        v = getattr(ins, "vma", None)
        if v is not None:
            by_vma[v] = i

    for j, ins in enumerate(insns):
        tgt = getattr(ins, "target", None)
        if tgt is None:
            continue
        pos = by_vma.get(tgt)
        # 只认向后跳转，且跳距不能太长（真循环体一般在 200 条指令内）
        if pos is None or pos >= j or (j - pos) > 200:
            continue

        body = insns[pos:j + 1]

        # 判据 1：循环体里有带立即数的 xor
        xor_ins = None
        for b in body:
            if b.mnem == "xor" and getattr(b, "imm", None) is not None:
                xor_ins = b
                break
        if xor_ins is None:
            continue

        # 判据 2：既读内存又写内存（密文 → 明文 的搬运特征）
        has_load = False
        has_store = False
        data_ref = None
        for b in body:
            ops = b.ops or ""
            if "ptr [" not in ops:
                continue
            # 目的操作数是不是内存：`... ptr [..], src` 里 ptr[ 在逗号之前
            comma = ops.find(",")
            lhs = ops[:comma] if comma >= 0 else ops
            if "ptr [" in lhs:
                has_store = True
            else:
                has_load = True
                if data_ref is None and getattr(b, "mem_ref", None):
                    data_ref = b.mem_ref
        if not (has_load and has_store):
            continue

        key = int(xor_ins.imm) & 0xFF
        found.append({
            "key": key,
            "loop_start_vma": getattr(insns[pos], "vma", None),
            "loop_end_vma": getattr(ins, "vma", None),
            "xor_vma": getattr(xor_ins, "vma", None),
            "body_insns": len(body),
            "data_ref": data_ref,
            "evidence": [getattr(b, "text", "") for b in body[:12]],
        })
        if len(found) >= max_results:
            break

    # 去重：同一个 key + 同一循环起点只留一条
    seen = set()
    dedup = []
    for f in found:
        k = (f["key"], f["loop_start_vma"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(f)
    return {"loops": dedup, "warnings": []}


def xor_loops_to_strings(reader, loops, min_len: int = _MIN_CIPHER,
                         max_results: int = 100):
    """对已识别的解密循环，把它推导出的 key 套用到数据上并抽取明文。

    因为有**代码证据**（循环 + 立即数 key），这里的门槛可以放宽：
    不再需要锚点判据 —— 这是"结构性消除误报"带来的收益。
    """
    out = []
    for lp in loops:
        ref = lp.get("data_ref")
        if not ref:
            continue
        key = lp["key"]
        chunk = reader.read(ref, 512)
        if len(chunk) < min_len:
            continue
        dec = bytes(b ^ key for b in chunk)
        for rel, s in _extract_strings(dec, min_len):
            if len(s) > MAX_STR:
                continue
            out.append({
                "string": s,
                "method": "xor-loop",
                "key": key,
                "offset": ref + rel,
                "loop_start_vma": lp.get("loop_start_vma"),
                "evidence": lp.get("evidence"),
            })
        if len(out) >= max_results:
            break
    # 去重
    seen = set()
    dedup = []
    for r in out:
        if r["string"] in seen:
            continue
        seen.add(r["string"])
        dedup.append(r)
    return {"strings": dedup[:max_results], "warnings": []}


def try_xor_decode(data: bytes, min_len: int = _MIN_CIPHER):
    """尝试单字节 XOR 解密。成功返回 (明文, key)；否则 (None, None)。

    取**分数最高**的 key，而不是"可打印率最高"——
    后者会在大量 key 上并列 100%，导致选中垃圾解（实测踩过）。
    """
    if not data or len(data) < min_len:
        return None, None
    best = None
    for key in range(1, 256):
        score, out = _xor_score(data, key)
        if score < 0:
            continue
        txt = out.split(b"\x00", 1)[0]
        if len(txt) < min_len:
            continue
        # 排序键：分数优先，其次长度（同样可信时取更长的）
        cand = (score, len(txt), key, txt)
        if best is None or cand[:2] > best[:2]:
            best = cand
    if best is None:
        return None, None
    # 分数太低说明"勉强过线"，不认 —— 宁可漏报不误报。
    # 0.72 是实测阈值：真明文串得分普遍 ≥0.85，伪明文（整体偏移的错解）
    # 落在 0.70–0.80 区间，取 0.72 能把大部分错解挡在外面。
    if best[0] < 0.72:
        return None, None
    return best[3], best[2]


def recover_xor_strings(reader, regions, min_len: int = 8,
                        max_results: int = 200):
    """在高熵/数据区里扫 XOR 加密的字符串。

    `regions` 是可迭代的 (offset, size, name) —— 通常传数据段。
    每次取一段窗口尝试单字节 XOR，命中就记录并跳过该窗口。
    """
    warnings = []
    found = []
    scanned_regions = 0
    for off, size, name in regions:
        scanned_regions += 1
        if size <= 0:
            continue
        pos = off
        end = off + min(size, 4 * 1024 * 1024)
        while pos < end and len(found) < max_results:
            chunk = reader.read(pos, 64)
            if len(chunk) < min_len:
                break
            # 试探更长的密文：逐步加长直到解不出可打印串
            got = None
            for length in (64, 48, 32, 24, 16, min_len):
                length = min(length, len(chunk))
                if length < min_len:
                    continue
                txt, key = try_xor_decode(chunk[:length], min_len)
                if txt is not None:
                    got = (txt, key, length)
                    break
            if got is None:
                pos += 16   # 滑动步长：16 字节，容忍不对齐
                continue
            txt, key, length = got
            if len(txt) > MAX_STR:
                txt = txt[:MAX_STR]
            found.append({
                "string": txt.decode("ascii", "replace"),
                "method": "xor-single",
                "key": key,
                "offset": pos,
                "length": length,
                "region": name,
            })
            pos += length

    # 去重
    seen = set()
    dedup = []
    for r in found:
        if r["string"] in seen:
            continue
        seen.add(r["string"])
        dedup.append(r)
    # scanned_regions 必须反映**真正扫过**的区间数。原写法
    # len(list(regions)) 只对带 __len__ 的对象成立，对生成器返回 None，
    # 而且 list() 会把已经遍历过的迭代器再要一遍 —— 统计值不可信。
    return {"strings": dedup[:max_results], "warnings": warnings,
            "scanned_regions": scanned_regions}
