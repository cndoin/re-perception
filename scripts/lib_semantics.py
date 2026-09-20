"""
lib_semantics.py —— 函数级语义摘要：把"一堆汇编"压缩成一眼能读懂的结论

逆向最耗时的三件事是：重命名（这函数干嘛的）、行为判断（有没有加密/联网/反调试）、
关键逻辑定位（哪个函数碰了那个字符串）。这一层就是为这三件事服务的：

    api_tag()               API 名 -> 行为类别（反调试/加解密/网络/...）
    string_vma_map()        数据区字符串 -> VMA 映射（做字符串交叉引用）
    summarize_functions()   每个函数的语义画像

设计取舍：
  * 类别靠 **API 名子串 + DLL 名** 判定，不做控制流/数据流推理 —— 前者可靠，
    后者在缺少符号的二进制上极易误判。宁可标"未知"，也不猜。
  * 一个 API 只归一个主类别（按 _CAT_ORDER 优先级），避免满屏噪音标签。
"""

from lib_x86 import K_CALL, K_JMP, K_CJMP

# ---------------------------------------------------------------- 行为类别表

# 一个 API 只归一类，按顺序匹配：越靠前越"特化"。
# 例：GetTickCount 同时像"时间"和"反调试"，按优先级归到反调试（更符合逆向意图）。
API_TAGS: dict[str, tuple[str, ...]] = {
    # 强信号：这些 API 除了反调试基本没别的正经用途
    "反调试": (
        "isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess",
        "zwqueryinformationprocess", "ntsetinformationthread",
        "zwsetinformationthread", "outputdebugstring", "ntqueryobject",
        "ntquerysysteminformation", "getthreadcontext", "setthreadcontext",
        "unhandledexceptionfilter", "setunhandledexceptionfilter",
        "ntqueryinformationthread", "hidethreadfromdebugger",
    ),
    # 弱信号：既可能反调试（计时/探测），也完全可能是正常性能计数。
    # 【已修 bug】早期版本把它们混进"反调试"，结果 CRT 初始化函数一调用
    # IsProcessorFeaturePresent 就被判成反调试，再沿调用链传染全二进制。
    # 现在单列一类并带问号，明确告诉使用者"这只是线索，不是结论"。
    "反调试(弱)": (
        "isprocessorfeaturepresent", "gettickcount", "queryperformancecounter",
        "queryperformancefrequency", "rdtsc", "cpuid", "getstartupinfo",
        "findwindowa", "findwindoww", "zwterminateprocess", "rtlgetversion",
        "ntclose",
    ),
    "加解密": (
        "crypt", "bcrypt", "ncrypt", "encrypt", "decrypt", "hash", "md5",
        "sha1", "sha256", "sha512", "aes", "rc4", "rsa", "base64",
        "cert", "ssl", "tls", "random", "genrandom", "checksum", "crc",
    ),
    "网络": (
        "socket", "wsa", "connect", "send", "recv", "bind", "listen", "accept",
        "internetopen", "internetread", "internetwrite", "http", "ftp", "url",
        "gethostbyname", "getaddrinfo", "urldownloadtofile", "wininet",
        "winhttp", "netapi", "netuser", "ldap", "sspi", "acquirecredential",
    ),
    "注册表": (
        "regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue",
        "regdeletekey", "regenumkey", "regclosekey", "regsavekey",
    ),
    "进程线程": (
        "createprocess", "createthread", "createremotethread", "openprocess",
        "writeprocessmemory", "readprocessmemory", "virtualalloc",
        "virtualprotect", "virtualquery", "createremotethread", "loadlibrary",
        "getprocaddress", "winexec", "shellexecute", "exitprocess",
        "terminateprocess", "ntcreate", "queueuserapc", "setwindowshookex",
        "rtlcreateuserthread", "suspendthread", "resumethread",
    ),
    "文件": (
        "createfile", "readfile", "writefile", "deletefile", "setfilepointer",
        "setfileattributes", "findfirstfile", "findnextfile", "getfilesize",
        "movefile", "copyfile", "createdirectory", "removedirectory",
        "getmodulefilename", "gettemppath", "getsystemdirectory",
        "getfullpathname", "flushfilebuffers", "deviceiocontrol",
        "getdrivetype", "getlogicaldrive",
    ),
    "内存": (
        "heapalloc", "heapfree", "heaprealloc", "localalloc", "globalalloc",
        "rtlallocateheap", "rtlfreeheap", "malloc", "calloc", "realloc",
        "memcpy", "memset", "memmove", "memcmp", "rtlcopymemory",
        "mapviewoffile", "createfilemapping",
    ),
    "字符串": (
        "lstrcpy", "lstrcat", "lstrlen", "lstrcmp", "strcpy", "strcat",
        "strlen", "strcmp", "strncmp", "strstr", "wcsstr", "sprintf",
        "wsprintf", "swprintf", "vsnprintf", "multibytetowidechar",
        "widechartomultibyte", "charlower", "charupper", "ischar",
    ),
    "界面": (
        "messagebox", "createwindow", "dialogbox", "getdlgitem", "sendmessage",
        "postmessage", "showwindow", "setwindowtext", "getwindowtext",
        "drawtext", "textout", "invalidate", "settimer", "registerclass",
        "defwindowproc", "dispatchmessage", "getmessage", "peekmessage",
    ),
    "时间": (
        "getsystemtime", "getlocaltime", "systemtimetofiletime", "sleep",
        "waitforsingleobject", "waitformultipleobjects", "timegettime",
    ),
}

CAT_ORDER = ("反调试", "反调试(弱)", "加解密", "网络", "注册表", "进程线程",
             "文件", "内存", "字符串", "界面", "时间")

# 太通用、不足以推断行为的 API：打上它们只会制造噪音。
# 例：GetCurrentProcess 几乎每个函数都会调，标成"进程线程"毫无信息量。
NOISE_API = frozenset((
    "getcurrentprocess", "getcurrentthread", "getcurrentprocessid",
    "getcurrentthreadid", "getlasterror", "setlasterror",
    "rtlntstatustodoserror", "ntcurrenttib", "gettickcount64",
))


def is_noise_api(api: str) -> bool:
    """"kernel32!GetCurrentProcess" 这类无信息量的 API。"""
    _, name = split_api(api)
    return name.lower().replace("_", "") in NOISE_API

DLL_TAGS: dict[str, str] = {
    "ws2_32.dll": "网络", "wininet.dll": "网络", "winhttp.dll": "网络",
    "netapi32.dll": "网络", "iphlpapi.dll": "网络", "dnsapi.dll": "网络",
    "advapi32.dll": "注册表", "crypt32.dll": "加解密", "bcrypt.dll": "加解密",
    "ncrypt.dll": "加解密", "cryptsp.dll": "加解密",
    "user32.dll": "界面", "gdi32.dll": "界面", "comctl32.dll": "界面",
    "gdiplus.dll": "界面", "d3d11.dll": "界面",
}

# Win x64 调用约定：整数参数依次用 rcx/rdx/r8/r9
ARG_REGS = ("rcx", "rdx", "r8", "r9")
ARG_REGS32 = ("ecx", "edx", "r8d", "r9d")


def api_tag(api: str, dll: str = "") -> str | None:
    """给一个 API 归一个主行为类别。匹配不上返回 None（不猜）。"""
    n = (api or "").lower()
    if not n:
        return None
    for cat in CAT_ORDER:
        for kw in API_TAGS[cat]:
            if kw in n:
                return cat
    d = (dll or "").lower()
    return DLL_TAGS.get(d)


def split_api(sym: str) -> tuple[str, str]:
    """"kernel32!CreateFileW" -> ("kernel32", "CreateFileW")"""
    if "!" in sym:
        d, _, n = sym.partition("!")
        return d, n
    return "", sym


# ---------------------------------------------------------------- 字符串 VMA 映射

def _data_spans(ident: dict) -> list[tuple[int, int, int]]:
    """数据节的 (文件偏移, 大小, VMA)。代码节排除在外。"""
    det = ident.get("detail") or {}
    base = det.get("image_base") or 0
    spans: list[tuple[int, int, int]] = []
    if ident.get("format") == "pe":
        for s in det.get("sections", []) or []:
            chars = " ".join(s.get("chars", [])).upper()
            if "EXECUTE" in chars or "CODE" in chars:
                continue
            raw = s.get("raw_size") or 0
            if not raw:
                continue
            spans.append((s.get("raw_offset", 0), raw,
                          base + s.get("virtual_address", 0)))
    elif ident.get("format") == "elf":
        for s in det.get("sections", []) or []:
            if s.get("flags", 0) & 0x4:          # SHF_EXECINSTR
                continue
            if s.get("type") == 8:               # SHT_NOBITS (.bss) 无文件内容
                continue
            spans.append((s.get("offset", 0), s.get("size", 0), s.get("addr", 0)))
    return spans


def string_vma_map(path: str, ident: dict, min_len: int = 5,
                   limit: int = 40000) -> dict[int, str]:
    """
    把数据区里的字符串映射成 {VMA: 文本}，用于"哪个函数引用了这个字符串"。

    注意 scan_strings 的第一个参数是**文件路径**（不是 bytes），
    它返回 dict（items 里是 {offset, value, ...}）。
    """
    from lib_analyze import scan_strings

    spans = _data_spans(ident)
    if not spans:
        return {}

    def off2vma(off: int) -> int | None:
        for raw_off, size, vma in spans:
            if raw_off <= off < raw_off + size:
                return vma + (off - raw_off)
        return None

    # 【不要在这里兜异常】这里曾写成 `except Exception: return {}`，
    # 结果是 re.py:594 那个精心写的 `res["_string_map_error"] = ...` 永远不触发，
    # 变成死代码。字符串扫描一崩，整个 semantics 的字符串交叉引用全缺，
    # 却报 ok:true —— 正是本项目最忌讳的"失败被上报为成功"。
    # 让异常上抛给调用方，由那层登记并告知用户。
    res = scan_strings(path, min_len=min_len, max_items=limit,
                       categorize=False)
    out: dict[int, str] = {}
    for it in (res or {}).get("items", []):
        v = off2vma(it.get("offset", -1))
        if v is not None:
            out[v] = it.get("value") or ""
    return out


# ---------------------------------------------------------------- 函数语义画像

def resolve_thunks(idx, funcs: list[dict], iat_map: dict[int, str]) -> dict[int, str]:
    """
    解析 MSVC 风格的导入跳板：call thunk_xxx -> thunk 里 jmp [IAT槽位]。

    不做这一步，几乎每个导入调用都只会显示成"调用了 thunk_140001c84"，
    语义分析等于失效（实机验证：notepad.exe 走的全是 thunk）。
    判定：函数只有 1 条指令、是间接 jmp、目标落在 IAT 里。
    """
    out: dict[int, str] = {}
    if not iat_map:
        return out
    for f in funcs:
        offs = f.get("_offs") or []
        if len(offs) != 1:
            continue
        ins = ins_at(idx, offs[0])
        if ins is None or ins.mnem != "jmp" or ins.kind != K_JMP:
            continue
        # 优先用解码器算好的 mem_ref（RIP 相对或绝对地址都算得对），
        # 没有再退回手工按 disp 推算（老路径，bit 宽度处理不全）
        cand = [ins.mem_ref]
        if ins.disp is not None:
            cand.append(ins.vma + ins.size + ins.disp)
            cand.append(ins.disp)
        for tgt in cand:
            if tgt is None:
                continue
            api = iat_map.get(tgt)
            if api:
                out[ins.vma] = api
                break
    return out


def _vma_str(v) -> str:
    """start_vma 可能是 int（find_functions 直接返回）也可能是 "0x..."
    （analyze 为了 JSON 化转过），统一成十六进制字符串。"""
    if isinstance(v, bool):
        return "0x0"
    if isinstance(v, int):
        return hex(v)
    if isinstance(v, str) and v:
        return v
    return "0x0"


def ins_at(idx, off):
    """
    取偏移 off 处的指令。

    【已修 bug 1】CodeIndex.insn 是**懒加载**的（只有 decode_at/linear_scan
    才填充）。直接 idx.insn.get(o) 在索引未预热时静默返回 None ——
    表现为"分析结果全空"却没有任何报错，极难排查。这里统一走 decode_at。

    【已修 bug 2】旧实现在 decode_at 抛异常时**静默**退回 `idx.insn.get`。
    两者都会返回 None，于是"解码器真崩了"和"这个偏移本来就没指令"完全
    无法区分 —— 又是一次失败被伪装成空结果。现在把异常记到 idx._ins_at_errors
    上（有界，最多留 32 条），调用方可据此判断索引是不是整体失效了。
    """
    dec = getattr(idx, "decode_at", None)
    if callable(dec):
        try:
            i = dec(off)
            if i is not None:
                return i
        except Exception as e:
            errs = getattr(idx, "_ins_at_errors", None)
            if errs is None:
                errs = []
                try:
                    idx._ins_at_errors = errs
                except Exception:
                    errs = None
            if errs is not None and len(errs) < 32:
                errs.append("%s@0x%x: %s: %s"
                            % (type(idx).__name__, off, type(e).__name__, e))
            # 解码器抛异常说明索引本身可能已废；不要再退回懒加载字典
            # 假装成功（那会返回 None 且毫无痕迹）。
            return None
    return idx.insn.get(off)


def ins_at_errors(idx) -> list:
    """取出 ins_at 累计的解码异常（供 CLI 提示"索引可能失效"）。"""
    return list(getattr(idx, "_ins_at_errors", []) or [])


def _candidate_addrs(ins) -> list[int]:
    """一条指令可能引用到的绝对地址（用于字符串 XREF）。"""
    out = []
    if ins.imm:
        out.append(ins.imm)
    if ins.disp is not None:
        # RIP 相对：目标 = 指令结束地址 + disp；也可能是绝对地址（SIB 无 base）
        out.append(ins.vma + ins.size + ins.disp)
        out.append(ins.disp)
    return out


def summarize_functions(idx, funcs: list[dict], iat_map: dict[int, str],
                        str_map: dict[int, str], limit: int = 400,
                        thunk_map: dict[int, str] | None = None) -> list[dict]:
    """
    给每个函数做语义画像。funcs 来自 lib_code.find_functions（需带 _offs）。
    thunk_map 是导入跳板（thunk VMA -> api），见 resolve_thunks。
    """
    thunk_map = thunk_map or {}
    # VMA -> 函数名：把内部调用也渲染成人能读的名字（sub_140001234 也算名字）
    name_by_vma: dict[int, str] = {}
    for g in funcs:
        sv = g.get("start_vma")
        try:
            name_by_vma[int(sv, 16) if isinstance(sv, str) else int(sv)] = g.get("name") or ""
        except (TypeError, ValueError):
            # start_vma 缺失/为 None/非数字：只是这个函数无法按 VMA 索引，
            # 不影响其它函数，属于可跳过的单条坏数据。
            continue
    out: list[dict] = []
    for f in funcs[:limit]:
        offs = f.get("_offs") or []
        if not offs:
            continue
        insns = [ins_at(idx, o) for o in offs]
        insns = [i for i in insns if i is not None]
        if not insns:
            continue

        # --- 调用目标 ---
        calls: list[dict] = []
        seen_api: dict[str, int] = {}
        seen_callee: dict[str, int] = {}
        callee_vmas: set[int] = set()      # 内部被调函数地址（供标签传播）
        for ins in insns:
            # jmp 也算：编译器把"函数末尾直接跳到 API"优化成尾调用
            # （实机验证：notepad.exe 里 HeapAlloc/HeapFree/RaiseException 等
            #  就是以 jmp [IAT] 结尾的，不算进去会漏判这些函数的行为）
            if ins.kind not in (K_CALL, K_JMP):
                continue
            tgt = ins.target
            ref = ins.mem_ref
            if tgt is None and ref is None:
                continue
            # 1) 直接命中 IAT 槽位 2) 经由 thunk 跳板
            # 3) MSVC 主流写法 call/jmp qword ptr [rip+x]：目标运行时才定
            #    （target=None），但引用的 IAT 槽位是编译期常量 —— 用 mem_ref 还原
            api = None
            for a in (tgt, ref):
                if a is None:
                    continue
                api = iat_map.get(a) or thunk_map.get(a)
                if api:
                    break
            # 内部调用：给出被调函数名
            callee = None
            if api is None and tgt is not None and ins.kind == K_CALL:
                callee = name_by_vma.get(tgt)
                if callee:
                    callee_vmas.add(tgt)
            if api is None and callee is None:
                continue
            item = {"at_vma": hex(ins.vma),
                    "kind": "tail_jmp" if (api and ins.kind == K_JMP) else
                            ("indirect" if tgt is None else "direct"),
                    "target": hex(tgt) if tgt is not None else None,
                    "mem_ref": hex(ref) if ref is not None else None,
                    "api": api,
                    "callee": callee}
            calls.append(item)
            if api:
                seen_api[api] = seen_api.get(api, 0) + 1
            elif callee:
                seen_callee[callee] = seen_callee.get(callee, 0) + 1

        # --- 行为标签 ---
        tags: list[str] = []
        for api in seen_api:
            if is_noise_api(api):
                continue
            dll, name = split_api(api)
            t = api_tag(name, dll)
            if t and t not in tags:
                tags.append(t)

        # --- 引用的字符串 ---
        refs: list[str] = []
        seen_ref = set()
        if str_map:
            for ins in insns:
                for a in _candidate_addrs(ins):
                    s = str_map.get(a)
                    if s and s not in seen_ref:
                        seen_ref.add(s)
                        refs.append(s)
                    if len(refs) >= 12:
                        break
                if len(refs) >= 12:
                    break

        # --- 栈帧：序言里的 sub rsp, N ---
        stack = 0
        for ins in insns[:10]:
            if ins.mnem in ("sub", "add") and ins.ops.startswith("rsp,"):
                v = ins.imm or 0
                if v:
                    stack = v
                    break

        # --- 参数推断：函数前段被读取的 Win64 参数寄存器 ---
        args: list[str] = []
        head = insns[:16]
        for reg in ARG_REGS:
            for ins in head:
                ops = ins.ops or ""
                # 出现在逗号右侧（作为源）才算"被读取"
                if ops.count(",") and ops.split(",", 1)[1].strip().startswith(reg):
                    args.append(reg)
                    break
                if ins.mnem in ("test", "cmp") and ops.endswith(reg):
                    args.append(reg)
                    break
        arg_names = ARG_REGS[:len(args)] if args else []

        # --- 结构特征 ---
        xor_cnt = sum(1 for i in insns if i.mnem in ("xor", "pxor", "xorps", "vxorps"))
        has_loop = False
        lo = insns[0].vma
        hi = insns[-1].vma
        for ins in insns:
            if ins.kind in (K_JMP, K_CJMP) and ins.target is not None:
                if lo <= ins.target <= ins.vma:      # 往回跳 = 循环
                    has_loop = True
                    break

        # --- 导入跳板：函数本身就是一条 jmp [IAT]，名字还原成它跳向的 API ---
        thunk_of = None
        sv = _as_vma_int(f.get("start_vma"))
        if sv is not None:
            thunk_of = thunk_map.get(sv)

        bb = f.get("bb_count") or 0
        out.append({
            "name": f.get("name"),
            "thunk_of": thunk_of,
            "_cv": callee_vmas,                # 传播用，最后弹出
            "start_vma": _vma_str(f.get("start_vma")),
            "end_vma": _vma_str(f.get("end_vma")),
            "insn_count": len(insns),
            "bb_count": bb,
            "stack_frame": hex(stack) if stack else None,
            "args": list(arg_names),
            "call_count": len(calls),
            "api_calls": [{"api": k, "count": v} for k, v in
                          sorted(seen_api.items(), key=lambda t: -t[1])][:20],
            "callees": [{"name": k, "count": v} for k, v in
                        sorted(seen_callee.items(), key=lambda t: -t[1])][:10],
            "tags": tags,
            "strings": refs[:12],
            "features": {
                "loop": has_loop,
                "xor_dense": (xor_cnt / len(insns)) > 0.12 if insns else False,
                "xor_count": xor_cnt,
            },
            "summary": "",                     # 传播完再生成（标签可能变多）
            "_tags": tags,
            "_seen_api": seen_api,
            "_refs": refs,
            "_has_loop": has_loop,
            "_stack": stack,
            "_seen_callee": seen_callee,
        })

    _propagate_tags(out)
    for s in out:
        s.pop("_cv", None)
        s["summary"] = _one_line(s["name"], s["tags"], s.pop("_seen_api"),
                                 s.pop("_refs"), s.pop("_has_loop"),
                                 s.pop("_stack"), s.pop("_seen_callee"),
                                 s.get("thunk_of"), s.get("inherited_tags"))
        s.pop("_tags", None)
    return out


def _propagate_tags(sums: list[dict], max_depth: int = 3) -> None:
    """
    沿调用链把行为标签从被调函数传给调用者（原地修改 sums）。

    为什么必须做：真实二进制里大量函数是 wrapper —— 自己不碰任何 API，
    行为全在它调用的子函数里。只按直接调用打标签的话，"这函数在干嘛"
    会有大半是"未知"，看板就废了。

    传播层数封顶（默认 3）：既避免调用环打转，也避免"几乎所有函数都
    继承到同一堆标签"这种信息量归零的结果。
    """
    vma2i: dict[int, int] = {}
    for i, s in enumerate(sums):
        v = _as_vma_int(s.get("start_vma"))
        if v is not None:
            vma2i[v] = i

    for _ in range(max_depth):
        changed = False
        for i, s in enumerate(sums):
            if s.get("thunk_of"):
                s.setdefault("inherited_tags", [])
                continue
            direct = list(s.get("_tags") or s.get("tags") or [])
            got = set(direct) | set(s.get("inherited_tags") or [])
            for cv in s.get("_cv") or ():
                j = vma2i.get(cv)
                if j is None or j == i:
                    continue
                o = sums[j]
                # 枢纽函数不参与传播：CRT 初始化、消息分发这类函数一口气
                # 调用几十个不同领域的 API，身上挂着七八个标签。让它们传播
                # 等于把"全都有"传染给整个二进制 —— 标签从此不再有信息量。
                # 判据：自身标签数 ≤ 2 才认为它语义专一，可以传播。
                o_tags = (o.get("_tags") or o.get("tags") or [])
                if len(o_tags) + len(o.get("inherited_tags") or []) > 2:
                    continue
                for t in list(o_tags) + list(o.get("inherited_tags") or []):
                    if t not in got:
                        got.add(t)
                        changed = True
            inh = sorted(t for t in got if t not in direct)
            if inh != s.get("inherited_tags"):
                changed = True
            s["inherited_tags"] = inh
        if not changed:
            break

    for s in sums:
        s["tags"] = list(s.get("_tags") or s.get("tags") or [])
        s["tags_all"] = s["tags"] + list(s.get("inherited_tags") or [])


def _as_vma_int(v) -> int | None:
    """start_vma 可能是 int 也可能是 "0x..."，统一成 int；失败返回 None。"""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v:
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v, 16)
        except ValueError:
            return None
    return None


def _one_line(name, tags, api_map, refs, has_loop, stack, callee_map=None,
              thunk_of: str | None = None, inherited: list[str] | None = None) -> str:
    """一行人话摘要。宁可短，不可编造。"""
    parts = []
    if thunk_of:
        return f"{name}: [导入跳板] -> {thunk_of}"
    if tags:
        parts.append("[" + "/".join(tags) + "]")
    elif inherited:
        # 自己没直接调 API，行为是从被调函数继承来的 —— 标清楚来源，别装作亲眼所见
        parts.append("[" + "/".join(inherited) + "↑继承]")
    else:
        parts.append("[未知]")
    if api_map:
        top = sorted(api_map.items(), key=lambda t: -t[1])[:3]
        parts.append("调用 " + ", ".join(k for k, _ in top))
    elif callee_map:
        top = sorted(callee_map.items(), key=lambda t: -t[1])[:3]
        parts.append("调用内部 " + ", ".join(k for k, _ in top))
    else:
        parts.append("无外部调用")
    if refs:
        parts.append("引用字符串 " + ", ".join(repr(s) for s in refs[:2]))
    tail = []
    if has_loop:
        tail.append("含循环")
    if stack:
        tail.append(f"栈帧 {hex(stack)}")
    if tail:
        parts.append("；".join(tail))
    return f"{name}: " + "；".join(parts)


def cluster_by_tag(sums: list[dict]) -> dict[str, list[str]]:
    """按行为类别把函数分组 —— 找"加密在哪""联网在哪"时直接看这里。

    用 tags_all（直接 + 继承）：不然 wrapper 函数全落进"未知"，分组就没用了。
    """
    out: dict[str, list[str]] = {}
    for s in sums:
        for t in (s.get("tags_all") or s.get("tags") or ["未知"]):
            out.setdefault(t, [])
            if len(out[t]) < 200:          # 只截"展示用"的地址列表
                out[t].append(s["start_vma"])
    return dict(sorted(out.items(), key=lambda kv: -len(kv[1])))


def tag_counts(sums: list[dict]) -> dict[str, int]:
    """每个标签的**真实**函数数（不受 cluster_by_tag 的地址截断影响）。"""
    c: dict[str, int] = {}
    for s in sums:
        for t in (s.get("tags_all") or s.get("tags") or ["未知"]):
            c[t] = c.get(t, 0) + 1
    return dict(sorted(c.items(), key=lambda kv: -kv[1]))
