# -*- coding: utf-8 -*-
"""端到端功能测试：把全部子命令在真实样本上跑一遍。

判定标准（不是"跑完就算过"）：
  * 退出码必须属于该命令的合法集合
  * --json 输出必须是合法 JSON，且 ok=true（除非本用例预期的失败场景）
  * 关键字段必须存在且类型正确
  * stdout 不得混入人类可读噪声（--json 模式）

用法：python _dev/_e2e.py
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
SKILL = os.path.dirname(SCRIPTS)
PY = sys.executable
RE = os.path.join(SCRIPTS, "re.py")

PASS, FAIL = [], []
RPT = None   # 报告落盘用的临时目录（main 里建立）


def run(args, expect_rc=(0,), timeout=180, cwd=None):
    p = subprocess.run([PY, RE] + args, cwd=cwd or SCRIPTS,
                       capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return p


def case(name, args, expect_rc=(0,), need_json=True, check=None,
         timeout=180, cwd=None):
    try:
        p = run(args, expect_rc, timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        FAIL.append((name, "超时 >%ds" % timeout))
        return None
    if p.returncode not in expect_rc:
        FAIL.append((name, "退出码 %d 不在 %s；stderr=%s"
                     % (p.returncode, expect_rc, p.stderr.strip()[:300])))
        return None
    obj = None
    if need_json:
        try:
            obj = json.loads(p.stdout)
        except Exception as e:
            FAIL.append((name, "stdout 不是合法 JSON：%s；前 200 字=%r"
                         % (e, p.stdout[:200])))
            return None
        if not isinstance(obj, (dict, list)):
            FAIL.append((name, "JSON 顶层类型异常：%s" % type(obj).__name__))
            return None
        if isinstance(obj, dict) and expect_rc == (0,) and obj.get("ok") is False:
            FAIL.append((name, "ok=false：%s" % json.dumps(
                obj, ensure_ascii=False)[:300]))
            return None
    if check:
        try:
            msg = check(obj, p)
        except Exception as e:
            FAIL.append((name, "断言抛异常：%s: %s" % (type(e).__name__, e)))
            return None
        if msg:
            FAIL.append((name, msg))
            return None
    PASS.append(name)
    return obj


def need(obj, *keys):
    """断言 dict 里这些键都在（支持 'a.b' 形式）。

    每个键都从 obj 顶层重新下钻 —— 曾经 cur 不重置、逐键累积下钻，
    多键断言第二个键起永远报缺字段（首次多键使用即暴露）。
    """
    for k in keys:
        cur = obj
        for part in k.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return "缺字段 %s" % k
            cur = cur[part]
    return None


def samples():
    """挑真实样本。优先系统自带文件，避免依赖外部下载。

    **只在 Windows 上能拿到 PE 样本**（取自 System32）。Linux / macOS 上
    这些路径不存在，本函数会返回空 exe/dll，随后 main() 失败退出 ——
    这是刻意的：不拿合成样本凑数，也不静默跳过。
    CI 里这个 job 因此跑在 windows-latest。
    """
    out = {}

    def first(*paths):
        for p in paths:
            if os.path.isfile(p):
                return p
        return None

    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    out["exe"] = first(os.path.join(sysroot, "System32", "notepad.exe"),
                       os.path.join(sysroot, "notepad.exe"))
    out["dll"] = first(os.path.join(sysroot, "System32", "kernel32.dll"),
                       os.path.join(sysroot, "System32", "user32.dll"))
    out["dll2"] = first(os.path.join(sysroot, "System32", "advapi32.dll"))
    out["sys"] = first(os.path.join(sysroot, "System32", "ntdll.dll"))
    out["driver"] = first(os.path.join(sysroot, "System32", "drivers", "null.sys"),
                          os.path.join(sysroot, "System32", "ntoskrnl.exe"))
    out["text"] = first(os.path.join(SKILL, "SKILL.md"))
    out["py"] = first(os.path.join(SCRIPTS, "re.py"))
    return {k: v for k, v in out.items() if v}


def main():
    global RPT
    RPT = tempfile.mkdtemp(prefix="re-e2e-rpt-")
    S = samples()
    print("样本：")
    for k, v in S.items():
        print("  %-8s %s  (%d B)" % (k, v, os.path.getsize(v)))
    print()

    exe, dll, dll2, text = S.get("exe"), S.get("dll"), S.get("dll2"), S.get("text")
    if not exe or not dll:
        # 必须失败退出，不能静默跳过：否则 CI 上会出现「0 个用例全通过」的
        # 永不拦截的门。但要把原因说清楚，别让 Linux 上的贡献者一头雾水。
        print("！缺少 PE 样本，无法继续。")
        print("  本端到端测试依赖 Windows 的 System32 文件（notepad.exe /")
        print("  kernel32.dll / ntdll.dll / null.sys），Linux 与 macOS 没有。")
        print(f"  当前平台：{sys.platform}")
        print("  请在 Windows 上运行，或改跑 `python selftest.py`（全平台可用）。")
        return 1

    # ---------- doctor ----------
    case("doctor", ["doctor", "--json"], check=lambda o, p: need(o, "ok"))

    # ---------- identify ----------
    case("identify(PE exe)", ["identify", exe, "--json"],
         check=lambda o, p: need(o, "format"))
    case("identify(dll)", ["identify", dll, "--json"],
         check=lambda o, p: need(o, "format"))
    if text:
        case("identify(text)", ["identify", text, "--json"],
             check=lambda o, p: need(o, "format"))

    # ---------- magic ----------
    case("magic", ["magic", "--json"])

    # ---------- strings ----------
    case("strings", ["strings", exe, "--json", "--max-items", "2000"],
         check=lambda o, p: need(o, "count") if isinstance(o, dict) else None)
    case("strings(regex)", ["strings", exe, "--json", "--max-items", "500",
                            "--pattern", "Get"])

    # ---------- entropy ----------
    case("entropy", ["entropy", exe, "--json"],
         check=lambda o, p: need(o, "overall_entropy") if isinstance(o, dict) else None)

    # ---------- imports ----------
    case("imports", ["imports", exe, "--json"])
    case("imports(driver)", ["imports", S["driver"], "--json"]) if S.get("driver") else None

    # ---------- info ----------
    case("info(PE)", ["info", exe, "--json"])
    case("info(PE dll)", ["info", dll, "--json"])

    # ---------- triage ----------
    case("triage", ["triage", exe, "--json"], timeout=300)
    case("triage(dll)", ["triage", dll, "--json"], timeout=300)

    # ---------- carve ----------
    case("carve", ["carve", exe, "--json"], timeout=300)

    # ---------- diff ----------
    case("diff(同文件)", ["diff", exe, exe, "--json"])
    case("diff(不同文件)", ["diff", exe, dll, "--json"], timeout=300)

    # ---------- plan ----------
    case("plan", ["plan", exe, "--json"])

    # ---------- report ----------
    # 【为什么必须显式 --out】exe 是 System32 里的 notepad.exe，默认输出
    # 位置是"目标旁边"→ 受保护目录不可写。产品会自动降级到当前目录
    # （见下面的降级用例），但这里的**主用例**只想测"报告能正常生成"，
    # 不该把环境权限当成被测对象 —— 否则同样的代码在管理员机器上绿、
    # 在普通机器上红，用例本身变得不可信。
    case("report", ["report", exe, "--json", "--out", RPT], timeout=300)

    # 回归守卫：受保护目录下的目标，无 --out 时必须降级而不是失败。
    # 这条守着 cmd_report 的 writable_fallback 逻辑 —— 旧版直接退出码 4，
    # 用户拿 notepad.exe 试第一次就踩到。
    #
    # 【cwd 为什么要指定】降级会把报告写到**当前工作目录**。若沿用默认的
    # cwd=SCRIPTS，报告就落在源码目录里（notepad.exe.re-report.md），
    # 被 _lint 的"测试残留物"护栏当成发布物残留反复抓到。
    # 让这条用例在自己的临时目录里跑，产物随之可丢弃。
    FALLBACK_CWD = tempfile.mkdtemp(prefix="re-e2e-fallback-")

    def _report_fallback_ok(o, p):
        if not isinstance(o, dict):
            return "顶层不是对象"
        if not o.get("ok"):
            return "降级路径下 ok 不为 true"
        rp = o.get("report")
        if not rp or not os.path.isfile(rp):
            return "返回的 report 路径不存在：%r" % rp
        if o.get("writable_fallback"):
            if not o.get("note"):
                return "缺少 note 说明降级原因"
            # 报告必须真的落在降级目录里（cwd），而不是别处
            if os.path.dirname(os.path.abspath(rp)) != os.path.abspath(FALLBACK_CWD):
                return "降级报告不在 cwd 下：%r" % rp
        else:
            # GitHub 的 Windows runner 可能有权写 System32；此时没有发生降级，
            # 直接写到目标旁边也是正确结果。清理测试自己生成的报告。
            expected = os.path.abspath(exe + ".re-report.md")
            if os.path.abspath(rp) != expected:
                return "未降级但报告位置异常：%r" % rp
            try:
                os.unlink(rp)
            except OSError:
                pass
        return None

    case("report(受保护目录降级)", ["report", exe, "--json"],
         check=_report_fallback_ok, timeout=300, cwd=FALLBACK_CWD)

    # ---------- evidence（证据契约层，REA 移植） ----------
    # 把 identify 的发现包装成可溯源证据（内容哈希 ID ev-<sha256[:32]> +
    # confidence 三分 observed/derived/inferred + limitations 必填），
    # 并登记残余未知项。这里验"证据契约层在真实 PE 上跑得通、产出结构
    # 完整、ID 形态正确、证据链强度取下限"，不验结论强弱本身。
    #
    # 【断言字段取自实测】ID 字段名是 evidence_id（不是 id），confidence
    # 取值是 observed/derived/inferred，limitations 是非空 list —— 这些都
    # 在写用例前实跑过 notepad.exe 确认，避免臆测字段名造成假失败。
    def _evidence_e2e_ok(o, p):
        if not isinstance(o, dict):
            return "顶层不是对象"
        if not o.get("ok"):
            return "证据契约层 ok 不为 true"
        evs = o.get("evidence")
        if not isinstance(evs, list) or not evs:
            return "evidence 不是非空列表：%r" % (evs,)
        for e in evs:
            if not isinstance(e, dict):
                return "证据项不是对象：%r" % (e,)
            eid = e.get("evidence_id")
            if not (isinstance(eid, str) and eid.startswith("ev-")):
                return "证据 ID 形态异常：%r" % (eid,)
            if e.get("confidence") not in ("observed", "derived", "inferred"):
                return "证据 confidence 非法：%r" % (e.get("confidence"),)
            if not isinstance(e.get("limitations"), list) or not e.get("limitations"):
                return "证据缺 limitations（必填）：%r" % eid
        adj = o.get("adjudication")
        if not isinstance(adj, dict) or "strength" not in adj:
            return "adjudication 缺 strength：%r" % (adj,)
        if not isinstance(o.get("unknowns"), list):
            return "unknowns 不是列表：%r" % (o.get("unknowns"),)
        return None

    case("evidence", ["evidence", exe, "--json"],
         check=_evidence_e2e_ok, timeout=300)

    # ---------- disasm ----------
    case("disasm", ["disasm", exe, "--json", "--max-insns", "200"])

    # ---------- funcs ----------
    # 注意：--top 是「只显示前 N 个」，--max-insns 是「扫描指令预算」。
    # 千万别写 --max：argparse 会把它当成 --max-insns 的前缀缩写，静默把
    # 扫描预算压到个位数，函数数直接归零却不报错。
    case("funcs", ["funcs", exe, "--json", "--top", "60"], timeout=300)

    # ---------- cfg ----------
    o = case("funcs(取一个函数做 cfg)", ["funcs", exe, "--json", "--top", "30"],
             timeout=300)
    fns = (o or {}).get("functions") if isinstance(o, dict) else None
    starts = []
    if isinstance(fns, list):
        for f in fns:
            for k in ("start_vma", "start", "vma", "addr", "entry"):
                if isinstance(f, dict) and f.get(k) is not None:
                    starts.append(f[k])
                    break
    if starts:
        s0 = starts[0]
        s0h = ("%x" % s0) if isinstance(s0, int) else str(s0)
        s0h = s0h[2:] if s0h.lower().startswith("0x") else s0h
        case("cfg", ["cfg", exe, s0h, "--json"], timeout=300)
    else:
        FAIL.append(("cfg", "funcs 返回 %d 个函数但都取不到地址，样例=%s"
                     % (len(fns or []), (fns or [{}])[0])))

    # ---------- struct / ir（IR + 控制流结构化） ----------
    def _struct_ok(o, p):
        if not isinstance(o, dict):
            return "顶层不是对象"
        fns2 = o.get("functions")
        if not isinstance(fns2, list) or not fns2:
            return "没有 functions 输出"
        for k in ("loops", "conditionals", "switches", "structure",
                  "cyclomatic"):
            if k not in fns2[0]:
                return "函数输出缺字段 %s" % k
        return None

    case("struct", ["struct", exe, "--json", "--max-functions", "2"],
         check=_struct_ok, timeout=300)
    if starts:
        s0s = ("0x%x" % starts[0]) if isinstance(starts[0], int) else str(starts[0])
        case("struct(--addr)", ["struct", exe, "--addr", s0s, "--json"],
             check=_struct_ok, timeout=300)

    def _ir_ok(o, p):
        msg = _struct_ok(o, p)
        if msg:
            return msg
        for f in o.get("functions", []):
            ir = f.get("ir")
            if not isinstance(ir, list) or not ir:
                return "ir 子命令没有 IR 明细"
            if "op" not in ir[0]:
                return "IR 条目缺 op 字段"
            break
        return None

    case("ir", ["ir", exe, "--json", "--max-functions", "1"],
         check=_ir_ok, timeout=300)

    # ---------- xref ----------
    case("xref(Top 引用者)", ["xref", exe, "--json"], timeout=300)
    if starts:
        s0x = ("0x%x" % starts[0]) if isinstance(starts[0], int) else str(starts[0])
        case("xref(--addr)", ["xref", exe, "--addr", s0x, "--json"], timeout=300)

    # ---------- sim ----------
    case("sim(同文件)", ["sim", exe, exe, "--json"], timeout=300)
    case("sim(不同文件)", ["sim", exe, dll, "--json"], timeout=300)

    # ---------- semantics ----------
    case("semantics", ["semantics", exe, "--json", "--limit", "30"], timeout=300)

    # ---------- 文档一致性：SKILL.md 里写的用法必须真的能用 ----------
    # （cfg 位置参数 / xref --addr 是文档承诺的接口，改坏了要在 CI 里炸）
    if starts:
        raw = starts[0]
        pos = ("%x" % raw) if isinstance(raw, int) else str(raw).replace("0x", "")
        case("文档: cfg <目标> <地址>", ["cfg", exe, pos, "--json"], timeout=300)
        addrx = ("0x%x" % raw) if isinstance(raw, int) else str(raw)
        case("文档: xref --addr", ["xref", exe, "--addr", addrx, "--json"],
             timeout=300)
    case("文档: funcs --top", ["funcs", exe, "--top", "5", "--json"], timeout=300)

    # ---------- funcs 截断语义：预算用尽时必须标注为片段 ----------
    def _trunc_ok(o, p):
        if not isinstance(o, dict):
            return "顶层不是对象"
        if o.get("truncated") and not o.get("partial"):
            return "truncated=true 但 partial 未置位（截断结果会被误当完整结论）"
        if o.get("truncated") and not o.get("truncated_note"):
            return "truncated=true 但没有 truncated_note 说明"
        return None

    case("funcs 截断时标注 partial", ["funcs", exe, "--json",
                                      "--max-insns", "100"],
         check=_trunc_ok, timeout=120)

    # ---------- 错误路径（这些必须"失败得正确"）----------
    case("identify(不存在)", ["identify", "Z:/__no_such_file__", "--json"],
         expect_rc=(3,))
    case("info(不存在)", ["info", "Z:/__no_such_file__", "--json"], expect_rc=(3,))
    case("identify(目录)", ["identify", SCRIPTS, "--json"], expect_rc=(3, 4))

    # ---------- 补充检查器：布局 / PE 资源 / 架构 / plist / .NET / Go / EVM / demangle ----------
    def _peres_ok(o, p):
        m = need(o, "ok", "count", "entries")
        if m:
            return m
        if len(o.get("entries") or []) > 8:
            return "entries 超出 --max-entries=8"
        return None

    def _degraded(o, p):
        # 反向保护：非目标格式必须 ok:False + reason 申报，不许假阳性
        if o.get("ok") is not False:
            return "非目标格式竟判 ok（假阳性）: %s" % str(o)[:150]
        return need(o, "reason")

    def _dm_rust(o, p):
        if o.get("kind") != "rust-legacy":
            return "Rust 名字未走 rust-legacy 路由: %s" % o.get("kind")
        if "h0123" in (o.get("demangled") or ""):
            return "crate hash 泄漏进还原名: %s" % o.get("demangled")
        return None

    case("layout(PE 布局缓解)", ["layout", exe, "--json"],
         check=lambda o, p: need(o, "ok", "format", "mitigations"))
    case("peres(PE 资源树)", ["peres", exe, "--json", "--max-entries", "8"],
         check=_peres_ok)
    case("archs(PE 反向降级)", ["archs", exe, "--json"], expect_rc=(3,),
         check=_degraded)
    case("plist(PE 反向降级)", ["plist", exe, "--json"], expect_rc=(3,),
         check=_degraded)
    case("dotnet(原生 PE 降级)", ["dotnet", exe, "--json"], expect_rc=(3,),
         check=_degraded)
    case("goinfo(非 Go 降级)", ["goinfo", exe, "--json"], expect_rc=(3,),
         check=_degraded)
    case("evm(hex dispatch)", ["evm", "0x63a9059cbb14", "--json"],
         check=lambda o, p: need(o, "ok", "selectors"))
    case("demangle(Itanium)", ["demangle", "_ZN3std2fs5writeE", "--json"],
         check=lambda o, p: need(o, "ok", "demangled"))
    case("demangle(Rust legacy)", ["demangle", "_ZN3std2fs17h0123456789abcdefE",
                                   "--json"], check=_dm_rust)

    # ---------- 分析补全：capability / obfstr / symbols ----------
    case("capability(能力规则)", ["capability", exe, "--json", "--limit", "20"],
         timeout=300, check=lambda o, p: need(o, "ok"))
    case("obfstr(混淆串)", ["obfstr", exe, "--json", "--limit", "20"],
         timeout=300, check=lambda o, p: need(o, "ok"))
    case("symbols(符号)", ["symbols", exe, "--json", "--limit", "50"],
         timeout=300, check=lambda o, p: need(o, "ok", "symbols"))

    # ---------- 平台契约层：provider / unknowns / bundle ----------
    case("provider(选择与探测)", ["provider", "--json"],
         check=lambda o, p: need(o, "ok", "selection", "probes"))
    reg = os.path.join(RPT, "reg.json")
    case("unknowns(list)", ["unknowns", "list", "--registry", reg, "--json"],
         check=lambda o, p: need(o, "ok", "count", "unknowns"))
    case("unknowns(record)", ["unknowns", "record", "--registry", reg,
                              "--question", "e2e：该样本是否加壳？",
                              "--blocked-by", "缺动态环境", "--json"],
         check=lambda o, p: need(o, "ok", "unknown.unknown_id"))
    b1 = os.path.join(RPT, "bundle_a.json")
    case("bundle(export)", ["bundle", "export", "--target", exe, "--out", b1,
                            "--json"], timeout=300,
         check=lambda o, p: need(o, "ok", "digest", "count"))
    case("bundle(import)", ["bundle", "import", "--infile", b1, "--lenient",
                            "--json"], timeout=300,
         check=lambda o, p: need(o, "ok"))
    case("bundle(compare)", ["bundle", "compare", "--a", b1, "--b", b1, "--json"],
         timeout=300,
         check=lambda o, p: need(o, "ok", "unchanged_count", "changed_count"))

    # ---------- 编排元工具：case 状态目录 / result / flow / require / toolgraph ----------
    case_dir = os.path.join(RPT, "case_e2e")
    case("case(init)", ["case", "init", "--dir", case_dir, "--target", exe, "--json"],
         check=lambda o, p: need(o, "ok", "case_dir"))
    # 用 identify 的输出当存档样本：小而无截断 —— result 的分类是逐字面的，
    # 截断输出会被如实归类 partial（ok:false），不适合当"成功转述"用例。
    # （magic 不接 target，是魔数表命令 —— 拿它当载荷会得到 argparse 空输出。）
    pr = run(["identify", exe, "--json"])
    str_out = os.path.join(RPT, "identify_out.json")
    with open(str_out, "w", encoding="utf-8") as f:
        f.write(pr.stdout)
    case("case(save)", ["case", "save", "--dir", case_dir, "--cmd", "identify",
                        "--from-file", str_out, "--target", exe, "--json"],
         check=lambda o, p: need(o, "ok", "artifact"))
    case("case(load)", ["case", "load", "--dir", case_dir, "--cmd", "identify",
                        "--target", exe, "--json"],
         check=lambda o, p: need(o, "ok", "summary"))
    case("case(status)", ["case", "status", "--dir", case_dir, "--target", exe,
                          "--json"],
         check=lambda o, p: need(o, "ok", "have_count"))
    case("case(journal)", ["case", "journal", "--dir", case_dir, "--json"],
         check=lambda o, p: need(o, "ok", "count"))
    case("result(摘要+分类)", ["result", "--from-file", str_out, "--cmd", "identify",
                              "--exit-code", "0", "--json"],
         check=lambda o, p: need(o, "ok", "kind", "next_action"))
    case("flow(工作流)", ["flow", "--json"],
         check=lambda o, p: need(o, "ok", "next_batch"))
    case("require(意图检索)", ["require", "提取字符串并找可疑 IP", "--json"],
         check=lambda o, p: need(o, "ok", "recommendations"))
    case("toolgraph(转移图)", ["toolgraph", "--json"],
         check=lambda o, p: need(o, "ok", "candidates"))

    # ---------- 应用 / 镜像 / 网络面（APK/IPA/ISO/接口/端口/网络/固件/复刻） ----------
    import gzip as _gzip
    import io as _io
    import struct as _st
    import tarfile as _tf
    import zipfile as _zf

    def _axml_min():
        """最小 AXML manifest（字符串池 + manifest/application 两层元素）。"""
        strs = ["manifest", "package", "com.e2e.t", "application", "name"]
        n = len(strs)
        offs, blob = [], b""
        for s in strs:
            offs.append(len(blob))   # offsets 必须逐串累加真实字节偏移
            blob += _st.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
        while len(blob) % 4:
            blob += b"\x00"
        start = 28 + 4 * n
        pool = _st.pack("<HHI", 0x0001, 28, start + len(blob)) + \
            _st.pack("<IIIII", n, 0, 0, start, 0) + \
            b"".join(_st.pack("<I", o) for o in offs) + blob

        def el(kind, name_i, attrs):
            if kind == 0x0102:
                body = _st.pack("<IIHHHHHH", 0xFFFFFFFF, name_i, 20, 20, len(attrs),
                                0, 0, 0) + b"".join(attrs)
            else:
                body = _st.pack("<II", 0xFFFFFFFF, name_i)
            return _st.pack("<HHI", kind, 0x10, 16 + len(body)) + b"\x00" * 8 + body

        def at(name_i, val_i):
            return _st.pack("<IIIHBBI", 0xFFFFFFFF, name_i, val_i, 8, 0, 0x03, val_i)

        c = el(0x0102, 0, [at(1, 2)])            # <manifest package=...>
        c += el(0x0102, 3, [at(4, 2)])           # <application name=...>
        c += el(0x0103, 3, [])                   # </application>
        c += el(0x0103, 0, [])                   # </manifest>
        return _st.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(c)) + pool + c

    apk_f = os.path.join(RPT, "e2e.apk")
    with _zf.ZipFile(apk_f, "w") as zf:
        zf.writestr("AndroidManifest.xml", _axml_min())
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    ipa_f = os.path.join(RPT, "e2e.ipa")
    import plistlib as _pl
    with _zf.ZipFile(ipa_f, "w") as zf:
        zf.writestr("Payload/T.app/Info.plist", _pl.dumps(
            {"CFBundleIdentifier": "com.e2e.t", "CFBundleExecutable": "T",
             "MinimumOSVersion": "14.0"}))
    # ISO9660 最小镜像（PVD + 根目录 + 一个文件）
    iso_f = os.path.join(RPT, "e2e.iso")

    def _b32(v):
        return _st.pack("<I", v) + _st.pack(">I", v)

    def _b16(v):
        return _st.pack("<H", v) + _st.pack(">H", v)

    def _drec(name, lba, size, isdir):
        nb = len(name)
        rl = 33 + nb + ((33 + nb) % 2)
        b = bytearray(rl)
        b[0] = rl
        b[2:10] = _b32(lba)
        b[10:18] = _b32(size)
        b[25] = 0x02 if isdir else 0
        b[28:32] = _b16(1)
        b[32] = nb
        b[33:33 + nb] = name
        return bytes(b)

    SECT, nsec = 2048, 24
    img = bytearray(nsec * SECT)
    pvd = bytearray(SECT)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[40:46] = b"E2EISO"
    pvd[80:88] = _b32(nsec)
    pvd[120:124] = _b16(1)
    pvd[128:132] = _b16(SECT)
    rr = _drec(b"\x00", 20, SECT, True)
    pvd[156:156 + len(rr)] = rr
    img[16 * SECT:17 * SECT] = pvd
    term = bytearray(SECT)
    term[0] = 255
    term[1:6] = b"CD001"
    img[17 * SECT:18 * SECT] = term
    dird = bytearray(SECT)
    pos = 0
    for nm, lba, sz, dd in [(b"\x00", 20, SECT, True), (b"\x01", 20, SECT, True),
                            (b"F.TXT;1", 21, 3, False)]:
        r = _drec(nm, lba, sz, dd)
        dird[pos:pos + len(r)] = r
        pos += len(r)
    img[20 * SECT:21 * SECT] = dird
    img[21 * SECT:21 * SECT + 3] = b"e2e"
    with open(iso_f, "wb") as f:
        f.write(bytes(img))
    # 固件（内嵌 gzip + tar）
    fw_f = os.path.join(RPT, "e2e_fw.bin")
    bio = _io.BytesIO()
    with _tf.open(fileobj=bio, mode="w") as tf:
        ti = _tf.TarInfo("x.txt")
        ti.size = 2
        tf.addfile(ti, _io.BytesIO(b"ok"))
    with open(fw_f, "wb") as f:
        f.write(b"\x00" * 128 + _gzip.compress(b"z" * 40) + bio.getvalue())
    # 复刻源树
    tree = os.path.join(RPT, "e2e_tree")
    os.makedirs(os.path.join(tree, "sub"), exist_ok=True)
    with open(os.path.join(tree, "sub", "f.bin"), "wb") as f:
        f.write(b"\x01\x02")

    def _uleb(v):
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _dex_full():
        """全表 DEX（class_data + code_item + invoke）—— stub DEX 进不了方法级。"""
        strs = ["Lcom/example/t;", "V", "init", "Landroid/util/Log;", "d",
                "Ljava/lang/String;", "I", "https://api.example.com/x",
                "Ldemo/Api;", "call", "IL", "helper"]
        T_MAIN, T_VOID, T_LOG, T_STR, T_INT, T_API = range(6)
        types = [0, 1, 3, 5, 6, 8]
        protos = [(1, T_VOID, 0), (10, T_INT, [T_STR, T_STR])]
        methods = [(T_MAIN, 0, 2), (T_LOG, 1, 4), (T_API, 0, 9), (T_MAIN, 0, 11)]

        def sitem(s):
            return _uleb(len(s)) + s.encode("utf-8") + b"\x00"

        hdr = 0x70
        sio, tio = hdr, hdr + 4 * len(strs)
        pio, mio = tio + 4 * len(types), tio + 4 * len(types) + 12 * len(protos)
        cio = mio + 8 * len(methods)
        cur = cio + 32
        tlo = cur
        tl = _st.pack("<I", 2) + _st.pack("<HH", T_STR, T_STR)
        cur += len(tl)
        insns = [0x001A, 0x0007, 0x2071, 0x0001, 0x0000,
                 0x0071, 0x0002, 0x0000, 0x000E]
        codeo = cur
        code = (_st.pack("<HHHH", 3, 1, 2, 0) + _st.pack("<II", 0, len(insns)) +
                b"".join(_st.pack("<H", u) for u in insns))
        cur += len(code)
        cdo = cur
        cd = (_uleb(0) + _uleb(0) + _uleb(2) + _uleb(0) +
              _uleb(0) + _uleb(0x10001) + _uleb(codeo) +
              _uleb(3) + _uleb(0x2) + _uleb(0))
        cur += len(cd)
        sd = b"".join(sitem(s) for s in strs)
        fs = cur + len(sd)
        out = bytearray(fs)
        out[0:8] = b"dex\n035\x00"
        for off, val in ((32, fs), (36, 0x70), (40, 0x12345678),
                         (56, len(strs)), (60, sio), (64, len(types)), (68, tio),
                         (72, len(protos)), (76, pio), (80, 0), (84, mio),
                         (88, len(methods)), (92, mio), (96, 1), (100, cio),
                         (104, fs - hdr), (108, hdr)):
            _st.pack_into("<I", out, off, val)

        def put(o, blob):
            out[o:o + len(blob)] = blob

        o = cur
        for i, s in enumerate(strs):
            put(sio + 4 * i, _st.pack("<I", o))
            o += len(sitem(s))
        for i, t in enumerate(types):
            put(tio + 4 * i, _st.pack("<I", t))
        for i, (sh, ret, par) in enumerate(protos):
            put(pio + 12 * i,
                _st.pack("<III", sh, ret, tlo if par else 0))
        for i, (c, p_, n) in enumerate(methods):
            put(mio + 8 * i, _st.pack("<HHI", c, p_, n))
        put(cio, _st.pack("<IIIIIIII", T_MAIN, 0x1, 0xFFFFFFFF, 0,
                          0xFFFFFFFF, 0, cdo, 0))
        put(tlo, tl)
        put(codeo, code)
        put(cdo, cd)
        put(cur, sd)
        return bytes(out)

    dex_full_f = os.path.join(RPT, "e2e_full.dex")
    with open(dex_full_f, "wb") as f:
        f.write(_dex_full())

    case("apk(APK 逆向)", ["apk", apk_f, "--json"],
         check=lambda o, p: need(o, "ok", "manifest", "dex") or
         (None if o["manifest"].get("package") == "com.e2e.t" else "包名不对"))
    case("dexmap(DEX 方法级接口地图)", ["dexmap", dex_full_f, "--json"],
         check=lambda o, p: need(o, "ok", "api_surface", "totals", "jni") or
         (None if any("Log;->d" in m["ref"] for e in o["api_surface"]
                      for m in e["methods"]) else "api_surface 漏报外部调用"))
    case("ipa(IPA 逆向)", ["ipa", ipa_f, "--json"],
         check=lambda o, p: need(o, "ok", "info_plist") or
         (None if o["info_plist"].get("bundle_id") == "com.e2e.t" else "bundle 不对"))
    case("iso(镜像清单)", ["iso", iso_f, "--json"],
         check=lambda o, p: need(o, "ok", "entries") or
         (None if any(e["path"] == "F.TXT" for e in o["entries"]) else "目录项漏"))
    iso_out = os.path.join(RPT, "e2e_iso_out")
    case("iso(提取)", ["iso", iso_f, "--extract", iso_out, "--json"],
         check=lambda o, p: need(o, "ok", "extracted"))
    case("endpoints(应用内接口)", ["endpoints", exe, "--json"],
         check=lambda o, p: need(o, "ok", "counts"))
    case("ports(端口接口)", ["ports", exe, "--json"],
         check=lambda o, p: need(o, "ok", "counts", "explicit_ports", "derived_ports"))
    case("netaddr(网络地址)", ["netaddr", exe, "--json"],
         check=lambda o, p: need(o, "ok", "counts", "urls", "ipv4", "domains"))
    case("fsx(固件扫描)", ["fsx", fw_f, "--json"],
         check=lambda o, p: need(o, "ok", "hits") or
         (None if any(h["key"] == "gzip" for h in o["hits"]) else "gzip 漏报"))
    fx_out = os.path.join(RPT, "e2e_fsx_out")
    case("fsx(嵌入提取)", ["fsx", fw_f, "--extract", fx_out, "--json"],
         check=lambda o, p: need(o, "ok", "extracted"))
    case("replica(确定性清单)", ["replica", tree, "--json"],
         check=lambda o, p: need(o, "ok", "manifest", "tree_sha256"))
    rep_tar = os.path.join(RPT, "e2e_replica.tar")
    case("replica(复刻打包)", ["replica", tree, "--build", rep_tar, "--json"],
         check=lambda o, p: need(o, "ok", "out_sha256"))

    print("=" * 72)
    for n, m in FAIL:
        print("FAIL  %-32s %s" % (n, m))
    print("=" * 72)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
