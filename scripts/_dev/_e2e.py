# -*- coding: utf-8 -*-
"""端到端功能测试：把 26 个子命令全部在真实样本上跑一遍。

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


def run(args, expect_rc=(0,), timeout=180):
    p = subprocess.run([PY, RE] + args, cwd=SCRIPTS,
                       capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return p


def case(name, args, expect_rc=(0,), need_json=True, check=None,
         timeout=180):
    try:
        p = run(args, expect_rc, timeout)
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
    """断言 dict 里这些键都在（支持 'a.b' 形式）。"""
    cur = obj
    for k in keys:
        for part in k.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return "缺字段 %s" % k
            cur = cur[part]
    return None


def samples():
    """挑真实样本。优先系统自带文件，避免依赖外部下载。"""
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
        print("！缺少 PE 样本，无法继续；请在有 System32 的机器上跑")
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
    def _report_fallback_ok(o, p):
        if not isinstance(o, dict):
            return "顶层不是对象"
        if not o.get("ok"):
            return "降级路径下 ok 不为 true"
        if not o.get("writable_fallback"):
            return "未标出 writable_fallback（静默换位置＝假成功）"
        if not o.get("note"):
            return "缺少 note 说明降级原因"
        return None

    case("report(受保护目录降级)", ["report", exe, "--json"],
         check=_report_fallback_ok, timeout=300)

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

    print("=" * 72)
    for n, m in FAIL:
        print("FAIL  %-32s %s" % (n, m))
    print("=" * 72)
    print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
