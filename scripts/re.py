# -*- coding: utf-8 -*-
"""
re.py —— 逆向工程工具箱 CLI（Reverse Engineering Toolkit）

设计约定（AI 调用时请遵守）：
  1. 一律加 --json 读取结构化输出；人类可读输出只用于给人看。
  2. stdout 只放数据；提示、警告、错误说明走 stderr。
  3. 退出码：0 成功 / 2 用法错误 / 3 目标不可读 / 4 分析过程出错。
     --json 模式下错误也会输出一个 {"ok": false, ...} 的 JSON 到 stdout，便于程序判断。
  4. 路径用正斜杠；含空格必须加引号。

子命令：
  doctor    探测本机可用工具链
  identify  识别文件类型与架构（含结构解析）
  strings   流式提取字符串（可按类别/正则过滤）
  entropy   整体熵 + 分块熵曲线（定位加密/压缩段）
  imports   导入表 / 依赖库（行为地图）
  info      按格式深度解析
  triage    一站式初筛（识别+熵+字符串+IOC+加壳判断）
  carve     按魔数雕刻嵌入文件
  diff      两文件字节级差分
  plan      生成下一步分析计划
  report    生成 Markdown 分析报告
  magic     魔数速查
  disasm    反汇编（x86/x64/ARM64/Thumb）
  funcs     函数识别 + 指纹 + XREF（把字节变成函数）
  cfg       单个函数的控制流图
  xref      交叉引用（谁调用了谁）
  sim       两份二进制的函数级差分比对
  semantics 函数级语义摘要（调了什么 API / 什么行为）
  capability 能力识别（capa 风格规则库 → 行为结论 + ATT&CK）
  symbols   符号恢复（C++/MSVC/Rust demangle + Go pclntab）
  obfstr    混淆字符串恢复（栈字符串 + XOR 解密循环）
  require   按自然语言意图检索该用哪些子命令（AI 选路入口）
  flow      分阶段工作流编排：现在该跑哪些（可并行的同批给出）
  case      分析状态目录：结果落盘、复用、过期检测
  result    结果摘要 + 错误分类（防 AI 无效重试）
  toolgraph 工具转移图：这个跑完之后该跑哪个
"""

# 【维护提醒】上面的子命令清单就是 --help 的 epilog，必须与 add_parser()
# 的真实注册列表保持同步。曾经漏掉 semantics / capability 两条 ——
# 于是 --help 里看不到它们，用户根本不知道有这两个能力（文档漏报）。
# selftest 的 t_cli_help_covers_all_subcommands 会守住这条不变量。

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lib_analyze as A          # noqa: E402
import lib_formats as F          # noqa: E402
import lib_tools as T            # noqa: E402
import lib_disasm as D           # noqa: E402
import lib_names as N            # noqa: E402
import lib_obfstr as OS          # noqa: E402
import lib_agent as AG           # noqa: E402

EXIT_OK, EXIT_USAGE, EXIT_TARGET, EXIT_RUNTIME = 0, 2, 3, 4
VERSION = "1.3.3"


# ---------------------------------------------------------------- 输出

def emit(data, as_json: bool, indent: int = 2):
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=indent, default=str))
    return data


def fail(msg: str, code: int, as_json: bool, extra: dict | None = None):
    payload = {"ok": False, "error": msg}
    if extra:
        payload.update(extra)
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(code)


def need_path(p: str, as_json: bool):
    if not os.path.exists(p):
        fail(f"目标不存在：{p}", EXIT_TARGET, as_json)
    if os.path.isdir(p):
        fail(f"目标是目录不是文件：{p}", EXIT_TARGET, as_json)


# ---------------------------------------------------------------- 人类可读格式化

def _fmt_ident(d: dict) -> str:
    L = []
    L.append(f"文件    : {d.get('basename')}")
    L.append(f"路径    : {d.get('path')}")
    L.append(f"大小    : {d.get('size', 0):,} 字节")
    L.append(f"格式    : {d.get('format')}  ({d.get('label')})  置信度 {d.get('confidence')}")
    L.append(f"魔数    : {d.get('magic_hex')}  |{d.get('magic_ascii')}|")
    if d.get("arch"):
        L.append(f"架构    : {d.get('arch')} {d.get('bits') or ''}位 {d.get('endian') or ''}")
    det = d.get("detail") or {}
    if det.get("parse_ok"):
        for k in ("file_kind", "subsystem", "elf_type", "filetype", "dex_version",
                  "subtype", "python_version", "wasm_version"):
            if det.get(k):
                L.append(f"类型    : {det[k]}")
    for n in d.get("notes", []):
        L.append(f"提示    : {n}")
    det = d.get("detail") or {}
    if det.get("packer_signals"):
        L.append("加壳线索:")
        for s in det["packer_signals"]:
            L.append(f"  - {s}")
    if det.get("sections"):
        L.append("节表（前 12 个，熵 ≥7 通常意味着压缩/加密）:")
        L.append(f"  {'名称':<12}{'虚拟大小':>12}{'原始大小':>12}{'熵':>8}  属性")
        for s in det["sections"][:12]:
            L.append(f"  {s.get('name', '')[:12]:<12}{s.get('virtual_size', 0):>12,}"
                     f"{s.get('raw_size', 0):>12,}{s.get('entropy', 0):>8.2f}  "
                     f"{','.join(s.get('chars', [])[:3]) if s.get('chars') else ''}")
    if det.get("errors"):
        L.append(f"解析异常: {det['errors']}")
    return "\n".join(L)


def _fmt_strings(d: dict) -> str:
    L = [f"提取 {d.get('count')} 条（最小长度 {d.get('min_len')}，扫描 {d.get('scanned_bytes', 0):,} 字节，"
         f"耗时 {d.get('scan_seconds')}s）"]
    if d.get("truncated"):
        L.append(f"！已达上限 {d.get('max_items')} 条，结果被截断（用 --max-items 调大或加 --pattern 过滤）")
    if d.get("timed_out"):
        L.append("！触发时间预算，提前停止")
    if d.get("categories"):
        L.append("类别统计: " + "  ".join(f"{k}={v}" for k, v in d["categories"].items()))
    L.append("")
    for it in d.get("items", [])[:200]:
        cat = f"[{it['category']}] " if it.get("category") else ""
        L.append(f"0x{it['offset']:08X} {it['encoding']:<8}{cat}{it['value'][:160]}")
    if len(d.get("items", [])) > 200:
        L.append(f"... 还有 {len(d['items']) - 200} 条（加 --json 可拿到全量）")
    return "\n".join(L)


def _fmt_plan(d: dict) -> str:
    L = [f"目标    : {d.get('target')}",
         f"路由    : {d.get('format')} → {d.get('route')}   目标导向: {d.get('goal')}",
         f"关键洞察: {d.get('key_insight')}",
         f"方针    : {d.get('goal_tip')}", ""]
    # 加速层排在主流程之前：它的作用就是先砍掉工作量，做完再看需不需要走完整流程
    if d.get("accel"):
        L.append("⚡ 加速层（先做这些，投入产出比最高）:")
        for s in d["accel"]:
            L.append(f"■ {s['stage']}｜{s['title']}")
            for c in s["commands"]:
                L.append(f"    $ {c}")
            L.append(f"    · {s['note']}")
        L.append("")
    L.append("主流程:")
    for s in d.get("steps", []):
        L.append(f"■ {s['stage']}｜{s['title']}")
        for c in s["commands"]:
            L.append(f"    $ {c}")
        L.append(f"    · {s['note']}")
    if d.get("install_hints"):
        L.append("")
        L.append("建议补齐的工具（本机缺失）:")
        for h in d["install_hints"]:
            L.append(f"  - {h['cmd']}：{h['desc']}  {h['url']}")
    return "\n".join(L)


def _fmt_doctor(d: dict) -> str:
    L = [f"系统    : {d.get('platform')}",
         f"Python  : {d.get('python')}  ({d.get('python_exe')})",
         f"工具    : {d.get('present_count')}/{d.get('tool_count')} 可用", ""]
    L.append("可用工具:")
    by_cat: dict[str, list] = {}
    for t in d.get("present", []):
        by_cat.setdefault(t["cat"], []).append(t["cmd"])
    for cat, cmds in sorted(by_cat.items()):
        L.append(f"  [{cat}] {', '.join(cmds)}")
    L.append("")
    mods = ", ".join(m["module"] for m in d.get("python_modules", []) if m["available"])
    L.append("可用 Python 模块:")
    L.append("  " + (mods if mods else "（无；可选装 pefile/capstone/angr/androguard 等增强能力）"))
    L.append("")

    # 环境变量：AI 辅助层与 Java 系工具的启用前提
    L.append("关键环境变量:")
    any_env = False
    for e in d.get("env_probes", []):
        state = "已设置" if e.get("dir_exists") else ("值无效" if e.get("value") else "未设置")
        L.append(f"  {e['name']:<20} {state:<6} {e['desc']}")
        any_env = True
    if not any_env:
        L.append("  （无）")
    L.append("")

    # AI 辅助层：能否让 LLM 直接驾驶反编译器
    L.append(f"AI 辅助层: {d.get('ai_ready_count', 0)}/{len(d.get('ai_stack', []))} 就绪")
    for a in d.get("ai_stack", []):
        mark = "[就绪] " if a.get("ready") else "[待配] "
        L.append(f"  {mark}{a['id']}: {a['desc']}")
        L.append(f"           {a['how']}  {a['url']}")
    L.append("")
    L.append(f"说明    : {d.get('note')}")
    return "\n".join(L)


def _fmt_entropy(d: dict) -> str:
    L = [f"大小    : {d.get('size'):,} 字节   窗口 {d.get('window')}",
         f"整体熵  : {d.get('overall_entropy')}" + ("（采样估算）" if d.get("sampled") else "")]
    for k in ("null_byte_ratio", "printable_ratio"):
        if d.get(k) is not None:
            L.append(f"{k:<18}: {d[k]}")
    if d.get("high_entropy_regions"):
        L.append("高熵区段（≥7.0，压缩/加密嫌疑）:")
        for r in d["high_entropy_regions"]:
            L.append(f"  0x{r['start']:08X} – 0x{r['end']:08X}  ({(r['end'] - r['start']) / 1024:.1f}KB, {r['windows']} 窗口)")
    else:
        L.append("高熵区段: 无")
    L.append("熵曲线（offset: entropy）:")
    line = []
    for w in d.get("windows", [])[:64]:
        line.append(f"0x{w['offset']:06X}:{w['entropy']:.2f}")
    L.append("  " + "  ".join(line))
    return "\n".join(L)


# ---------------------------------------------------------------- 子命令


def cmd_doctor(args):
    d = T.doctor()
    d["ok"] = True
    if not args.json:
        print(_fmt_doctor(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_identify(args):
    need_path(args.target, args.json)
    if args.max_parse_size:
        F.MAX_PARSE_SIZE = args.max_parse_size
    d = F.identify(args.target, deep=not args.no_deep)
    d["ok"] = True
    if not args.json:
        print(_fmt_ident(d))
        return EXIT_OK
    if args.compact:
        # 精简视图：给 AI 快速判断用，去掉大字段
        for k in ("strings_sample", "dynamic_symbols_sample", "symbols_sample",
                  "entries_sample", "sections", "resources_sample"):
            det = d.get("detail")
            if isinstance(det, dict) and k in det:
                v = det[k]
                det[k] = v[:20] if isinstance(v, list) else v
    emit(d, True)
    return EXIT_OK


def cmd_strings(args):
    need_path(args.target, args.json)
    encs = tuple(args.encoding.split(","))
    d = A.scan_strings(args.target, min_len=args.min, encodings=encs,
                       max_items=args.max_items, pattern=args.pattern,
                       dedupe=args.dedupe, budget_seconds=args.budget_seconds,
                       categorize=not args.no_categorize)
    d["ok"] = not d.get("error")
    if args.categories_only:
        d.pop("items", None)
        if not args.json:
            print("类别统计: " + "  ".join(f"{k}={v}" for k, v in (d.get("categories") or {}).items()))
            return EXIT_OK
        emit(d, True)
        return EXIT_OK
    if not args.json:
        print(_fmt_strings(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_entropy(args):
    need_path(args.target, args.json)
    d = A.entropy_profile(args.target, window=args.window, max_windows=args.max_windows)
    d["ok"] = True
    if not args.json:
        print(_fmt_entropy(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_imports(args):
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    det = ident.get("detail") or {}
    out: dict = {"path": args.target, "format": ident.get("format"), "ok": True}
    if det.get("parser") == "pe":
        out["kind"] = "PE 导入表"
        out["modules"] = [{"dll": m["dll"], "count": m["count"],
                           "functions": ([f["name"] for f in m["functions"]] if args.full else
                                         [f["name"] for f in m["functions"]][:40])}
                          for m in det.get("imports", [])]
        out["module_count"] = det.get("import_module_count")
        out["function_count"] = det.get("import_function_count")
        if det.get("exports"):
            out["exports"] = det["exports"][:200]
    elif det.get("parser") == "elf":
        out["kind"] = "ELF 动态依赖"
        out["needed"] = det.get("needed")
        out["soname"] = det.get("soname")
        out["is_static"] = det.get("is_static")
        out["dynamic_symbols"] = det.get("dynamic_symbols_sample", [])[:400]
        out["dynamic_symbol_count"] = det.get("dynamic_symbol_count")
        out["checksec"] = det.get("checksec")
    elif det.get("parser") == "macho":
        out["kind"] = "Mach-O 依赖库"
        out["dylibs"] = det.get("dylibs")
        out["rpaths"] = det.get("rpaths")
        out["symbols"] = (det.get("symbols_sample") or [])[:400]
    else:
        out["kind"] = "无导入表（该格式不适用）"
        out["note"] = "可用 strings 看引用的库名/函数名作为替代线索"
    if not args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return EXIT_OK
    emit(out, True)
    return EXIT_OK


def cmd_info(args):
    need_path(args.target, args.json)
    if args.max_parse_size:
        F.MAX_PARSE_SIZE = args.max_parse_size
    d = F.identify(args.target, deep=True)
    d["ok"] = True
    if not args.json:
        print(_fmt_ident(d))
        det = d.get("detail") or {}
        if det.get("parse_ok"):
            print("\n----- 结构详情 -----")
            for k, v in det.items():
                if k in ("sections", "segments", "strings_sample", "classes_sample",
                         "dynamic_symbols_sample", "symbols_sample", "entries_sample",
                         "resources_sample", "native_libs", "assets", "imports", "exports"):
                    continue
                if isinstance(v, (list, dict)) and len(str(v)) > 400:
                    v = str(v)[:400] + " ..."
                print(f"{k:<28}: {v}")
            print("\n（完整结构请加 --json）")
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_disasm(args):
    """反汇编：默认取最大可执行区起始处的一段。"""
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    d = D.disasm_file(args.target, ident, region=args.section,
                      base_vma=args.base, offset=args.offset,
                      length=args.length, max_insns=args.max_insns)
    d["ok"] = d.get("ok", False)
    if not d["ok"]:
        if args.json:
            emit(d, True)
            return EXIT_RUNTIME
        fail(d.get("error", "反汇编失败"), EXIT_RUNTIME, args.json)
    if not args.json:
        print(_fmt_disasm(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_funcs(args):
    """函数识别 + 指纹 + 交叉引用统计。"""
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    d = D.analyze_file(args.target, ident, region=args.section,
                       max_insns=args.max_insns)
    d.pop("_idx", None)
    d["ok"] = d.get("ok", False)
    if not d["ok"]:
        if args.json:
            emit(d, True)
            return EXIT_RUNTIME
        fail(d.get("error", "分析失败"), EXIT_RUNTIME, args.json)
    if not args.json:
        print(_fmt_funcs(d, args.top))
        return EXIT_OK
    if args.summary:
        d.pop("functions", None)
    elif args.top:
        d["functions"] = d.get("functions", [])[:args.top]
    emit(d, True)
    return EXIT_OK


def cmd_cfg(args):
    """单个函数的控制流图。"""
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    d = D.cfg_of(args.target, ident, target=args.addr)
    d["ok"] = d.get("ok", False)
    if not args.json:
        if not d["ok"]:
            print("失败：" + str(d.get("error")))
            return EXIT_RUNTIME
        print(_fmt_cfg(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK if d["ok"] else EXIT_RUNTIME


def cmd_xref(args):
    """交叉引用：谁调用了谁。"""
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    d = D.analyze_file(args.target, ident, region=args.section)
    d.pop("_idx", None)
    if not d.get("ok"):
        if args.json:
            emit(d, True)
            return EXIT_RUNTIME
        fail(d.get("error", "分析失败"), EXIT_RUNTIME, args.json)
    x = d.get("xrefs", {})
    if args.addr:
        key = args.addr.lower()
        key = key if key.startswith("0x") else "0x" + key
        callers = x.get("callers", {}).get(key, [])
        callees = x.get("callees", {}).get(key, [])
        out = {"ok": True, "target": key, "callers": callers, "callees": callees}
        if not args.json:
            print(f"地址 {key}")
            print(f"  被调用（callers）: {', '.join(callers) or '（无）'}")
            print(f"  调用  （callees）: {', '.join(callees) or '（无）'}")
            return EXIT_OK
        emit(out, True)
        return EXIT_OK
    if not args.json:
        print(_fmt_xref(d))
        return EXIT_OK
    emit({"ok": True, "function_count": d.get("function_count"),
          "caller_count": x.get("caller_count"), "xrefs": x}, True)
    return EXIT_OK


def cmd_sim(args):
    """两份二进制的函数级相似度比对（差分分析）。"""
    need_path(args.a, args.json)
    need_path(args.b, args.json)
    from lib_code import match_functions
    ia, ib = F.identify(args.a, deep=True), F.identify(args.b, deep=True)
    ra = D.analyze_file(args.a, ia)
    rb = D.analyze_file(args.b, ib)
    ra.pop("_idx", None)
    rb.pop("_idx", None)
    if not ra.get("ok") or not rb.get("ok"):
        msg = ra.get("error") or rb.get("error") or "分析失败"
        if args.json:
            emit({"ok": False, "error": msg}, True)
            return EXIT_RUNTIME
        fail(msg, EXIT_RUNTIME, args.json)
    res = match_functions(ra["functions"], rb["functions"],
                          threshold=args.threshold)
    res["ok"] = True
    res["a"] = args.a
    res["b"] = args.b
    res["threshold"] = args.threshold
    if not args.json:
        print(_fmt_sim(res))
        return EXIT_OK
    emit(res, True)
    return EXIT_OK


def _fmt_disasm(d: dict) -> str:
    L = []
    L.append(f"目标    : {d.get('path')}")
    L.append(f"代码区  : {d.get('region')}  [{d.get('arch')}]  基址 {d.get('base_vma')}")
    L.append(f"范围    : 文件偏移 {d.get('file_offset')}  共 {d.get('bytes')} 字节")
    L.append(f"指令数  : {d.get('insn_count')}   非法指令 {d.get('invalid_count')}")
    L.append("")
    for i in d.get("insns", []):
        tgt = f"  ; -> {i['target']}" if i.get("target") else ""
        L.append(f"  {i['vma']:>18}  {i['bytes']:<20} {i['mnem']} {i['ops']}{tgt}".rstrip())
    return "\n".join(L)


def _fmt_funcs(d: dict, top: int = 0) -> str:
    L = []
    L.append(f"目标    : {d.get('path')}  [{d.get('arch')}]  代码区 {d.get('region')}")
    L.append(f"基址    : {d.get('base_vma')}   入口点 {', '.join(d.get('entry_points', [])) or '（无）'}")
    L.append(f"解码指令: {d.get('decoded_insns')}   覆盖 {d.get('coverage')}")
    L.append(f"函数数  : {d.get('function_count')}   调用边 {d.get('call_count')}"
             f"   XREF 入口 {d.get('xrefs', {}).get('caller_count')}")
    if d.get("truncated"):
        L.append("!! 达到指令预算上限，结果不完整（提高 --max-insns 或指定 --section）")
        L.append("   上面「函数数 / 覆盖」只统计已解码的片段，不代表整个代码区。")
    L.append("")
    fs = d.get("functions", [])
    if top:
        fs = fs[:top]
    L.append(f"{'入口':<18} {'结束':<18} {'指令':>5} {'块':>4} {'调用':>5}  名称")
    for f in fs:
        L.append(f"{f['start_vma']:<18} {f['end_vma']:<18} "
                 f"{f['insn_count']:>5} {f['bb_count']:>4} {len(f['calls']):>5}  {f['name']}")
    return "\n".join(L)


def _fmt_cfg(d: dict) -> str:
    L = []
    L.append(f"函数    : {d.get('function')}  {d.get('start_vma')} - {d.get('end_vma')}")
    L.append(f"基本块  : {d.get('block_count')}   边 {d.get('edge_count')}")
    L.append("")
    L.append("  块:")
    for n in d.get("nodes", []):
        L.append(f"    #{n['id']:<3} {n['start_vma']} - {n['end_vma']}  ({n['insn_count']} 条)")
    L.append("")
    L.append("  边:")
    for e in d.get("edges", []):
        if e["type"] == "call":
            L.append(f"    #{e['from']} --call--> {e.get('target_vma')} (外部)")
        else:
            L.append(f"    #{e['from']} --{e['type']}--> #{e['to']}")
    return "\n".join(L)


def _fmt_xref(d: dict) -> str:
    x = d.get("xrefs", {})
    L = [f"函数总数: {d.get('function_count')}   被调用方入口: {x.get('caller_count')}", ""]
    L.append("被引用最多的目标（callers 数量 Top）:")
    items = sorted(((k, len(v)) for k, v in x.get("callers", {}).items()),
                   key=lambda t: -t[1])[:20]
    for k, n in items:
        who = ", ".join(x["callers"][k][:5])
        L.append(f"  {k:<20} 被 {n} 处调用   调用者: {who}")
    return "\n".join(L)


def _fmt_sim(d: dict) -> str:
    L = []
    L.append(f"A: {d.get('a')}  ({d.get('total_a')} 个函数)")
    L.append(f"B: {d.get('b')}  ({d.get('total_b')} 个函数)")
    L.append(f"匹配    : {d.get('matched')}   相似度阈值 {d.get('threshold', '')}")
    L.append(f"匹配率  : A {d.get('match_rate_a')}   B {d.get('match_rate_b')}"
             f"   比较次数 {d.get('comparisons')}")
    L.append("")
    L.append(f"{'A 地址':<20} {'B 地址':<20} {'分数':>7}  A 名称 -> B 名称")
    for m in d.get("matches", [])[:30]:
        L.append(f"{m['a']:<20} {m['b']:<20} {m['score']:>7}  "
                 f"{m['a_name']} -> {m['b_name']}")
    if d.get("unmatched_a"):
        L.append("")
        L.append(f"仅在 A 中出现（前 10）: {', '.join(d['unmatched_a'][:10])}")
    if d.get("unmatched_b"):
        L.append(f"仅在 B 中出现（前 10）: {', '.join(d['unmatched_b'][:10])}")
    return "\n".join(L)


def cmd_semantics(args):
    """函数级语义摘要：这个函数调了什么、在干什么、碰了哪些字符串。"""
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    res = D.analyze_file(args.target, ident, region=args.section,
                         max_insns=args.max_insns)
    if not res.get("ok"):
        if args.json:
            emit({"ok": False, "error": res.get("error")}, True)
            return EXIT_RUNTIME
        fail(res.get("error") or "分析失败", EXIT_RUNTIME, args.json)

    idx = res.pop("_idx", None)
    funcs = res.get("functions", [])
    from lib_code import find_functions
    if idx is not None and (not funcs or not funcs[0].get("_offs")):
        funcs = find_functions(idx, seeds=D.entry_points(ident),
                               symbols=D.symbols_from(ident))

    iat = D.resolve_iat(ident)
    str_map = {}
    if not args.no_strings:
        try:
            from lib_semantics import string_vma_map
            str_map = string_vma_map(args.target, ident)
        except Exception as e:                      # 字符串映射失败不该拖垮主流程
            str_map = {}
            res["_string_map_error"] = f"{type(e).__name__}: {e}"

    from lib_semantics import (summarize_functions, cluster_by_tag, CAT_ORDER,
                               resolve_thunks, tag_counts)
    thunks = resolve_thunks(idx, funcs, iat)
    sums = summarize_functions(idx, funcs, iat, str_map,
                               limit=args.limit, thunk_map=thunks)

    # 静态链接库函数 / 密码学常量识别：把 sub_140001234 认成 memset / AES…
    hints: dict[int, dict] = {}
    const_hits: list[dict] = []
    if not args.no_libscan:
        try:
            from lib_libscan import (scan_const_tables, identify_libfuncs,
                                     summarize_hints)
            const_hits = scan_const_tables(args.target, ident)
            hints = identify_libfuncs(idx, funcs, const_hits)
        except Exception as e:          # 识别失败不该拖垮主流程
            res["_libscan_error"] = f"{type(e).__name__}: {e}"
    if hints:
        from lib_semantics import _as_vma_int
        for s in sums:
            h = hints.get(_as_vma_int(s.get("start_vma")))
            if h:
                s["lib_hint"] = {k: v for k, v in h.items() if k != "start_vma"}

    out = {
        "ok": True,
        "path": args.target,
        "format": ident.get("format"),
        "arch": res.get("arch"),
        "region": res.get("region"),
        "iat_resolved": len(iat),
        "thunk_resolved": len(thunks),
        "string_map_size": len(str_map),
        "function_count": len(funcs),
        "analyzed": len(sums),
        "const_tables": [{"name": c["name"], "tag": c["tag"], "vma": hex(c["vma"])}
                         for c in const_hits],
        "lib_hints": summarize_hints(hints) if hints else [],
        "lib_hint_count": len(hints),
        "tag_clusters": cluster_by_tag(sums),
        "tag_counts": tag_counts(sums),
        "tag_order": list(CAT_ORDER),
        "functions": sums,
    }
    if res.get("_libscan_error"):
        out["warning"] = res["_libscan_error"]
    if args.tag:
        out["functions"] = [s for s in sums if args.tag in (s.get("tags") or [])]
        out["filtered_by_tag"] = args.tag
    if res.get("_string_map_error"):
        out["warning"] = res["_string_map_error"]
    if not args.json:
        print(_fmt_semantics(out))
        return EXIT_OK
    emit(out, True)
    return EXIT_OK


def _fmt_semantics(d: dict) -> str:
    L = []
    L.append(f"目标    : {d.get('path')}  [{d.get('arch')}]  代码区 {d.get('region')}")
    L.append(f"函数    : 识别 {d.get('function_count')} 个，已分析 {d.get('analyzed')} 个")
    L.append(f"IAT 解析: {d.get('iat_resolved')} 个导入函数，"
             f"{d.get('thunk_resolved')} 个跳板   字符串表 {d.get('string_map_size')} 条")
    if d.get("lib_hint_count"):
        L.append(f"库函数/算法识别: {d['lib_hint_count']} 个函数")
    if d.get("const_tables"):
        L.append("常量表（写死的算法指纹）:")
        for c in d["const_tables"][:8]:
            L.append(f"  {c['name']:<22} @{c['vma']}  [{c.get('tag') or '-'}]")
    if d.get("lib_hints"):
        L.append("识别出的家族:")
        for h in d["lib_hints"][:10]:
            L.append(f"  {h['name']:<26} {h['count']:>3} 个  置信度 {h['confidence']}")
    if d.get("filtered_by_tag"):
        L.append(f"过滤    : 只看标签 {d['filtered_by_tag']}")
    L.append("")
    L.append("按行为分组（找关键逻辑先看这里）:")
    counts = d.get("tag_counts") or {}
    for tag, addrs in (d.get("tag_clusters") or {}).items():
        n = counts.get(tag, len(addrs))     # 用真实计数，别把截断后的长度当总数
        L.append(f"  {tag:<10} {n:>4} 个  {', '.join(addrs[:6])}"
                 f"{' ...' if n > 6 else ''}")
    L.append("")
    L.append("函数语义:")
    for s in d.get("functions", [])[:40]:
        L.append(f"  {s['summary']}")
        if s.get("lib_hint"):
            h = s["lib_hint"]
            L.append(f"      识别: {h['name']}（置信度 {h['confidence']}：{h['reason']}）")
        if s.get("api_calls"):
            apis = ", ".join(f"{a['api']}×{a['count']}" if a["count"] > 1 else a["api"]
                             for a in s["api_calls"][:6])
            L.append(f"      API: {apis}")
        if s.get("strings"):
            L.append(f"      字符串: {' | '.join(repr(x) for x in s['strings'][:4])}")
    return "\n".join(L)


def cmd_triage(args):
    need_path(args.target, args.json)
    if args.max_parse_size:
        F.MAX_PARSE_SIZE = args.max_parse_size
    t0 = time.time()
    d = A.triage(args.target, min_len=args.min, max_strings=args.max_items,
                 pattern=args.pattern, budget_seconds=args.budget_seconds)
    d["ok"] = not bool((d.get("identify") or {}).get("errors"))
    d["total_seconds"] = round(time.time() - t0, 3)

    if not args.json:
        ident = d.get("identify", {})
        print(_fmt_ident(ident))
        print()
        print(_fmt_entropy(d.get("entropy", {})))
        print()
        pk = d.get("packer", {})
        print(f"加壳判断: {pk.get('level')}")
        for s in pk.get("signals", []):
            print(f"  - {s}")
        print()
        s = d.get("strings", {})
        print(f"字符串  : {s.get('count')} 条（{s.get('scan_seconds')}s）")
        if s.get("categories"):
            print("  " + "  ".join(f"{k}={v}" for k, v in s["categories"].items()))
        for cat, items in (d.get("leads") or {}).items():
            print(f"\n▸ {cat}（{len(items)}）")
            for it in items[:8]:
                print(f"    0x{it['offset']:08X}  {it['value'][:120]}")
        print(f"\n总耗时  : {d.get('total_seconds')}s")
        return EXIT_OK

    if args.no_strings:
        d.pop("strings", None)
    emit(d, True)
    return EXIT_OK


def cmd_carve(args):
    need_path(args.target, args.json)
    out_dir = args.out
    if out_dir and os.path.isfile(out_dir):
        fail("--out 必须是目录", EXIT_USAGE, args.json)
    d = A.carve(args.target, out_dir=out_dir, max_files=args.max_files,
                max_total=args.max_total, align=args.align)
    d["ok"] = not d.get("error")
    if not args.json:
        print(f"命中 {d.get('hit_count')} 处嵌入文件特征（扫描耗时 {d.get('seconds')}s）")
        for h in d.get("hits", [])[:80]:
            print(f"  0x{h['offset']:08X}  {h['key']:<12} {h['label']}")
        if d.get("extracted"):
            print(f"\n已落盘 {len(d['extracted'])} 个文件到 {out_dir}（共 {d.get('written_bytes'):,} 字节）")
            for e in d["extracted"][:40]:
                print(f"  {e['file']}  ({e['size']:,} 字节)")
        elif out_dir:
            print("\n（未提取到文件）")
        else:
            print("\n（只列清单未落盘；加 --out <目录> 才会写文件）")
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_diff(args):
    for p in (args.a, args.b):
        need_path(p, args.json)
    d = A.diff_files(args.a, args.b, block=args.block, max_ranges=args.max_ranges)
    d["ok"] = True
    if not args.json:
        print(f"A: {args.a} ({d['size_a']:,} 字节)")
        print(f"B: {args.b} ({d['size_b']:,} 字节)")
        print(f"大小差 : {d['size_delta']:+,}")
        print(f"相似度 : {d['similarity']}")
        print(f"差异字节: {d['changed_bytes']:,}")
        print(f"变更区间: {len(d['changed_ranges'])} 段")
        for r in d["changed_ranges"][:40]:
            print(f"  0x{r['start']:08X} – 0x{r['end']:08X}  ({r['end'] - r['start']:,} 字节)"
                  + (f"  {r['note']}" if r.get("note") else ""))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_plan(args):
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)
    tools = T.doctor() if not args.no_tools else None
    d = T.build_plan(ident, tools, goal=args.goal)
    d["ok"] = True
    if not args.json:
        print(_fmt_plan(d))
        return EXIT_OK
    emit(d, True)
    return EXIT_OK


def cmd_magic(args):
    if args.hex:
        hx = args.hex.replace(" ", "").replace("0x", "")
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            fail("十六进制格式不正确", EXIT_USAGE, args.json)
        hits = [m for m in F.MAGICS if raw.startswith(m["sig"]) or m["sig"].startswith(raw)]
    elif args.name:
        q = args.name.lower()
        hits = [m for m in F.MAGICS if q in m["label"].lower() or q in m["key"].lower()]
    else:
        hits = F.MAGICS
    out = {"ok": True, "count": len(hits),
           "entries": [{k: m[k] for k in ("key", "label", "cat")} |
                       {"sig_hex": m["sig"].hex(), "offset": m["off"]}
                       for m in hits]}
    if not args.json:
        for m in hits:
            print(f"{m['sig'].hex():<20} off={m['off']:<4} [{m['cat']:<8}] {m['label']}")
        return EXIT_OK
    emit(out, True)
    return EXIT_OK


def cmd_report(args):
    need_path(args.target, args.json)
    if args.max_parse_size:
        F.MAX_PARSE_SIZE = args.max_parse_size
    ident = F.identify(args.target, deep=True)
    ent = A.entropy_profile(args.target)
    st = A.scan_strings(args.target, min_len=args.min, max_items=args.max_items,
                        pattern=args.pattern)
    tools = T.doctor() if not args.no_tools else None
    plan = T.build_plan(ident, tools, goal=args.goal)
    packer = A.packer_verdict(ident, ent)

    md = render_report(args.target, ident, ent, st, plan, packer)
    fname = os.path.basename(args.target) + ".re-report.md"
    fallback = None

    if args.out:
        # 用户显式指定了位置 —— 不做任何自作主张的降级，写不进去就报错。
        out_path = args.out
        if os.path.isdir(out_path):
            out_path = os.path.join(out_path, fname)
        candidates = [out_path]
    else:
        # 【已修 bug 1】原先默认写 os.getcwd()。这看着合理，实则是个地雷：
        # selftest 用 cwd=scripts/ 跑 CLI，于是每次自检都会在**源码目录**里
        # 生成 <目标>.re-report.md —— 测试残留被当成发布内容（真实发生过）。
        #
        # 【已修 bug 2】改成"写目标文件旁边"后又发现新问题：目标是
        # C:/Windows/System32/notepad.exe 这类受保护目录里的文件时，旁边
        # 根本不可写，report 直接以退出码 4 失败 —— 用户一上手就踩到。
        #
        # 【不要用 os.access 预测可写性】Windows 上 os.access(dir, W_OK)
        # 只看只读属性位、**不查 ACL**，System32 会被判成"可写"但实写仍
        # EACCES —— 降级分支永远走不到。本项目最忌"预测成功、实际失败"，
        # 所以改为**真写一次**，失败再换下一个候选。
        beside = os.path.join(os.path.dirname(os.path.abspath(args.target)), fname)
        alt = os.path.join(os.getcwd(), fname)
        candidates = [beside]
        if os.path.abspath(beside) != os.path.abspath(alt):
            candidates.append(alt)

    out_path, written, err = candidates[0], False, None
    for idx, cand in enumerate(candidates):
        try:
            with open(cand, "w", encoding="utf-8") as f:
                f.write(md)
            out_path, written = cand, True
            if idx > 0:
                fallback = candidates[0]
            break
        except OSError as e:
            err = e

    if not written:
        hint = ("" if args.out else
                "；目标所在目录不可写，退到当前目录仍失败，"
                "请用 --out <目录> 显式指定可写位置")
        fail(f"报告写入失败：{err}{hint}", EXIT_RUNTIME, args.json)

    res = {"ok": True, "report": out_path, "bytes": len(md.encode("utf-8"))}
    if fallback:
        # 降级必须可见：否则 AI 会按预期路径去读文件却读到空 —— 那就是假成功。
        res["writable_fallback"] = fallback
        res["note"] = ("目标所在目录不可写，报告已改写到当前工作目录；"
                       "如需固定位置请用 --out 指定")
    if not args.json:
        print(f"报告已生成：{out_path}（{res['bytes']:,} 字节）")
        if fallback:
            print(f"！目标目录不可写，未能写到 {fallback}，已改到当前目录",
                  file=sys.stderr)
        return EXIT_OK
    emit(res, True)
    return EXIT_OK


def render_report(path, ident, ent, st, plan, packer) -> str:
    det = ident.get("detail") or {}
    L = []
    A_ = L.append
    A_(f"# 逆向初筛报告：{os.path.basename(path)}\n")
    A_(f"- 目标路径：`{path}`")
    A_(f"- 文件大小：{ident.get('size', 0):,} 字节")
    A_(f"- 报告生成：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    A_("")

    A_("## 1. 识别结论\n")
    A_(f"| 项 | 值 |\n|---|---|")
    A_(f"| 格式 | {ident.get('format')}（{ident.get('label')}） |")
    A_(f"| 置信度 | {ident.get('confidence')} |")
    A_(f"| 架构 | {ident.get('arch') or '-'} {ident.get('bits') or ''} 位 {ident.get('endian') or ''} |")
    A_(f"| 魔数 | `{ident.get('magic_hex')}` |")
    for k in ("file_kind", "subsystem", "elf_type", "filetype", "subtype",
              "python_version", "dex_version", "wasm_version"):
        if det.get(k):
            A_(f"| {k} | {det[k]} |")
    A_("")

    A_("## 2. 熵与加壳判断\n")
    A_(f"- 整体熵：**{ent.get('overall_entropy')}**（8.0 为上限；≥7.2 通常意味着整文件压缩/加密）")
    if ent.get("null_byte_ratio") is not None:
        A_(f"- 空字节占比：{ent['null_byte_ratio']}　可打印占比：{ent.get('printable_ratio')}")
    A_(f"- 加壳嫌疑等级：**{packer.get('level')}**")
    if packer.get("signals"):
        for s in packer["signals"]:
            A_(f"  - {s}")
    A_("")

    A_("## 3. 字符串线索\n")
    A_(f"共提取 {st.get('count')} 条（最小长度 {st.get('min_len')}，耗时 {st.get('scan_seconds')}s）\n")
    if st.get("categories"):
        A_("| 类别 | 数量 |\n|---|---|")
        for k, v in st["categories"].items():
            label = A.CATEGORY_LABELS.get(k, k)
            A_(f"| {label} | {v} |")
        A_("")
    leads = plan_leads(st)
    for cat, items in leads.items():
        A_(f"### {A.CATEGORY_LABELS.get(cat, cat)}\n")
        for it in items[:12]:
            A_(f"- `0x{it['offset']:08X}` {_md_escape(it['value'][:200])}")
        A_("")

    A_("## 4. 结构要点\n")
    if det.get("sections"):
        A_("| 节名 | 虚拟大小 | 原始大小 | 熵 |\n|---|---|---|---|")
        for s in det["sections"][:20]:
            A_(f"| {s.get('name', '')} | {s.get('virtual_size', 0):,} | {s.get('raw_size', 0):,} | {s.get('entropy', 0):.2f} |")
        A_("")
    if det.get("imports"):
        A_("主要导入模块：" + "、".join(f"{m['dll']}({m['count']})" for m in det["imports"][:24]))
        A_("")
    if det.get("needed"):
        A_("动态依赖：" + "、".join(det["needed"][:40]))
        A_("")
    if det.get("dylibs"):
        A_("依赖库：" + "、".join(det["dylibs"][:40]))
        A_("")
    if det.get("pdb_path"):
        A_(f"- PDB 路径（泄露源码目录）：`{det['pdb_path']}`")
    if det.get("checksec"):
        A_(f"- checksec：{json.dumps(det['checksec'], ensure_ascii=False)}")
    if det.get("apk"):
        apk = det["apk"]
        A_(f"- DEX：{len(apk.get('dex_files', []))} 个，合计 {apk.get('dex_total_size', 0):,} 字节")
        A_(f"- ABI：{', '.join(apk.get('abis', [])) or '-'}")
        if apk.get("packer_hits"):
            A_("- 加固特征命中：" + "、".join(f"{h['file']} → {h['vendor']}" for h in apk["packer_hits"]))
        if apk.get("packer_heuristic"):
            A_(f"- 启发式：{apk['packer_heuristic']}")
        if apk.get("manifest_strings", {}).get("permissions"):
            A_("- 权限（来自 Manifest 字符串池）：" + "、".join(apk["manifest_strings"]["permissions"][:40]))
        _ms = apk.get("manifest_strings", {})
        if _ms.get("_error"):
            A_(f"- ⚠️ Manifest 字符串池抽取失败（结果不可信）：{_ms['_error']}")
        elif _ms.get("_note"):
            A_(f"- 注：{_ms['_note']}")
    A_("")

    A_("## 5. 下一步计划\n")
    A_(f"> {plan.get('key_insight') or ''}\n")
    for s in plan.get("steps", []):
        A_(f"### {s['stage']}｜{s['title']}\n")
        for c in s["commands"]:
            A_(f"```bash\n{c}\n```")
        A_(f"{s['note']}\n")
    A_("")

    A_("## 6. 合规提醒\n")
    A_("- 只对**自己拥有或已书面授权**的目标做逆向；恶意样本必须在隔离环境分析。")
    A_("- 反编译产物、还原的源码、提取的密钥**一律不对外分发**。")
    A_("- 发现漏洞走正规渠道披露（CNCERT / CNNVD / 厂商 SRC / 甲方安全部门）。")
    A_("- 中国法域下，对加壳样本脱壳可能触及《计算机软件保护条例》第 24 条的"
      "「避开技术措施」认定，商业项目请勿赌这一解释。")
    return "\n".join(L)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _default_rules_dir() -> str:
    """规则目录默认在技能包根目录的 rules/ 下。"""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "rules")


def cmd_capability(args):
    """
    能力识别：用 capa 风格的规则库判断样本「能做什么」。

    这是把静态结构（导入表/字符串/指令）升级成**行为结论**的一步：
      triage 告诉你"有什么"，semantics 告诉你"每个函数在干什么"，
      capability 直接回答"这个样本具备哪些能力、对应哪些 ATT&CK 技术"。
    """
    need_path(args.target, args.json)
    from lib_rules import load_rules, build_features, match_rules

    rules_dir = args.rules or _default_rules_dir()
    rule_files = None
    if args.rule:
        # 指定单条/多条规则（按名字过滤），找不到就直说，不要静默少跑
        rule_files = [r.strip() for r in args.rule.split(",") if r.strip()]

    rules, rule_errs = load_rules(rules_dir)
    if not rules:
        fail(f"没有加载到任何规则（目录: {rules_dir}）", EXIT_RUNTIME, args.json,
             {"load_errors": rule_errs})
    if rule_files:
        want = set(rule_files)
        picked = [r for r in rules if r.name in want]
        missing = sorted(want - {r.name for r in picked})
        if missing:
            fail("规则不存在：%s" % ", ".join(missing), EXIT_USAGE, args.json,
                 {"available": sorted(r.name for r in rules)})
        rules = picked

    ident = F.identify(args.target, deep=True)
    res = D.analyze_file(args.target, ident, region=args.section,
                         max_insns=args.max_insns)
    if not res.get("ok"):
        fail(res.get("error") or "分析失败", EXIT_RUNTIME, args.json)

    idx = res.pop("_idx", None)
    funcs = res.get("functions", [])
    from lib_code import find_functions
    if idx is not None and (not funcs or not funcs[0].get("_offs")):
        funcs = find_functions(idx, seeds=D.entry_points(ident),
                               symbols=D.symbols_from(ident))

    iat = D.resolve_iat(ident)
    str_map: dict[int, str] = {}
    warnings: list[str] = []
    if not args.no_strings and idx is not None:
        try:
            from lib_semantics import string_vma_map
            str_map = string_vma_map(args.target, ident)
        except Exception as e:
            warnings.append("字符串映射失败：%s: %s" % (type(e).__name__, e))

    sem = None
    if idx is not None and funcs:
        try:
            from lib_semantics import summarize_functions, resolve_thunks
            thunks = resolve_thunks(idx, funcs, iat)
            sem = {"functions": summarize_functions(idx, funcs, iat, str_map,
                                                    limit=args.limit,
                                                    thunk_map=thunks)}
        except Exception as e:
            # 语义层挂了 → api 特征会缺失 → 规则会大面积漏报。
            # 这绝不能静默：必须作为 warning 带出去，否则用户会把
            # "没命中"误读成"样本没这个能力"。
            warnings.append("语义层失败（api 特征缺失，规则会漏报）：%s: %s"
                            % (type(e).__name__, e))

    feats = build_features(args.target, ident, idx, funcs, iat_map=iat, sem=sem)
    for e in (feats.get("errors") or []):
        warnings.append("特征抽取：" + e)

    matched = match_rules(rules, feats)
    for e in (matched.get("errors") or []):
        warnings.append("匹配：" + e)
    # 空规则集必须显式说出来：否则"0 条命中"会被误读成
    # "样本没有这些能力"，而实际是规则压根没加载上。
    if matched.get("empty") and matched.get("reason"):
        warnings.append("能力规则未生效：" + matched["reason"])

    hits = matched["hits"]
    # 同一规则在多处命中时合并成一条，位置单独列（更贴近 capa 的输出形态）
    merged: dict[str, dict] = {}
    for h in hits:
        m = merged.get(h["rule"])
        if m is None:
            m = dict(h)
            m["locations"] = []
            merged[h["rule"]] = m
        loc = h.get("location")
        if loc and loc not in m["locations"]:
            m["locations"].append(loc)
    rows = sorted(merged.values(),
                  key=lambda x: (x.get("namespace") or "", x["rule"]))

    out = {
        "ok": True,
        "path": args.target,
        "format": ident.get("format"),
        "arch": ident.get("arch"),
        "bits": ident.get("bits"),
        "rules_dir": rules_dir,
        "rules_loaded": len(rules),
        "rule_load_errors": rule_errs,
        "functions": len(funcs),
        "hit_rules": len(rows),
        "hit_total": len(hits),
        "by_namespace": {k: sorted(set(v))
                         for k, v in sorted(matched["by_namespace"].items())},
        "att_ck": matched["att_ck"],
        "capabilities": rows,
        "feature_stats": {
            "api": sum(len(f["api"]) for f in feats["functions"].values()),
            "mnemonic": sum(len(f["mnemonic"]) for f in feats["functions"].values()),
            "number": sum(len(f["number"]) for f in feats["functions"].values()),
            "file_strings": len(feats["file"]["string"]),
            "file_imports": len(feats["file"]["import"]),
        },
    }
    if warnings:
        out["warnings"] = warnings
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_capability(out))
    return EXIT_OK


def cmd_symbols(args):
    """
    符号恢复：把修饰名还原成人能读的名字。

    这是「省事层」里投入产出比最高的一步 —— **能拿到名字就不用逆**。

    覆盖：
      - C++ Itanium ABI（`_ZN3foo3barEi` → `foo::bar(int)`）
      - MSVC（`?bar@foo@@QAEHXZ` → `int __thiscall foo::bar(void)`）
      - Rust legacy（`_ZN4core3fmt5write17h...`）与 Rust v0（`_RNvC...`）
      - Go pclntab（`main.main` / `net/http.(*Server).Serve`）—— strip 后仍在
      - C 调用约定装饰（`_printf@8` / `__imp_x`）

    注意：符号**来自目标自身的符号表**，不是猜的。目标被 strip 且非 Go 时
    结果为空，此时必须看 `warnings`，不要把"空"当成"没有函数"。
    """
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)

    res, warnings = N.recover_symbols(
        ident,
        want_demangle=not args.no_demangle,
        want_go=not args.no_go,
        path=args.target,
        limit=args.limit,
    )

    # 只保留"真的被还原了"的（默认）；--all 时全给
    syms = res.get("symbols") or []
    if not args.all:
        shown = [s for s in syms if s.get("changed")]
        # 全都没变化但又确实有符号 —— 说明本来就没被修饰，给原始列表更有用
        if not shown and syms:
            shown = syms
        syms = shown

    out = {
        "ok": True,
        "path": args.target,
        "format": ident.get("format"),
        "arch": ident.get("arch"),
        "bits": ident.get("bits"),
        "counts": res.get("counts"),
        "dialect_stats": res.get("stats"),
        "demangled_total": sum(1 for s in (res.get("symbols") or []) if s.get("changed")),
        "returned": len(syms),
        "symbols": syms[:args.limit],
        "go": res.get("go"),
    }
    if res.get("empty"):
        out["empty"] = True
        out["reason"] = res.get("reason")
    if warnings:
        out["warnings"] = warnings
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_symbols(out))
    return EXIT_OK


def _fmt_symbols(d: dict) -> str:
    L = []
    L.append(f"目标    : {d.get('path')}  [{d.get('format')} {d.get('arch')}]")
    c = d.get("counts") or {}
    L.append(f"符号总数: {c.get('total', 0)}"
             f"（其中 {c.get('demangled_changed', 0)} 条需要还原）")
    go = d.get("go") or {}
    if go:
        L.append(f"Go      : {go.get('go_version_hint')} / "
                 f"恢复出 {go.get('count')} 个函数名（声明 {go.get('nfunc_declared')}）")
    else:
        L.append("Go      : 未发现 pclntab（非 Go 程序，或版本不支持）")
    st = d.get("dialect_stats") or {}
    if st:
        L.append("方言分布: " + " / ".join(f"{k} {v}" for k, v in sorted(st.items())))
    L.append("")
    syms = d.get("symbols") or []
    if not syms:
        L.append("（没有可展示的符号）")
        if d.get("reason"):
            L.append("原因: " + d["reason"])
    else:
        w = max((len(s.get("raw") or "") for s in syms[:60]), default=8)
        w = min(max(w, 8), 48)
        for s in syms[:60]:
            raw = (s.get("raw") or "")
            if len(raw) > w:
                raw = raw[:w - 1] + "…"
            L.append(f"  {raw:<{w}}  {s.get('demangled')}")
        if len(syms) > 60:
            L.append(f"  … 还有 {len(syms) - 60} 条（--limit 调整，或加 --json）")
    for wmsg in d.get("warnings") or []:
        L.append("⚠ " + wmsg)
    return "\n".join(L)


# ================================================================
# AI 调用协议子命令（require / flow / case / result / toolgraph）
# ================================================================
#
# 这 5 个子命令不是"分析能力"，而是**给 AI 用的元工具**：
# 它们回答的是"我该用哪个工具、按什么顺序、结果放哪、失败了该怎么办"。
#
# 动机见 lib_agent.py 顶部的调研说明：工具超过 10–15 个时 LLM 的选择
# 准确率就会下降，所以选路应该下沉成确定性代码，而不是让模型每次在
# 21 个命令里自己挑。

def _merge_case_from_args(args) -> str | None:
    """从命令行参数里取 case 目录（统一处理默认值）。"""
    return getattr(args, "case", None) or getattr(args, "dir", None)


def cmd_require(args):
    """
    按意图检索该用哪些子命令。

    这是 AI **第一个该跑**的命令：把"我要解决什么问题"丢进来，
    拿回 Top-K 个最相关的子命令（含可直接执行的命令模板）。

    对标 AWS AgentCore 的语义工具发现（x_amz_bedrock_agentcore_search）
    与 MCP-Zero 的 discover_tool 模式：不让模型面对全量工具目录，
    而是先检索再选择，把候选压到 5–10 个。

    **没命中是正常结果**，会给 reason 与 hint，别反复重试同样的说法。
    """
    if args.list:
        out = AG.list_catalog(top_k=args.limit, stage=args.stage)
        if not out.get("ok"):
            fail(out.get("error") or "未知阶段", EXIT_USAGE, args.json,
                 {"hint": out.get("hint")})
        if args.json:
            emit(out, True)
            return EXIT_OK
        print(_fmt_catalog(out))
        return EXIT_OK

    if not args.intent:
        fail("缺少意图描述。用法：re.py require \"这文件是不是加壳了\"",
             EXIT_USAGE, args.json,
             {"hint": "或加 --list 看全部工具目录"})

    out = AG.recommend(args.intent, fmt=args.format, top_k=args.limit,
                       stage=args.stage, explain=args.explain,
                       min_score=args.min_score)
    if not out.get("ok"):
        fail(out.get("reason") or "检索失败", EXIT_USAGE, args.json,
             {"hint": out.get("hint")})
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_require(out))
    return EXIT_OK


def _fmt_require(d: dict) -> str:
    L = [f"意图    : {d.get('query')}"]
    if d.get("format"):
        L.append(f"格式    : {d['format']}")
    if d.get("stage"):
        L.append(f"阶段    : {d['stage']}")
    recs = d.get("recommendations") or []
    if not recs:
        L.append("")
        L.append("没有匹配到子命令。")
        if d.get("reason"):
            L.append(f"原因    : {d['reason']}")
        if d.get("hint"):
            L.append(f"建议    : {d['hint']}")
        return "\n".join(L)
    L.append(f"推荐 {len(recs)} 个（按相关性排序）：")
    for i, r in enumerate(recs, 1):
        L.append(f"  {i}. {r['name']:<10} {r['score']:>5}  {r['summary']}")
        L.append(f"     {r['command']}")
        if r.get("why"):
            L.append(f"     理由：{'；'.join(r['why'])}")
    if d.get("hint"):
        L.append("")
        L.append(f"提示    : {d['hint']}")
    return "\n".join(L)


def _fmt_catalog(d: dict) -> str:
    L = [f"工具目录：{d.get('count')} / {d.get('total_catalog')} 个"
         + (f"（阶段 {d['stage']}）" if d.get("stage") else "")]
    cur_stage = None
    for t in d.get("tools", []):
        if t["stage"] != cur_stage:
            cur_stage = t["stage"]
            L.append(f"\n[{cur_stage}]")
        flag = " (写盘)" if t.get("risky") else ""
        L.append(f"  {t['name']:<10} {t['cost']:<7}{flag}  {t['summary']}")
    return "\n".join(L)


def cmd_flow(args):
    """
    分阶段工作流编排：告诉我现在该跑哪些命令。

    对标 Blazytko 的 agentic pipeline —— 不给 AI 一个开放式工具集，
    而是给"明确的阶段 + 每步该产出什么"。核心价值：
      * AI 不必自己规划调用顺序；
      * 互不依赖的步骤被标成同一批，可以并行跑（省墙钟时间）；
      * 已经跑过的步骤自动跳过（配合 case 目录）。

    `--case <目录>` 时会自动从 case 里读已完成步骤。
    """
    have = list(args.have or [])
    case_dir = _merge_case_from_args(args)
    out = AG.flow(stage=args.stage, have=have, case_dir=case_dir,
                  target=args.target)
    if not out.get("ok"):
        fail(out.get("error") or "未知阶段", EXIT_USAGE, args.json,
             {"hint": out.get("hint"), "stages": AG.STAGES})
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_flow(out))
    return EXIT_OK


def _fmt_flow(d: dict) -> str:
    L = []
    if d.get("stage"):
        L.append(f"阶段    : {d['stage']}")
    if d.get("target"):
        L.append(f"目标    : {d['target']}")
    L.append(f"已完成  : {d.get('done_count')} 步"
             + ("  " + ", ".join(d["done"]) if d.get("done") else ""))
    L.append(f"待执行  : {d.get('pending_count')} 步")
    nb = d.get("next_batch") or []
    if nb:
        L.append("")
        L.append(f"▶ 现在并行跑这 {len(nb)} 个（互不依赖）：")
        for e in nb:
            L.append(f"  · {e['cmd']:<10} {e['why']}")
            L.append(f"    {e['command']}")
            L.append(f"    产出：{e['yields']}")
    else:
        L.append("")
        L.append("该阶段没有待执行步骤。")
    if d.get("blocked"):
        L.append("")
        L.append("⏸ 在等前置产出（先跑完前面的）：")
        for b in d["blocked"][:6]:
            L.append(f"  · {b['id']:<10} 需要 {'/'.join(b['waiting_for'])}")
    for n in d.get("notes") or []:
        L.append(f"注意    : {n}")
    if d.get("plan_summary"):
        L.append("")
        L.append(d["plan_summary"])
    return "\n".join(L)


def cmd_case(args):
    """
    分析状态目录（case）：结果落盘、复用、过期检测。

    对标 Blazytko 的 **persistent on-disk case directory**。四个理由：
      1. 抗上下文溢出 —— 大 JSON 留盘上，上下文只放摘要；
      2. 不重复调用 —— 同一个命令对同一目标跑过就有记录；
      3. 可断点续跑 —— 换会话/上下文清空后接着干；
      4. 可审计 —— 分析过程留痕（journal.jsonl）。

    **过期检测**：目标文件大小或 mtime 变了，旧结果就拒绝返回
    （除非显式 --allow-stale）——防止 AI 拿旧结论当新证据。
    """
    act = args.action
    case_dir = _merge_case_from_args(args)

    if act == "init":
        if not case_dir:
            fail("case init 需要 --dir <目录>", EXIT_USAGE, args.json)
        out = AG.case_init(case_dir, target=args.target, note=args.note or "")
    elif act == "status":
        out = AG.case_status(case_dir, target=args.target)
    elif act == "show" or act == "load":
        if not args.cmd:
            fail(f"case {act} 需要 --cmd <子命令名>", EXIT_USAGE, args.json)
        out = AG.case_load(case_dir, args.cmd, target=args.target,
                           allow_stale=args.allow_stale)
        out["summary"] = AG.summarize(args.cmd, out.get("data"))
        if args.raw is False:
            out.pop("data", None)
    elif act == "save":
        if not args.cmd:
            fail("case save 需要 --cmd <子命令名>", EXIT_USAGE, args.json)
        if not args.from_file:
            fail("case save 需要 --from-file <JSON 文件>",
                 EXIT_USAGE, args.json,
                 {"hint": "用法：re.py <命令> --json > out.json，"
                          "再 case save --cmd <命令> --from-file out.json"})
        data = _load_json_file(args.from_file, args.json)
        out = AG.case_save(case_dir, args.cmd, data, target=args.target,
                           stale_after=args.stale_after or 0)
    elif act == "journal":
        out = AG.case_journal(case_dir, limit=args.limit or 200)
    else:
        fail(f"未知 case 动作：{act}", EXIT_USAGE, args.json,
             {"hint": "可用：init / status / save / show / journal"})

    if not out.get("ok"):
        fail(out.get("error") or "case 操作失败", EXIT_RUNTIME, args.json,
             {"hint": out.get("hint")})
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_case(out, act))
    return EXIT_OK


def _load_json_file(path: str, as_json: bool):
    """读一个 JSON 文件；读不出就报受控错误（不静默返回 None）。"""
    if not os.path.exists(path):
        fail(f"文件不存在：{path}", EXIT_TARGET, as_json)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except ValueError as e:
        fail(f"文件不是合法 JSON：{path} —— {e}", EXIT_RUNTIME, as_json)
    except OSError as e:
        fail(f"文件读不出来：{path} —— {e}", EXIT_TARGET, as_json)
    return None


def _fmt_case(d: dict, act: str) -> str:
    L = []
    if act == "init":
        L.append(f"case 目录 : {d.get('case_dir')}")
        L.append("状态      : " + ("已存在，已补齐缺项" if d.get("existed")
                                   else "已创建"))
        m = d.get("manifest") or {}
        if m.get("target"):
            L.append(f"目标      : {m['target']}")
        L.append(f"工具版本  : {m.get('tool_version')}")
    elif act == "status":
        L.append(f"case 目录 : {d.get('case_dir')}")
        if d.get("target"):
            L.append(f"目标      : {d['target']}")
        L.append(f"已有结果  : {d.get('have_count')} 个"
                 + ("  " + ", ".join(d.get("have", [])) if d.get("have") else ""))
        if d.get("stale"):
            L.append(f"已过期    : {d['stale_count']} 个")
            for s in d["stale"][:6]:
                L.append(f"  · {s['name']}：{s['reason']}")
        if d.get("broken"):
            L.append(f"索引损坏  : {len(d['broken'])} 个")
        L.append(f"还没有    : {d.get('missing_count')} 个"
                 + ("  " + ", ".join(d.get("missing", [])[:10])
                    if d.get("missing") else ""))
        for w in d.get("warnings") or []:
            L.append(f"警告      : {w}")
    elif act in ("show", "load"):
        L.append(f"命令      : {d.get('cmd')}")
        L.append(f"保存时间  : {d.get('saved_at')}")
        if d.get("target"):
            L.append(f"目标      : {d['target']}")
        if d.get("stale"):
            L.append("注意      : 结果已过期（--allow-stale 才返回）")
        s = d.get("summary") or {}
        if s.get("ok"):
            L.append(f"结果分类  : {s.get('kind')}")
            L.append("摘要字段  :")
            for k, v in (s.get("summary") or {}).items():
                L.append(f"  {k} = {_brief(v)}")
        elif s:
            L.append(f"（无法摘要：{s.get('note')}）")
        if d.get("data") is not None and not s:
            L.append("（完整数据见 JSON 输出）")
    elif act == "save":
        L.append(f"已保存    : {d.get('name')}  →  {d.get('artifact')}")
        L.append(f"大小      : {d.get('bytes', 0):,} 字节")
        e = d.get("entry") or {}
        L.append(f"结果分类  : {e.get('kind')}")
    elif act == "journal":
        L.append(f"流水记录  : {d.get('count')} 条"
                 f"（累计 {d.get('total_records')}）")
        for r in (d.get("records") or [])[-12:]:
            L.append(f"  {r.get('ts')}  {r.get('event')}  "
                     f"{r.get('cmd')}  [{r.get('kind')}]")
    return "\n".join(L)


def _brief(v, cap: int = 120) -> str:
    """把字段值压成一行短描述。"""
    if isinstance(v, list):
        return f"[{len(v)} 项] " + str(v[:2])[:cap]
    if isinstance(v, dict):
        return "{" + ", ".join(list(v.keys())[:6]) + "}"
    s = str(v)
    return s[:cap] + ("…" if len(s) > cap else "")


def cmd_result(args):
    """
    结果摘要 + 错误分类。

    两个作用：
      1. **摘要** —— 子命令 JSON 字段很多，AI 决策只需要一小撮。
         这里按白名单抽取（不是随机截断），保证同一命令永远返回同一批字段。
      2. **错误分类** —— 把结果归成 5 类并给出明确处置：
         usage_error / target_error / empty_result / partial / engine_error。

    【最重要的一条】`empty_result` 是**正常结果**（语义上就是"没有"），
    处置是"不要重试"。研究里反复出现的浪费就是 Agent 把正常空结果
    当失败然后反复重试。
    """
    if args.from_file:
        data = _load_json_file(args.from_file, args.json)
        cmd = args.cmd or "unknown"
        code = args.exit_code or 0
    elif args.stdin:
        raw = sys.stdin.read()
        if not raw.strip():
            # 空 stdin 通常是上游命令没产出（比如 argparse 直接把用法打到
            # stderr 后退出）。这**不是** result 的用法错误，而是上游失败，
            # 所以要按上游失败语义报告，别甩锅给调用方。
            data = {"ok": False,
                    "error": "stdin 为空 —— 上游命令没有产生任何输出"}
        else:
            try:
                data = json.loads(raw)
            except ValueError:
                # 非 JSON（多半是 argparse 的 usage 文本）：保留前几行当证据，
                # 让 AI 能看出到底发生了什么，而不是只看到"解析失败"。
                head = " | ".join(
                    ln.strip() for ln in raw.strip().splitlines()[:3])
                data = {"ok": False,
                        "error": "stdin 不是 JSON（上游可能直接打出了用法/"
                                 "错误文本）：" + head[:300]}
        cmd = args.cmd or "unknown"
        code = args.exit_code or 0
    else:
        fail("需要 --from-file <JSON> 或 --stdin", EXIT_USAGE, args.json,
             {"hint": "用法：re.py triage x.exe --json | "
                      "re.py result --stdin --cmd triage"})

    if not args.cmd:
        # 能从数据里推出命令名吗？推不出就说明白，不猜。
        cmd = (data.get("cmd") if isinstance(data, dict) else None) or "unknown"

    cls = AG.classify_error(data, exit_code=code)
    summ = AG.summarize(cmd, data, list_cap=args.limit or 5)

    # 【为什么 ok 不能写死 True】result 最常见的用法是管道：
    #   re.py triage x --json | re.py result --stdin
    # 上游崩了 → 我们收到的 payload 是失败体 → 我们把它归类成 engine_error，
    # 但顶层却报 ok:true。这正是本项目最忌讳的"失败被上报为成功"：
    # 调用方一看 ok 就往下走，实际上手上什么都没有。
    # 所以：result 自己没出错 ≠ 它转述的结果是成功的。
    # 只有当被转述的结果本身成功时，顶层才置 ok。
    payload_ok = (cls["kind"] == AG.KIND_OK)
    out = {
        "ok": payload_ok,
        "cmd": cmd,
        "kind": cls["kind"],
        "handling": cls["handling"],
        "retryable": cls["retryable"],
        "next_action": cls["next_action"],
        "reason": cls["reason"],
        "evidence": cls["evidence"],
        "summary": summ.get("summary"),
        "omitted_fields": summ.get("omitted_fields"),
        "note": summ.get("note"),
    }
    sw = cls.get("swallowed")
    if sw:
        out["swallowed"] = sw
    if args.json:
        # 注意：这里仍返回 EXIT_OK。因为 result **自己**执行成功了
        # （分类、摘要都拿到了），退出码描述的是"我这个进程干得怎么样"。
        # 被转述结果的好坏由 ok/kind/next_action 表达。
        # 两者分开，脚本才能区分"result 挂了"和"上游挂了"。
        emit(out, True)
        return EXIT_OK
    print(_fmt_result(out))
    return EXIT_OK


def _fmt_result(d: dict) -> str:
    L = [f"命令      : {d.get('cmd')}"]
    L.append(f"结果分类  : {d.get('kind')}")
    L.append(f"是否可重试: {'是' if d.get('retryable') else '否'}")
    L.append(f"下一步动作: {d.get('next_action')}")
    if d.get("reason"):
        L.append(f"原因      : {d['reason']}")
    L.append(f"处置建议  : {d.get('handling')}")
    s = d.get("summary") or {}
    if s:
        L.append("")
        L.append("摘要（AI 决策需要的字段）：")
        for k, v in s.items():
            L.append(f"  {k} = {_brief(v, 200)}")
    if d.get("note"):
        L.append("")
        L.append(f"备注      : {d['note']}")
    om = d.get("omitted_fields") or []
    if om:
        L.append(f"未摘取字段: {len(om)} 个（需要时读原始 JSON）")
    return "\n".join(L)


def cmd_toolgraph(args):
    """
    工具转移图：这个跑完之后该跑哪个。

    对标 AutoTool (AAAI 2026) 的 Tool Inertia Graph —— 工具调用有很强的
    顺序惯性（ScienceWorld 里 go_to → look_around 占 88.7%），
    把它建模成图就能免掉一次模型推理（论文实测省最多 30%）。

    初始权重来自**工作流先验**（人工核对，标注为 prior）；
    给了 `--case` 时会从实际执行流水里学习并调整，标记为 prior+learned。
    """
    out = AG.toolgraph(current=args.cmd, case_dir=_merge_case_from_args(args),
                       top_k=args.limit or 3, context=args.context or "")
    if not out.get("ok"):
        fail(out.get("error") or "未知命令", EXIT_USAGE, args.json,
             {"hint": out.get("hint")})
    if args.check:
        out = AG.suggest_next_with_check(args.cmd, args.check,
                                         _merge_case_from_args(args))
        if not out.get("ok"):
            fail(out.get("error") or "校验失败", EXIT_USAGE, args.json)
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_toolgraph(out, args.check))
    return EXIT_OK


def _fmt_toolgraph(d: dict, intended: str | None) -> str:
    L = []
    if intended:
        L.append(f"当前      : {d.get('current')}")
        L.append(f"打算跑    : {d.get('intended')}")
        L.append(f"是否合流程: {'是' if d.get('intended_ok') else '否'}")
        if d.get("note"):
            L.append(d["note"])
        sug = d.get("suggestion")
        if sug:
            L.append(f"流程预测  : {sug['cmd']}  —— {sug['why']}")
        return "\n".join(L)

    L.append(f"当前      : {d.get('current') or '(起点)'}")
    L.append(f"权重来源  : {d.get('weights_source')}")
    cands = d.get("candidates") or []
    if cands:
        L.append("接下来建议:")
        for c in cands:
            L.append(f"  · {c['cmd']:<10} 权重 {c['weight']}  {c['why']}")
            L.append(f"    {c['command']}")
    else:
        L.append("没有预设的后续步骤（通常是终点或需要按具体问题检索）。")
    if d.get("learned_edges"):
        L.append("")
        L.append("从流水学到的转移（次数）：")
        for k, v in list(d["learned_edges"].items())[:8]:
            L.append(f"  {k} → {v}")
    for w in d.get("warnings") or []:
        L.append(f"警告      : {w}")
    if d.get("note"):
        L.append(d["note"])
    return "\n".join(L)


def cmd_obfstr(args):
    """
    混淆字符串恢复：把 `strings` 看不见的字符串挖出来。

    恶意样本常把 C2 地址、注册表键、API 名藏起来，让静态字符串扫描全瞎：

      - **栈字符串** —— 逐字节 `mov [rsp+N], imm8` 在栈上拼串，
        字节在文件里从不连续。含宽字节变体（`mov dword [rsp+N], imm32`）。
      - **XOR 加密串** —— 数据段存密文，循环逐字节 XOR 单字节密钥后使用。

    做法来自 FLOSS：**静态模拟指令对内存的影响**，不执行目标代码。
    只读分析，不写盘。

    **XOR 为什么靠"找解密循环"而不是穷举密钥**：实测在 notepad.exe /
    kernel32.dll 上穷举滑窗会稳定打出 20–29 条垃圾（短窗口上任何统计判据
    都会偶然命中）。改为先定位**解密循环**（有代码证据 + 立即数 key），
    再套用到数据上 —— 真实未混淆二进制上误报为 0。
    """
    need_path(args.target, args.json)
    ident = F.identify(args.target, deep=True)

    out = {
        "ok": True,
        "path": args.target,
        "format": ident.get("format"),
        "arch": ident.get("arch"),
        "bits": ident.get("bits"),
        "stack_strings": [],
        "xor_strings": [],
        "xor_loops": [],
    }
    warnings = []

    want_stack = not args.no_stack
    want_xor = not args.no_xor

    if not want_stack and not want_xor:
        fail("--no-stack 与 --no-xor 不能同时给（那就什么都不做了）",
             EXIT_USAGE, args.json)

    if want_stack or want_xor:
        res = D.analyze_file(args.target, ident, region=args.section,
                             max_insns=args.max_insns)
        if not res.get("ok"):
            fail(res.get("error") or "反汇编失败（混淆字符串恢复需要指令流）",
                 EXIT_RUNTIME, args.json)
        idx = res.pop("_idx", None)
        if idx is None:
            fail("内部错误：没有得到指令索引，无法做混淆字符串恢复",
                 EXIT_RUNTIME, args.json)
        insns = sorted(idx.insn.values(), key=lambda x: x.offset)

        if want_stack:
            sr = OS.recover_stack_strings(insns, base_vma=idx.base,
                                          max_results=args.limit)
            out["stack_strings"] = sr["strings"]
            out["stack_store_count"] = sr.get("store_count", 0)
            warnings.extend(sr.get("warnings") or [])

        if want_xor:
            lr = OS.find_xor_loops(insns, max_results=args.limit)
            out["xor_loops"] = lr["loops"]
            warnings.extend(lr.get("warnings") or [])
            if lr["loops"]:
                from lib_formats import Reader
                r = Reader(args.target)
                xr = OS.xor_loops_to_strings(r, lr["loops"],
                                             max_results=args.limit)
                out["xor_strings"] = xr["strings"]
                warnings.extend(xr.get("warnings") or [])
            else:
                # 没有解密循环是**正常结果**（未混淆的二进制就是没有），
                # 但要说明"我们确实找过"，否则会被误读成"没实现"。
                out["xor_note"] = ("未发现单字节 XOR 解密循环。"
                                   "这不代表没有加密串 —— 多字节/RC4/AES 不在覆盖范围内")

    out["total"] = len(out["stack_strings"]) + len(out["xor_strings"])
    if not out["total"]:
        out["empty"] = True
        out["reason"] = ("未恢复出混淆字符串。可能：目标未使用这些混淆手法，"
                         "或代码区超出 --max-insns 上限，或架构不在支持范围")
    if warnings:
        out["warnings"] = warnings
    if args.json:
        emit(out, True)
        return EXIT_OK
    print(_fmt_obfstr(out))
    return EXIT_OK


def _fmt_obfstr(d: dict) -> str:
    L = []
    L.append(f"目标      : {d.get('path')}  [{d.get('format')} {d.get('arch')}]")
    L.append(f"栈字符串  : {len(d.get('stack_strings') or [])} 条"
             f"（扫描到 {d.get('stack_store_count', 0)} 条立即数写栈指令）")
    loops = d.get("xor_loops") or []
    xstr = d.get("xor_strings") or []
    L.append(f"XOR 解密  : {len(loops)} 个解密循环 → {len(xstr)} 条明文")
    if d.get("xor_note"):
        L.append(f"            {d['xor_note']}")
    L.append("")

    ss = d.get("stack_strings") or []
    if ss:
        L.append("── 栈字符串（逐字节/多字节写栈拼出来的）──")
        for s in ss[:40]:
            L.append(f"   0x{s.get('offset', 0):08x}  {s.get('string')!r}"
                     f"  ({s.get('store_insns')} 条写栈)")
    xs = d.get("xor_strings") or []
    if xs:
        L.append("── XOR 解出的明文 ──")
        for s in xs[:40]:
            L.append(f"   0x{s.get('offset', 0):08x}  key=0x{s.get('key', 0):02x}"
                     f"  {s.get('string')!r}")
    if loops:
        L.append("── 解密循环证据（可回 disasm 复核）──")
        for lp in loops[:10]:
            L.append(f"   key=0x{lp.get('key', 0):02x} "
                     f"@0x{(lp.get('loop_start_vma') or 0):x}"
                     f"..0x{(lp.get('loop_end_vma') or 0):x}"
                     f"  体 {lp.get('body_insns')} 条指令")
            for ev in (lp.get("evidence") or [])[:5]:
                L.append(f"       {ev}")
    if d.get("empty"):
        L.append("（没有恢复出混淆字符串）")
        L.append("原因: " + str(d.get("reason")))
    for w in d.get("warnings") or []:
        L.append("⚠ " + w)
    return "\n".join(L)


def _fmt_capability(d: dict) -> str:
    L = []
    L.append(f"目标    : {d.get('path')}  [{d.get('arch')}/{d.get('bits')}位]")
    L.append(f"规则库  : {d.get('rules_dir')}")
    L.append(f"规则加载: {d.get('rules_loaded')} 条"
             + (f"（{len(d['rule_load_errors'])} 条有错！）"
                if d.get("rule_load_errors") else "，无错误"))
    fs = d.get("feature_stats") or {}
    L.append(f"特征规模: API {fs.get('api')} / 助记符 {fs.get('mnemonic')} / "
             f"立即数 {fs.get('number')} / 字符串 {fs.get('file_strings')} / "
             f"导入 {fs.get('file_imports')}")
    L.append(f"函数    : {d.get('functions')} 个")
    L.append("")
    if not d.get("capabilities"):
        L.append("未命中任何能力规则。")
        L.append("注意：这不等于样本无害 —— 可能只是规则库没覆盖到这类行为，")
        L.append("      或语义层/字符串抽取失败导致特征缺失（见下方告警）。")
    else:
        L.append(f"命中 {d.get('hit_rules')} 条能力（共 {d.get('hit_total')} 处）：")
        cur_ns = None
        for c in d["capabilities"]:
            ns = c.get("namespace") or "(未分类)"
            if ns != cur_ns:
                L.append("")
                L.append(f"  [{ns}]")
                cur_ns = ns
            locs = c.get("locations") or []
            loctxt = (", ".join(locs[:4]) + ("…" if len(locs) > 4 else "")) if locs else "-"
            L.append(f"    · {c['rule']}")
            if c.get("description"):
                L.append(f"        说明: {c['description']}")
            L.append(f"        位置: {loctxt}")
            if c.get("att_ck"):
                L.append(f"        ATT&CK: {', '.join(c['att_ck'])}")
    if d.get("att_ck"):
        L.append("")
        L.append("ATT&CK 技术映射汇总：")
        for a in d["att_ck"]:
            L.append(f"  * {a}")
    if d.get("rule_load_errors"):
        L.append("")
        L.append("规则加载错误：")
        for e in d["rule_load_errors"][:10]:
            L.append(f"  ! {e}")
    if d.get("warnings"):
        L.append("")
        L.append("告警（会影响结论完整性，务必读）：")
        for w in d["warnings"][:10]:
            L.append(f"  ! {w}")
    return "\n".join(L)


def plan_leads(st: dict) -> dict:
    leads: dict[str, list] = {}
    for it in st.get("items", []):
        c = it.get("category")
        if not c:
            continue
        leads.setdefault(c, [])
        if len(leads[c]) < 12:
            leads[c].append(it)
    return {k: leads[k] for k in A.CATEGORY_ORDER if k in leads}


# ---------------------------------------------------------------- 参数解析


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="re.py", description="逆向工程工具箱（零第三方依赖）",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--version", action="version", version=f"re.py {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, help_, fn):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--json", action="store_true", help="输出 JSON（AI 调用请始终加）")
        s.set_defaults(func=fn)
        return s

    add("doctor", "探测本机可用工具链", cmd_doctor)

    s = add("identify", "识别文件类型与架构", cmd_identify)
    s.add_argument("target")
    s.add_argument("--no-deep", action="store_true", help="只做魔数识别，不做结构解析")
    s.add_argument("--compact", action="store_true", help="JSON 精简视图（截断大字段）")
    s.add_argument("--max-parse-size", type=int, help="结构解析的大小上限（字节）")

    s = add("strings", "流式提取字符串", cmd_strings)
    s.add_argument("target")
    s.add_argument("--min", type=int, default=6, help="最小长度（默认 6）")
    s.add_argument("--encoding", default="ascii,utf16le", help="ascii / utf16le，逗号分隔")
    s.add_argument("--max-items", type=int, default=20000, help="输出上限，达到即停止扫描")
    s.add_argument("--pattern", help="只保留匹配该正则的字符串")
    s.add_argument("--dedupe", action="store_true", help="按内容去重")
    s.add_argument("--categories-only", action="store_true", help="只输出类别统计")
    s.add_argument("--no-categorize", action="store_true", help="不做分类（更快）")
    s.add_argument("--budget-seconds", type=float, help="时间预算，超时即停")

    s = add("entropy", "整体熵 + 分块熵曲线", cmd_entropy)
    s.add_argument("target")
    s.add_argument("--window", type=int, default=4096)
    s.add_argument("--max-windows", type=int, default=512)

    s = add("imports", "导入表 / 依赖库", cmd_imports)
    s.add_argument("target")
    s.add_argument("--full", action="store_true", help="输出全部函数名（可能很长）")

    s = add("info", "按格式深度解析", cmd_info)
    s.add_argument("target")
    s.add_argument("--max-parse-size", type=int)

    s = add("triage", "一站式初筛（推荐第一个跑）", cmd_triage)
    s.add_argument("target")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--max-items", type=int, default=20000)
    s.add_argument("--pattern")
    s.add_argument("--budget-seconds", type=float)
    s.add_argument("--no-strings", action="store_true", help="JSON 中去掉字符串明细")
    s.add_argument("--max-parse-size", type=int)

    s = add("carve", "按魔数雕刻嵌入文件", cmd_carve)
    s.add_argument("target")
    s.add_argument("--out", help="提取目录（不指定则只列清单）")
    s.add_argument("--align", type=int, default=1, help="偏移对齐要求")
    s.add_argument("--max-files", type=int, default=100)
    s.add_argument("--max-total", type=int, default=256 * 1024 * 1024)

    s = add("diff", "两文件字节级差分", cmd_diff)
    s.add_argument("a")
    s.add_argument("b")
    s.add_argument("--block", type=int, default=4096)
    s.add_argument("--max-ranges", type=int, default=200)

    s = add("plan", "生成下一步分析计划", cmd_plan)
    s.add_argument("target")
    s.add_argument("--goal", default="auto",
                   help="auto/understand/behavior/algorithm/protocol/malware")
    s.add_argument("--no-tools", action="store_true", help="跳过工具链探测（更快）")

    s = add("report", "生成 Markdown 分析报告", cmd_report)
    s.add_argument("target")
    s.add_argument("--out", help="输出路径（文件或目录）；不指定时写到目标旁边，目标目录不可写则退到当前目录")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--max-items", type=int, default=20000)
    s.add_argument("--pattern")
    s.add_argument("--goal", default="auto")
    s.add_argument("--no-tools", action="store_true")
    s.add_argument("--max-parse-size", type=int)

    s = add("magic", "魔数速查", cmd_magic)
    s.add_argument("--hex", help="按十六进制前缀查询，如 4D5A")
    s.add_argument("--name", help="按名称查询，如 ELF")

    s = add("disasm", "反汇编（x86/x64/ARM64/Thumb）", cmd_disasm)
    s.add_argument("target")
    s.add_argument("--section", help="指定节名，如 .text（默认取最大可执行区）")
    s.add_argument("--base", type=lambda x: int(x, 0), help="强制装载基址")
    s.add_argument("--offset", type=int, default=0, help="区内起始偏移")
    s.add_argument("--length", type=int, default=4096, help="反汇编字节数（默认 4096）")
    s.add_argument("--max-insns", type=int, default=20000)

    s = add("funcs", "函数识别 + 指纹 + XREF", cmd_funcs)
    s.add_argument("target")
    s.add_argument("--section")
    s.add_argument("--max-insns", type=int, default=300000)
    s.add_argument("--top", type=int, help="只显示前 N 个函数")
    s.add_argument("--summary", action="store_true", help="JSON 中去掉函数明细")

    s = add("cfg", "单个函数的控制流图", cmd_cfg)
    s.add_argument("target")
    s.add_argument("addr", help="函数入口地址（十六进制，如 140001094）")

    s = add("xref", "交叉引用（谁调用了谁）", cmd_xref)
    s.add_argument("target")
    s.add_argument("--addr", help="查指定地址；不给则输出 Top 引用者")
    s.add_argument("--section")

    s = add("sim", "两份二进制的函数级差分比对", cmd_sim)
    s.add_argument("a")
    s.add_argument("b")
    s.add_argument("--threshold", type=float, default=0.65, help="相似度阈值（默认 0.65）")

    s = add("semantics", "函数级语义摘要（调了什么 API / 什么行为）", cmd_semantics)
    s.add_argument("target")
    s.add_argument("--section", help="指定节名")
    s.add_argument("--tag", help="只输出带该标签的函数，如 加解密 / 网络 / 反调试")
    s.add_argument("--limit", type=int, default=400, help="最多分析多少个函数")
    s.add_argument("--max-insns", type=int, default=300000)
    s.add_argument("--no-strings", action="store_true", help="跳过字符串交叉引用（更快）")
    s.add_argument("--no-libscan", action="store_true",
                   help="跳过库函数/密码学常量识别（更快）")

    s = add("capability", "能力识别（capa 风格规则库 → 行为结论 + ATT&CK）",
            cmd_capability)
    s.add_argument("target")
    s.add_argument("--rules", help="规则目录（默认技能包根目录下的 rules/）")
    s.add_argument("--rule", help="只跑指定规则（逗号分隔的规则名）")
    s.add_argument("--section", help="指定节名")
    s.add_argument("--limit", type=int, default=400, help="语义层最多分析多少个函数")
    s.add_argument("--max-insns", type=int, default=300000)
    s.add_argument("--no-strings", action="store_true", help="跳过字符串交叉引用（更快）")

    s = add("symbols", "符号恢复（C++/MSVC/Rust demangle + Go pclntab）",
            cmd_symbols)
    s.add_argument("target")
    s.add_argument("--limit", type=int, default=2000, help="最多输出多少条（默认 2000）")
    s.add_argument("--all", action="store_true",
                   help="输出全部符号（默认只输出被还原过的）")
    s.add_argument("--no-demangle", action="store_true", help="不做名字还原，只列原名")
    s.add_argument("--no-go", action="store_true", help="跳过 Go pclntab 扫描（更快）")

    # ---- AI 调用协议（元工具） ----

    s = add("require", "按意图检索该用哪些子命令（AI 选路入口）", cmd_require)
    s.add_argument("intent", nargs="?", help="自然语言描述要解决的问题")
    s.add_argument("--list", action="store_true", help="列出全部工具目录")
    s.add_argument("--format", help="目标格式（pe/elf/macho），用于过滤")
    s.add_argument("--stage", help="限定阶段：" + "/".join(AG.STAGES))
    s.add_argument("--limit", type=int, default=6, help="返回条数（默认 6）")
    s.add_argument("--min-score", type=float, default=1.0,
                   help="最低分阈值（低于此分不返回，默认 1.0）")
    s.add_argument("--explain", action="store_true", help="给出打分理由")

    s = add("flow", "分阶段工作流：现在该跑哪些（可并行同批给出）", cmd_flow)
    s.add_argument("--stage", help="只看某阶段：" + "/".join(AG.STAGES))
    s.add_argument("--have", nargs="*", help="已完成/已有结果的步骤 id")
    s.add_argument("--case", help="case 目录（自动读已完成步骤）")
    s.add_argument("--target", help="目标路径（用于生成命令模板）")

    s = add("case", "分析状态目录：结果落盘、复用、过期检测", cmd_case)
    s.add_argument("action",
                   choices=["init", "status", "save", "show", "load", "journal"],
                   help="init/status/save/show/journal")
    s.add_argument("--dir", help="case 目录路径")
    s.add_argument("--cmd", help="子命令名（save/show 需要）")
    s.add_argument("--from-file", help="save 时从该 JSON 文件读结果")
    s.add_argument("--target", help="目标路径（用于过期检测）")
    s.add_argument("--note", help="init 时写入的备注")
    s.add_argument("--stale-after", type=int, default=0,
                   help="秒；超过则算过期（0=只按目标是否变更判断）")
    s.add_argument("--allow-stale", action="store_true",
                   help="show 时即使过期也返回数据")
    s.add_argument("--raw", action="store_true",
                   help="show 时保留完整原始数据")

    s = add("result", "结果摘要 + 错误分类（防无效重试）", cmd_result)
    s.add_argument("--from-file", help="读该 JSON 文件")
    s.add_argument("--stdin", action="store_true", help="从 stdin 读 JSON")
    s.add_argument("--cmd", help="产生该 JSON 的子命令名")
    s.add_argument("--exit-code", type=int, default=0, help="原命令退出码")
    s.add_argument("--limit", type=int, default=5, help="列表字段保留条数")

    s = add("toolgraph", "工具转移图：这个跑完之后该跑哪个", cmd_toolgraph)
    s.add_argument("--cmd", help="当前命令名（不给则按流程起点）")
    s.add_argument("--case", help="case 目录（用于在线学习转移权重）")
    s.add_argument("--limit", type=int, default=3, help="候选数量")
    s.add_argument("--context", help="当前意图（用于上下文相关评分）")
    s.add_argument("--check", help="校验打算跑的下一步是否合流程")

    s = add("obfstr", "混淆字符串恢复（栈字符串 + XOR 解密循环）", cmd_obfstr)
    s.add_argument("target")
    s.add_argument("--section", help="指定代码节名")
    s.add_argument("--max-insns", type=int, default=200000,
                   help="反汇编指令上限（默认 200000）")
    s.add_argument("--limit", type=int, default=200, help="每类最多输出多少条")
    s.add_argument("--no-stack", action="store_true", help="跳过栈字符串恢复")
    s.add_argument("--no-xor", action="store_true", help="跳过 XOR 解密循环分析")

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        fail(f"目标不存在：{e}", EXIT_TARGET, getattr(args, "json", False))
    except IsADirectoryError as e:
        fail(f"目标是目录：{e}", EXIT_USAGE, getattr(args, "json", False))
    except KeyboardInterrupt:
        fail("用户中断", EXIT_RUNTIME, getattr(args, "json", False))
    except Exception as e:
        fail(f"{type(e).__name__}: {e}", EXIT_RUNTIME, getattr(args, "json", False))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
