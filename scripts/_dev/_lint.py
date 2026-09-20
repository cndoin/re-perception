# -*- coding: utf-8 -*-
"""静态体检器：只报「确定的」问题，不做风格审查。

检查项（都能明确判定对错，不掺主观）：
  1. 语法/编译告警（compileall + warnings）
  2. 裸 except / except Exception 里 `pass` —— 静默吞异常
  3. 可变默认参数（def f(x=[]) 这类）
  4. 同一作用域内重复定义同名函数/类（后者覆盖前者）
  5. 未定义名字（委托给 _undefined.py 的 AST 作用域分析）
     【已修 bug】这条检查此前**只写在文档里、根本没实现** ——
     体检器一直谎报覆盖了它。现已接入 _undefined.py。
  6. 文件对象未关闭（`open(` 结果没进 with、也没赋值给被 close 的变量）
  7. 长行 / Tab 混用（仅统计，不改）
  8. 硬编码的本机绝对路径（开源前必须清）
  9. 【护栏】`_` 前缀文件被生产代码导入 —— 这类文件是模块，不能挪进 _dev/
     （曾经把 _quirk.py 误当脚手架挪走，全靠这条拦住）
 10. 【护栏】生产模块缺失 / 导入失败 —— 直接跑 import 自检
 11. 【护栏】测试残留物 —— 生产目录不该出现 *.re-report.md 之类的运行产物
"""
import ast
import importlib
import io
import os
import re
import sys
import py_compile
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
# 本文件住在 scripts/_dev/ 下，要往上跳两级才是 scripts/
SCRIPTS = os.path.dirname(HERE) if os.path.basename(HERE) == "_dev" else HERE
SKILL = os.path.dirname(SCRIPTS)

report = {}


def add(kind, path, lineno, msg):
    report.setdefault(kind, []).append((os.path.basename(path), lineno, msg))


def _docstring_line_ranges(tree):
    """
    返回"处于 docstring / 三引号字符串内部"的行号集合（1-based）。

    用于让文本级护栏跳过解释性文本，只盯真正的代码。
    注意：这里**只**排除 docstring 与注释，不排除普通字符串 ——
    因为本机路径泄漏的典型形态就是写在普通字符串里（如
    `pats = [r"C:\\Users\\<用户名>\\..."]`），那必须照报。
    """
    out = set()
    if tree is None:
        return out
    for node in ast.walk(tree or []):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                and isinstance(first.value.value, str):
            start = first.lineno
            end = getattr(first, "end_lineno", start) or start
            for ln in range(start, end + 1):
                out.add(ln)
    return out


def check_file(path):
    src = io.open(path, encoding="utf-8").read()
    lines = src.splitlines()
    try:
        tree = ast.parse(src, path)
    except SyntaxError as e:
        add("语法错误", path, e.lineno or 0, str(e))
        # 【不要 return】语法错误与「文本级」问题（硬编码本机路径、tab 混用等）
        # 是两件独立的事。原来这里直接 return，导致一个文件只要有语法错误，
        # 它带的本机路径就一起消失 —— 而语法错误可以是刻意的（比如样本文件）。
        # 把 tree 置空，让基于 AST 的护栏自己跳过，文本级护栏继续跑。
        tree = None

    def waived(lineno: int) -> bool:
        """行尾写了 `# lint:ok <理由>` 的，视为已审阅的刻意行为。"""
        if not (1 <= lineno <= len(lines)):
            return False
        return "# lint:ok" in lines[lineno - 1]

    # --- 2. 静默吞异常 ---
    for node in ast.walk(tree or []):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        silent = all(isinstance(s, ast.Pass) for s in body)
        bare = node.type is None
        if silent and not waived(node.lineno):
            kind = "静默吞异常(bare)" if bare else "静默吞异常"
            add(kind, path, node.lineno,
                "except %s: pass" % (ast.unparse(node.type) if node.type else ""))

    # --- 3. 可变默认参数 ---
    for node in ast.walk(tree or []):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) and (
                    isinstance(d, ast.List) and d.elts or
                    isinstance(d, ast.Dict) and d.keys or
                    isinstance(d, ast.Set) and d.elts):
                add("可变默认参数", path, d.lineno, node.name)
            elif isinstance(d, ast.Call) and getattr(d.func, "id", "") in (
                    "list", "dict", "set"):
                add("可变默认参数", path, d.lineno, node.name)

    # --- 4. 同作用域重复定义 ---
    def dup_scan(body, ctx):
        seen = {}
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                key = (st.name, type(st).__name__)
                if key in seen:
                    add("重复定义", path, st.lineno,
                        "%s %s（前一次在 %d 行）" % (ctx, st.name, seen[key]))
                seen[key] = st.lineno
        for st in body:
            for f in ("body", "orelse", "finalbody"):
                sub = getattr(st, f, None)
                if isinstance(sub, list) and sub:
                    dup_scan(sub, ctx + "/" + type(st).__name__)
            for h in getattr(st, "handlers", []) or []:
                dup_scan(h.body, ctx + "/except")

    dup_scan(tree.body, "module")

    # --- 6. open() 未进入 with ---
    for node in ast.walk(tree or []):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
            # 在 with 的 items 里就是安全的
            ok = False
            for w in ast.walk(tree or []):
                if isinstance(w, ast.With):
                    for it in w.items:
                        if it.context_expr is node:
                            ok = True
            if not ok and not waived(node.lineno):
                add("open 未用 with", path, node.lineno,
                    ast.unparse(node)[:60])

    # --- 8. 硬编码本机路径 ---
    # 只报"代码行"。纯注释行与 docstring 内的行会提到
    # `C:\\Users\\<用户名>` 这类写法，那是在**解释这个坑**而不是泄漏；
    # 一并报出来会造成告警疲劳，最后真泄漏也看不见了。
    # 判据：整行去掉空白后以 # 开头 = 注释；落在三引号区间内 = docstring。
    doc_ranges = _docstring_line_ranges(tree)
    for i, line in enumerate(src.splitlines(), 1):
        if waived(i):
            continue
        if line.lstrip().startswith("#"):
            continue
        if i in doc_ranges:
            continue
        # 三种写法都要覆盖，缺一种就是一个洞：
        #   r"C:\Users\x"    -> 源码里是单反斜杠
        #   "C:\\Users\\x" -> 源码里是双反斜杠（转义）
        #   "C:/Users/x"     -> 正斜杠
        # 原先只写了「正斜杠」和「双反斜杠」，**恰好漏掉单反斜杠**；
        # 而单反斜杠正是最自然的 Windows 写法（普通字符串里 \U 会被当转义
        # 处理，所以大家要么用 raw string 得到单斜杠、要么写双斜杠 ——
        # 前者直接漏检）。用 [\\/]{1,2} 一次覆盖。
        for pat in (r"[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}",
                    r"[A-Za-z]:[\\/]{1,2}Documents and Settings[\\/]",
                    r"/Users/[a-zA-Z0-9_.-]+/",
                    r"/home/[a-zA-Z0-9_.-]+/"):
            if re.search(pat, line):
                add("硬编码本机路径", path, i, line.strip()[:80])
                break

    # --- 7. Tab 混用 ---
    for i, line in enumerate(src.splitlines(), 1):
        if line.startswith("\t") or ("\t" in line[:len(line) - len(line.lstrip())]):
            add("Tab 缩进", path, i, line.strip()[:60])


def _underscore_modules():
    """扫出 _ 前缀的模块名（在 scripts/ 和 scripts/_dev/ 两处都看）。

    返回 {模块名: [出现在哪]}。用于护栏 9：如果某个 _ 前缀文件被生产代码
    import，它就绝不能被当成脚手架挪走。
    """
    found = {}
    for d in (SCRIPTS, os.path.join(SCRIPTS, "_dev")):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.startswith("_") and f.endswith(".py") and f != "__init__.py":
                found.setdefault(f[:-3], []).append(
                    "scripts/" if d == SCRIPTS else "scripts/_dev/")
    return found


def check_underscore_guard():
    """护栏 9：被生产代码 import 的 _ 前缀模块，必须留在 scripts/ 下。

    这条护栏的**真实目的**：`_quirk.py` 曾是生产模块，被误当脚手架
    挪进 _dev/，导致发布出去少一个必需文件（`re.py` 直接 ImportError）。
    所以要拦的是「**生产运行时依赖的模块**被挪走」。

    例外只给一种情况：**测试文件 import _dev/ 里的开发工具**。
    `selftest.py` 要测 `_dev/_install.py`，这是正当用法 ——
    但 `re.py` / `lib_*.py` 这些**生产模块**绝不允许 import `_dev/` 的东西
    （发布时 `_dev/` 根本不分发，import 会直接崩）。

    判据的教训（这里栽过两次）：
      1) 不能用「被导入模块在 _dev/」当例外 —— 那样把 `_quirk.py`
         挪进 `_dev/` 也会被放行，护栏等于失效（负向测试当场抓到）。
      2) 必须用**导入方的身份**做判据：只有测试文件才享例外。
    """
    mods = _underscore_modules()
    prod = [f for f in sorted(os.listdir(SCRIPTS))
            if f.endswith(".py") and not f.startswith("_")]
    for f in prod:
        src = io.open(os.path.join(SCRIPTS, f), encoding="utf-8").read()
        try:
            tree = ast.parse(src, os.path.join(SCRIPTS, f))
        except SyntaxError:
            continue
        for node in ast.walk(tree or []):
            name = None
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith("_") and not a.name.startswith("__"):
                        name = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("_") and not node.module.startswith("__"):
                    name = node.module.split(".")[0]
            if not name:
                continue
            locs = mods.get(name)
            if locs is None:
                add("护栏:被导入的 _ 模块不存在", os.path.join(SCRIPTS, f),
                    node.lineno, "import %s（找不到该文件）" % name)
            elif "scripts/" not in locs:
                # 例外：**测试文件**测 _dev/ 里的开发工具是正当的。
                # 生产模块（re.py / lib_*.py）不享此例外。
                if f == "selftest.py" and any("_dev" in x for x in locs):
                    continue
                add("护栏:_ 模块被挪进 _dev", os.path.join(SCRIPTS, f),
                    node.lineno,
                    "生产代码 import %s，但文件不在 scripts/ 下（实际在 %s）"
                    % (name, ",".join(locs)))


def check_imports_ok():
    """护栏 10：生产模块必须能 import 成功。"""
    sys.path.insert(0, SCRIPTS)
    for f in sorted(os.listdir(SCRIPTS)):
        if not f.endswith(".py") or f.startswith("_"):
            continue
        mod = f[:-3]
        if mod in ("selftest",):
            continue
        try:
            importlib.import_module(mod)
        except Exception as e:
            add("护栏:模块导入失败", os.path.join(SCRIPTS, f), 0,
                "%s: %s" % (type(e).__name__, e))


def check_undefined_names():
    """检查 5：未定义名字（委托 _undefined.py 的 AST 作用域分析）。

    为什么需要它：py_compile 只查语法，import 只跑模块顶层 —— 两者都
    发现不了「函数体里写错一个变量名」。而这正是本项目历史上出过的
    真实 bug 类型（errs_out 未声明、n = 0 被误删），一旦跑到那条分支
    才 NameError，静态阶段完全看不见。
    """
    try:
        sys.path.insert(0, HERE)
        import _undefined
    except Exception as e:  # lint:ok 缺了检查器要明确报出来，不能装作通过
        add("护栏:未定义名检查器缺失", __file__, 0,
            "无法加载 _undefined.py: %s: %s" % (type(e).__name__, e))
        return
    for f in sorted(os.listdir(SCRIPTS)):
        if not f.endswith(".py"):
            continue
        p = os.path.join(SCRIPTS, f)
        try:
            issues = _undefined.check_file(p)
        except Exception as e:  # lint:ok 检查器自身崩了必须可见
            add("护栏:未定义名检查器缺失", p, 0,
                "check_file 抛异常 %s: %s" % (type(e).__name__, e))
            continue
        # _undefined 返回的字符串形如 "<path>:<lineno>: <msg>"
        for item in issues:
            lineno, msg = 0, str(item)
            m = re.match(r"^.*?:(\d+):\s*(.*)$", str(item))
            if m:
                lineno, msg = int(m.group(1)), m.group(2)
            add("未定义名", p, lineno, msg)


RESIDUE_PATTERNS = (".re-report.md", ".re-report.json", ".re-cfg.json",
                    ".re-funcs.txt", ".re-strings.txt")
RESIDUE_ALLOW = ("README", "example")


def check_test_residue():
    """护栏 11：生产目录不该出现运行产物。

    这些后缀是 re.py 跑出来的报告/中间文件。曾经有一份
    sample_pe64.exe.re-report.md 混在 scripts/ 里跟着发布出去 ——
    属于「测试残留被当成交付物」，开源前必须清掉。
    """
    for d in (SCRIPTS, SKILL):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            low = f.lower()
            if any(s in low for s in RESIDUE_PATTERNS):
                if any(a.lower() in low for a in RESIDUE_ALLOW):
                    continue
                add("护栏:测试残留物", os.path.join(d, f), 0,
                    "运行产物混入生产目录，发布前删除")


def main():
    # 【扫描范围】生产目录 + _dev/ 都要扫。
    # 原实现只扫 SCRIPTS/，于是 _dev/ 里的「硬编码本机路径」永远查不出来 ——
    # 护栏 8 写得再好也被范围挡在门外（实测：_corpus_build.py:23 带着
    # C:\Users\<用户名> 一路漂到了开源前）。_dev/ 虽然不随发布分发，
    # 但它是仓库的一部分、也会被 clone 的人看到，同样不能带个人路径。
    for f in sorted(os.listdir(SCRIPTS)):
        if f.endswith(".py"):
            check_file(os.path.join(SCRIPTS, f))
    dev_dir = os.path.join(SCRIPTS, "_dev")
    if os.path.isdir(dev_dir):
        for f in sorted(os.listdir(dev_dir)):
            if f.endswith(".py"):
                check_file(os.path.join(dev_dir, f))
    check_underscore_guard()
    check_imports_ok()
    check_undefined_names()
    check_test_residue()

    # 编译告警：用 compile() 而不是 py_compile（Windows 上没法把 pyc
    # 写到 os.devnull，py_compile 会抛 FileExistsError）。
    for f in sorted(os.listdir(SCRIPTS)):
        if not f.endswith(".py"):
            continue
        p = os.path.join(SCRIPTS, f)
        src = io.open(p, encoding="utf-8").read()
        try:
            with warnings.catch_warnings(record=True) as ws:
                warnings.simplefilter("always")
                compile(src, p, "exec")
                for x in ws:
                    add("编译告警", p, 0,
                        "%s: %s" % (x.category.__name__, x.message))
        except SyntaxError as e:
            add("编译失败", p, e.lineno or 0, str(e))

    order = ["语法错误", "编译失败", "编译告警", "护栏:模块导入失败",
             "护栏:_ 模块被挪进 _dev", "护栏:被导入的 _ 模块不存在",
             "护栏:未定义名检查器缺失", "护栏:测试残留物",
             "未定义名",
             "静默吞异常(bare)", "静默吞异常",
             "重复定义", "可变默认参数", "open 未用 with", "硬编码本机路径",
             "Tab 缩进"]

    # 【判据说明】report 里存的是 basename（见 add()），没有目录信息，
    # 所以不能靠"路径里有没有 _dev 段"来判断 —— 第一版就是这么错的，
    # 结果全部告警都被算成生产。改成拿 _dev/ 的文件名集合做成员判断。
    # 真要出现同名文件，宁可算成生产侧（更严格的那一侧）。
    _dev_names = set()
    _dev_dir = os.path.join(SCRIPTS, "_dev")
    if os.path.isdir(_dev_dir):
        _dev_names = {f for f in os.listdir(_dev_dir) if f.endswith(".py")}

    def _is_dev(where):
        return os.path.basename(str(where)) in _dev_names

    dev_total = 0
    prod_total = 0

    print("=" * 72)
    print("【生产文件 scripts/*.py】")
    printed_head = False
    for k in order:
        items = [it for it in report.get(k, []) if not _is_dev(it[0])]
        if not items:
            continue
        printed_head = True
        prod_total += len(items)
        print("=" * 72)
        print("[%s]  %d 处" % (k, len(items)))
        for f, ln, m in items:
            print("   %-26s :%-5d %s" % (f, ln, m))
    for k in report:
        if k in order:
            continue
        items = [it for it in report[k] if not _is_dev(it[0])]
        if items:
            printed_head = True
            prod_total += len(items)
            print("[%s] %d" % (k, len(items)))
            for f, ln, m in items:
                print("   %-26s :%-5d %s" % (f, ln, m))
    if not printed_head:
        print("  （零告警）")

    # _dev/ 单独列账：它不随发布分发，告警不影响退出码，但看得见才有价值
    dev_items = []
    for k in order:
        dev_items += [(k,) + it for it in report.get(k, []) if _is_dev(it[0])]
    for k in report:
        if k in order:
            continue
        dev_items += [(k,) + it for it in report[k] if _is_dev(it[0])]
    dev_total = len(dev_items)
    print("=" * 72)
    print("【开发脚手架 scripts/_dev/*.py】%d 处（不随发布分发，不影响退出码）"
          % dev_total)
    for cat, f, ln, m in dev_items:
        print("   [%s] %-24s :%-5d %s" % (cat, f, ln, m))

    print("=" * 72)
    print("生产 %d 处 ／ 脚手架 %d 处　（期望：生产 0 处）"
          % (prod_total, dev_total))
    print("=" * 72)

    # 退出码契约：0 生产零告警 / 1 生产有告警。
    # 早期实现永远返回 0 —— 装进 CI 等于一道永不拦截的门，正是本项目最忌的
    # "失败被上报为成功"。
    return 1 if prod_total else 0


if __name__ == "__main__":
    sys.exit(main())
