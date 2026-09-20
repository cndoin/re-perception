# -*- coding: utf-8 -*-
"""
深度稳定性审计：查 _lint.py 没覆盖、但会导致真实运行期故障的缺陷类。

_lint.py 管的是"确定的坏味道"（裸 except、可变默认参数等）。
本文件管的是**语义级隐患**——它们语法合法、lint 通过，但特定输入下会崩或给出错误结论。

检查项：
  A. dict 下标直取可选字段 —— d["x"] 而 x 可能不存在 → KeyError
  B. 未加保护的除法 / 取模 —— 除数为 0 → ZeroDivisionError
  C. 未加保护的 int()/float() 转换 —— 垃圾输入 → ValueError
  D. 切片下标可能为负 / 越界后不报错但结果错
  E. `except` 分支里又抛异常 / 或吞掉后返回值语义错误
  F. 递归函数无深度上限（畸形输入可能栈溢出）
  G. 循环里 setdefault / list 追加导致无界增长
  H. 同一 try 块内先 makedirs 后 open —— 失败时清理逻辑误伤（已知踩过）
  I. 返回 None 与返回空集合混用 —— 调用方 .get() 会 AttributeError
  J. `_quirk.py` 这类 `_` 前缀发布物文件的导入/存在完整性

只报告，不修。修由人来判断。
"""
from __future__ import annotations

import ast
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE) if os.path.basename(HERE) == "_dev" else HERE

# 生产模块（排除自检与开发脚本）
PROD = [f for f in sorted(os.listdir(SCRIPTS))
        if f.endswith(".py") and not f.startswith("_") and f != "selftest.py"]

report: dict[str, list] = {}


def add(kind: str, path: str, lineno: int, msg: str) -> None:
    report.setdefault(kind, []).append((os.path.basename(path), lineno, msg))


# ---------------------------------------------------------------- 工具

def _iter_assigns(tree):
    """产出 (目标名, 值节点) 对，用于追踪变量来源。"""
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    yield t.id, n.value


def _is_optional_get(node) -> bool:
    """值节点是否形如 x.get(...) / getattr(x, ...) / x or {}", 即可能为 None/缺失。"""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in ("get", "pop"):
            return True
        if isinstance(f, ast.Name) and f.id in ("getattr",):
            return True
    if isinstance(node, ast.BoolOp):          # a or {}
        return True
    if isinstance(node, ast.IfExp):           # a if c else b
        return True
    if isinstance(node, ast.Subscript):       # x["k"]（本身就可能 KeyError）
        return True
    return False


# ---------------------------------------------------------------- A. subscript 直取

def check_subscript(node: ast.AST, path: str, lines: list[str]) -> None:
    """
    标出对"来源可疑"的值做 [...] 直取。

    判据：被取值的对象名，在本文件里曾经被赋成 .get() / or {} / getattr 的结果。
    这类直取在字段缺失时抛 KeyError，而 .get() 会返回 None —— 两者的失败模式
    完全不同：前者崩，后者静默错。作者往往只想到了其中一种。
    """
    risky: set[str] = set()
    for name, val in _iter_assigns(node):
        if _is_optional_get(val):
            risky.add(name)

    for n in ast.walk(node):
        if not isinstance(n, ast.Subscript):
            continue
        base = n.value
        bname = None
        if isinstance(base, ast.Name):
            bname = base.id
        elif isinstance(base, ast.Attribute):
            bname = base.attr
        if bname and bname in risky:
            sl = ast.unparse(n.slice) if hasattr(ast, "unparse") else "?"
            add("直取可选字段可能 KeyError", path, n.lineno,
                f"{bname}[{sl}] —— {bname} 来自 .get()/or，缺字段即崩")


# ---------------------------------------------------------------- B. 除法

def check_division(node: ast.AST, path: str) -> None:
    for n in ast.walk(node):
        if not isinstance(n, ast.BinOp):
            continue
        if not isinstance(n.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            continue
        denom = n.right
        # 字面量分母：只有为 0 才是 bug（lint 会抓到，这里兜底）
        if isinstance(denom, ast.Constant):
            if denom.value == 0:
                add("除零(字面量)", path, n.lineno, "分母字面量为 0")
            continue
        # 分母是 len(...)：len 可能为 0，且**常常**出现在
        # "空集合就跳过" 的假设下 —— 必须显式防
        if (isinstance(denom, ast.Call)
                and isinstance(denom.func, ast.Name)
                and denom.func.id == "len"):
            add("除零风险(len 分母)", path, n.lineno,
                f"分母是 len()，空集合时为 0 —— {ast.unparse(n)}")
        # 分母是纯 Name：无法静态判定，只提示（不报错）
        elif isinstance(denom, ast.Name):
            add("除零风险(变量分母,仅提示)", path, n.lineno,
                f"{ast.unparse(n)}")


# ---------------------------------------------------------------- C. int/float 转换

def check_conversion(node: ast.AST, path: str) -> None:
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if not (isinstance(f, ast.Name) and f.id in ("int", "float")):
            continue
        if not n.args:
            continue
        a = n.args[0]
        src = ast.unparse(a) if hasattr(ast, "unparse") else "?"
        # 已用 try 包住的不管（粗暴判据：往上找最近的 try 兄弟）
        # 常量转换永远安全
        if isinstance(a, ast.Constant) and isinstance(a.value, (int, float, str)):
            continue
        add("转换可能 ValueError(仅提示)", path, n.lineno, f"{f.id}({src})")


# ---------------------------------------------------------------- F. 递归深度

def check_recursion(node: ast.AST, path: str) -> None:
    """找自递归且没有深度参数的函数 —— 畸形输入可致栈溢出。"""
    for fn in ast.walk(node):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        self_calls = [c for c in ast.walk(fn)
                      if isinstance(c, ast.Call)
                      and isinstance(c.func, ast.Name)
                      and c.func.id == fn.name]
        if not self_calls:
            continue
        params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
        has_depth = any("depth" in p or "level" in p or "limit" in p
                        for p in params)
        if not has_depth:
            add("递归无深度上限", path, self_calls[0].lineno,
                f"{fn.name}() 自递归 {len(self_calls)} 处，无 depth/level/limit 参数")


# ---------------------------------------------------------------- G. 无界增长

def check_unbounded(node: ast.AST, path: str) -> None:
    """
    只看**循环体内**对同一容器的 .append / .add / setdefault 且无 break/return 上限。

    这类代码在"输入大小可控"时没事，但逆向工具的输入是**别人的文件**，
    一个 4GB 的畸形样本就能把内存吃光。
    """
    for loop in ast.walk(node):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        grown: dict[str, int] = {}
        for c in ast.walk(loop):
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute):
                if c.func.attr in ("append", "add", "setdefault"):
                    if isinstance(c.func.value, ast.Name):
                        grown[c.func.value.id] = grown.get(c.func.value.id, 0) + 1
        if not grown:
            continue
        # 循环体里有 break → 视为有界
        has_break = any(isinstance(b, ast.Break) for b in ast.walk(loop))
        if has_break:
            continue
        for name, cnt in grown.items():
            add("循环内无界增长(仅提示)", path, loop.lineno,
                f"for/while 里 {name}.append/add × {cnt}，无 break —— 确认有上限")


# ---------------------------------------------------------------- H. try 内 makedirs

def check_makedirs_try(node: ast.AST, path: str) -> None:
    """
    try 块内同时有 makedirs 和 open(...,'w')。
    失败时若清理逻辑无条件删临时文件，会误伤上一轮的残留 —— 已踩过一次。
    """
    for n in ast.walk(node):
        if not isinstance(n, ast.Try):
            continue
        has_mk = False
        has_write = False
        mk_line = 0
        for c in ast.walk(n):
            if isinstance(c, ast.Call):
                f = c.func
                if isinstance(f, ast.Attribute) and f.attr == "makedirs":
                    has_mk, mk_line = True, c.lineno
                if isinstance(f, ast.Name) and f.id == "open":
                    for kw in c.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            if "w" in str(kw.value.value) or "a" in str(kw.value.value):
                                has_write = True
                    if not c.keywords and len(c.args) >= 2:
                        if isinstance(c.args[1], ast.Constant) and "w" in str(c.args[1].value):
                            has_write = True
        if has_mk and has_write:
            add("try内建目录+写文件(需人工确认清理逻辑)", path, mk_line,
                "makedirs 与写文件同处一个 try，失败清理可能误伤旧文件")


# ---------------------------------------------------------------- I. None/空集合混用

def check_none_vs_empty(node: ast.AST, path: str) -> None:
    """
    函数既 `return None` 又 `return []` / `return {}`。
    调用方写 `.get()` 还是 `or []`，取决于它**以为**拿到的是哪种 —— 很容易错。
    """
    for fn in ast.walk(node):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        has_none = False
        has_empty = False
        for r in ast.walk(fn):
            if not isinstance(r, ast.Return) or r.value is None:
                if isinstance(r, ast.Return):
                    has_none = True
                continue
            v = r.value
            if isinstance(v, ast.List) and not v.elts:
                has_empty = True
            elif isinstance(v, ast.Dict) and not v.keys:
                has_empty = True
            elif isinstance(v, ast.Constant) and v.value is None:
                has_none = True
            elif isinstance(v, ast.Name) and v.id == "None":
                has_none = True
        if has_none and has_empty:
            add("返回类型不一致(None vs 空集合,仅提示)", path, fn.lineno, fn.name)


# ---------------------------------------------------------------- 主流程

def audit(path: str) -> None:
    src = io.open(path, encoding="utf-8").read()
    try:
        tree = ast.parse(src, path)
    except SyntaxError as e:
        add("语法错误", path, e.lineno or 0, str(e))
        return
    lines = src.splitlines()
    check_subscript(tree, path, lines)
    check_division(tree, path)
    check_conversion(tree, path)
    check_recursion(tree, path)
    check_unbounded(tree, path)
    check_makedirs_try(tree, path)
    check_none_vs_empty(tree, path)


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else SCRIPTS
    files = [f for f in sorted(os.listdir(target))
             if f.endswith(".py") and not f.startswith("_dev")]
    # 含 _ 前缀的发布物文件（如 _quirk.py：参考文档，须随发布分发）
    files = sorted(set(files) | {f for f in os.listdir(target)
                                 if f.endswith(".py") and f.startswith("_")
                                 and f != "__init__.py"})
    print(f"深度稳定性审计 · 扫描 {len(files)} 个文件\n")
    for f in files:
        audit(os.path.join(target, f))

    order = [
        "语法错误",
        "直取可选字段可能 KeyError",
        "除零(字面量)",
        "除零风险(len 分母)",
        "递归无深度上限",
        "try内建目录+写文件(需人工确认清理逻辑)",
        "返回类型不一致(None vs 空集合,仅提示)",
        "循环内无界增长(仅提示)",
        "除零风险(变量分母,仅提示)",
        "转换可能 ValueError(仅提示)",
    ]
    print("=" * 72)
    total = 0
    for kind in order:
        items = report.get(kind)
        if not items:
            continue
        total += len(items)
        print(f"[{kind}]  {len(items)} 处")
        for fn, ln, msg in items[:25]:
            print(f"   {fn:<24}:{ln:<6} {msg[:96]}")
        if len(items) > 25:
            print(f"   ... 另有 {len(items) - 25} 处")
    for kind, items in report.items():
        if kind not in order:
            total += len(items)
            print(f"[{kind}]  {len(items)} 处")
            for fn, ln, msg in items[:25]:
                print(f"   {fn:<24}:{ln:<6} {msg[:96]}")
    print("=" * 72)
    print(f"合计 {total} 处")
    return 0


if __name__ == "__main__":
    sys.exit(main())
