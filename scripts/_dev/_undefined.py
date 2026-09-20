# -*- coding: utf-8 -*-
"""
AST 静态检查器：找「未定义名」等 py_compile 抓不到的问题。

为什么需要它：py_compile 只查语法，import 只跑顶层代码 —— 函数体里
写错变量名（本项目的历史 bug 就有 `errs_out` 未声明、`n = 0` 被误删）
两边都抓不到，只会在**那条分支真的被执行时**才炸。

零依赖约束下不能装 pyflakes，所以这里手写一个够用的作用域分析：
  · 收集模块级 / 函数级 / 类级绑定的名字
  · 递归遍历函数体，发现「读了一个从未绑定过的名字」就报出来
  · 显式放行内置、导入名、global/nonlocal、以及常见 dunder

不是完整实现（不做控制流、不做闭包精细分析），但对本项目的
「自赋值前使用 / 变量名拼错 / 漏声明」这类问题命中率足够。
"""
import ast
import builtins
import os
import sys

BUILTINS = set(dir(builtins))


class Scope:
    """一个作用域里被绑定的名字集合。"""

    def __init__(self, parent=None):
        self.names: set[str] = set()
        self.parent = parent

    def has(self, name: str) -> bool:
        s = self
        while s is not None:
            if name in s.names:
                return True
            s = s.parent
        return False


def _bind_target(node, scope: "Scope") -> None:
    """把赋值/循环/with/except 的目标名字收进当前作用域。"""
    if isinstance(node, ast.Name):
        scope.names.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for e in node.elts:
            _bind_target(e, scope)
    elif isinstance(node, ast.Starred):
        _bind_target(node.value, scope)
    # 属性/下标赋值不新增名字


def _bind_args(args, scope: "Scope") -> None:
    """把函数/ lambda 的形参绑定进作用域（别忘了这才是最常见的绑定来源）。"""
    for d in (list(getattr(args, "posonlyargs", [])) + list(args.args)
              + list(args.kwonlyargs)):
        scope.names.add(d.arg)
    if args.vararg:
        scope.names.add(args.vararg.arg)
    if args.kwarg:
        scope.names.add(args.kwarg.arg)


class FuncChecker(ast.NodeVisitor):
    """
    函数体检查器。

    关键设计：**先递归收集本作用域绑定的所有名字，再检查引用**。
    这样 `x = 1` 写在 `print(x)` 之后也不会误报（Python 里合法）。
    """

    def __init__(self, module_scope: Scope, filename: str, errors: list):
        self.module_scope = module_scope
        self.filename = filename
        self.errors = errors
        self.scope = Scope(module_scope)
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def _err(self, node, name, what="未定义"):
        self.errors.append(
            "%s:%d: %s `%s`" % (self.filename, getattr(node, "lineno", 0), what, name)
        )

    # ---- 预扫描：收集本作用域全部绑定 ----
    def collect(self, body, args=None) -> None:
        """
        收集本作用域里**所有**被绑定的名字。

        先收集再检查（而不是边遍历边判断）是刻意的：
        `x = 1` 写在 `print(x)` 之后在 Python 里是合法的，
        边遍历边判断会误报。
        """
        if args is not None:
            _bind_args(args, self.scope)
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scope.names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                self.scope.names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.scope.names.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    self.scope.names.add((a.asname or a.name).split(".")[0])
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.scope.names.add(node.name)
            elif isinstance(node, ast.Global):
                self.globals.update(node.names)
            elif isinstance(node, ast.Nonlocal):
                self.nonlocals.update(node.names)
            elif isinstance(node, ast.comprehension):
                _bind_target(node.target, self.scope)

    # ---- 检查引用 ----
    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            nm = node.id
            if nm in self.globals or nm in self.nonlocals:
                return
            if nm in BUILTINS:
                return
            if not self.scope.has(nm):
                self._err(node, nm)

    def visit_FunctionDef(self, node):
        # 嵌套函数：单独起一个作用域（父作用域可见）
        inner = FuncChecker(self.scope, self.filename, self.errors)
        inner.scope = Scope(self.scope)
        inner.collect(node.body, node.args)
        for stmt in node.body:
            inner.visit(stmt)
        # 装饰器/默认值在**外层**作用域求值
        for dec in node.decorator_list:
            self.visit(dec)
        for d in (node.args.defaults + [x for x in node.args.kw_defaults if x]):
            self.visit(d)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for dec in node.decorator_list:
            self.visit(dec)
        for b in node.bases:
            self.visit(b)
        inner = FuncChecker(self.scope, self.filename, self.errors)
        inner.scope = Scope(self.scope)
        inner.collect(node.body, None)
        for stmt in node.body:
            inner.visit(stmt)

    def visit_Lambda(self, node):
        inner = FuncChecker(self.scope, self.filename, self.errors)
        inner.scope = Scope(self.scope)
        _bind_args(node.args, inner.scope)
        inner.visit(node.body)
        for d in (node.args.defaults + [x for x in node.args.kw_defaults if x]):
            self.visit(d)

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)


def check_file(path: str) -> list[str]:
    src = open(path, encoding="utf-8").read()
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError as e:
        return ["%s:%s: 语法错误 %s" % (path, e.lineno, e.msg)]

    errors: list[str] = []
    # 模块作用域：先收集全部顶层绑定
    mod = Scope()
    mod.names |= BUILTINS
    # `__file__` / `__name__` 等模块级魔法名由解释器注入，不是未定义
    mod.names |= {"__file__", "__name__", "__doc__", "__package__",
                  "__spec__", "__loader__", "__builtins__", "__debug__"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            mod.names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            mod.names.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                mod.names.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            mod.names.add(node.name)

    fn = FuncChecker(mod, path, errors)
    for stmt in tree.body:
        fn.visit(stmt)
    return errors


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    scripts = os.path.dirname(here)
    targets = sorted(
        os.path.join(scripts, f) for f in os.listdir(scripts) if f.endswith(".py")
    )
    # _dev 下的脚手架也查，但排除历史快照（它本就是旧版本，必然与当前不一致）
    dev = os.path.join(scripts, "_dev")
    if os.path.isdir(dev):
        for f in sorted(os.listdir(dev)):
            if f.endswith(".py") and not f.startswith("_lib_symbols_before"):
                targets.append(os.path.join(dev, f))

    all_err: list[str] = []
    for p in targets:
        all_err.extend(check_file(p))

    print("=" * 72)
    if not all_err:
        print("未定义名检查：0 处问题（扫描 %d 个文件）" % len(targets))
    else:
        print("未定义名检查：%d 处问题" % len(all_err))
        for e in all_err:
            print("  " + e)
    print("=" * 72)
    return 1 if all_err else 0


if __name__ == "__main__":
    sys.exit(main())
