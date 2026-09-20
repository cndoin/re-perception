# -*- coding: utf-8 -*-
"""
lib_symbols.py —— 符号名 demangle（零第三方依赖）

为什么这是逆向里最先要补的一环：

  剥了符号的二进制，满屏都是这三种看不懂的字符串——
    _ZNK3foo4impl12decodeB5cxx11ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
    ?process@Packet@net@@QEAAXPEAX_K@Z
    _RNvCsd0nQ7_3mylib9transform
  分别对应 Itanium C++ ABI（GCC/Clang）、MSVC、Rust v0。

  人肉逆它们要花几十秒到几分钟一个；写个解析器，几千个符号几百毫秒出来，
  顺手把模板实参、命名空间层级、类成员、调用约定、参数表全还原 ——
  这是"比人快"最直接的一个点。

四套解码器：
  1. Itanium C++ ABI（_Z 前缀：Linux / macOS / Android / iOS 的 C++ 基本全是它）
  2. MSVC（? 前缀：Windows C++ / 驱动 / COM）
  3. Rust legacy（_ZN..17h<hash>E）
  4. Rust v0（_R..：punycode ident / 泛型 / 生命周期 / const 泛型）

诚实说明（不把糊弄当完整）：
  - Itanium 覆盖日常绝大多数形态：嵌套名、模板、替换表、成员函数 CV/ref 限定、
    运算符、operator""、数组长度、thunk、typeinfo/vtable/guard/TLS 特殊名。
    函数指针数组形态、个别 vendor 扩展算子会走"原样返回"。
  - MSVC 是**启发式**解析。访问属性 / 调用约定那几个字母历史上版本差异很多，
    本文件用"多候选试解析 + 必须精确吃到收尾 Z"自纠错：宁可少认，不认错。
    且**不做** backward-reference 类型回溯的完整还原，遇到就认不出来。
  - Rust v0 的路径 backref（B<idx>）未实现（通用工程师很少手工翻它），
    遇到含 B 的 v0 符号返回原名，不会输出半截结果。
  - 任何一路认不出来，一律**原样返回输入**。

公共 API：
  demangle(name)          -> str   自动识别方言，失败原样返回
  demangle_many(names)    -> dict  批量
  detect_dialect(name)    -> str   给人看的方言标签
  clean_symbol(name)      -> str   去掉 C / stdcall / fastcall 装饰
"""

from __future__ import annotations

# 【命名订正】这个值的真实含义是「单次 demangle 里 guard() 的**累计调用
# 次数**」，不是嵌套深度 —— guard() 每次进入递归记一次、出来不减。
# 因为每次 guard() 调用都对应一次递归进入，所以累计次数 >= 当前深度，
# 用它照样能把无限递归挡住（实测三个解析器类都是**每个符号新建实例**：
# _Ita(body) / _Msvc(s) / _RV0(body)，depth 每次从 0 起，不存在跨符号累积。
# 见下方三个 guard() 的注释。）
# 副作用：一个**很宽**的名字（模板嵌套深、参数多）总节点数超过 200 也会被
# 判 _Fail。这是刻意的复杂度兜底，不是漏洞 —— 超出范围时返回原始名，不会
# 给出错误的解析结果。
_MAX_DEPTH = 200
_MAX_LEN = 8192


class _Fail(Exception):
    """内部信号：解析失败。对外一律表现为"原样返回"。"""


# ================================================================ 入口

def demangle(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > _MAX_LEN:
        return name
    try:
        return _demangle_inner(name)
    except Exception:
        return name


def demangle_many(names) -> dict:
    return {n: demangle(n) for n in names}


def _try(s: str, fn) -> str | None:
    try:
        r = fn(s)
    except Exception:
        return None
    return r if isinstance(r, str) and r else None


def _demangle_inner(name: str) -> str:
    if name.startswith("?"):
        r = _try(name, _msvc)
        return r if r is not None else name

    st = name
    for _ in range(2):
        if st.startswith("_"):
            st = st[1:]

    if st.startswith("R") and len(st) > 2:
        r = _try(st, _rust_v0)
        if r:
            return r
    if st.startswith("ZN"):
        r = _try(st, _rust_legacy)
        if r:
            return r
        r = _try(st, _itanium)
        if r:
            return r
    if st.startswith("Z"):
        r = _try(st, _itanium)
        if r:
            return r
    return clean_symbol(name)


def clean_symbol(name: str) -> str:
    """去掉 C / x86 调用约定装饰：_printf / _foo@8 / @foo@4 / __imp_foo。"""
    s = name
    if s.startswith("__imp_"):
        s = s[6:] + " (import thunk)"
    if s.startswith("__"):
        return s
    if s.startswith("@") or s.startswith("_"):
        s = s[1:]
    if "@" in s and not s.startswith("?"):
        head, _, tail = s.rpartition("@")
        if tail.isdigit():
            s = head
    return s


def detect_dialect(name: str) -> str:
    st = name
    for _ in range(2):
        if st.startswith("_"):
            st = st[1:]
    if name.startswith("?"):
        return "msvc"
    if st.startswith("R") and _try(st, _rust_v0):
        return "rust-v0"
    if st.startswith("ZN"):
        return "rust-legacy" if _try(st, _rust_legacy) else "itanium"
    if st.startswith("Z"):
        return "itanium"
    return "plain"


# ================================================================ Itanium C++ ABI

_ITANIUM_BUILTIN = {
    "v": "void", "w": "wchar_t", "b": "bool", "c": "char", "a": "signed char",
    "h": "unsigned char", "s": "short", "t": "unsigned short", "i": "int",
    "j": "unsigned int", "l": "long", "m": "unsigned long", "x": "long long",
    "y": "unsigned long long", "n": "__int128", "o": "unsigned __int128",
    "f": "float", "d": "double", "e": "long double", "g": "__float128",
    "z": "...",
}

# D 打头的扩展内建类型（C++11 之后的 char16_t / auto / decltype / 定长浮点）
_ITANIUM_EXT = {
    "Dd": "decimal64", "De": "decimal128", "Df": "decimal32", "Dh": "half",
    "Di": "char32_t", "Ds": "char16_t", "Du": "char8_t", "Da": "auto",
    "Dc": "decltype(auto)", "Dn": "decltype(nullptr)",
}

# ABI 写死的替换缩写
_ITANIUM_STD = {
    "St": "std",
    "Sa": "std::allocator",
    "Sb": "std::basic_string",
    "Ss": "std::basic_string<char, std::char_traits<char>, std::allocator<char>>",
    "Si": "std::basic_istream<char, std::char_traits<char>>",
    "So": "std::basic_ostream<char, std::char_traits<char>>",
    "Sd": "std::basic_iostream<char, std::char_traits<char>>",
}

# 运算符码（两位）。对照 GCC libiberty cp-demangle.c 的 cplus_demangle_operators
_ITANIUM_OPS = {
    "nw": "new", "na": "new[]", "dl": "delete", "da": "delete[]",
    "aw": "co_await",
    "pl": "+", "mi": "-", "ml": "*", "dv": "/", "rm": "%",
    "an": "&", "or": "|", "eo": "^", "co": "~",
    "aS": "=", "pL": "+=", "mI": "-=", "mL": "*=", "dV": "/=", "rM": "%=",
    "aN": "&=", "oR": "|=", "eO": "^=",
    "ls": "<<", "rs": ">>", "lS": "<<=", "rS": ">>=",
    "eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">=",
    "ss": "<=>", "nt": "!", "aa": "&&", "oo": "||",
    "pp": "++", "mm": "--", "cm": ",", "pm": "->*", "pt": "->",
    "cl": "()", "ix": "[]", "qu": "?",
}

_SUB_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class _Ita:
    """Itanium C++ ABI 递归下降解析器。"""

    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.subs: list[str] = []
        self.tmpl = False        # 最近解析的**最内层**名字是否带模板实参
        self.scope = ""          # 当前所在作用域（用于还原构造函数名 A::A）
        self.std_pending = False  # 刚读到一个"仅前缀"的 std 缩写（St/Sa/Sb）
        self.depth = 0

    # ---- 读写 ----
    def eof(self):
        return self.i >= len(self.s)

    def peek(self, n=1):
        return self.s[self.i:self.i + n]

    def take(self, n=1):
        if self.i + n > len(self.s):
            raise _Fail
        r = self.s[self.i:self.i + n]
        self.i += n
        return r

    def eat(self, tok):
        if self.s.startswith(tok, self.i):
            self.i += len(tok)
            return True
        return False

    def expect(self, tok):
        if not self.eat(tok):
            raise _Fail

    def number(self):
        j = self.i
        while j < len(self.s) and self.s[j].isdigit():
            j += 1
        if j == self.i:
            raise _Fail
        r = int(self.s[self.i:j])
        self.i = j
        return r

    def guard(self):
        """进入一层解析时调用，累计计数并在超限时中止。

        注意：这里是**累计计数**，出来不减 —— 详见 _MAX_DEPTH 处的说明。
        别照着"深度"的名字去给它加 try/finally 递减：那样会让预算限制失效。
        """
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _Fail

    # ---- 替换表 ----
    def push(self, v):
        self.subs.append(v)
        return v

    def sub(self, idx):
        if idx >= len(self.subs):
            raise _Fail
        return self.subs[idx]

    def substitution(self):
        c = self.peek(2)
        if len(c) == 2 and c in _ITANIUM_STD:
            self.take(2)
            self.std_pending = c in ("St", "Sa", "Sb")
            if not self.std_pending:
                self.tmpl = False
            return _ITANIUM_STD[c]
        self.expect("S")
        if self.eat("_"):
            return self.sub(0)
        j = self.i
        while j < len(self.s) and self.s[j] in _SUB_ALPHA:
            j += 1
        if j >= len(self.s) or self.s[j] != "_":
            raise _Fail
        raw = self.s[self.i:j]
        self.i = j + 1
        n = 0
        for ch in raw:
            n = n * 36 + _SUB_ALPHA.index(ch)
        return self.sub(n + 1)

    # ---- encoding ----
    def encoding(self):
        c = self.peek(2)
        if len(c) == 2 and c[0] == "T":
            k = c[1]
            if k in "Vv":
                self.take(2)
                return "vtable for " + self.push(self.type())
            if k in "IS":
                kind = "typeinfo name for " if k == "S" else "typeinfo for "
                self.take(2)
                return kind + self.push(self.type())
            if k == "T":
                self.take(2)
                return "VTT for " + self.push(self.type())
            if k == "H":
                self.take(2)
                return "TLS init function for " + self.push(self.name())
            if k == "W":
                self.take(2)
                return "TLS wrapper function for " + self.push(self.name())
            if k == "h":
                self.take(2)
                self.number()
                self.expect("_")
                return "non-virtual thunk to " + self.encoding()
            if k == "v":
                self.take(2)
                self.number()
                self.expect("_")
                self.number()
                self.expect("_")
                return "virtual thunk to " + self.encoding()
            if k == "c":
                self.take(2)
                self.number()
                self.expect("_")
                self.number()
                self.expect("_")
                return "covariant return thunk to " + self.encoding()
        special = {"GV": "guard variable for ", "GR": "reference temporary for ",
                   "TH": "thread-local init routine for ",
                   "TW": "thread-local wrapper routine for "}
        if c in special:
            self.take(2)
            return special[c] + self.push(self.name())

        nm = self.push(self.name())
        if self.eof():
            return nm                       # 数据符号
        ret = self.type() if self.tmpl else None
        params = []
        while not self.eof():
            params.append(self.type())
        if params == ["void"]:
            params = []
        sig = nm + "(" + ", ".join(params) + ")"
        return (ret + " " + sig) if ret else sig

    # ---- 名字 ----
    def name(self):
        c = self.peek(1)
        if c == "N":
            return self.nested_name()
        if c == "Z":
            return self.local_name()
        if c == "S":
            base = self.substitution()
            if self.std_pending:
                # <unscoped-name> ::= St <unqualified-name>  —— std / allocator /
                # basic_string 只是前缀，后面必须再跟一个名字，否则会吞掉一半
                # （_ZSt4swapIiE... 里 std 后面是 4swap）。
                self.std_pending = False
                base = base + "::" + self.name_core()
            return self.maybe_template(base)
        return self.unscoped_name()

    def maybe_template(self, base):
        if self.peek(1) == "I":
            args = self.template_args()
            self.tmpl = True
            return self.push(f"{base}<{args}>")
        self.tmpl = False
        return base

    def unscoped_name(self):
        base = self.name_core()
        if self.peek(1) == "I":
            args = self.template_args()
            self.tmpl = True
            return self.push(f"{base}<{args}>")
        self.tmpl = False
        return base

    def name_core(self):
        c = self.peek(2)
        if len(c) == 2:
            if c in _ITANIUM_OPS:
                self.take(2)
                if c == "li":
                    return 'operator""' + self.source_name()
                return "operator" + _ITANIUM_OPS[c]
            if c[0] == "C" and c[1] in "1234578":
                self.take(2)
                return self.scope if self.scope else "{ctor}"
            if c[0] == "D" and c[1] in "0125":
                self.take(2)
                return "~" + self.scope if self.scope else "{dtor}"
            if c == "cv":
                self.take(2)
                return "operator " + self.type()
            if c[0] == "v" and c[1].isdigit():
                self.take(2)
                return "operator" + self.source_name()
        if self.peek(1) == "L":
            self.take(1)
        return self.source_name()

    def source_name(self):
        n = self.number()
        if n <= 0:
            raise _Fail
        return self.take(n)

    def template_args(self):
        self.expect("I")
        out = []
        while not self.eof() and self.peek(1) != "E":
            out.append(self.template_arg())
        self.expect("E")
        return ", ".join(out)

    def template_arg(self):
        if self.peek(1) == "L":
            return self.expr_primary()
        return self.type()

    def expr_primary(self):
        self.expect("L")
        ty = None
        c = self.peek(1)
        if c in _ITANIUM_BUILTIN:
            ty = _ITANIUM_BUILTIN[self.take(1)]
        elif c == "b":
            self.take(1)
            v = "true" if self.eat("1") else "false"
            self.expect("E")
            return v
        j = self.s.find("E", self.i)
        if j < 0:
            raise _Fail
        v = self.s[self.i:j]
        self.i = j + 1
        neg = False
        if v.startswith("n"):
            neg, v = True, v[1:]
        if ty in ("char", "signed char", "unsigned char", "wchar_t",
                  "char16_t", "char32_t", "char8_t", "bool"):
            try:
                iv = int(v)
                if ty == "bool":
                    return "true" if iv else "false"
                if 32 <= iv < 127:
                    return f"'{chr(iv)}'"
                return ("-" if neg else "") + str(iv)
            except ValueError:
                return v
        return ("-" if neg else "") + v

    def nested_name(self):
        self.expect("N")
        quals = self.cv_prefix()
        parts: list[str] = []
        first = True
        while not self.eof() and self.peek(1) != "E":
            prefix = "::".join(parts)
            saved_scope, self.scope = self.scope, prefix
            if self.peek(1) == "S":
                comp = self.substitution()
                if self.std_pending:
                    self.std_pending = False
                    comp = comp + "::" + self.name_core()
            else:
                comp = self.name_core()
            self.scope = saved_scope
            if self.peek(1) == "I":
                args = self.template_args()
                comp = f"{comp}<{args}>"
            parts.append(comp)
            if prefix:
                self.push(prefix + "::" + comp)
            else:
                self.push(comp)
            first = False
        self.expect("E")
        full = "::".join(parts)
        if quals:
            full += " " + quals
        self.tmpl = False     # 嵌套名的最后一段不带模板实参时，函数没有返回类型
        return self.push(full)

    def cv_prefix(self):
        out = []
        while self.peek(1) in ("r", "V", "K"):
            ch = self.take(1)
            out.append({"r": "restrict", "V": "volatile", "K": "const"}[ch])
        return " ".join(reversed(out))

    def local_name(self):
        self.expect("Z")
        outer = self.encoding_scope()
        self.expect("E")
        if self.eat("s"):
            return outer + "::string literal"
        if self.eat("d"):
            self.number()
            return outer
        tail = "::" + self.name()
        if self.peek(1) == "_":
            self.take(1)
            self.number()
        return outer + tail

    def encoding_scope(self):
        nm = self.push(self.name())
        if self.eof() or self.peek(1) == "E":
            return nm
        if self.tmpl:
            self.type()
        params = []
        while not self.eof() and self.peek(1) != "E":
            params.append(self.type())
        if params == ["void"]:
            params = []
        return nm + "(" + ", ".join(params) + ")"

    # ---- 类型 ----
    def type(self):
        self.guard()
        quals = self.cv_prefix()
        core = self.type_core()
        return core + " " + quals if quals else core

    def type_core(self):
        c = self.peek(1)
        if c == "":
            raise _Fail
        if c == "P":
            self.take(1)
            return self.type() + "*"
        if c == "R":
            self.take(1)
            return self.type() + "&"
        if c == "O":
            self.take(1)
            return self.type() + "&&"
        if c == "C":
            self.take(1)
            return "complex " + self.type()
        if c == "G":
            self.take(1)
            return "imaginary " + self.type()
        if c == "M":
            self.take(1)
            cls = self.type()
            mem = self.type()
            return f"{mem} {cls}::*"
        if c == "U":
            self.take(1)
            return self.source_name() + " " + self.type()
        if c == "A":
            self.take(1)
            if self.peek(1).isdigit():
                n = self.number()
                self.expect("_")
                return f"{self.type()} [{n}]"
            if self.peek(1) == "_":
                self.take(1)
                return f"{self.type()} []"
            self.expr_primary()
            self.expect("_")
            return f"{self.type()} []"
        if c == "F":
            self.take(1)
            self.eat("Y")
            ret = None
            params = []
            while not self.eof() and self.peek(1) != "E":
                params.append(self.type())
            self.expect("E")
            if params and params[0] == "void" and len(params) == 1:
                params = []
            sig = ret + " (" + ", ".join(params) + ")" if ret \
                else "(" + ", ".join(params) + ")"
            return sig
        if c == "T":
            self.take(1)
            return "T" + str(self.sub_index())
        if c == "S":
            base = self.substitution()
            return self.maybe_template(base)
        if c == "N":
            return self.nested_name()
        if c == "D":
            e = self.peek(2)
            if e in _ITANIUM_EXT:
                self.take(2)
                return _ITANIUM_EXT[e]
            if e == "DF":
                self.take(2)
                self.number()
                self.expect("_")
                return "_Float"
        if c in _ITANIUM_BUILTIN:
            self.take(1)
            return _ITANIUM_BUILTIN[c]
        if c.isdigit():
            return self.unscoped_name()
        raise _Fail

    def sub_index(self):
        if self.eat("_"):
            return 0
        j = self.i
        while j < len(self.s) and self.s[j] in _SUB_ALPHA:
            j += 1
        if j >= len(self.s) or self.s[j] != "_":
            raise _Fail
        raw = self.s[self.i:j]
        self.i = j + 1
        n = 0
        for ch in raw:
            n = n * 36 + _SUB_ALPHA.index(ch)
        return n + 1


def _itanium(s: str) -> str:
    """s 已剥掉前导下划线，必须以 Z 打头。"""
    if not s.startswith("Z"):
        raise _Fail
    body = s[1:]
    p = _Ita(body)
    r = p.encoding()
    if p.i != len(body):
        raise _Fail
    return r


# ================================================================ MSVC

_MSVC_BASE = {
    "X": "void", "D": "char", "C": "signed char", "E": "unsigned char",
    "F": "short", "G": "unsigned short", "H": "int", "I": "unsigned int",
    "J": "long", "K": "unsigned long", "M": "float", "N": "double",
    "O": "long double", "Z": "...",
}

_MSVC_EXT_BASE = {
    "_D": "__int8", "_E": "unsigned __int8", "_F": "__int16",
    "_G": "unsigned __int16", "_H": "__int32", "_I": "unsigned __int32",
    "_J": "__int64", "_K": "unsigned __int64", "_L": "__int128",
    "_M": "unsigned __int128", "_N": "bool", "_S": "char16_t",
    "_U": "char32_t", "_W": "wchar_t",
}

_MSVC_CV = {"A": "", "B": "const ", "C": "volatile ", "D": "const volatile "}

_MSVC_PTR = {
    "P": "*", "Q": "* const ", "R": "* volatile ", "S": "* const volatile ",
    "A": "&", "B": "volatile &",
}

_MSVC_EXTRA = {"E": "__ptr64", "I": "__restrict", "F": "__unaligned",
               "G": "__based", "H": "__based"}

_MSVC_CC = {
    "A": "__cdecl", "B": "__cdecl", "C": "__pascal", "D": "__pascal",
    "E": "__thiscall", "F": "__thiscall", "G": "__stdcall", "H": "__stdcall",
    "I": "__fastcall", "J": "__fastcall", "K": "", "L": "", "M": "__clrcall",
}

_MSVC_ACCESS = ["private", "protected", "public"]

# ================================================================ MSVC
#
# MSVC 名称修饰解码器。
#
# 本实现严格按 LLVM 官方 demangler 的文法移植：
#     llvm/lib/Demangle/MicrosoftDemangle.cpp
#     llvm/lib/Demangle/MicrosoftDemangleNodes.cpp
# 结构上保留了原实现的两棵树思想：
#     parse  -> AST（节点对象）
#     output -> 把 AST 渲染成文本
# 这样做的好处是渲染细节（空格插入规则、`(void)`、`__ptr64` 落点、限定符
# 位置）可以和 LLVM 完全一致，而不是靠字符串拼接去凑。
#
# 关键文法（与 LLVM 一致，之前手写版本在这里全错）：
#   <qualifiers>     成员用 QRST，非成员用 ABCD —— 是两套不相交的字母表
#   <pointer-type>   A=引用 P/Q/R/S=const/volatile 各种指针 $$Q=右值引用
#   <member-ptr>     P6 是非成员函数指针，P8 才是成员函数指针
#   <array>          Y<rank><dim...>[$$C<cv>]<element>
#   <number>         单个数字 0-9 表示 n+1；多位数用 A-P 表示十六进制
#   <backref>        数字可以回溯引用前面已解析过的类型/名字



# ---------------------------------------------------------------- 限定符位

_Q_NONE = 0
_Q_CONST = 1 << 0
_Q_VOLATILE = 1 << 1
_Q_FAR = 1 << 2
_Q_HUGE = 1 << 3
_Q_UNALIGNED = 1 << 4
_Q_RESTRICT = 1 << 5
_Q_POINTER64 = 1 << 6

# ---------------------------------------------------------------- 函数类别位

_FC_NONE = 0
_FC_PRIVATE = 1 << 0
_FC_PROTECTED = 1 << 1
_FC_PUBLIC = 1 << 2
_FC_STATIC = 1 << 3
_FC_VIRTUAL = 1 << 4
_FC_FAR = 1 << 5
_FC_EXTERN_C = 1 << 6
_FC_NO_PARAMETER_LIST = 1 << 7
_FC_STATIC_THIS_ADJUST = 1 << 8
_FC_VIRTUAL_THIS_ADJUST = 1 << 9
_FC_VIRTUAL_THIS_ADJUST_EX = 1 << 10
_FC_GLOBAL = 1 << 11

# 输出标志（LLVM 的 OutputFlags）
_OF_DEFAULT = 0
_OF_NO_ACCESS_SPECIFIER = 1 << 0
_OF_NO_MEMBER_TYPE = 1 << 1
_OF_NO_VARIABLE_TYPE = 1 << 2
_OF_NO_RETURN_TYPE = 1 << 3
_OF_NO_CALLING_CONVENTION = 1 << 4
_OF_NO_VOID_PARAMETER = 1 << 5
_OF_NO_TAG_SPECIFIER = 1 << 6
_OF_NO_DECORATIVE_RTTI = 1 << 7

# 指针亲和性
_AFF_POINTER = "pointer"
_AFF_REFERENCE = "reference"
_AFF_RVALUE = "rvalue"

# ---------------------------------------------------------------- 基础类型表

_MSVC_PRIM = {
    "X": "void", "D": "char", "C": "signed char", "E": "unsigned char",
    "F": "short", "G": "unsigned short", "H": "int", "I": "unsigned int",
    "J": "long", "K": "unsigned long", "M": "float", "N": "double",
    "O": "long double",
}
_MSVC_PRIM_US = {
    "N": "bool", "J": "__int64", "K": "unsigned __int64", "W": "wchar_t",
    "Q": "char8_t", "S": "char16_t", "U": "char32_t",
    "P": "auto", "T": "decltype(auto)",
}
_MSVC_TAG = {"T": "union", "U": "struct", "V": "class", "W": "enum"}

_MSVC_STORE_NAME = {
    "0": ("private", True), "1": ("protected", True), "2": ("public", True),
    "3": (None, False), "4": (None, False),
    "5": ("private", True), "6": (None, False), "7": (None, False),
}

_MSVC_CC_NAME = {
    "A": "__cdecl", "B": "__cdecl", "C": "__pascal", "D": "__pascal",
    "E": "__thiscall", "F": "__thiscall", "G": "__stdcall", "H": "__stdcall",
    "I": "__fastcall", "J": "__fastcall", "K": "", "L": "",
    "M": "__clrcall", "N": "__clrcall",
    "O": "__eabi", "P": "__eabi", "Q": "__vectorcall",
    # Swift 家族：LLVM 的表只区分 S=Swift / W=SwiftAsync，输出
    # `__attribute__((__swiftcall__))`；但 dbghelp 有**三个**变体，
    # 且用的是 `__swift_N` 这个 LLVM 里完全没有的写法。逐字母实测：
    #   S,T -> __swift_1     U,V -> __swift_2     W -> __swift_3
    # 最小用例：?m@C@@CUGXZ -> private: static unsigned short __swift_2 C::m(void)
    # 语料里这一类 4 条（cppgc 的 EnsureGCInfoIndex）。
    "S": "__swift_1", "T": "__swift_1",
    "U": "__swift_2", "V": "__swift_2",
    "W": "__swift_3",
    "X": "", "Y": "", "Z": "",
}

# 非成员 cv 字母 -> 位（x64 成员函数头里的那个 cv 字符用同一张表）
_MSVC_CV_BITS = {"A": _Q_NONE, "B": _Q_CONST, "C": _Q_VOLATILE,
                 "D": _Q_CONST | _Q_VOLATILE}

# C++/CX 帽指针（hat, `^`）的 cv 编码。**LLVM 里没有这一套**，是从
# dbghelp 实测穷举出来的 —— $AA/$AB/$AC/$AD 与上面的 A/B/C/D 四个
# cv 字母一一对应，只是换成 `$A<x>` 三字符写法：
#   ?f@C@@QEAAHPE$AAVObject@2@@Z -> class Object::Object ^ __ptr64
#   ?f@C@@QEAAHPE$ABVObject@2@@Z -> class Object::Object const ^ __ptr64
#   ?f@C@@QEAAHPE$ACVObject@2@@Z -> class Object::Object volatile ^ __ptr64
#   ?f@C@@QEAAHPE$ADVObject@2@@Z -> class Object::Object const volatile ^ __ptr64
# 另有 $AE，dbghelp 会输出 `?? ::Z ...` 垃圾，按失败处理。
_HAT_CV = {"$AA": _Q_NONE, "$AB": _Q_CONST,
           "$AC": _Q_VOLATILE, "$AD": _Q_CONST | _Q_VOLATILE}

# 运算符表（Basic / Under / DoubleUnder 三组）
_MSVC_OPS_BASIC = {
    "0": None, "1": None, "2": "operator new", "3": "operator delete",
    "4": "operator=", "5": "operator>>", "6": "operator<<", "7": "operator!",
    "8": "operator==", "9": "operator!=", "A": "operator[]", "B": None,
    "C": "operator->", "D": "operator*", "E": "operator++", "F": "operator--",
    "G": "operator-", "H": "operator+", "I": "operator&", "J": "operator->*",
    "K": "operator/", "L": "operator%", "M": "operator<", "N": "operator<=",
    "O": "operator>", "P": "operator>=", "Q": "operator,", "R": "operator()",
    "S": "operator~", "T": "operator^", "U": "operator|", "V": "operator&&",
    "W": "operator||", "X": "operator*=", "Y": "operator+=", "Z": "operator-=",
}
_MSVC_OPS_UNDER = {
    "0": "operator/=", "1": "operator%=", "2": "operator>>=", "3": "operator<<=",
    "4": "operator&=", "5": "operator|=", "6": "operator^=",
    "7": "vftable", "8": "vbtable", "9": "vcall",
    "A": "typeof", "B": "local static guard", "C": "string literal",
    "D": "vbase destructor", "E": "vector deleting destructor",
    "F": "default constructor closure", "G": "scalar deleting destructor",
    "H": "vector constructor iterator", "I": "vector destructor iterator",
    "J": "vector vbase constructor iterator", "K": "virtual displacement map",
    "L": "eh vector constructor iterator", "M": "eh vector destructor iterator",
    "N": "eh vector vbase constructor iterator", "O": "copy constructor closure",
    "P": None, "Q": None, "R": None, "S": "local vftable",
    "T": "local vftable constructor closure",
    "U": "operator new[]", "V": "operator delete[]",
}

# 这些是编译器合成的"特殊名字"，MSVC 的 undname/dbghelp 会把它们用反引号
# 包起来输出（`vbase destructor'、`default constructor closure' 等），
# 与普通运算符名区分开。实测语料里这一类占剩余差异的 68%（36/53）。
# 注意：只包这些合成名，不收 "operator=" 这类真运算符。
_MSVC_SPECIAL_NAMES = {
    "vftable", "vbtable", "vcall", "typeof", "local static guard",
    "string literal", "vbase destructor", "vector deleting destructor",
    "default constructor closure", "scalar deleting destructor",
    "vector constructor iterator", "vector destructor iterator",
    "vector vbase constructor iterator", "virtual displacement map",
    "eh vector constructor iterator", "eh vector destructor iterator",
    "eh vector vbase constructor iterator", "copy constructor closure",
    "local vftable", "local vftable constructor closure",
    "managed vector constructor iterator",
    "managed vector destructor iterator",
    "eh vector copy constructor iterator",
    "eh vector vbase copy constructor iterator",
}
_MSVC_OPS_DUNDER = {
    "A": "managed vector constructor iterator",
    "B": "managed vector destructor iterator",
    "C": "eh vector copy constructor iterator",
    "D": "eh vector vbase copy constructor iterator",
    "E": None, "F": None,
    "G": "vector copy constructor iterator",
    "H": "vector vbase copy constructor iterator",
    "I": "managed vector vbase copy constructor iterator",
    "J": None, "K": None, "L": "operator co_await", "M": "operator<=>",
}


# ================================================================ AST 节点
#
# 每个节点只负责「把自身渲染成字符串」，参数是 (flags, out 上下文)。
# _Out 类模拟 LLVM 的 OutputBuffer：核心是 outputSpaceIfNecessary ——
# 只有当已有内容且末尾是字母数字或 '>' 时才补空格。这条规则决定了
# `int * __ptr64 __cdecl foo(void)` 里所有空格的正确位置。


class _Out:
    """输出缓冲。

    有一个延迟写机制 `close_tpl()`，专门解决嵌套模板收尾的空格问题：
    MSVC 的 undname 输出 `char_traits<char> >`（两个 '>' 之间带空格），
    但单层模板必须是 `Vec<int>`（不带空格）。这必须**先知道后面还有没有
    '>'** 才能决定，所以把待写的 '>' 暂存起来，等下一次写操作时结算：
      * 若下一个字符是 '>'  -> 先补一个空格
      * 否则                -> 直接写 '>'
    """
    __slots__ = ("s", "_pend", "_qpend")

    def __init__(self):
        self.s = ""
        self._pend = 0        # 待写的 '>' 个数
        # 待写的 '>' 里，有几个是「限定类型模板实参」的收尾。
        # 见 close_tpl_qualified() 的说明。
        self._qpend = 0

    def w(self, text: str):
        if self._pend:
            self._flush_pend(text[:1])
        self.s += text

    def _flush_pend(self, nxt: str):
        """结算待写的 '>'。

        nxt 是紧随其后的第一个字符（可能为空，表示这里是缓冲末尾）。
        注意 `n > 1` 的情况：多个待写 '>' 本身构成嵌套收尾，
        它们之间也要插空格（`a<b<c> > >`），所以第 2 个起的 '>' 前面
        必须补空格 —— 这正是 `nxt == ">"` 之外还要处理 `n > 1` 的原因。

        `_qpend` 记的是「最内层那一个 '>' 是否要额外前置空格」。
        dbghelp 对用 `$$C`（LLVM: "Type has qualifiers"）编码的模板实参
        会在收尾 '>' 前多写一个空格：
            MemorySpan<char const >      （符号里是 ?$MemorySpan@$$CBD@v8@@）
            AutoDeleteVector<unsigned short const >
        而非限定实参不写：
            MemorySpan<unsigned short>   （符号里是 ?$MemorySpan@G@v8@@）
        语料里这一类共 83 条，是 "仍不一致" 里最大的一档。
        """
        n = self._pend
        q = self._qpend
        self._pend = 0
        self._qpend = 0
        # 记录写入前缓冲长度，后面算"最内层 '>' 的位置"要用它，
        # 不能在写完之后再按 len(self.s) 反推 —— 一旦 n > 1，
        # 这一段是 `> > >` 三个字符，从末尾数偏移会算错。
        base = len(self.s)
        if nxt == ">":
            # 后面还有真实内容，且是 '>'：整串都当嵌套收尾
            self.s += " >" * n
        elif n > 1:
            # 这些都是相邻的收尾 '>'，第一个直接写，其余各补一个空格
            self.s += ">" + " >" * (n - 1)
        else:
            self.s += ">"
        # 限定实参（$$C）：空格必须加在**最内层那个 '>' 之前**，因为
        # dbghelp 的空格紧跟着该实参的类型名。最内层 '>' 的位置就是
        # base +（nxt == '>' 时前面先补了一个空格 ? 1 : 0）。
        if q:
            ins = base + (1 if nxt == ">" else 0)
            if ins > 0 and not self.s[ins - 1].isspace():
                self.s = self.s[:ins] + " " + self.s[ins:]

    def close_tpl(self):
        """登记一个待写的模板收尾 '>'（延迟到下一步结算）。"""
        self._pend += 1

    def close_tpl_qualified(self):
        """登记一个「限定类型模板实参」的收尾 '>'。

        只在最内层那个 '>' 上生效（外层嵌套收尾仍然按普通规则处理），
        因为 dbghelp 的空格加在紧跟自己那个实参的 '>' 前。
        """
        self._pend += 1
        self._qpend += 1

    def finish(self) -> str:
        if self._pend:
            self._flush_pend("")
        return self.s

    def space_if_needed(self):
        if self._pend:
            self._flush_pend("")
        if not self.s:
            return
        c = self.s[-1]
        if c.isalnum() or c == ">":
            self.s += " "

    def __str__(self):
        return self.finish()


def _out_qualifiers(o: _Out, q: int, space_before: bool, space_after: bool):
    if q == _Q_NONE:
        return
    n0 = len(o.s)
    for mask, txt in ((_Q_CONST, "const"), (_Q_VOLATILE, "volatile"),
                      (_Q_RESTRICT, "__restrict")):
        if not (q & mask):
            continue
        if space_before:
            o.w(" ")
        o.w(txt)
        space_before = True
    if space_after and len(o.s) > n0:
        o.w(" ")


def _cv_text(q: int) -> str:
    """把 cv 位掩码渲染成文本，顺序固定 const -> volatile。

    渲染顺序有实测依据：`peAcd` 类符号 dbghelp 输出
    `const volatile`，反过来（volatile const）在任何样本里都没出现过。
    """
    parts = []
    if q & _Q_CONST:
        parts.append("const")
    if q & _Q_VOLATILE:
        parts.append("volatile")
    return " ".join(parts)


def _out_calling_convention(o: _Out, cc: str):
    o.space_if_needed()
    o.w(cc)


class _Node:
    """所有 AST 节点的基类。"""
    __slots__ = ()

    def out_pre(self, o: _Out, flags: int):
        pass

    def out_post(self, o: _Out, flags: int):
        pass

    def out(self, o: _Out, flags: int):
        self.out_pre(o, flags)
        self.out_post(o, flags)


def _close_angle(o: _Out):
    """登记一个待写的模板收尾 '>'。

    具体插不插空格由 _Out 在下一步结算时决定（见 _Out.close_tpl）。
    """
    o.close_tpl()


def _out_tparams(o: _Out, flags: int, tparams):
    """渲染 `<a,b,c>` 形式的模板实参表。

    用 `$$C`（LLVM: "Type has qualifiers"）编码的模板实参，dbghelp 会在它
    后面多写一个空格 —— 不管它后面紧跟的是收尾 `>` 还是分隔 `,`：
        ?$MemorySpan@$$CBD@v8@@           -> MemorySpan<char const >
        ?$initializer_list@U?$pair@$$CBV?$basic_string@...@@@..@@
                                         -> ...<class std::allocator<char> > const ,class ...>
    非限定实参则不留空格：
        ?$MemorySpan@G@v8@@               -> MemorySpan<unsigned short>
    分隔符 dbghelp 用不带空格的 `,`（LLVM 用 ", "）。
    """
    if not tparams:
        return
    o.w("<")
    for i, t in enumerate(tparams):
        if i:
            o.w(",")
        t.out(o, flags)
        if isinstance(t, _QualArg):
            # 限定实参：后面立刻补一个空格（无论下一个字符是 ',' 还是 '>'）。
            # 收尾 '>' 的那个空格由 close_tpl_qualified 在延迟结算时补，
            # 因为它要参与嵌套收尾的空格规则；这里只处理「不是最后一个」
            # 的情况，也就是后面跟着分隔 ','。
            if i + 1 < len(tparams):
                o.w(" ")
    if isinstance(tparams[-1], _QualArg):
        o.close_tpl_qualified()
    else:
        o.close_tpl()


class _QualArg(_Node):
    """包一层，标记「这个模板实参在符号里带 $$C 前缀」。

    只影响模板收尾 '>' 前是否补空格，不改变实参自身的输出。
    """
    __slots__ = ("inner",)

    def __init__(self, inner):
        self.inner = inner

    def out(self, o, flags):
        self.inner.out(o, flags)

    def out_pre(self, o, flags):
        self.inner.out_pre(o, flags)

    def out_post(self, o, flags):
        self.inner.out_post(o, flags)


class _Prim(_Node):
    __slots__ = ("name", "quals")

    def __init__(self, name, quals=0):
        self.name = name
        self.quals = quals

    def out_pre(self, o, flags):
        o.w(self.name)
        _out_qualifiers(o, self.quals, True, False)

    def out_post(self, o, flags):
        pass


class _Custom(_Node):
    """?<identifier>@ 形式的自定义（用户定义）类型。"""
    __slots__ = ("ident",)

    def __init__(self, ident):
        self.ident = ident

    def out_pre(self, o, flags):
        o.w(self.ident)

    def out_post(self, o, flags):
        pass


class _Tag(_Node):
    __slots__ = ("tag", "qname", "quals")

    def __init__(self, tag, qname, quals=0):
        self.tag = tag
        # qname 既可以是 _QName 节点，也可以是字符串
        self.qname = qname
        self.quals = quals

    def out_pre(self, o, flags):
        if not (flags & _OF_NO_TAG_SPECIFIER):
            o.w(self.tag)
            o.w(" ")
        if isinstance(self.qname, str):
            o.w(self.qname)
        else:
            self.qname.out(o, flags)
        _out_qualifiers(o, self.quals, True, False)

    def out_post(self, o, flags):
        pass


def _is_tag(node) -> bool:
    """判断节点是不是 tag 类型（struct/class/union/enum）。

    dbghelp 在 tag 类型与 '*' 之间总会补一个空格，这一点跟 LLVM 的
    outputSpaceIfNecessary（只看字母数字和 '>'）不同，必须单独处理。
    """
    return isinstance(node, _Tag)


class _Ptr(_Node):
    __slots__ = ("pointee", "quals", "affinity", "class_parent", "hat",
                 "hat_cv", "hat_unaligned")

    def __init__(self, pointee, quals, affinity, class_parent=None, hat=False,
                 hat_cv=0, hat_unaligned=False):
        self.pointee = pointee
        self.quals = quals
        self.affinity = affinity
        self.class_parent = class_parent
        self.hat = hat
        # 帽指针指向对象的 cv 限定：$AA/$AB/$AC/$AD 四个码位分别对应
        # 无 / const / volatile / const volatile。见 _HAT_CV。
        self.hat_cv = hat_cv
        self.hat_unaligned = hat_unaligned

    def out_pre(self, o, flags):
        fn_ptr = isinstance(self.pointee, _FuncSig)
        if fn_ptr:
            self.pointee.out_pre_signature(o, flags & ~_OF_NO_RETURN_TYPE)
        else:
            self.pointee.out_pre(o, flags)

        # tag 类型（struct/class/union/enum）后面一定补一个空格，
        # 不管它最后一个字符是什么。dbghelp 实测：
        #   ?f@@YAXPEAUHWND__@@@Z -> struct HWND__ * __ptr64
        #   ?f@@YAXPEAUabc_@@@Z   -> struct abc_ * __ptr64
        # 而 outputSpaceIfNecessary 只看 alnum/'>'，遇到结尾是 '_' 的
        # 具名 tag 就不会补空格，会出现 `struct HWND__*`。语料里这一处
        # 差异占 817 条（全部"仅空格差异"的绝大多数）。
        if _is_tag(self.pointee):
            if o.s and not o.s.endswith(" "):
                o.w(" ")
        else:
            o.space_if_needed()
        if self.quals & _Q_UNALIGNED:
            o.w("__unaligned ")

        if isinstance(self.pointee, (_Arr, _FuncSig)):
            o.w("(")
            if fn_ptr and not (flags & _OF_NO_CALLING_CONVENTION):
                # 调用约定写在 `(` 之后、`*` 之前（LLVM 的
                # PointerTypeNode::outputPre 把 cc 从 signature 里挪到这个
                # 位置）。空格的有无是 LLVM 与 dbghelp 的又一处分歧：
                #   LLVM    : outputCallingConvention(); OB << " ";  -> `(__cdecl *)`
                #   dbghelp : 非成员函数指针**不加**空格            -> `(__cdecl*)`
                #             成员函数指针**加**空格              -> `(__cdecl C::*)`
                # 实测两例：
                #   ?f@@YAXP6AHXZ@Z  -> void __cdecl f(int (__cdecl*)(void))
                #   ?f@@YAXP8C@@EAA_NXZ@Z
                #                    -> void __cdecl f(bool (__cdecl C::*)(void) __ptr64)
                # 既然本引擎以 dbghelp 为对齐目标（分析者看到的是 IDA/WinDbg
                # 的输出），这里按 dbghelp 处理：只有带 ClassParent 时才补空格。
                o.w(self.pointee.cc)
                if self.class_parent is not None:
                    o.w(" ")

        if self.class_parent is not None:
            if isinstance(self.class_parent, str):
                o.w(self.class_parent)
            else:
                self.class_parent.out(o, flags)
            o.w("::")

        if self.affinity == _AFF_POINTER:
            if self.hat:
                # WinRT 帽指针用 '^' 代替 '*'。实测 dbghelp 的顺序是
                # `const volatile __unaligned ^`：
                #   PE$AAVString@Platform@@ -> class Platform::String ^ __ptr64
                #   PE$ABVString@Platform@@ -> class Platform::String const ^ __ptr64
                #   PE$ACVString@Platform@@ -> class Platform::String volatile ^ ...
                #   PE$ADVString@Platform@@ -> class Platform::String const volatile ^ ...
                # 注意：普通指针的 const 写在 '*' 之后（`* __ptr64 const`），
                # 帽指针则写在 '^' 之前，两者顺序相反。写 cv 时不能走
                # o.w(" const")，否则前面已经补过的空格会变成双空格。
                if self.hat_cv:
                    if o.s and not o.s.endswith(" ") and not o.s.endswith("("):
                        o.w(" ")
                    o.w(_cv_text(self.hat_cv))
                    o.w(" ")
                if self.hat_unaligned:
                    o.w("__unaligned ")
                o.w("^")
            else:
                o.w("*")
        elif self.affinity == _AFF_REFERENCE:
            o.w("&")
        else:
            o.w("&&")
        # 指针自身的限定符。dbghelp 的顺序是 `__ptr64` 在前、`const` 在后，
        # 且两者与 `*` 之间都有空格（例如 `int * __ptr64 const`）。
        if self.quals & _Q_POINTER64:
            o.w(" __ptr64")
        if self.hat:
            # 帽指针的 const 已经在 '^' 前面写过了，这里不要再写一次
            if self.quals & (_Q_CONST | _Q_VOLATILE | _Q_RESTRICT):
                o.w(" ")
            _out_qualifiers(o, self.quals, False, False)
            return
        if self.quals & (_Q_CONST | _Q_VOLATILE | _Q_RESTRICT):
            o.w(" ")
        _out_qualifiers(o, self.quals, False, False)

    def out_post(self, o, flags):
        if isinstance(self.pointee, (_Arr, _FuncSig)):
            o.w(")")
        if isinstance(self.pointee, _FuncSig):
            self.pointee.out_post(o, flags & ~_OF_NO_RETURN_TYPE)
        else:
            self.pointee.out_post(o, flags)


class _Arr(_Node):
    __slots__ = ("element", "dims", "quals")

    def __init__(self, element, dims, quals=0):
        self.element = element
        self.dims = dims
        self.quals = quals

    def out_pre(self, o, flags):
        self.element.out_pre(o, flags)
        _out_qualifiers(o, self.quals, True, False)

    def out_post(self, o, flags):
        # 裸数组的元素类型与 '[' 之间要留一个空格：`char [3]`。
        # 但如果数组是指针的 pointee，写的是 `char (*)[3]`，'[' 紧贴 ')'，
        # 不能留空格。dbghelp 实测：
        #   ?f@@YAX$$BY02D@Z  -> void __cdecl f(char [3])
        #   ?f@@YAXPAY02D@Z   -> void __cdecl f(char (*)[3])
        # 区分办法：看此刻缓冲末尾是不是 ')'（指针已经把 `(class_parent*`
        # 写完了），是则不加空格。
        if not (o.s and o.s[-1] == ")"):
            o.space_if_needed()
        o.w("[")
        for i, d in enumerate(self.dims):
            if i:
                o.w("][")
            o.w(str(d))
        o.w("]")
        self.element.out_post(o, flags)


class _FuncSig(_Node):
    __slots__ = ("fc", "cc", "ret", "params", "variadic", "is_noexcept",
                 "quals", "ref_qual", "this_adjust", "is_thunk", "cv_bits",
                 "cx_head_cv")

    def __init__(self):
        self.fc = _FC_NONE
        self.cc = ""
        self.ret = None
        self.params = None
        self.variadic = False
        self.is_noexcept = False
        self.quals = 0
        self.cv_bits = 0
        self.ref_qual = None
        self.this_adjust = None
        self.is_thunk = False
        # C++/CX：cv 来自函数头位的 $Ax（而不是普通 cv 字母）。
        # 此时 dbghelp 把 cv 紧贴 ')' 写（`)const`），无前导空格。
        self.cx_head_cv = False

    def out_pre_signature(self, o, flags):
        if not (flags & _OF_NO_ACCESS_SPECIFIER):
            if self.fc & _FC_PUBLIC:
                o.w("public: ")
            if self.fc & _FC_PROTECTED:
                o.w("protected: ")
            if self.fc & _FC_PRIVATE:
                o.w("private: ")

        if not (flags & _OF_NO_MEMBER_TYPE):
            if not (self.fc & _FC_GLOBAL):
                if self.fc & _FC_STATIC:
                    o.w("static ")
            if self.fc & _FC_VIRTUAL:
                o.w("virtual ")
            if self.fc & _FC_EXTERN_C:
                o.w('extern "C" ')

        if self.is_thunk:
            o.w("[thunk]: ")

        if not (flags & _OF_NO_RETURN_TYPE) and self.ret is not None:
            self.ret.out_pre(o, flags)
            o.w(" ")

    def out_pre(self, o, flags):
        self.out_pre_signature(o, flags)
        if not (flags & _OF_NO_CALLING_CONVENTION) and self.cc:
            _out_calling_convention(o, self.cc)

    def out_post(self, o, flags):
        if not (self.fc & _FC_NO_PARAMETER_LIST):
            o.w("(")
            if self.params:
                for i, p in enumerate(self.params):
                    if i:
                        o.w(",")
                    p.out(o, flags)
            elif not (flags & _OF_NO_VOID_PARAMETER):
                o.w("void")
            if self.variadic:
                if o.s and o.s[-1] != "(":
                    o.w(",")
                o.w("...")
            o.w(")")

        q = self.quals | self.cv_bits
        # C++/CX 函数头位的 $Ax：cv 紧贴 ')' 写，**不带前导空格**。
        # 实测（dbghelp 为权威）：
        #   ?m@C@@QE$ABA@XZ  -> public: __cdecl C::m(void)const __ptr64
        #   ?m@C@@QEBA A@XZ  -> public: __cdecl C::m(void) const __ptr64
        # 两者 cv 语义相同（都是 const），只有空格不同 —— 说明 $Ax 与
        # 普通 cv 字母在 dbghelp 里走的是两条不同的输出分支。
        # 多个限定符时 dbghelp 只省第一个空格（`)const volatile`），
        # 所以 sep 只在第一个 token 上为空。
        sep = "" if self.cx_head_cv else " "
        if q & _Q_CONST:
            o.w(sep + "const")
            sep = " "
        if q & _Q_VOLATILE:
            o.w(sep + "volatile")
            sep = " "
        if q & _Q_RESTRICT:
            o.w(" __restrict")
        if q & _Q_UNALIGNED:
            o.w(" __unaligned")
        if self.is_noexcept:
            o.w(" noexcept")
        if self.quals & _Q_POINTER64:
            o.w(" __ptr64")
            # 引用限定符紧贴 __ptr64，中间**不**加空格。实测：
            #   ?m@C@@QEHAAHXZ -> int __cdecl C::m(void) __ptr64&&
            #   ?m@C@@QEHAAGHXZ -> ... __ptr64&   （'G' = '&'）
            # 这是 dbghelp 的写法（LLVM 的 outputPost 用 `OB << " "` 走
            # space_if_needed，会输出 `__ptr64 &&`）。语料里这一类 17 条，
            # 全部集中在 Qt 的引用限定成员函数上。
            if self.ref_qual:
                o.w(self.ref_qual)
        elif self.ref_qual == "&":
            o.w(" &")
        elif self.ref_qual == "&&":
            o.w(" &&")

        if self.is_thunk and self.this_adjust:
            adj, mode = self.this_adjust
            if mode == "static":
                o.w("`adjustor{%s}'" % adj)
            elif mode == "vtordisp":
                o.w("`vtordisp{%s, %s}'" % adj)
            else:
                o.w("`vtordispex{%s}'" % ", ".join(str(x) for x in adj))

        if not (flags & _OF_NO_RETURN_TYPE) and self.ret is not None:
            self.ret.out_post(o, flags)


class _Ident(_Node):
    """简单标识符，可携带模板参数。"""
    __slots__ = ("name", "tparams")

    def __init__(self, name, tparams=None):
        self.name = name
        self.tparams = tparams

    def out(self, o, flags):
        o.w(self.name)
        _out_tparams(o, flags, self.tparams)


class _Structor(_Node):
    """构造函数 / 析构函数标识符。"""
    __slots__ = ("is_dtor", "cls", "tparams")

    def __init__(self, is_dtor, cls, tparams=None):
        self.is_dtor = is_dtor
        self.cls = cls
        self.tparams = tparams

    def out(self, o, flags):
        if self.is_dtor:
            o.w("~")
        if isinstance(self.cls, str):
            o.w(self.cls)
        elif self.cls is not None:
            self.cls.out(o, flags)
        _out_tparams(o, flags, self.tparams)


class _ConvOp(_Node):
    """operator <type>() 转换运算符。"""
    __slots__ = ("target", "tparams")

    def __init__(self, target=None, tparams=None):
        self.target = target
        self.tparams = tparams

    def out(self, o, flags):
        o.w("operator ")
        if self.target is not None:
            self.target.out_pre(o, flags)
            self.target.out_post(o, flags)
        _out_tparams(o, flags, self.tparams)


class _Named(_Node):
    """普通名字（运算符名 / vftable 之类合成名）。"""
    __slots__ = ("name", "tparams")

    def __init__(self, name, tparams=None):
        self.name = name
        self.tparams = tparams

    def out(self, o, flags):
        if self.name in _MSVC_SPECIAL_NAMES:
            # 编译器合成名用反引号包裹：`vbase destructor'
            o.w("`")
            o.w(self.name)
            o.w("'")
        else:
            o.w(self.name)
        _out_tparams(o, flags, self.tparams)


class _LitOp(_Node):
    """operator "" _suffix"""
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def out(self, o, flags):
        o.w('operator "" ')
        o.w(self.name)


class _LocalStaticGuard(_Node):
    __slots__ = ("is_thread", "scope_index")

    def __init__(self, is_thread):
        self.is_thread = is_thread
        self.scope_index = None

    def out(self, o, flags):
        o.w("`%s static guard'" % ("thread" if self.is_thread else "local"))
        if self.scope_index is not None:
            o.w("{%d}" % self.scope_index)


class _VcallThunk(_Node):
    __slots__ = ("offset",)

    def __init__(self, offset=0):
        self.offset = offset

    def out(self, o, flags):
        o.w("`vcall'{%d}" % self.offset)


class _QName(_Node):
    """A::B::C"""
    __slots__ = ("parts",)

    def __init__(self, parts):
        self.parts = parts

    def out(self, o, flags):
        for i, p in enumerate(self.parts):
            if i:
                o.w("::")
            p.out(o, flags)


class _Empty(_Node):
    __slots__ = ("name",)

    def __init__(self, name=""):
        self.name = name

    def out(self, o, flags):
        o.w(self.name)


# ---------------------------------------------------------------- 顶层符号


class _FuncSym(_Node):
    __slots__ = ("sig", "name")

    def __init__(self, sig, name=None):
        self.sig = sig
        self.name = name

    def out(self, o, flags):
        # 转换运算符（operator T）不能把返回类型写在前面 —— 返回类型
        # 本身就是运算符名的一部分（`operator unsigned __int64`）。
        # 对应 LLVM 里 FunctionSignatureNode::outputPre 的
        # `if (!(Flags & OF_NoReturnType) && ReturnType)` 判断。
        if self._is_conv_op():
            flags = flags | _OF_NO_RETURN_TYPE
        self.sig.out_pre(o, flags)
        o.space_if_needed()
        if self.name is not None:
            self.name.out(o, flags)
        self.sig.out_post(o, flags)

    def _is_conv_op(self) -> bool:
        """限定的名字里最后一段是不是转换运算符。"""
        n = self.name
        if not isinstance(n, _QName) or not n.parts:
            return False
        return isinstance(n.parts[-1], _ConvOp)


class _VarSym(_Node):
    __slots__ = ("sc_private", "sc_public", "sc_protected", "is_static",
                 "ty", "name")

    def __init__(self, access=None, is_static=False, ty=None, name=None):
        self.sc_private = access == "private"
        self.sc_public = access == "public"
        self.sc_protected = access == "protected"
        self.is_static = is_static
        self.ty = ty
        self.name = name

    def out(self, o, flags):
        if not (flags & _OF_NO_ACCESS_SPECIFIER):
            if self.sc_private:
                o.w("private: ")
            elif self.sc_public:
                o.w("public: ")
            elif self.sc_protected:
                o.w("protected: ")
        if not (flags & _OF_NO_MEMBER_TYPE) and self.is_static:
            o.w("static ")
        if not (flags & _OF_NO_VARIABLE_TYPE) and self.ty is not None:
            self.ty.out_pre(o, flags)
        if self.name is not None:
            # 数组/函数指针类型的变量名要跟 `(*` / `(` 之间留空格：
            # dbghelp 输出 `char const (* __ptr64 g)[2]`。
            if (isinstance(self.ty, _Ptr)
                    and isinstance(self.ty.pointee, (_Arr, _FuncSig))):
                if o.s and not o.s.endswith(" "):
                    o.w(" ")
            else:
                o.space_if_needed()
            self.name.out(o, flags)
        if not (flags & _OF_NO_VARIABLE_TYPE) and self.ty is not None:
            self.ty.out_post(o, flags)


class _SpecialTable(_Node):
    __slots__ = ("name", "quals", "targets")

    def __init__(self, name, quals=0, targets=None):
        self.name = name
        self.quals = quals
        self.targets = targets

    def out(self, o, flags):
        _out_qualifiers(o, self.quals, False, True)
        self.name.out(o, flags)
        if self.targets:
            o.w("{for `")
            for i, t in enumerate(self.targets):
                if i:
                    o.w("'s `")
                t.out(o, flags)
            o.w("'}")


class _Raw(_Node):
    """原样输出（MD5 名字、字符串字面量等）。"""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text

    def out(self, o, flags):
        o.w(self.text)


class _RttiTypeDesc(_Node):
    __slots__ = ("ty", "label")

    def __init__(self, ty, label):
        self.ty = ty
        self.label = label

    def out(self, o, flags):
        self.ty.out_pre(o, flags)
        o.space_if_needed()
        o.w(self.label)
        self.ty.out_post(o, flags)


class _RttiBaseClassDesc(_Node):
    __slots__ = ("nv_off", "vbptr_off", "vbtable_off", "flags_bits", "qname")

    def __init__(self, nv, vbp, vbt, fl, qname):
        self.nv_off = nv
        self.vbptr_off = vbp
        self.vbtable_off = vbt
        self.flags_bits = fl
        self.qname = qname

    def out(self, o, flags):
        o.w("`RTTI Base Class Descriptor at (")
        o.w("%d,%d,%d,%d)'" % (self.nv_off, self.vbptr_off,
                               self.vbtable_off, self.flags_bits))
        o.space_if_needed()
        self.qname.out(o, flags)


class _DynInit(_Node):
    __slots__ = ("is_dtor", "var_name", "fn")

    def __init__(self, is_dtor):
        self.is_dtor = is_dtor
        self.var_name = None
        self.fn = None

    def out(self, o, flags):
        if self.fn is not None:
            self.fn.sig.out_pre(o, flags)
            o.space_if_needed()
            o.w("`dynamic %s for `" % ("atexit destructor" if self.is_dtor
                                       else "initializer"))
            if self.var_name is not None:
                self.var_name.out(o, flags)
            o.w("''")
            self.fn.sig.out_post(o, flags)


# ================================================================ 解析器


class _Msvc:
    """按 LLVM 文法解析 MSVC 修饰名。"""

    MAX_NAMES = 10
    MAX_PARAMS = 10

    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.depth = 0
        # 名字回溯表（LLVM Backrefs.Names）—— 只存字符串
        self.names: list[str] = []
        # 参数回溯表（LLVM Backrefs.FunctionParams）
        self.fparams: list[_Node] = []

    # ---- 基本读写 ----
    def look(self, n=1):
        return self.s[self.i:self.i + n]

    def at(self, pos):
        return self.s[pos] if pos < len(self.s) else ""

    def take(self, n=1):
        if self.i + n > len(self.s):
            raise _Fail
        r = self.s[self.i:self.i + n]
        self.i += n
        return r

    def eat(self, tok):
        if self.s.startswith(tok, self.i):
            self.i += len(tok)
            return True
        return False

    def expect(self, tok):
        if not self.eat(tok):
            raise _Fail

    def rest(self):
        return self.s[self.i:]

    def done(self):
        return self.i >= len(self.s)

    def guard(self):
        """进入一层解析时调用，累计计数并在超限时中止。

        注意：这里是**累计计数**，出来不减 —— 详见 _MAX_DEPTH 处的说明。
        别照着"深度"的名字去给它加 try/finally 递减：那样会让预算限制失效。
        """
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _Fail

    # ---- 数字 ----
    def number(self):
        """<number>：单个 0-9 表示 n+1；否则 A-P 组成的十六进制，@ 结尾。"""
        neg = self.eat("?")
        c = self.look(1)
        if c and c.isdigit():
            self.take(1)
            return int(c) + 1, neg
        val = 0
        n = 0
        while True:
            c = self.look(1)
            if not c:
                raise _Fail
            if c == "@":
                self.take(1)
                return val, neg
            if "A" <= c <= "P":
                val = (val << 4) + (ord(c) - ord("A"))
                self.take(1)
                n += 1
                continue
            raise _Fail

    def unsign(self):
        v, neg = self.number()
        if neg:
            raise _Fail
        return v

    def sign(self):
        v, neg = self.number()
        return -v if neg else v

    # ---- 名字回溯 ----
    def memorize(self, text: str):
        if len(self.names) >= self.MAX_NAMES:
            return
        if text in self.names:
            return
        self.names.append(text)

    def memorize_node(self, node):
        o = _Out()
        node.out(o, _OF_DEFAULT)
        # 必须用 finish() 而不是 o.s —— 模板收尾的 '>' 是延迟写的，
        # 直接取 o.s 会把 '>' 丢掉，记忆下来的名字变成 '_Yarn<char' 这种
        # 残缺形态，后面回溯（如 V01@）再渲染出来就是错的。
        self.memorize(o.finish())

    def backref_name(self):
        c = self.look(1)
        if not c.isdigit():
            raise _Fail
        idx = int(c)
        if idx >= len(self.names):
            raise _Fail
        self.take(1)
        return _Named(self.names[idx])

    # ---- 简单字符串 ----
    def simple_string(self, memorize: bool) -> str:
        j = self.s.find("@", self.i)
        if j < 0 or j == self.i:
            raise _Fail
        r = self.s[self.i:j]
        self.i = j + 1
        if memorize:
            self.memorize(r)
        return r

    def simple_name(self, memorize=True):
        return _Ident(self.simple_string(memorize))

    # ---- 函数标识符码 ----
    def func_ident_code(self):
        self.expect("?")
        if self.eat("__"):
            grp = "D"
        elif self.eat("_"):
            grp = "U"
        else:
            grp = "B"
        c = self.look(1)
        if not c or not (c.isdigit() or ("A" <= c <= "Z")):
            raise _Fail
        self.take(1)
        if grp == "B":
            if c == "0":
                return ("structor", False)
            if c == "1":
                return ("structor", True)
            if c == "B":
                return ("convop", None)
            return ("intrinsic", _MSVC_OPS_BASIC.get(c))
        if grp == "U":
            return ("intrinsic", _MSVC_OPS_UNDER.get(c))
        if c == "K":
            return ("litop", None)
        return ("intrinsic", _MSVC_OPS_DUNDER.get(c))

    # ---- 模板实例化 ----
    def template_inst_name(self, mode: str):
        """mode: 'simple' | 'template'"""
        if not self.eat("?$"):
            raise _Fail
        # 模板内部有独立的回溯上下文
        outer_names = self.names
        outer_params = self.fparams
        self.names = []
        self.fparams = []
        try:
            ident = self.unqualified_symbol_name("simple")
            if isinstance(ident, _ConvOp) or isinstance(ident, _Structor):
                raise _Fail
            ident.tparams = self.template_param_list()
        finally:
            self.names = outer_names
            self.fparams = outer_params
        if mode == "template":
            self.memorize_node(ident)
        return ident

    def unqualified_symbol_name(self, mode: str):
        c = self.look(1)
        if c.isdigit():
            return self.backref_name()
        if not c:
            raise _Fail
        if self.look(2) == "?$":
            return self.template_inst_name(mode)
        if c == "?":
            kind, arg = self.func_ident_code()
            if kind == "structor":
                return _Structor(arg, "?")
            if kind == "convop":
                return _ConvOp()
            if kind == "litop":
                return _LitOp(self.simple_string(False))
            if arg is None:
                raise _Fail
            return _Named(arg)
        return self.simple_name(mode == "simple")

    def unqualified_type_name(self, memorize=True):
        c = self.look(1)
        if c.isdigit():
            return self.backref_name()
        if self.look(2) == "?$":
            return self.template_inst_name("template")
        return self.simple_name(memorize)

    # ---- 作用域链 ----
    def name_scope_piece(self):
        c = self.look(1)
        if c.isdigit():
            return self.backref_name()
        if self.look(2) == "?$":
            return self.template_inst_name("template")
        if self.look(2) == "?A":
            return self.anon_namespace_name()
        if self._starts_local_scope():
            return self.locally_scoped_name()
        return self.simple_name(True)

    def _starts_local_scope(self) -> bool:
        if self.look(1) != "?":
            return False
        j = self.s.find("?", self.i + 1)
        if j < 0:
            return False
        cand = self.s[self.i + 1:j]
        if not cand:
            return False
        if len(cand) == 1:
            return cand == "@" or cand.isdigit()
        if not cand.endswith("@"):
            return False
        cand = cand[:-1]
        if not cand or not ("B" <= cand[0] <= "P"):
            return False
        return all("A" <= ch <= "P" for ch in cand[1:])

    def anon_namespace_name(self):
        self.expect("?A")
        j = self.s.find("@", self.i)
        if j < 0:
            raise _Fail
        self.memorize(self.s[self.i:j])
        self.i = j + 1
        return _Ident("`anonymous namespace'")

    def locally_scoped_name(self):
        self.expect("?")
        num, _ = self.number()
        self.expect("?")
        scope = self.parse_symbol_here()
        o = _Out()
        o.w("`")
        scope.out(o, _OF_DEFAULT)
        o.w("'::`%d'" % num)
        return _Ident(o.s)

    def name_scope_chain(self, unqualified):
        parts = [unqualified]
        while not self.eat("@"):
            if self.done():
                raise _Fail
            parts.insert(0, self.name_scope_piece())
        return _QName(parts)

    def fully_qualified_type_name(self):
        return self.name_scope_chain(self.unqualified_type_name(True))

    def fully_qualified_symbol_name(self):
        ident = self.unqualified_symbol_name("simple")
        qn = self.name_scope_chain(ident)
        if isinstance(ident, _Structor):
            if len(qn.parts) < 2:
                raise _Fail
            ident.cls = qn.parts[-2]
        return qn, ident
    # ---- 类型判别 ----
    def _is_member_ptr(self):
        """返回 (是否成员指针, 消耗长度)。"""
        start = self.i
        c = self.at(self.i)
        if c == "$":
            return False, 0
        if c == "A":
            return False, 0
        if c not in "PQRS":
            return False, 0
        self.i += 1
        c2 = self.at(self.i)
        if c2.isdigit():
            self.i = start
            if c2 not in "68":
                raise _Fail
            return c2 == "8", 0
        self.eat("E")
        self.eat("I")
        self.eat("F")
        if self.look(2) == "$$Q":
            pass
        # WinRT 帽指针 "PE$AA".."PE$AD"：'$' 不是成员指针的限定符字母，
        # 必须在这里识别出来并判为「非成员指针」，否则会误抛 _Fail，
        # 导致所有含帽指针的符号（实测 133 条）整条解析失败。
        # 注意必须用 _HAT_CV（$AA/$AB/$AC/$AD 四个码位），旧实现只判
        # "$AA"/"$AB"，于是 $AC（volatile 帽）和 $AD（const volatile 帽）
        # 仍然抛 _Fail —— 语料里的 4 条全挂。
        if self.look(3) in _HAT_CV:
            self.i = start
            return False, 0
        c3 = self.at(self.i)
        self.i = start
        if c3 in "ABCD" or c3 == "":
            return False, 0
        if c3 in "QRST":
            return True, 0
        raise _Fail

    # ---- 类型解析 ----
    def parse_type(self, qmm="drop"):
        """qmm: 'mangle' 读限定符 | 'result' 仅当有前导 ? | 'drop' 不读"""
        self.guard()
        quals = 0
        if qmm == "mangle":
            quals, _ = self.qualifiers()
        elif qmm == "result":
            if self.eat("?"):
                quals, _ = self.qualifiers()

        if self.done():
            raise _Fail

        c = self.look(1)
        if c in "TUVW":
            ty = self.class_type()
        elif self.look(3) == "$$Q" or c in "APQRS":
            # 右值引用是 3 个字符的 "$$Q"，必须先按 3 字符前缀判断；
            # 旧代码写成 `c == "$$Q"`，而 c 只取了 1 个字符，永远不成立，
            # 导致所有含右值引用的符号（实测语料里 23 条，全是
            # basic_iostream/istream/ostream 的移动构造与移动赋值）直接失败。
            is_mem, _ = self._is_member_ptr()
            if is_mem:
                ty = self.member_pointer_type()
            else:
                ty = self.pointer_type()
        elif c == "Y":
            ty = self.array_type()
        elif self.look(7) == "$$A8@@":
            self.take(7)
            ty = self.function_type(True)
        elif self.look(4) == "$$A6":
            self.take(4)
            ty = self.function_type(False)
        elif c == "?":
            ty = self.custom_type()
        else:
            ty = self.primitive_type()

        ty.quals = getattr(ty, "quals", 0) | quals
        return ty

    def qualifiers(self):
        """<qualifiers>：成员 QRST，非成员 ABCD。返回 (位, 是否成员)。"""
        c = self.look(1)
        if not c:
            raise _Fail
        self.take(1)
        if c == "Q":
            return _Q_NONE, True
        if c == "R":
            return _Q_CONST, True
        if c == "S":
            return _Q_VOLATILE, True
        if c == "T":
            return _Q_CONST | _Q_VOLATILE, True
        if c == "A":
            return _Q_NONE, False
        if c == "B":
            return _Q_CONST, False
        if c == "C":
            return _Q_VOLATILE, False
        if c == "D":
            return _Q_CONST | _Q_VOLATILE, False
        raise _Fail

    def ptr_ext_quals(self):
        q = 0
        if self.eat("E"):
            q |= _Q_POINTER64
        if self.eat("I"):
            q |= _Q_RESTRICT
        if self.eat("F"):
            q |= _Q_UNALIGNED
        return q

    def ptr_cv_quals(self):
        if self.eat("$$Q"):
            return _Q_NONE, _AFF_RVALUE
        c = self.look(1)
        if not c:
            raise _Fail
        self.take(1)
        if c == "A":
            return _Q_NONE, _AFF_REFERENCE
        if c == "P":
            return _Q_NONE, _AFF_POINTER
        if c == "Q":
            return _Q_CONST, _AFF_POINTER
        if c == "R":
            return _Q_VOLATILE, _AFF_POINTER
        if c == "S":
            return _Q_CONST | _Q_VOLATILE, _AFF_POINTER
        raise _Fail

    def primitive_type(self):
        if self.eat("$$T"):
            return _Prim("std::nullptr_t")
        c = self.look(1)
        if not c:
            raise _Fail
        self.take(1)
        if c in _MSVC_PRIM:
            return _Prim(_MSVC_PRIM[c])
        if c == "_":
            c2 = self.look(1)
            if c2 in _MSVC_PRIM_US:
                self.take(1)
                return _Prim(_MSVC_PRIM_US[c2])
        raise _Fail

    def class_type(self):
        c = self.take(1)
        if c not in _MSVC_TAG:
            raise _Fail
        if c == "W":
            if not self.eat("4"):
                raise _Fail
        return _Tag(_MSVC_TAG[c], self.fully_qualified_type_name())

    def pointer_type(self):
        quals, aff = self.ptr_cv_quals()
        if self.eat("6"):
            return _Ptr(self.function_type(False), quals, aff)
        quals |= self.ptr_ext_quals()
        # WinRT 帽指针（hat）：紧跟在指针限定符之后。
        #   PE$AAVString@Platform@@ -> class Platform::String ^ __ptr64
        #   PE$ABVString@Platform@@ -> class Platform::String const ^ __ptr64
        #   PE$ACVString@Platform@@ -> class Platform::String volatile ^ ...
        #   PE$ADVString@Platform@@ -> class Platform::String const volatile ^ ...
        #   QE$AAVString@Platform@@ -> class Platform::String ^ __ptr64 const
        # 这是 MSVC 对 C++/CX 的私有扩展，LLVM 的 MicrosoftDemangle **没有**
        # 实现，语义靠实测穷举（见 _HAT_CV）。要点：$Ax 之后紧跟的就是
        # pointee 类型，**不再读限定符**（用 qmm="drop"），否则会把
        # 'V'/'U' 当成限定符字母而抛 _Fail。
        hat = self.look(3)
        if hat in _HAT_CV:
            self.take(3)
            return _Ptr(self.parse_type("drop"), quals, aff, hat=True,
                        hat_cv=_HAT_CV[hat])
        pointee = self.parse_type("mangle")
        return _Ptr(pointee, quals, aff)

    def member_pointer_type(self):
        quals, aff = self.ptr_cv_quals()
        quals |= self.ptr_ext_quals()
        if self.eat("8"):
            # LLVM: demangleMemberPointerType 的 '8' 分支是
            #   ClassParent = demangleFullyQualifiedTypeName(M)
            #   Pointee     = demangleFunctionType(M, /*HasThisQuals=*/true)
            # 注意 HasThisQuals=true 表示**要**读 `E`/`I`/`F` 扩展限定符、
            # 引用限定符和 cv 限定符（不能用 skip_this_quals），因为那个
            # `E` 就是尾部的 `__ptr64`。实测：
            #   ?f@@YAXP8C@@EAA_NXZ@Z
            #     -> void __cdecl f(bool (__cdecl C::*)(void) __ptr64)
            # 这里 `E`->__ptr64、`A`->无cv、`A`->__cdecl、`_N`->bool、`X`->void。
            # 旧代码传 skip_this_quals=True，于是 `E` 被当成 __thiscall 调用
            # 约定吃掉，后面全部错位，含 P8 的符号（实测 104+32 条）全失败。
            parent = self.fully_qualified_type_name()
            return _Ptr(self.function_type(True), quals, aff,
                        class_parent=parent)
        pointee_quals, _ = self.qualifiers()
        parent = self.fully_qualified_type_name()
        pointee = self.parse_type("drop")
        pointee.quals = getattr(pointee, "quals", 0) | pointee_quals
        return _Ptr(pointee, quals, aff, class_parent=parent)

    def array_type(self):
        self.expect("Y")
        rank, neg = self.number()
        if neg or rank == 0:
            raise _Fail
        dims = []
        for _ in range(rank):
            d, neg = self.number()
            if neg:
                raise _Fail
            dims.append(d)
        quals = 0
        if self.eat("$$C"):
            quals, is_mem = self.qualifiers()
            if is_mem:
                raise _Fail
        elem = self.parse_type("drop")
        return _Arr(elem, dims, quals)

    def custom_type(self):
        self.expect("?")
        ident = self.unqualified_type_name(True)
        if not self.eat("@"):
            raise _Fail
        o = _Out()
        ident.out(o, _OF_DEFAULT)
        return _Custom(o.s)

    def function_type(self, has_this: bool, skip_this_quals: bool = False):
        """<function-type>

        skip_this_quals=True 表示调用方是 x64 成员函数的四字母头，此时
        __ptr64 / cv / 调用约定都已经在 function_class 里读过了。
        """
        sig = _FuncSig()
        if has_this and not skip_this_quals:
            sig.quals = self.ptr_ext_quals()
            # C++/CX 帽指针的成员函数：'E'（__ptr64 标记）之后允许紧跟
            # $AA/$AB/$AC/$AD 来**替代** cv 字母。实测（dbghelp 为唯一权威）：
            #   QE$AAA@...  == QEAA A@...   ($AA → cv 无，  cc='A')
            #   QE$ABA@...  == QEBA A@...   ($AB → cv const, cc='A')
            #   QE$ADVObject@2@@Z
            #       -> class Platform::Object const volatile __unaligned ^
            #          __ptr64 const
            # 也就是说 $Ax 占掉的是 <qualifiers> 那一格，后面的字母
            # 直接就是 <calling-convention>。因此命中时必须**跳过**
            # qualifiers() 的读取，否则会把 'A'(cc) 误当 cv 吃掉，
            # 再让 'A'/'@' 错位，导致构造函数被当成静态函数、参数被当成
            # 返回值（实测 133 条帽指针符号全错）。
            # 位置也固定：只能紧跟 'E'，写成 QEAA$AAA / SA$AAA / YA$AAA
            # 都会被 dbghelp 判为不可解。这是 LLVM 未实现的私有扩展
            # （LLVM 在 '$' 处直接判失败）。
            hat_cv = False
            tail = self.look(3)
            if tail in _HAT_CV:
                self.take(3)
                sig.quals |= _HAT_CV[tail]
                sig.cx_head_cv = True
                hat_cv = True
            if self.eat("G"):
                sig.ref_qual = "&"
            elif self.eat("H"):
                sig.ref_qual = "&&"
            if not hat_cv:
                q, _ = self.qualifiers()
                sig.quals |= q
        if not skip_this_quals:
            sig.cc = self.calling_convention()
        is_structor = self.eat("@")
        if not is_structor:
            sig.ret = self.parse_type("result")
        sig.params, sig.variadic = self.param_list()
        sig.is_noexcept = self.throw_spec()
        return sig

    def calling_convention(self):
        c = self.look(1)
        if not c:
            raise _Fail
        self.take(1)
        return _MSVC_CC_NAME.get(c, "")

    def throw_spec(self):
        if self.eat("_E"):
            return True
        if self.eat("Z"):
            return False
        raise _Fail

    def param_list(self):
        if self.eat("X"):
            return None, False
        params = []
        variadic = False
        while True:
            c = self.look(1)
            if c in ("@", "Z") or c == "":
                break
            if c.isdigit():
                n = int(c)
                if n >= len(self.fparams):
                    raise _Fail
                self.take(1)
                params.append(self.fparams[n])
                continue
            start = self.i
            ty = self.parse_type("drop")
            consumed = self.i - start
            if consumed == 0:
                raise _Fail
            params.append(ty)
            if len(self.fparams) <= 9 and consumed > 1:
                self.fparams.append(ty)
        if self.eat("@"):
            return params, variadic
        if self.eat("Z"):
            return params, True
        raise _Fail

    # ---- 模板参数 ----
    def template_param_list(self):
        params = []
        while not self.look(1) == "@":
            if not self.look(1):
                raise _Fail
            if self.eat("$S") or self.eat("$$V") or self.eat("$$$V") or self.eat("$$Z"):
                continue
            is_auto = self.eat("$M")
            if is_auto:
                self.parse_type("drop")
            self._template_param(params, is_auto)
        self.eat("@")
        return params

    def _template_param(self, params, is_auto):
        if self.eat("$$Y"):
            params.append(self.fully_qualified_type_name())
            return
        if self.eat("$$B"):
            params.append(self.parse_type("drop"))
            return
        if self.eat("$$C"):
            # LLVM: `$$C` = "Type has qualifiers"（模板实参专用前缀）。
            # 用 _QualArg 包一层，让模板收尾 '>' 前补一个空格以对齐 dbghelp。
            params.append(_QualArg(self.parse_type("mangle")))
            return
        if self.look(2) == "$E":
            self.take(2)
            params.append(self._ref_template_param())
            return
        if self.look(2) in ("$1", "$H", "$I", "$J") and not is_auto:
            self.take(2)
            params.append(self._member_fn_template_param(is_auto))
            return
        if self.look(2) in ("$F", "$G") and not is_auto:
            self.take(2)
            params.append(self._member_data_template_param())
            return
        if self.look(2) == "$0" and not is_auto:
            self.take(2)
            v, neg = self.number()
            params.append(_Named(("-" if neg else "") + str(v)))
            return
        params.append(self.parse_type("drop"))

    def _ref_template_param(self):
        sym = self.parse_symbol_here()
        o = _Out()
        o.w("&")
        sym.out(o, _OF_DEFAULT)
        return _Named(o.s)

    def _member_fn_template_param(self, is_auto):
        """成员函数指针型模板实参：`$1` / `$H` / `$I` / `$J`。

        调用方（_template_param）已经吃掉了 `$` 和继承说明符两个字符，
        所以这里**不能**再 take(1) —— 那样会把符号开头的 `?` 当说明符吃掉，
        导致后续全部错位（实测 112 条含 $1/$H/$I/$J 的符号全废）。
        修正前后对比：
            输入        ?$SimpleInstanceFactory@$1?NewLarvalArray@...XZ@
            调用方游标   ^ 指向 '$'
            调用后游标   ^ 指向 '?'（即 spec 已消费）
        LLVM 的 demangleTemplateParameterList 也是在这里
        `MangledName.remove_prefix(1)` 只删一个 '$'，说明符留给
        InheritanceSpecifier = MangledName.front() 再删。

        输出形态（dbghelp 为权威）：
            class SimpleInstanceFactory<&public: static struct ISerializable *
                __ptr64 __cdecl UnBCL::_::StaticArrayOps<unsigned char>::
                NewLarvalArray(void)>
        即 `&` + 完整解出的符号 + 继承/偏移（H/I/J 才有）。
        """
        spec = self.at(self.i)
        sym = None
        if self.look(1) == "?":
            sym = self.parse_symbol_here()
            memo = getattr(sym, "name", None)
            if memo is not None:
                self.memorize_node(memo)
        offs = []
        # 继承说明符：1 单继承（无偏移）、H 多继承（1 个）、
        # I 虚继承（2 个）、J 未指定（3 个）。
        order = {"1": 1, "H": 2, "I": 3, "J": 4}.get(spec, 0)
        for _ in range(order - 1):
            offs.append(self.sign())
        o = _Out()
        o.w("&")
        for x in offs:
            o.w(str(x) + ",")
        if sym is not None:
            sym.out(o, _OF_DEFAULT)
        return _Named(o.s)

    def _member_data_template_param(self):
        """数据成员指针型模板实参：`$F`（1 个偏移）/ `$G`（2 个偏移）。

        同 _member_fn_template_param：调用方已经吃掉 `$` 和说明符，
        这里只能读不能 take，输出形如 `8BDXE,2`（偏移,偏移）。
        """
        spec = self.at(self.i)
        offs = []
        order = {"F": 2, "G": 3}.get(spec, 0)
        for _ in range(order - 1):
            offs.append(self.sign())
        o = _Out()
        for x in offs:
            o.w(str(x) + ",")
        return _Named(o.s)

    # ---- 符号 ----
    def parse_symbol_here(self):
        """在当前位置解析一个完整符号（用于局部作用域/模板参数引用）。"""
        if self.look(1) == ".":
            self.take(1)
            ty = self.parse_type("result")
            if not self.done():
                raise _Fail
            return _RttiTypeDesc(ty, "`RTTI Type Descriptor Name'")
        self.expect("?")
        return self.parse_symbol_body()

    def parse_symbol_body(self):
        """已经吃掉开头的 '?'。

        注意：MSVC 的特殊符号在这里还剩一个前导 '?'，例如完整符号
        `??_7Test@@6B@` 被外层吃掉第一个 '?' 之后是 `?_7Test@@6B@`，
        所以前缀要连 '?' 一起匹配（LLVM 的 consumeSpecialIntrinsicKind
        也是这么写的）。
        """
        # 特殊内在符号
        for pre, kind in (("?_7", "vftable"), ("?_8", "vbtable"),
                          ("?_S", "local vftable"), ("?_R4", "RTTI COL")):
            if self.look(len(pre)) == pre:
                save = self.i
                self.take(len(pre))
                try:
                    return self._special_table(kind)
                except _Fail:
                    self.i = save
        if self.look(3) == "?_9":
            self.take(3)
            return self._vcall_thunk()
        if self.look(3) == "?_B":
            self.take(3)
            return self._local_static_guard(False)
        if self.look(4) == "?__J":
            self.take(4)
            return self._local_static_guard(True)
        if self.look(4) == "?_R0":
            self.take(4)
            ty = self.parse_type("result")
            if not self.eat("@8") or not self.done():
                raise _Fail
            return _RttiTypeDesc(ty, "`RTTI Type Descriptor'")
        if self.look(4) in ("?_R2", "?_R3"):
            label = ("`RTTI Base Class Array'" if self.look(4) == "?_R2"
                     else "`RTTI Class Hierarchy Descriptor'")
            self.take(4)
            return self._untyped_var(label)
        if self.look(4) == "?_R1":
            self.take(4)
            return self._rtti_base_class_desc()
        if self.look(4) in ("?__E", "?__F"):
            is_dtor = self.look(4) == "?__F"
            self.take(4)
            return self._init_fini(is_dtor)
        if self.look(3) == "?_C":
            self.take(3)
            return self._string_literal()
        if self.look(3) in ("?_A", "?_P"):
            raise _Fail
        return self.declarator()

    def _special_table(self, kind):
        label = {"vftable": "`vftable'", "vbtable": "`vbtable'",
                 "local vftable": "`local vftable'",
                 "RTTI COL": "`RTTI Complete Object Locator'"}[kind]
        qn = self.name_scope_chain(_Named(label))
        if self.done():
            raise _Fail
        front = self.take(1)
        if front not in ("6", "7"):
            raise _Fail
        quals, _ = self.qualifiers()
        targets = []
        while not self.eat("@"):
            targets.append(self.fully_qualified_type_name())
        return _SpecialTable(qn, quals, targets or None)

    def _vcall_thunk(self):
        qn = self.name_scope_chain(_VcallThunk(0))
        if not self.eat("$B"):
            raise _Fail
        off = self.unsign()
        if not self.eat("A"):
            raise _Fail
        sig = _FuncSig()
        sig.fc = _FC_NO_PARAMETER_LIST
        sig.cc = self.calling_convention()
        thunk = _VcallThunk(off)
        qn.parts[-1] = thunk
        return _FuncSym(sig, qn)

    def _local_static_guard(self, is_thread):
        ident = _LocalStaticGuard(is_thread)
        qn = self.name_scope_chain(ident)
        if self.eat("4IA"):
            pass
        elif not self.eat("5"):
            raise _Fail
        if not self.done():
            ident.scope_index = self.unsign()
        return _VarSym(access=None, is_static=False, ty=None, name=qn)

    def _untyped_var(self, label):
        qn = self.name_scope_chain(_Named(label))
        if not self.eat("8"):
            raise _Fail
        return _VarSym(access=None, is_static=False, ty=None, name=qn)

    def _rtti_base_class_desc(self):
        nv = self.unsign()
        vbp = self.sign()
        vbt = self.unsign()
        fl = self.unsign()
        qn = self.name_scope_chain(_Named("`RTTI Base Class Descriptor'"))
        self.eat("8")
        return _RttiBaseClassDesc(nv, vbp, vbt, fl, qn)

    def _init_fini(self, is_dtor):
        node = _DynInit(is_dtor)
        known_static = self.eat("?")
        sym = self.parse_declarator()
        if isinstance(sym, _VarSym):
            node.var_name = sym.name
            for _ in range(2 if known_static else 1):
                if not self.eat("@"):
                    raise _Fail
            sig = self.function_encoding()
            node.fn = _FuncSym(sig)
            return node
        if known_static:
            raise _Fail
        node.fn = sym
        node.var_name = sym.name
        return node

    def _string_literal(self):
        if not self.eat("@_"):
            raise _Fail
        ch = self.take(1)
        if ch not in ("0", "1"):
            raise _Fail
        is_wchar = ch == "1"
        size, neg = self.number()
        if neg or size < (2 if is_wchar else 1):
            raise _Fail
        j = self.s.find("@", self.i)
        if j < 0:
            raise _Fail
        crc = self.s[self.i:j]
        self.i = j + 1
        if self.done():
            raise _Fail
        # 解析字符序列
        chars = []
        if is_wchar:
            while not self.eat("@"):
                if size % 2 or size == 0 or len(self.rest()) < 2:
                    raise _Fail
                code = int(self.take(2), 16)
                size -= 2
                chars.append(chr(code) if code else "")
        else:
            while not self.eat("@"):
                if size == 0:
                    raise _Fail
                code = int(self.take(2), 16)
                size -= 1
                chars.append(chr(code) if code else "")
        text = "".join(chars)
        kind = 'L' if is_wchar else ''
        return _Raw('`string\'{%s"%s"}' % (kind, text))

    # ---- 声明符 ----
    def declarator(self):
        qn, ident = self.fully_qualified_symbol_name()
        sym = self.encoded_symbol(qn, ident)
        if isinstance(sym, _FuncSym) and sym.name is None:
            sym.name = qn
        elif isinstance(sym, _VarSym) and sym.name is None:
            sym.name = qn
        return sym

    def parse_declarator(self):
        return self.declarator()

    def encoded_symbol(self, qn, ident):
        if self.done():
            raise _Fail
        c = self.look(1)
        if c in "01234":
            access, is_static = _MSVC_STORE_NAME[self.take(1)]
            ty = self.parse_type("drop")
            if isinstance(ty, _Ptr):
                extra = self.ptr_ext_quals()
                ty.quals |= extra
                pointee_quals, _ = self.qualifiers()
                if ty.class_parent is not None:
                    self.fully_qualified_type_name()
                ty.pointee.quals = getattr(ty.pointee, "quals", 0) | pointee_quals
            else:
                ty.quals = getattr(ty, "quals", 0) | self.qualifiers()[0]
            return _VarSym(access=access, is_static=is_static, ty=ty)
        sig = self.function_encoding()
        if isinstance(ident, _ConvOp) and sig.ret is not None:
            ident.target = sig.ret
        return _FuncSym(sig)

    def function_class(self):
        """<function-class>：LLVM 的 F 字符表。

        x64 成员函数的头部是 `<access>E<cv><cc>`，其中那个 'E' 在 LLVM 的
        表里表示 private+virtual，但实测它同时充当 __ptr64 标志。为了与
        dbghelp 输出一致，这里先探测「access + 'E' + cv + cc」这一四字母
        形态，命中时把 E 记为 __ptr64 并从 class 表中剔除。
        """
        self._pending_ptr64 = False
        # 探测 x64 成员函数四字母头：<access> E <cv> <cc>  例如 QEAA
        head = self.look(4)
        if (len(head) == 4 and "A" <= head[0] <= "X" and head[1] == "E"
                and head[2] in "ABCD" and head[3] in _MSVC_CC_NAME):
            self.take(4)
            self._pending_ptr64 = True
            c0 = head[0]
            base = _FC_PRIVATE if c0 < "I" else (
                _FC_PROTECTED if c0 < "Q" else _FC_PUBLIC)
            off = ord(c0) - ord("A")
            if off % 8 == 2:
                base |= _FC_STATIC
            elif off % 8 == 4:
                base |= _FC_VIRTUAL
            elif off % 8 == 6:
                base |= _FC_STATIC_THIS_ADJUST
            self._pending_cv = head[2]
            self._pending_cc = _MSVC_CC_NAME[head[3]]
            return base

        c = self.take(1)
        simple = {
            "9": _FC_EXTERN_C | _FC_NO_PARAMETER_LIST,
            "A": _FC_PRIVATE, "B": _FC_PRIVATE | _FC_FAR,
            "C": _FC_PRIVATE | _FC_STATIC,
            "D": _FC_PRIVATE | _FC_STATIC | _FC_FAR,
            "E": _FC_PRIVATE | _FC_VIRTUAL,
            "F": _FC_PRIVATE | _FC_VIRTUAL | _FC_FAR,
            "G": _FC_PRIVATE | _FC_STATIC_THIS_ADJUST,
            "H": _FC_PRIVATE | _FC_STATIC_THIS_ADJUST | _FC_FAR,
            "I": _FC_PROTECTED, "J": _FC_PROTECTED | _FC_FAR,
            "K": _FC_PROTECTED | _FC_STATIC,
            "L": _FC_PROTECTED | _FC_STATIC | _FC_FAR,
            "M": _FC_PROTECTED | _FC_VIRTUAL,
            "N": _FC_PROTECTED | _FC_VIRTUAL | _FC_FAR,
            "O": _FC_PROTECTED | _FC_VIRTUAL | _FC_STATIC_THIS_ADJUST,
            "P": (_FC_PROTECTED | _FC_VIRTUAL | _FC_STATIC_THIS_ADJUST | _FC_FAR),
            "Q": _FC_PUBLIC, "R": _FC_PUBLIC | _FC_FAR,
            "S": _FC_PUBLIC | _FC_STATIC,
            "T": _FC_PUBLIC | _FC_STATIC | _FC_FAR,
            "U": _FC_PUBLIC | _FC_VIRTUAL,
            "V": _FC_PUBLIC | _FC_VIRTUAL | _FC_FAR,
            "W": _FC_PUBLIC | _FC_VIRTUAL | _FC_STATIC_THIS_ADJUST,
            "X": _FC_PUBLIC | _FC_VIRTUAL | _FC_STATIC_THIS_ADJUST | _FC_FAR,
            "Y": _FC_GLOBAL, "Z": _FC_GLOBAL | _FC_FAR,
        }
        if c in simple:
            self._pending_cc = None
            return simple[c]
        if c == "$":
            vflag = _FC_VIRTUAL_THIS_ADJUST
            if self.eat("R"):
                vflag |= _FC_VIRTUAL_THIS_ADJUST_EX
            if self.done():
                raise _Fail
            c2 = self.take(1)
            base = {"0": _FC_PRIVATE, "1": _FC_PRIVATE | _FC_FAR,
                    "2": _FC_PROTECTED, "3": _FC_PROTECTED | _FC_FAR,
                    "4": _FC_PUBLIC, "5": _FC_PUBLIC | _FC_FAR}.get(c2)
            if base is None:
                raise _Fail
            self._pending_cc = None
            return base | _FC_VIRTUAL | vflag
        raise _Fail

    def function_encoding(self):
        extra = _FC_NONE
        if self.eat("$$J0"):
            extra = _FC_EXTERN_C
        self._pending_cc = None
        fc = self.function_class() | extra
        sig = _FuncSig()
        if self._pending_ptr64:
            sig.quals |= _Q_POINTER64
        if self._pending_cc is not None:
            sig.cc = self._pending_cc
        if fc & _FC_STATIC_THIS_ADJUST:
            sig.is_thunk = True
            sig.this_adjust = (self.sign(), "static")
        elif fc & _FC_VIRTUAL_THIS_ADJUST:
            sig.is_thunk = True
            if fc & _FC_VIRTUAL_THIS_ADJUST_EX:
                vbp = self.sign()
                vbo = self.sign()
                vt = self.sign()
                st = self.sign()
                sig.this_adjust = ((vbp, vbo, vt, st), "vtordispex")
            else:
                vt = self.sign()
                st = self.sign()
                sig.this_adjust = ((vt, st), "vtordisp")
        if fc & _FC_NO_PARAMETER_LIST:
            sig.fc = fc
            return sig
        has_this = not (fc & (_FC_GLOBAL | _FC_STATIC))
        inner = self.function_type(has_this, skip_this_quals=self._pending_ptr64)
        inner.fc = fc
        inner.is_thunk = sig.is_thunk
        inner.this_adjust = sig.this_adjust
        if self._pending_ptr64:
            inner.quals |= _Q_POINTER64
            inner.cv_bits = _MSVC_CV_BITS.get(self._pending_cv, 0)
            inner.cc = self._pending_cc
        return inner


# ================================================================ 入口


def _msvc_full(s: str):
    p = _Msvc(s)
    sym = p.parse_symbol_here()
    if not p.done():
        raise _Fail
    o = _Out()
    sym.out(o, _OF_DEFAULT)
    return o.finish()


# ================================================================ Rust


# ================================================================ MSVC 入口
# 上方是完整的 MSVC 引擎（原 _msvc_new.py 搬入）。对外只暴露 _msvc 一个
# 函数：失败返回 None，由 _demangle_inner 的 _try 回退到原符号名 ——
# 这与旧实现的契约一致（旧版也是解不出返回 None，不向上抛异常）。

def _msvc(s):
    """MSVC '?' 符号解码。成功返回字符串，失败返回 None。"""
    try:
        return _msvc_full(s)
    except Exception:
        return None


# ================================================================ Rust

_RUST_ESC = {
    "SP": "@", "BP": "*", "RF": "&", "LT": "<", "GT": ">",
    "LP": "(", "RP": ")", "C": ",",
}

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _rust_legacy_raw(s: str):
    """ZN<elem>+E -> ([elems], consumed)；elem = <len><body>。"""
    out, i, n = [], 2, len(s)
    while i < n and s[i] != "E":
        if not s[i].isdigit():
            return None
        j = i
        while j < n and s[j].isdigit():
            j += 1
        ln = int(s[i:j])
        if ln <= 0 or j + ln > n:
            return None
        out.append(s[j:j + ln])
        i = j + ln
    if i >= n or s[i] != "E":
        return None
    return out, i + 1


def _is_rust_hash(e: str) -> bool:
    return len(e) == 18 and e[0] == "h" and \
        all(c in "0123456789abcdef" for c in e[1:])


def _unescape_rust(elem: str) -> str:
    if elem.startswith("_$"):
        elem = elem[2:]
    elif elem.startswith("_"):
        elem = elem[1:]
    res, k = [], 0
    while k < len(elem):
        if elem[k] == "$":
            end = elem.find("$", k + 1)
            if end > 0:
                code = elem[k + 1:end]
                if code.startswith("u") and len(code) > 1:
                    try:
                        res.append(chr(int(code[1:], 16)))
                        k = end + 1
                        continue
                    except ValueError:  # lint:ok 非十六进制则退回落字面量分支
                        # $uXXXX 里不是合法十六进制 → 不是 Unicode 转义，
                        # 退回落字面量走下面的通用分支。
                        pass
                elif code in _RUST_ESC:
                    res.append(_RUST_ESC[code])
                    k = end + 1
                    continue
        if elem.startswith("..", k):
            res.append("::")
            k += 2
            continue
        res.append(elem[k])
        k += 1
    return "".join(res)


def _rust_legacy(s: str) -> str:
    """Rust legacy：ZN<path>E，尾部 17h<hash>E 的 hash 丢掉。"""
    if not s.startswith("ZN"):
        raise _Fail
    r = _rust_legacy_raw(s)
    if r is None:
        return None
    elems, consumed = r
    if not elems:
        raise _Fail
    if _is_rust_hash(elems[-1]):
        elems = elems[:-1]
    parts = [_unescape_rust(e) for e in elems]
    out = "::".join(p for p in parts if p)
    tail = s[consumed:]
    if tail:
        out += tail if tail.startswith(".") else ""
    return out or None

class _RV0:
    """
    Rust v0 解析器。严格照 rustc-demangle/src/v0.rs 的结构实现，
    与官方文档一致（不受我自己的猜测干扰）：

      ident        = [u] <十进制长度> [_可选] <len 字节>
      disambiguator= [s] <base62 到 '_'> + 1     （没有 s 就是 0）
      integer_62   = '_' 则 0，否则 base62 累积到 '_' 后 +1
      namespace    = A-Z -> 特殊命名空间 / a-z -> 实现相关
      path         = C dis ident
                   | N ns path dis ident
                   | M|X|Y ...
                   | I path generic-args
                   | B <backref>（未实现，直接放弃）
    """

    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.out: list[str] = []
        self.depth = 0

    # ---- 基础 ----
    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def take(self):
        if self.i >= len(self.s):
            raise _Fail
        c = self.s[self.i]
        self.i += 1
        return c

    def eat(self, tok):
        if self.s.startswith(tok, self.i):
            self.i += len(tok)
            return True
        return False

    def done(self):
        return self.i >= len(self.s)

    def rest(self):
        return self.s[self.i:]

    def guard(self):
        """进入一层解析时调用，累计计数并在超限时中止。

        注意：这里是**累计计数**，出来不减 —— 详见 _MAX_DEPTH 处的说明。
        别照着"深度"的名字去给它加 try/finally 递减：那样会让预算限制失效。
        """
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _Fail

    def digit10(self, mult=False):
        c = self.peek()
        if not c or not c.isdigit():
            raise _Fail
        self.i += 1
        return int(c)

    def integer_62(self) -> int:
        if self.eat("_"):
            return 0
        x = 0
        while True:
            c = self.take()
            if c == "_":
                break
            if c not in _B62:
                raise _Fail
            x = x * 62 + _B62.index(c)
        return x + 1

    def disambiguator(self) -> int:
        if not self.eat("s"):
            return 0
        return self.integer_62() + 1

    def ident(self) -> str:
        puny = self.eat("u")
        c = self.peek()
        if not c or not c.isdigit():
            raise _Fail
        n = 0
        while self.peek() and self.peek().isdigit():
            n = n * 10 + int(self.take())
        self.eat("_")                       # 可选分隔符，吃不吃都行
        body = self.s[self.i:self.i + n]
        if len(body) != n:
            raise _Fail
        self.i += n
        if not puny:
            return body
        # punycode：最后一个 '_' 之前是 ASCII 部分，之后是 punycode
        if "_" in body:
            ascii_part, puny_part = body.rsplit("_", 1)
        else:
            ascii_part, puny_part = "", body
        if not puny_part:
            raise _Fail
        return ascii_part + _punycode_decode(puny_part)

    def namespace(self):
        c = self.take()
        if "A" <= c <= "Z":
            return c
        if "a" <= c <= "z":
            return None
        raise _Fail

    def sep_list(self, fn, sep):
        n = 0
        while not self.done() and self.peek() != "E":
            if n:
                self.out.append(sep)
            fn()
            n += 1
        if self.peek() == "E":
            self.i += 1
        return n

    def skipped(self, fn):
        """解析但不输出（X/M 标签里 impl 自身的路径）。"""
        mark = len(self.out)
        try:
            fn()
        finally:
            del self.out[mark:]

    # ---- path ----
    def path(self, in_value: bool = False):
        self.guard()
        tag = self.take()
        if tag == "C":
            dis = self.disambiguator()
            name = self.ident()
            self.out.append(name)
            if dis:
                self.out.append("[" + format(dis, "x") + "]")
            return
        if tag == "N":
            ns = self.namespace()
            self.path(in_value)
            dis = self.disambiguator()
            name = self.ident()
            if ns is not None:
                label = {"C": "closure", "S": "shim"}.get(ns, ns)
                self.out.append("::{" + label)
                if name:
                    self.out.append(":" + name)
                self.out.append("#" + str(dis) + "}")
            elif name:
                self.out.append("::" + name)
            return
        if tag in ("M", "X", "Y"):
            if tag != "Y":
                self.disambiguator()
                self.skipped(lambda: self.path(False))
            self.out.append("<")
            self.ty()
            if tag != "M":
                self.out.append(" as ")
                self.path(False)
            self.out.append(">")
            return
        if tag == "I":
            self.path(in_value)
            if in_value:
                self.out.append("::")
            self.out.append("<")
            self.sep_list(self.generic_arg, ", ")
            self.out.append(">")
            return
        if tag == "B":
            raise _Fail      # backref 不实现：宁可原样返回，不输出半截结果
        raise _Fail

    def generic_arg(self):
        c = self.peek()
        if c == "L":
            self.i += 1
            lt = self.integer_62()
            self.out.append("'" + ("_" if lt == 0 else _lifetime_name(lt)))
            return
        if c == "K":
            self.i += 1
            self.const()
            return
        self.ty()

    # ---- 常量 ----
    def const(self):
        c = self.peek()
        if c == "p":
            self.i += 1
            self.out.append("_")
            return
        if c == "b":
            self.i += 1
            j = self.s.find("_", self.i)
            if j < 0:
                raise _Fail
            self.out.append("true" if self.s[self.i:j] == "1" else "false")
            self.i = j + 1
            return
        if c == "c":
            self.i += 1
            j = self.s.find("_", self.i)
            if j < 0:
                raise _Fail
            try:
                self.out.append("'" + chr(int(self.s[self.i:j], 16)) + "'")
            except ValueError:
                self.out.append("?")
            self.i = j + 1
            return
        if c == "e":
            self.i += 1
            self.out.append('"')
            while True:
                c = self.peek()
                if c in ("", "_"):
                    break
                self.out.append(self.take())
            self.eat("_")
            self.out.append('"')
            return
        neg = False
        if c == "n":
            self.i += 1
            neg = True
            c = self.peek()
        ty = _RV0_BASIC.get(c, "")
        if ty in ("i8", "i16", "i32", "i64", "i128", "isize",
                  "u8", "u16", "u32", "u64", "u128", "usize", "char"):
            self.i += 1
            j = self.s.find("_", self.i)
            if j < 0:
                raise _Fail
            body = self.s[self.i:j]
            self.i = j + 1
            try:
                self.out.append(("-" if neg else "") + str(int(body, 16)))
            except ValueError:
                self.out.append(("-" if neg else "") + "0x" + body.upper())
            return
        if self.peek().isupper():
            self.out.append("const{")
            self.path(False)
            self.out.append("}")
            return
        raise _Fail

    # ---- 类型 ----
    def ty(self):
        self.guard()
        if self.eat("w"):
            self.out.append("#[splat] ")
        tag = self.take()
        if tag in _RV0_BASIC:
            self.out.append(_RV0_BASIC[tag])
            return
        if tag in ("R", "Q"):
            self.out.append("&")
            if self.eat("L"):
                lt = self.integer_62()
                if lt:
                    self.out.append(_lifetime_name(lt) + " ")
            if tag != "R":
                self.out.append("mut ")
            self.ty()
            return
        if tag in ("P", "O"):
            self.out.append("*const " if tag == "P" else "*mut ")
            self.ty()
            return
        if tag in ("A", "S"):
            self.out.append("[")
            self.ty()
            if tag == "A":
                self.out.append("; ")
                self.const()
            self.out.append("]")
            return
        if tag == "T":
            self.out.append("(")
            n = self.sep_list(self.ty, ", ")
            if n == 1:
                self.out.append(",")
            self.out.append(")")
            return
        if tag == "F":
            unsafe_ = self.eat("U")
            abi = None
            if self.eat("K"):
                if self.eat("C"):
                    abi = "C"
                else:
                    abi = self.ident().replace("_", "-")
            if unsafe_:
                self.out.append("unsafe ")
            if abi:
                self.out.append('extern "' + abi + '" ')
            self.out.append("fn(")
            self.sep_list(self.ty, ", ")
            self.out.append(")")
            if self.eat("u"):
                pass                       # 返回类型 ()
            else:
                self.out.append(" -> ")
                self.ty()
            return
        if tag == "D":
            self.out.append("dyn ")
            self.sep_list(self.dyn_trait, " + ")
            if not self.eat("L"):
                raise _Fail
            lt = self.integer_62()
            if lt:
                self.out.append(" + " + _lifetime_name(lt))
            return
        if tag == "B":
            raise _Fail
        if tag == "W":
            self.ty()
            self.out.append(" is ")
            self.pat()
            return
        # 不是已知类型标签：退回一格，当 path 解
        self.i -= 1
        self.path(False)
        return

    def dyn_trait(self):
        self.path(False)
        inner = False
        while True:
            c = self.peek()
            if c == "p":
                self.i += 1
                continue
            if c == "I":
                self.i += 1
                self.path(False)
                inner = True
                continue
            break
        if inner:
            self.out.append("::")
        while not self.done() and self.peek() != "E":
            self.generic_arg()

    def pat(self):
        # 常量模式：能力有限，直接把剩余到 'E' 的部分吞掉
        depth = 0
        while not self.done():
            c = self.peek()
            if c == "E" and depth <= 0:
                return
            self.take()


def _lifename_from_index(idx: int) -> str:
    return _lifetime_name(idx)


_RV0_BASIC = {
    "b": "bool", "c": "char", "e": "str", "u": "()",
    "a": "i8", "s": "i16", "l": "i32", "x": "i64", "n": "i128", "i": "isize",
    "h": "u8", "t": "u16", "m": "u32", "y": "u64", "o": "u128", "j": "usize",
    "f": "f32", "d": "f64", "z": "!", "p": "_", "v": "...",
}


def _lifetime_name(idx: int) -> str:
    """生命周期编号 -> 名字。binder 深度未精确建模，输出 'a/'b/.../'_N。"""
    if idx <= 0:
        return "_"
    if idx <= 26:
        return chr(ord("a") + idx - 1)
    return "_" + str(idx)


def _rust_v0(s: str) -> str:
    """
    Rust v0：_R / __R / R + <path>。
    只识别第一段 path；后面若还有内容（第二段 path 或 .llvm.xxx 后缀），
    按 rustc 的做法原样接在后面 —— 信息保留，不虚构。
    """
    if len(s) < 3 or not s.startswith("R"):
        raise _Fail
    body = s[1:]
    if not (body[0].isupper() and body.isascii()):
        raise _Fail
    p = _RV0(body)
    p.path(True)
    return "".join(p.out) + p.rest()


# ---- punycode（Rust v0 的非 ASCII 标识符）----
_PUNY_BASE, _PUNY_TMIN, _PUNY_TMAX = 36, 1, 26
_PUNY_SKEW, _PUNY_DAMP = 38, 700


def _puny_adapt(delta, numpoints, firsttime):
    if firsttime:
        delta //= _PUNY_DAMP
    else:
        delta //= 2
    delta += delta // numpoints
    k = 0
    while delta > ((_PUNY_BASE - _PUNY_TMIN) * _PUNY_TMAX) // 2:
        delta //= _PUNY_BASE - _PUNY_TMIN
        k += _PUNY_BASE
    return k + (((_PUNY_BASE - _PUNY_TMIN + 1) * delta) // (delta + _PUNY_SKEW))


def _punycode_decode(s: str) -> str:
    out: list[str] = []
    n, i, bias = 128, 0, 72
    while i < len(s):
        oldi = i
        w = 1
        k = _PUNY_BASE
        i2 = i
        while True:
            if i >= len(s):
                raise _Fail
            c = s[i]
            i += 1
            if c not in _B62:
                raise _Fail
            d = _B62.index(c)
            i2 = i2 + d * w
            if k <= bias + _PUNY_TMIN:
                t = _PUNY_TMIN
            elif k >= bias + _PUNY_TMAX:
                t = _PUNY_TMAX
            else:
                t = k - bias
            if d < t:
                break
            w = w * (_PUNY_BASE - t)
            k += _PUNY_BASE
        out_len = len(out) + 1
        bias = _puny_adapt(i2 - oldi, out_len, oldi == 0)
        n = n + i2 // out_len
        i = i2 % out_len
        out.insert(i, chr(n))
    return "".join(out)
