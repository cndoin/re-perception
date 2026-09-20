# -*- coding: utf-8 -*-
"""做一个「知道 dbghelp 怪癖」的比较器，测出真实准确率。

已证实的 dbghelp 怪癖（来自 LLVM 源码 + C++ 语言规范）：
  1. `(void)const` —— dbghelp 在 const 前不写空格。
     LLVM 的 FunctionSignatureNode::outputPost 明确写 `OB << " const"`，
     所以规范写法是 `(void) const`。这是 dbghelp 的 bug。
  2. `(void)volatile` 同理。
把这两处归一化后再比，才反映引擎的真实正确率。
"""
import re


def canon(s):
    """归一化 dbghelp 的已知格式怪癖，便于衡量引擎的真实正确率。

    已用最小用例证实的 dbghelp 缺陷：
      1. `(void)const` —— CV 前不写空格（LLVM 写 " const"）。
      2. 变量尾部 storage class 的 `E` 与指针自身的 `E` 重复输出，
         得到 `int * __ptr64 __ptr64 x`。最小用例：`?x@@3PEAHEA`
         得到双 `__ptr64`，而 `?x@@3PEAH@Z` 只有一个，可见是重复。
         实测语料里这一类 26 条，形态固定为变量（`@@3PE..E..`）。
      3. 函数指针返回类型里 `*` 与调用约定之间不写空格
         （`(__cdecl*__cdecl f(void))(void)`）。
      4. **返回值位置的指针丢失自身的 const。**
         最小对照（同一个指针类型，只换位置）：
           返回值：?m@C@@QEAAQEAHXZ  -> int * __ptr64          （const 丢了）
           参  数：?m@C@@QEAAQEAHQEAH@Z
                                    -> int * __ptr64 const     （const 在）
         `Q` 在 <pointer-cvr-qualifiers> 里就是 const（LLVM 的
         demanglePointerCVQualifiers: case 'Q' -> Q_Const），参数位也照常
         输出，所以返回值位缺 const 是 dbghelp 的 bug。
         语料里这一类 48 条，形态集中在 `operator->()` 与返回 `T*` 的
         const 成员函数上。
      5. 引用限定符与 `__ptr64` 之间**不加**空格：`__ptr64&&`。
         （这一条引擎已按 dbghelp 对齐，无需归一化，仅作记录。）
      6. **变量自身的 const 被丢掉。**
         最小对照（同一条符号，只把成员指针换成数组）：
           ?PluginNames@QNetworkInformationBackend@@2QAY0BG@$$CB_SA
             -> char16_t const (* QNetworkInformationBackend::PluginNames)[22]
         尾部 storage class 是 `A`（= const 静态成员），但 dbghelp 输出里
         完全看不见这个 const。同一族的还有：
           ?g_rgMouseMap@HWNDHost@DirectUI@@0QAY02$$CBIA
             -> unsigned int const (* DirectUI::HWNDHost::g_rgMouseMap)[3]
           ?GetCreateWizardDialog@Wizard_PageDesciption@@QEAAQ6APEAV...
             -> ... (__cdecl* Wizard_PageDesciption::GetCreateWizardDialog...)
         与缺陷 4 同源：dbghelp 在「变量/返回值」位置会丢限定符。
         语料里这一类 3 条（均带数组或成员函数指针的静态 const 成员）。
         **这一条不归一化** —— 引擎按语法正确输出 `(* const ...)` 才是对的，
         归一化等于把正确行为改错，会掩盖引擎自身的退化。

    注意：**嵌套模板的 `> >` 空格不是怪癖**，是引擎必须实现的正式规则
    （LLVM 的 outputTemplateParameterList 在紧邻 `>` 时补空格）。
    这一条曾用一条 re.sub 把 `> >` 压成 `>>` 糊过去，会掩盖真实回归，
    现已删掉 —— 删掉后分数不变，说明引擎本身已经正确。
    """
    if s is None:
        return None
    # 怪癖 1
    s = re.sub(r"\)(const|volatile|__restrict|__unaligned|noexcept)\b",
               r") \1", s)
    # 怪癖 2：连续两个 __ptr64 折叠成一个
    s = re.sub(r"(__ptr64)(\s+__ptr64)+", r"\1", s)
    # 怪癖 3：`*__cdecl` -> `* __cdecl`
    s = re.sub(r"\*(__[a-z]+)\b", r"* \1", s)
    # 怪癖 4：返回值位置指针的 const 被 dbghelp 丢掉。
    # 只在「函数签名起始处、紧邻调用约定的那个指针」上删 const —— 即
    # `* __ptr64 const __cdecl` / `* __ptr64 const <name>::` 这种形态。
    # 参数位不会匹配，因为它们后面跟的是 `,` 或 `)`，不是调用约定。
    s = re.sub(r"\*\s+__ptr64\s+const(\s+__cdecl|\s+__thiscall|\s+__stdcall"
               r"|\s+__fastcall|\s+__vectorcall|\s+__clrcall|\s+__pascal"
               r"|\s+swift\b)", r"* __ptr64\1", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()
