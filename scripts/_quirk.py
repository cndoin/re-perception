# -*- coding: utf-8 -*-
"""dbghelp 已知缺陷清单 —— **参考文档**，不是运行时模块。

一句话结论：**「与 dbghelp 逐字一致」不是正确性标准。**
dbghelp 自身至少有 6 个已用最小用例证实的缺陷，向它对齐等于把正确行为
改错。本模块只做一件事：把这些缺陷逐条记录在案，供人工对照时判读差异。

命名为 `_` 前缀是因为它**不被运行时使用**（无 import 方），而不是因为
它是脚手架 —— 它必须随发布分发，见下文「为什么不能挪进 `_dev/`」。

已证实的缺陷（证据来自 LLVM 源码 + C++ 语言规范 + 本项目最小用例）：

  1. `(void)const` —— CV 限定符前不写空格。
     LLVM 的 `FunctionSignatureNode::outputPost` 明确写 `OB << " const"`，
     规范写法是 `(void) const`。dbghelp 漏了空格。

  2. `(void)volatile` 与上条同理。

  3. 变量尾部 storage class 的 `E` 与指针自身的 `E` 重复输出，
     得到 `int * __ptr64 __ptr64 x`。
     最小用例：`?x@@3PEAHEA` 得到双 `__ptr64`，而 `?x@@3PEAH@Z` 只有一个，
     可见是重复。实测语料里这一类 26 条，形态固定为变量（`@@3PE..E..`）。

  4. 函数指针返回类型里 `*` 与调用约定之间不写空格：
     `(__cdecl*__cdecl f(void))(void)`。

  5. **返回值位置的指针丢失自身的 const。**
     最小对照（同一个指针类型，只换位置）：
       返回值：`?m@C@@QEAAQEAHXZ`        -> `int * __ptr64`        （const 丢了）
       参  数：`?m@C@@QEAAQEAHQEAH@Z`    -> `int * __ptr64 const`  （const 在）
     `Q` 在 `<pointer-cvr-qualifiers>` 里就是 const（LLVM 的
     `demanglePointerCVQualifiers: case 'Q' -> Q_Const`），参数位也照常
     输出，所以返回值位缺 const 是 dbghelp 的 bug。
     语料里这一类 48 条，形态集中在 `operator->()` 与返回 `T*` 的 const
     成员函数上。

  6. **变量自身的 const 被丢掉。**
     最小对照（同一条符号，只把成员指针换成数组）：
       `?PluginNames@QNetworkInformationBackend@@2QAY0BG@$$CB_SA`
         -> `char16_t const (* QNetworkInformationBackend::PluginNames)[22]`
     尾部 storage class 是 `A`（= const 静态成员），但 dbghelp 输出里
     完全看不见这个 const。同一族的还有：
       `?g_rgMouseMap@HWNDHost@DirectUI@@0QAY02$$CBIA`
         -> `unsigned int const (* DirectUI::HWNDHost::g_rgMouseMap)[3]`
       `?GetCreateWizardDialog@Wizard_PageDesciption@@QEAAQ6APEAV...`
         -> `... (__cdecl* Wizard_PageDesciption::GetCreateWizardDialog...)`
     与缺陷 5 同源：dbghelp 在「变量/返回值」位置会丢限定符。
     语料里这一类 3 条（均带数组或成员函数指针的静态 const 成员）。

**伪缺陷（必须澄清，否则会被误当怪癖去「归一化」）：**

  - 嵌套模板的 `> >` 空格**不是**怪癖，是引擎必须实现的正式规则
    （LLVM 的 `outputTemplateParameterList` 在紧邻 `>` 时补空格）。
    本项目历史上曾用一条 `re.sub(r">\\s*>", ">>", s)` 把 `> >` 压成 `>>`
    糊过去 —— 那会掩盖真实回归。删除后准确率不变，反证引擎本身正确。

  - 引用限定符与 `__ptr64` 之间不加空格（`__ptr64&&`）：引擎已按 dbghelp
    对齐，此处仅作记录，无需归一化。

为什么不能挪进 `_dev/`：

  本文件是**发布物**的一等公民 —— `README.md`、`CHANGELOG.md` 与
  `CONTRIBUTING.md` 都把它列为 dbghelp 差异的权威清单，用户读技能时
  需要它。`_dev/` 不随安装分发（见 `_dev/_install.py` 的 `_EXCLUDE_DIRS`），
  挪进去等于把这份证据从交付物里删掉。
  `_dev/_lint.py` 的护栏 9 正是在拦「`_` 模块被挪进 `_dev/`」这类误判。

历史备注：本模块曾含一个 `canon(s)` 函数，用于把上述怪癖归一化后再比对，
以便衡量引擎的**真实**准确率。它从未被任何生产模块或自检用例调用
（`git log -S"canon("` 可复核），且其归一化逻辑本身就是缺陷 6 所警示的
「把正确行为改错」。已删除；本文件现在是纯文档。
"""
