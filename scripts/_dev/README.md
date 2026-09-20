# 开发参考资料（不随发布分发）

本目录存放开发期的脚手架与参考资料，**不属于运行时依赖**，已被
`.gitignore` 排除。删掉整个目录不影响 `re.py` 与 `selftest.py` 运行。

## `_ref/` — LLVM 参考源码

这里原本放着 4 个 LLVM 源文件，用于**对照** MSVC / Itanium 名字修饰的
语法与渲染规则：

| 文件 | 用途 |
|---|---|
| `ItaniumDemangle.cpp` | Itanium ABI 解码语法 |
| `MicrosoftDemangle.cpp` | MSVC 解码语法（我们的主要参照） |
| `MicrosoftDemangleNodes.cpp` | 节点渲染规则（空格、`const` 位置等） |
| `MicrosoftDemangleNodes.h` | 节点结构定义 |

**为什么没有随仓库分发**：这些文件版权归 LLVM 项目所有（Apache-2.0
with LLVM Exceptions），体积约 320 KB，且本项目**并未移植它们的代码**——
只把它们当语法说明书读，MSVC 引擎是照着语法自行实现的。

需要时请自行获取：

```bash
# 任选一个 LLVM 版本，这里以 18.x 为例
curl -L -o _ref/MicrosoftDemangle.cpp \
  https://raw.githubusercontent.com/llvm/llvm-project/release/18.x/lib/Demangle/MicrosoftDemangle.cpp
curl -L -o _ref/MicrosoftDemangleNodes.cpp \
  https://raw.githubusercontent.com/llvm/llvm-project/release/18.x/lib/Demangle/MicrosoftDemangleNodes.cpp
curl -L -o _ref/MicrosoftDemangleNodes.h \
  https://raw.githubusercontent.com/llvm/llvm-project/release/18.x/lib/Demangle/MicrosoftDemangleNodes.h
curl -L -o _ref/ItaniumDemangle.cpp \
  https://raw.githubusercontent.com/llvm/llvm-project/release/18.x/lib/Demangle/ItaniumDemangle.cpp
```

## `_lint.py` — 静态体检器

只报**客观可判定**的问题，不做风格审查：语法/编译告警、静默吞异常、
可变默认参数、同作用域重复定义、`open()` 未用 `with`、硬编码本机路径、
Tab 缩进，外加两条护栏：

- **护栏 9**：`_` 前缀模块被生产代码 import，但文件不在 `scripts/` 下。
  曾经把 `_quirk.py` 误当脚手架挪走，靠这条拦住。
- **护栏 10**：生产模块 import 失败。

行尾写 `# lint:ok <理由>` 可豁免单行（用于已审阅的刻意行为）。

```bash
python _dev/_lint.py
```

## `_e2e.py` — 端到端功能测试

把 26 个子命令在真实系统文件（`notepad.exe` / `kernel32.dll` / `null.sys`
等）上全跑一遍，校验退出码、JSON 合法性、关键字段与 `ok` 契约。与
`selftest.py` 互补：自检偏单元与合成样本，本脚本偏真实文件的 CLI 集成。

```bash
python _dev/_e2e.py
```

## `_undefined.py` — 未定义名检查

手写 AST 作用域分析，零依赖下替代 pyflakes。`py_compile` 只查语法、`import`
只跑模块顶层，两者都发现不了「函数体里写错一个变量名」—— 而这正是本项目
历史上出过的真实 bug 类型（`errs_out` 未声明、`n = 0` 被误删），一旦跑到
那条分支才 `NameError`，静态阶段完全看不见。

```bash
python _dev/_undefined.py
```

## `_deepaudit.py` / `_adversarial.py` — 语义缺陷审计（静态 + 动态）

`_lint.py` 只能看语法与文本层面的问题。「全绿」只说明**已写的检查**没发现
问题，不说明没有问题 —— 于是补了这两个维度：

| 文件 | 方式 | 查什么 |
|---|---|---|
| `_deepaudit.py` | 静态（AST） | 可选值下标、无保护除法、无保护类型转换、负下标/越界切片、自递归无深度参数、循环内无界增长、`makedirs` 与写文件同处一个 `try` |
| `_adversarial.py` | 动态 | 用畸形输入真打一遍：超大表项数、深度炸弹、截断文件、位翻转、空文件、形状错误的第三方状态 |

这两个是 1.3.1 那轮「失败被上报为成功」普查的主力 —— 7 个真缺陷全是它们
逼出来的，不是读代码看出来的。

```bash
python _dev/_deepaudit.py
python _dev/_adversarial.py
```

## `_fuzz.py` / `_fuzzlib.py` — 稳定性压测

随机/变异输入扫所有解析器，期望**要么正常返回、要么明确报错，绝不允许
崩溃或静默返回空**。`_fuzzlib.py` 是被 `_fuzz.py` 驱动的变异库。

```bash
python _dev/_fuzz.py
```

## `_ossaudit.py` — 开源合规自审

**先量事实、再判合规**：从代码里实测 CATALOG 条目数、CLI 子命令集合
（跑 `re.py --help` 解析，不是正则抓 `add_parser`）、用例数、工具表条目数，
再据此核对文档数字、失效链接、失效脚本引用、生产模块是否漏进文档、
敏感信息泄漏与缺失的开源标配文件。

退出码：`0` 无高危项 / `1` 有高危项。**装进 CI 当门禁用。**

```bash
python _dev/_ossaudit.py
```

## `_t_yaml.py` / `_t_rules.py` — 能力规则引擎开发脚手架

写规则引擎时用的两个独立驱动，比 `selftest.py --only 能力规则` 输出更细，
排障时先用它们。

| 文件 | 用途 |
|---|---|
| `_t_yaml.py` | 只测自研 YAML 子集解析器：24 条断言，覆盖各类标量与 4 类必须报错的非法语法 |
| `_t_rules.py` | 对真实 PE 跑完整链路：`load_rules → identify → analyze_file → summarize_functions → build_features → match_rules`，打印命中、ATT&CK、命中位置、未命中清单 |

```bash
python _dev/_t_yaml.py
python _dev/_t_rules.py C:\Windows\System32\notepad.exe
```

> **注意**：`_t_rules.py` 里的流程必须与 `re.py` 的 `cmd_semantics` 保持一致。
> 早期版本自己拼流程，漏传了 `str_map`、又用了不存在的 `iat_map` 字段，
> 结果所有 api 特征为空、规则 0 命中 —— 看起来像引擎坏了，其实只是喂错了数据。
> 改流程时请对照 CLI 实现。

## `_corpus_*.py` — 语料构建与抽样

| 文件 | 用途 |
|---|---|
| `_corpus_build.py` | 从本机系统目录抽取 PE/DLL，构建符号语料 |
| `_corpus_scan.py` | 扫描语料，统计符号形态分布 |
| `_corpus_target.py` | 按目标抽样（用于定点对照实验） |

> **已归档**：MSVC 引擎开发期用过的一批快照（`_msvc_*` 四个脚本、
> `_lib_symbols_before_splice`、`_corpus_build2`）已完成使命 —— 引擎并入
> `lib_symbols.py` 后它们只是历史留档，零引用却占约 150 KB。
> 开源整理时移除。如需回溯，见 `git log`（或联系维护者）。

> 注：`_quirk.py` 曾经也在 `_dev/` 下（当时被误判为脚手架），现已回归
> `scripts/`——它是**生产模块**，被 `lib_symbols.py` 引用。
