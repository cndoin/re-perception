![re-perception 封面](assets/re-perception-hero.png)

[English](README.md) ｜ **简体中文**

# 逆向工程工具箱（reverse-engineering skill）

让 AI 按「正常逆向工程师的流程」去分析**任何**未知文件：识别 → 指纹 → 静态 → 动态 →
定点突破 → 建模验证 → 文档化。

- **零第三方依赖**：纯 Python 标准库，装完即用
- **全平台目标**：Windows PE / Linux ELF / macOS-iOS Mach-O / Android APK / iOS IPA /
  .NET / Java / Python pyc / Web-WASM-Electron / 固件 / 私有格式 / SQLite
- **内存有界、速度优先**：流式扫描，100MB 文件字符串扫描约 1 秒
- **只读分析**：不写目标文件、不打补丁、不生成注册码
- **自带自检**：144 个自检用例 + 76 项端到端集成，提交前必须全绿

> ⚠️ **仅限授权使用**。只对你自己拥有或已获书面授权的目标做逆向。
> 授权提示见 [USE-POLICY.md](USE-POLICY.md)；法律条款见 [LICENSE](LICENSE)（MIT）。

**English documentation:** [README.md](README.md) ・
[INSTALL.en.md](INSTALL.en.md) ・ [CONTRIBUTING.en.md](CONTRIBUTING.en.md) ・
[SECURITY.en.md](SECURITY.en.md) ・ [USE-POLICY.en.md](USE-POLICY.en.md) ・
[CODE_OF_CONDUCT.en.md](CODE_OF_CONDUCT.en.md)

## 安装到你的 AI

本技能遵循 **Agent Skills 开放标准**，同一份 `SKILL.md` 可直接用于
**Claude Code / Codex CLI / Hermes / OpenClaw / Cursor / Gemini CLI**。
各家只是技能目录不同：

```bash
cd scripts
python _dev/_install.py --auto --verify      # 探测本机装了哪些运行时
python _dev/_install.py --auto               # 装到全部探测到的运行时
```

| 运行时 | 个人级目录 | 项目级目录 |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex CLI | `$CODEX_HOME/skills/`（默认 `~/.codex/skills/`） | `.codex/skills/` |
| Hermes | `~/.hermes/skills/` | —— |
| OpenClaw | `~/.openclaw/skills/` | `.openclaw/skills/` |
| Cursor | ——（仅项目级） | `.cursor/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `.gemini/skills/` |

完整说明、手工装法与常见坑见 **[INSTALL.md](INSTALL.md)**。

### 操作系统 × 运行时兼容矩阵

工具箱是纯 Python 标准库（3.10+），无编译步骤、无二进制 wheel，
因此每个运行时在每个系统上都可用：

| 系统 \ 运行时 | Claude Code | Codex CLI | Hermes | OpenClaw | Cursor | Gemini CLI |
|---|---|---|---|---|---|---|
| Windows | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| macOS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Linux | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

可移植性依据：全库用 `os.path.join` / `os.sep`（无 `C:\` 硬编码）、
流式 I/O 不依赖 mmap 等平台特性，各格式解析器用字节级合成夹具验证
（PE/ELF/Mach-O 夹具与宿主系统无关）。

> 装完请**重开一次新会话** —— 技能在会话启动时扫描，中途装的当轮不加载。

## 快速开始

```bash
# 只需要 Python 3.10+，不需要 pip install 任何东西
cd reverse-engineering/scripts     # 仓库根下的 scripts/ 目录

python re.py doctor --json                  # 本机有哪些外部工具可用
python re.py triage 目标文件 --json         # 拿到未知目标先跑这个
python re.py plan 目标文件 --json           # 下一步该干什么
python re.py report 目标文件 --out 报告.md  # 出一份 Markdown 报告
```

> 拿到仓库后直接 `cd scripts` 即可运行 —— 无需安装、无需构建、无需虚拟环境。
> 若通过 `git clone` 获取，克隆后同样进 `scripts/`。

AI 调用时一律加 `--json`；退出码 `0/2/3/4` 分别代表成功/用法错误/目标不可读/分析出错。
所有子命令在 `--json` 下都会输出顶层 `ok` 字段（有自检用例守着这条契约）。

## 命令一览

共 **49 个子命令**，分三层：**38 个分析命令**（下表的分析层，可被编排层调度）、
**3 个平台/契约命令**（`provider` `unknowns` `bundle`，证据契约层横切能力）
与 **5 个编排/状态命令**（`require` `flow` `case` `result` `toolgraph`，供 AI 选路与缓存）。

| 命令 | 作用 |
|---|---|
| `doctor` | 探测本机工具链（83 个外部工具） |
| `identify` | 格式识别 + 结构解析（PE/ELF/Mach-O/DEX/ZIP/pyc/WASM/SQLite/class/固件头） |
| `strings` | 流式字符串提取（可按类别/正则过滤，支持 UTF-16） |
| `entropy` | 整体熵 + 分块熵曲线（定位加密/压缩段） |
| `imports` | 导入表 / 依赖库（行为地图） |
| `info` | 深度结构解析 |
| `triage` | **一站式初筛**（识别+熵+字符串+IOC+加壳判断） |
| `carve` | 按魔数雕刻嵌入文件（固件/覆盖层分析） |
| `apk` | Android APK 逆向（AXML Manifest 语义：包名/版本/权限/组件/导出面/签名，DEX 摘要，原生库） |
| `dexmap` | DEX 方法级接口地图（api_surface 调用面、JNI 符号双向映射、组件入口面、代码内 URL 归属） |
| `ipa` | iOS IPA 逆向（Info.plist / Bundle / 框架 / provisioning） |
| `iso` | ISO9660 光盘镜像清单与提取（含 Joliet、UDF 侦察） |
| `fsx` | 固件/嵌入文件系统签名扫描与提取（binwalk 式） |
| `replica` | 系统复刻（确定性清单 / 可重现打包 / 回验与篡改检出） |
| `endpoints` | 应用内接口（API 路径 / IPC / Intent Action / COM ProgID / gRPC / SOAP） |
| `ports` | 端口接口（显式端口 + 协议默认端口配对，observed/derived 置信分级） |
| `netaddr` | 连接网络地址（URL / IPv4 / IPv6 / 域名 / 邮箱 / UNC，带作用域标注） |
| `diff` | 两文件字节级差分（版本对比 / 私有格式破解） |
| `plan` | 生成分步分析计划（按本机工具裁剪） |
| `report` | 生成 Markdown 分析报告 |
| `magic` | 魔数速查 |
| `disasm` | 反汇编（x86 / x86-64 / ARM64 / Thumb） |
| `funcs` | 函数识别 + 指纹 + XREF |
| `cfg` | 单个函数的控制流图 |
| `struct` | 控制流结构化（if / loop / switch 识别 + 伪代码骨架） |
| `ir` | 指令级轻量 IR 提升（assign / load / store / branch 语义操作） |
| `xref` | 交叉引用（谁调用了谁） |
| `sim` | 两份二进制的函数级差分比对 |
| `semantics` | 函数级语义摘要（调了什么 API / 什么行为） |
| `capability` | 能力识别（capa 风格规则库 → 行为结论 + ATT&CK 映射） |
| `symbols` | 符号还原（C++/MSVC/Rust demangle + Go pclntab） |
| `obfstr` | 混淆字符串恢复（栈字符串 + XOR 解密循环） |
| `evidence` | 把分析发现包装成可溯源证据 + 登记残余未知项（证据契约层） |
| `layout` | 二进制布局 + 静态缓解（ELF program headers / PE DllCharacteristics） |
| `peres` | PE 资源树（类型/名字/语言） |
| `archs` | Mach-O / 胖二进制架构清单 |
| `plist` | Apple plist 解析（XML/二进制） |
| `dotnet` | .NET 托管程序集元数据（CLR 头、元数据流、程序集名） |
| `goinfo` | Go 二进制 buildinfo（编译器版本、模块、构建设置） |
| `evm` | EVM 字节码 dispatch selector 表 |
| `demangle` | 符号还原（C++/Rust/Swift 修饰名） |
| `provider` | 分析 provider 选择/探测（确定性选择、失败不降级） |
| `unknowns` | 残余未知项治理（登记/更新/裁决/乐观并发） |
| `bundle` | 证据 bundle 导出/导入/对比（规范字节、防篡改、可重放） |
| `require` | 按意图检索该用哪些子命令（AI 选路入口） |
| `flow` | 分阶段工作流：现在该跑哪些（可并行同批给出） |
| `case` | 分析状态目录：结果落盘、复用、过期检测 |
| `result` | 结果摘要 + 错误分类（防无效重试） |
| `toolgraph` | 工具转移图：这个跑完之后该跑哪个 |

## 自检

```bash
python selftest.py                     # 全量自检（144 个用例，约 3 分钟）
python selftest.py --only 性能          # 只跑某一类
python _dev/_lint.py                   # 静态体检（语法/静默吞异常/硬编码路径）
python _dev/_e2e.py                    # 端到端：49 个子命令在真实 PE 上全跑一遍
```

覆盖三条线：正确性（合成样本 + 实机文件）、稳定性（空文件/截断/位翻转变异/垃圾输入）、
性能（100MB 流式扫描）。另外还盯两条硬约束：**零第三方依赖** 与
**`--json` 的 `ok` 字段契约**。

### 门禁的退出码契约

检查工具**不是只看输出，退出码才作数**（否则在 CI 里就是一道永不拦截的门）：

| 命令 | 退出码 | 含义 |
|---|---|---|
| `selftest.py` | `0` 全绿 / `1` 有失败用例 / `2` `--only` 没匹配到任何用例 | 静默跑 0 个用例是错误，不是通过 |
| `_dev/_lint.py` | `0` 生产文件零告警 / `1` 生产文件有告警 | `_dev/` 脚手架的告警单独列账，不影响退出码 |
| `_dev/_undefined.py` | `0` 干净 / `1` 有问题 | 零依赖版 pyflakes |
| `_dev/_ossaudit.py` | `0` 无高危项 / `1` 有高危项 | 开源合规自审 |

### 一键跑门禁

有 `make` 的环境（Linux/macOS/WSL）直接：

```bash
make check     # lint + 未定义名 + 全量自检（提交前必跑）
make all       # check + 端到端 + 合规自审（发布前必跑）
make help      # 看全部目标
```

Windows 原生环境一般没有 `make`，照抄上面对应的 `python xxx.py` 命令即可 ——
`Makefile` 里没有任何逻辑，只是一串命令别名。

## 符号还原（MSVC / Itanium / Rust）

`lib_symbols.py` 内置三套 demangler，零外部依赖：

| 方言 | 前缀 | 覆盖 |
|---|---|---|
| Itanium C++ ABI | `_Z` | GCC/Clang：嵌套名、模板、替换表、成员 CV/ref 限定、运算符、thunk、typeinfo/vtable/guard/TLS |
| MSVC | `?` | Windows C++/驱动/COM：完整 LLVM 文法、回溯表、thunk、RTTI、C++/CX 帽指针 |
| Rust legacy / v0 | `_ZN…17h` / `_R` | legacy 哈希剥离；v0 的 punycode ident、泛型、生命周期、const 泛型 |

MSVC 一路以 `dbghelp!UnDecorateSymbolName` 为逐字对齐目标，**在 61,248 条
真实系统 DLL 导出符号上实测**：

```
有效样本 61205
  完全逐字一致      : 51337  (83.88%)
  计入 dbghelp 怪癖 : 61138  (99.89%)
  仍不一致          :    67  (0.11%)
  放弃              :     0  (0.00%)
  解出正确率(含怪癖): 99.89%
  端到端覆盖率      : 99.82%  （相对全部输入）
```

「dbghelp 怪癖」指 dbghelp 自身已用最小用例证实的缺陷（CV 前不写空格、
变量尾 `__ptr64` 重复、返回值位指针丢 `const` 等），逐条清单与最小用例见
`scripts/_quirk.py`（参考文档，无任何代码 import 它）。
**这 67 处不一致全部归因于 dbghelp 的缺陷，而非引擎的语法缺口**——本项目
不做「向缺陷对齐」，理由同样记录在该文件的模块 docstring 里。

> C++/CX 的 `^` 帽（hat）扩展 `$AA`–`$AD` 在 LLVM 里完全没有，是本项目自行
> 逆向出来的 2-bit CV 阶梯。详见 `references/research.md`。

## 目录结构

```
reverse-engineering/
├── SKILL.md                     # 技能主入口（AI 读这个，中文）
├── INSTALL.md / INSTALL.en.md   # **安装到各 AI 运行时**（中 / 英）
├── README.md                    # English README（主文档）
├── README.zh.md                 # 简体中文 README（本文件）
├── PUBLISHING.md / .en.md       # 开源发布指南（维护者手册，中 / 英）
├── CONTRIBUTING.md / .en.md     # 贡献指南（中 / 英）
├── SECURITY.md / SECURITY.en.md # 漏洞披露（中 / 英）
├── USE-POLICY.md / .en.md       # 使用政策（中 / 英，明确非许可证）
├── CODE_OF_CONDUCT.md / .en.md  # 行为准则（中 / 英）
├── LICENSE                      # MIT（标准全文，无附加限制）
├── CHANGELOG.md                 # 更新日志
├── Makefile                     # 常用命令入口（make test / lint / check）
├── .editorconfig                # 编辑器统一配置
├── .github/
│   ├── workflows/ci.yml         # CI：三平台 × 多 Python 版本
│   ├── ISSUE_TEMPLATE/          # issue 模板
│   └── PULL_REQUEST_TEMPLATE.md # PR 模板
├── references/
│   ├── workflow.md              # 通用方法论：五层模型 / 假说驱动 / SOP / ABI / 反调试
│   ├── playbooks.md             # 13 类目标的命门、工具链与坑点
│   ├── toolchain.md             # 工具矩阵、安装源、学习路线
│   ├── ecosystem.md             # 开源生态地图：四层堆栈 / 项目对照 / 选型决策树
│   ├── research.md              # 论文索引：按「卡在哪」组织（反编译/符号/BCSD/Agent/协议）
│   ├── ai-calling-protocol.md   # AI 怎么挑工具：意图检索 / 摘要层 / 编排协议
│   ├── top-tier-tools.md        # 顶尖逆向工程师的工具、套路与「AI 可达性」对照表
│   ├── open-source-survey.md    # 开源普查（2120 仓库）与能力矩阵（新命令的选型依据）
│   └── legal.md                 # 合规红线（中/美/欧盟 + 自查清单）
├── rules/                       # 能力规则库（capa 风格，`capability` 子命令加载）
│   └── imported/                # capa-rules 翻译规则 910 条（Apache-2.0，见 NOTICE.md）
│   ├── anti-analysis.yml        # 反调试 / 反分析
│   ├── crypto.yml               # AES 等加密常量与 API
│   ├── network.yml              # HTTP / 网络通信
│   └── process.yml              # 进程创建 / WMI / Shell
├── assets/
│   ├── frida-templates.js       # Frida Hook 模板（Native/Android/iOS/抓明文/脱壳）
│   └── notes-template.md        # 分析笔记模板
└── scripts/
    ├── re.py                    # CLI 入口（49 个子命令）
    ├── lib_formats.py           # 魔数库 + 各格式解析器
    ├── lib_analyze.py           # 字符串 / 熵 / IOC / 差分 / 雕刻
    ├── lib_disasm.py            # 反汇编调度
    ├── lib_x86.py               # x86 / x86-64 解码器
    ├── lib_arm.py               # ARM64 / Thumb 解码器
    ├── lib_code.py              # 函数识别 / CFG / XREF
    ├── lib_ir.py                # 轻量 IR 提升 + 控制流结构化
    ├── lib_semantics.py         # 函数语义画像
    ├── lib_libscan.py           # 库函数与密码学常量识别
    ├── lib_symbols.py           # MSVC / Itanium / Rust 名字修饰解析（demangle 引擎）
    ├── lib_names.py             # 符号恢复与还原（Go pclntab / 符号表 / 导出表汇总）
    ├── lib_obfstr.py            # 混淆字符串恢复（栈字符串 + XOR 解密循环）
    ├── lib_rules.py             # 能力规则引擎（自带 YAML 子集解析 + 特征匹配）
    ├── lib_agent.py             # 工具编排：意图→命令检索 / 工作流 / 状态 / 转移图
    ├── lib_evidence.py          # 证据契约层：证据模型 + 残余未知项治理（修订链/裁决/乐观并发）
    ├── lib_contracts.py         # 平台契约：错误契约 + Provider 抽象 + 阶段闭合 + 覆盖守卫
    ├── lib_bundle.py            # 证据 bundle 导出/导入/对比 + 快照复用（防篡改、可重放）
    ├── lib_inspect.py           # 补充检查器：布局缓解 / PE 资源 / Mach-O / plist / .NET / Go / EVM
    ├── lib_apk.py               # APK / IPA 逆向（AXML Manifest 语义、DEX 摘要、Info.plist）
    ├── lib_dexmap.py            # DEX 方法级接口地图（api_surface / JNI 映射 / 组件入口 / URL 归属）
    ├── lib_iso.py               # ISO9660 镜像解析 / 清单 / 安全提取
    ├── lib_netio.py             # 接口 / 端口 / 网络地址提取
    ├── lib_fsx.py               # 固件签名扫描、嵌入提取、确定性复刻
    ├── lib_tools.py             # 工具链探测 + 分析计划
    ├── _quirk.py                # dbghelp 已知缺陷清单（参考文档，非运行时模块）
    ├── selftest.py              # 自检套件（144 个用例，含 5 个安装用例）
    └── _dev/                    # 开发脚手架（不随发布分发）
        └── _install.py          # 跨运行时安装器（--auto 探测 / --verify 回验）
```

## 合规

只对自己拥有或书面授权的目标做逆向。恶意样本在隔离环境分析。
反编译产物、还原的源码、提取的密钥一律不外传。

- 法务条款：[LICENSE](LICENSE)（标准 MIT，无使用领域限制）
- 授权与合规提醒：[USE-POLICY.md](USE-POLICY.md)（**非许可证**）
- 合规红线（中/美/欧盟 + 自查清单）：`references/legal.md`
- 漏洞披露：[SECURITY.md](SECURITY.md)
