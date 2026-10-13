# 开源逆向工程普查（Open-source survey）

> 货比三家的证据留档。本工具新增/强化的每一项能力，都先在 GitHub 开源生态里
> 普查过「谁做得最好、好在哪」，再决定取什么、落到哪个命令上。

## 普查口径

- **来源**：GitHub Search API，按 star 降序。
- **覆盖面**：20 个分类查询（`disassembler` / `decompiler` / `binary-analysis` /
  `firmware` / `android-re` / `malware-analysis` / `unpacker` / `forensics` /
  `debugger` / `emulator` / `pe-parser` / `hex-editor` /
  `topic:reverse-engineering` / `topic:firmware` 等），每查询取前 120 条，
  **去重后 2120 个仓库**，逐条比对能力面。
- **筛选标准**（两满足其一即入候选）：
  1. Star 数高（生态公认）；
  2. 单项能力做得极好（一个项目只干一件事、但干到顶尖）。
- **产出**：附录的 Top 300 对比表（star 降序）+ 下方能力矩阵。
- **口径说明**：这是**能力对标**，不是推荐清单；列表混有蹭 topic 的杂项
  （安全研究生态的常见噪声），我们只取其中真实做逆向的项目做功能参照。

## 能力矩阵：头部项目功能点 → 本工具落点

| 能力域 | 代表项目（★ 数量级） | 它们的做法 | 本工具落点 |
|---|---|---|---|
| APK 逆向 | jadx（50.8k）、Apktool（25.8k）、MobSF（21.9k）、bytecode-viewer（15.6k） | 反编译 DEX/解包资源/Manifest 权限组件分析 | `apk`（AXML 语义解析：包名/版本/权限/组件/导出面/签名块/DEX 摘要/原生库）、`identify`、`strings` |
| IPA 逆向 | ipatool（11.6k）、FLEX（14.6k） | 解析 Info.plist / provisioning / 框架 | `ipa`（bundle id/最低系统/URL scheme/框架/dylib/embedded.mobileprovision）、`plist` |
| 光盘镜像 | xorriso/mkisofs 生态（ISO9660 工具链） | 挂载/提取/卷描述符解析 | `iso`（PVD/Joliet/UDF 侦察、目录遍历、安全提取） |
| 应用内接口 | jadx/MobSF 的 API 面提取、httptoolkit（3.6k）/whistle（15.7k）的接口观测 | 抓包或静态抽取 | `endpoints`（API 路径/Content URI/Intent Action/命名管道/COM ProgID/.NET·Java 类型/gRPC/SOAP） |
| 端口接口 | nmap 系服务探针（端口↔服务映射） | 动态探测 | `ports`（显式端口 + 协议默认端口配对，置信度分 observed/derived） |
| 网络地址 | IOC 抽取器、MOBF 网络面 | 正则抽取 | `netaddr`（URL/IPv4/IPv6/域名/邮箱/UNC，含版本号假阳性排除与地址作用域标注） |
| 固件分析 | binwalk（14.4k）、emba（3.7k） | 魔数签名扫描 + 嵌入文件系统提取 | `fsx`（24 条签名偏移扫描 + 流式解压提取，检不冒充提：无法内建解压的标注 `extractable: false`）、`carve` |
| 系统复刻 | sleuthkit/autopsy（3.4k）取证镜像、确定性构建（reproducible builds） | 镜像/快照 | `replica`（确定性清单 sha256 + 打包回验 + 篡改检出） |
| 反汇编/函数面 | Ghidra（85.9k）、radare2（25k）、cutter（20k）、ImHex（55.1k） | GUI 反汇编平台 | `disasm`/`funcs`/`cfg`/`xref`（纯 stdlib，CLI 层） |
| .NET/符号 | dnSpy（29.6k）、ILSpy（26.5k） | 托管反编译/调试 | `dotnet`（CLR 元数据）、`demangle`、`symbols` |
| 格式识别 | Detect-It-Easy（11.6k） | 外壳/编译器识别 | `identify`/`magic`/`triage` |
| 能力检测 | capa（Mandiant） | 规则库→行为结论 | `capability`（capa 风格规则 + ATT&CK 映射） |
| 差分/复现 | BinDiff 系 | 双样本差分 | `sim`/`diff` |
| 证据/编排 | ida-pro-mcp（12.7k）、Gepetto（3.4k） | AI 辅助逆向 | `evidence`/`require`/`flow`/`unknowns`（证据契约层 + 调用编排层） |

**诚实边界**（普查确认这些不属于本工具，不做、不冒充）：

- GUI 平台（Ghidra/Cutter/ImHex/x64dbg）—— 我们是 agent 可调用的 CLI 事实层，
  不复刻 GUI；
- 动态插桩/调试器/模拟器（Frida/delve/QEMU 系）—— 静态分析工具箱，不含运行时 hook；
- 完整反编译到源码 —— 我们给结构/字符串/符号/语义证据，不生成伪源码。

## 附录：Top 300 对比表（star 降序）

普查去重总量 2120 个仓库，下表为按 star 排序的前 300 个（含语言/分类/简介），
作为「至少看过 200 个」的可核验证据。
| # | 项目 | ★ | 语言 | 分类 | 简介 |
|---|------|---|------|------|------|
| 1 | [morluto/rea](https://github.com/morluto/rea) | 191722 | TypeScript | topic:reverse-engineering | Reverse engineer anything with agents, from app behavior down to native binaries. |
| 2 | [Hack-with-Github/Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) | 122420 | - | topic:reverse-engineering | A collection of various awesome lists for hackers, pentesters and security researchers |
| 3 | [ruvnet/RuView](https://github.com/ruvnet/RuView) | 97743 | Rust | topic:firmware | π RuView turns commodity WiFi signals into real-time spatial intelligence, vital sign monitoring, and presence detection — all without a sin |
| 4 | [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | 85935 | Java | reverse-engineering,topic:reverse-engineering | Ghidra is a software reverse engineering (SRE) framework |
| 5 | [xtekky/gpt4free](https://github.com/xtekky/gpt4free) | 66818 | Python | topic:reverse-engineering | The official gpt4free repository \| various collection of powerful language models \| opus 4.6 gpt 5.3 kimi 2.5 deepseek v3.2 gemini 3 |
| 6 | [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert) | 59737 | Go | exploit-dev | A simple zero-config tool to make locally trusted development certificates with any names you'd like. |
| 7 | [WerWolv/ImHex](https://github.com/WerWolv/ImHex) | 55127 | C++ | topic:reverse-engineering,hex-editor | 🔍 A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM. |
| 8 | [skylot/jadx](https://github.com/skylot/jadx) | 50892 | Java | decompiler | Dex to Java decompiler |
| 9 | [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) | 49831 | C++ | reverse-engineering,topic:reverse-engineering,malware-analysis | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware analysis. |
| 10 | [LeCoupa/awesome-cheatsheets](https://github.com/LeCoupa/awesome-cheatsheets) | 46557 | JavaScript | exploit-dev | 👩‍💻👨‍💻 Awesome cheatsheets for popular programming languages, frameworks and development tools. They include everything you should know in o |
| 11 | [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | 41609 | PowerShell | reverse-engineering | Reverse Engineering / Authorized Penetration Testing / Security Research Skill Router Pack AI-powered routing + On-demand toolchain bootstra |
| 12 | [huiyadanli/RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) | 38925 | C# | hex-editor | :trollface: A hex editor for WeChat/QQ/TIM - PC版微信/QQ/TIM防撤回补丁（我已经看到了，撤回也没用了） |
| 13 | [JCodesMore/ai-website-cloner-template](https://github.com/JCodesMore/ai-website-cloner-template) | 36693 | TypeScript | topic:reverse-engineering | Clone any website with one command using AI coding agents |
| 14 | [librepods-org/librepods](https://github.com/librepods-org/librepods) | 30280 | Kotlin | topic:reverse-engineering | AirPods liberated from Apple's ecosystem. |
| 15 | [The-Art-of-Hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) | 29733 | Jupyter Notebook | reverse-engineering | This repository is maintained by Omar Santos (@santosomar) and includes thousands of resources related to ethical hacking, bug bounties, dig |
| 16 | [dnSpy/dnSpy](https://github.com/dnSpy/dnSpy) | 29668 | C# | debugger | .NET debugger and assembly editor |
| 17 | [vuejs/vue-cli](https://github.com/vuejs/vue-cli) | 29517 | JavaScript | exploit-dev | 🛠️ webpack-based tooling for Vue.js Development |
| 18 | [pppscn/SmsForwarder](https://github.com/pppscn/SmsForwarder) | 28391 | Kotlin | android-re | 短信转发器——监控Android手机短信、来电、APP通知，并根据指定规则转发到其他手机：钉钉群自定义机器人、钉钉企业内机器人、企业微信群机器人、飞书机器人、企业微信应用消息、邮箱、bark、webhook、Telegram机器人、Server酱、PushPlus、手机短信等。包 |
| 19 | [mlflow/mlflow](https://github.com/mlflow/mlflow) | 28369 | Python | debugger | The open source AI engineering platform for agents, LLMs, and ML models. MLflow enables teams of all sizes to debug, evaluate, monitor, and  |
| 20 | [hashicorp/vagrant](https://github.com/hashicorp/vagrant) | 27216 | Ruby | exploit-dev | Vagrant is a tool for building and distributing development environments. |
| 21 | [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) | 26595 | C# | decompiler | .NET Decompiler with support for PDB generation, ReadyToRun, Metadata (&more) - cross-platform! |
| 22 | [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 25865 | Java | reverse-engineering,topic:reverse-engineering,android-re | A tool for reverse engineering Android apk files |
| 23 | [responsively-org/responsively-app](https://github.com/responsively-org/responsively-app) | 25281 | TypeScript | exploit-dev | A modified web browser that helps in responsive web development. A web developer's must have dev-tool. |
| 24 | [radareorg/radare2](https://github.com/radareorg/radare2) | 25016 | C | reverse-engineering,topic:reverse-engineering | UNIX-like reverse engineering framework and command-line toolset |
| 25 | [youhunwl/TVAPP](https://github.com/youhunwl/TVAPP) | 24952 | JavaScript | android-re |  收集全网 Android TV电视盒子应用，涵盖影视、直播、K歌、工具、游戏等类型，整理优质APK资源，支持便捷下载与自动更新。提供安全验证、分类索引与兼容性标注，助力用户打造家庭影音娱乐中心！              ✅ TVBox/影视仓等影音壳接口配置源。 |
| 26 | [go-delve/delve](https://github.com/go-delve/delve) | 24945 | Go | debugger | Delve is a debugger for the Go programming language. |
| 27 | [arendst/Tasmota](https://github.com/arendst/Tasmota) | 24832 | C | topic:firmware | Alternative firmware for ESP8266 and ESP32 based devices with easy configuration using webUI, OTA updates, automation using timers or rules, |
| 28 | [vuejs/devtools-v6](https://github.com/vuejs/devtools-v6) | 24672 | TypeScript | debugger | ⚙️ Browser devtools extension for debugging Vue.js applications. |
| 29 | [comet-ml/opik](https://github.com/comet-ml/opik) | 22564 | Python | debugger | Debug, evaluate, and monitor your LLM applications, RAG systems, and agentic workflows with comprehensive tracing, automated evaluations, an |
| 30 | [DarkFlippers/unleashed-firmware](https://github.com/DarkFlippers/unleashed-firmware) | 22502 | C | topic:firmware | Flipper Zero Unleashed Firmware |
| 31 | [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | 21932 | JavaScript | malware-analysis | Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and sec |
| 32 | [coze-dev/coze-studio](https://github.com/coze-dev/coze-studio) | 21702 | TypeScript | debugger,exploit-dev | An AI agent development platform with all-in-one visual tools, simplifying agent creation, debugging, and deployment like never before. Coze |
| 33 | [RPCS3/rpcs3](https://github.com/RPCS3/rpcs3) | 20050 | C++ | debugger | PlayStation 3 emulator and debugger |
| 34 | [rizinorg/cutter](https://github.com/rizinorg/cutter) | 19996 | C++ | reverse-engineering,topic:reverse-engineering | Free and Open Source Reverse Engineering Platform powered by rizin |
| 35 | [apollographql/apollo-client](https://github.com/apollographql/apollo-client) | 19797 | TypeScript | exploit-dev | The industry-leading GraphQL client for TypeScript, JavaScript, React, Vue, Angular, and more. Apollo Client delivers powerful caching, intu |
| 36 | [fruitcake/laravel-debugbar](https://github.com/fruitcake/laravel-debugbar) | 19291 | PHP | debugger | Debugbar for Laravel (Integrates PHP Debug Bar) |
| 37 | [FredKSchott/snowpack](https://github.com/FredKSchott/snowpack) | 19275 | JavaScript | exploit-dev | ESM-powered frontend build tool. Instant, lightweight, unbundled development. ✌️ |
| 38 | [cocos2d/cocos2d-x](https://github.com/cocos2d/cocos2d-x) | 19216 | C++ | exploit-dev | Cocos2d-x is a suite of open-source, cross-platform, game-development tools utilized by millions of developers across the globe. Its core ha |
| 39 | [muratcankoylan/Agent-Skills-for-Context-Engineering](https://github.com/muratcankoylan/Agent-Skills-for-Context-Engineering) | 18120 | Python | debugger | A comprehensive collection of Agent Skills for context engineering, multi-agent architectures, and production agent systems. Use when buildi |
| 40 | [rocketride-org/rocketride-server](https://github.com/rocketride-org/rocketride-server) | 17783 | Python | debugger | High-performance AI pipeline engine with a C++ core and 50+ Python-extensible nodes. Build, debug, and scale LLM workflows with 13+ model pr |
| 41 | [Tencent/tinker](https://github.com/Tencent/tinker) | 17659 | Java | android-re | Tinker is a hot-fix solution library for Android, it supports dex, library and resources update without reinstall apk. |
| 42 | [MarlinFirmware/Marlin](https://github.com/MarlinFirmware/Marlin) | 17618 | C++ | topic:firmware | Marlin is a firmware for RepRap 3D printers optimized for both 8 and 32 bit microcontrollers.  Marlin supports all common platforms.   Many  |
| 43 | [vitalysim/Awesome-Hacking-Resources](https://github.com/vitalysim/Awesome-Hacking-Resources) | 17501 | - | topic:reverse-engineering | A collection of hacking / penetration testing resources to make you better! |
| 44 | [flipperdevices/flipperzero-firmware](https://github.com/flipperdevices/flipperzero-firmware) | 16711 | C | topic:firmware | Flipper Zero firmware source code |
| 45 | [cool-RR/PySnooper](https://github.com/cool-RR/PySnooper) | 16577 | Python | debugger | Never use print for debugging again |
| 46 | [Tyrrrz/YoutubeDownloader](https://github.com/Tyrrrz/YoutubeDownloader) | 16412 | C# | topic:reverse-engineering | Downloads videos and playlists from YouTube |
| 47 | [winsiderss/systeminformer](https://github.com/winsiderss/systeminformer) | 16230 | C | debugger | A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware. Brought to you by Winsider  |
| 48 | [raga-ai-hub/RagaAI-Catalyst](https://github.com/raga-ai-hub/RagaAI-Catalyst) | 16175 | Python | debugger | Python SDK for Agent AI Observability, Monitoring and Evaluation Framework. Includes features like agent, llm and tools tracing, debugging m |
| 49 | [avwo/whistle](https://github.com/avwo/whistle) | 15727 | JavaScript | debugger | HTTP, HTTP2, HTTPS, Websocket debugging proxy |
| 50 | [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) | 15669 | Java | decompiler,reverse-engineering,android-re | A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More) |
| 51 | [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) | 15212 | Java | decompiler | A standalone Java Decompiler GUI |
| 52 | [FLEXTool/FLEX](https://github.com/FLEXTool/FLEX) | 14640 | Objective-C | debugger | An in-app debugging and exploration tool for iOS |
| 53 | [mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering) | 14619 | Assembly | reverse-engineering,topic:reverse-engineering | A FREE comprehensive reverse engineering tutorial covering x86, x64, 32-bit/64-bit ARM, 8-bit AVR and 32-bit RISC-V architectures. |
| 54 | [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) | 14462 | Rust | firmware | Firmware Analysis Tool |
| 55 | [rshipp/awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) | 14275 | - | malware-analysis | Defund the Police. |
| 56 | [seemoo-lab/openhaystack](https://github.com/seemoo-lab/openhaystack) | 13825 | Swift | topic:reverse-engineering | Build your own 'AirTags' 🏷 today! Framework for tracking personal Bluetooth devices via Apple's massive Find My network. |
| 57 | [HIllya51/LunaTranslator](https://github.com/HIllya51/LunaTranslator) | 13711 | C++ | topic:reverse-engineering | 视觉小说翻译器 / Visual Novel Translator |
| 58 | [m3y54m/Embedded-Engineering-Roadmap](https://github.com/m3y54m/Embedded-Engineering-Roadmap) | 13497 | JavaScript | topic:firmware | Comprehensive roadmap for aspiring Embedded Systems Engineers, featuring a curated list of learning resources |
| 59 | [ytisf/theZoo](https://github.com/ytisf/theZoo) | 13463 | Python | malware-analysis | A repository of LIVE malwares for your own joy and pleasure. theZoo is a project created to make the possibility of malware analysis open an |
| 60 | [facebook/flipper](https://github.com/facebook/flipper) | 13449 | TypeScript | debugger | A desktop debugging platform for mobile developers. |
| 61 | [OWASP/mastg](https://github.com/OWASP/mastg) | 13243 | Python | reverse-engineering,topic:reverse-engineering | The OWASP Mobile Application Security Testing Guide (MASTG) is a comprehensive manual for mobile app security testing and reverse engineerin |
| 62 | [gurugio/lowlevelprogramming-university](https://github.com/gurugio/lowlevelprogramming-university) | 12755 | - | topic:firmware | How to be low-level programmer |
| 63 | [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | 12752 | Python | reverse-engineering,topic:reverse-engineering | AI-powered reverse engineering assistant that bridges IDA Pro with language models through MCP. |
| 64 | [justcallmekoko/ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder) | 12749 | C++ | topic:firmware | A suite of WiFi/Bluetooth offensive and defensive tools for the ESP32 |
| 65 | [facebook/stetho](https://github.com/facebook/stetho) | 12646 | Java | debugger | Stetho is a debug bridge for Android applications, enabling the powerful Chrome Developer Tools and much more. |
| 66 | [node-inspector/node-inspector](https://github.com/node-inspector/node-inspector) | 12633 | JavaScript | debugger | Node.js debugger based on Blink Developer Tools |
| 67 | [devicons/devicon](https://github.com/devicons/devicon) | 11843 | CSS | exploit-dev | Set of icons representing programming languages, designing & development tools |
| 68 | [grafana/pyroscope](https://github.com/grafana/pyroscope) | 11699 | Go | debugger | Continuous Profiling Platform. Debug performance issues down to a single line of code |
| 69 | [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11688 | JavaScript | topic:reverse-engineering | Program for determining types of files for Windows, Linux and MacOS. |
| 70 | [majd/ipatool](https://github.com/majd/ipatool) | 11655 | Go | topic:reverse-engineering | Command-line tool that allows you to search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps on the App Store, and download .ipa or  |
| 71 | [debug-js/debug](https://github.com/debug-js/debug) | 11458 | JavaScript | debugger | A tiny JavaScript debugging utility modelled after Node.js core's debugging technique. Works in Node.js and web browsers |
| 72 | [WhiskeySockets/Baileys](https://github.com/WhiskeySockets/Baileys) | 11326 | JavaScript | topic:reverse-engineering | Socket-based TS/JavaScript API for WhatsApp Web |
| 73 | [Doriandarko/claude-engineer](https://github.com/Doriandarko/claude-engineer) | 11209 | Python | exploit-dev | Claude Engineer is an interactive command-line interface (CLI) that leverages the power of Anthropic's Claude-3.5-Sonnet model to assist wit |
| 74 | [baldurk/renderdoc](https://github.com/baldurk/renderdoc) | 11176 | C++ | debugger | RenderDoc is a stand-alone graphics debugging tool. |
| 75 | [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | 11047 | Python | reverse-engineering,topic:reverse-engineering | Exploit Development and Reverse Engineering with GDB & LLDB Made Easy |
| 76 | [GoogleChromeLabs/ndb](https://github.com/GoogleChromeLabs/ndb) | 10863 | JavaScript | debugger | ndb is an improved debugging experience for Node.js, enabled by Chrome DevTools |
| 77 | [OffcierCia/DeFi-Developer-Road-Map](https://github.com/OffcierCia/DeFi-Developer-Road-Map) | 10858 | JavaScript | exploit-dev | DeFi Developer roadmap is a curated Developer handbook which includes a list of the best tools for DApps development, resources and referenc |
| 78 | [rr-debugger/rr](https://github.com/rr-debugger/rr) | 10702 | C++ | debugger | Record and Replay Framework |
| 79 | [wtsxDev/reverse-engineering](https://github.com/wtsxDev/reverse-engineering) | 10556 | - | reverse-engineering | List of awesome reverse engineering resources |
| 80 | [brendangregg/perf-tools](https://github.com/brendangregg/perf-tools) | 10474 | Shell | pe-parser | Performance analysis tools based on Linux perf_events (aka perf) and ftrace |
| 81 | [jhen0409/react-native-debugger](https://github.com/jhen0409/react-native-debugger) | 10435 | JavaScript | debugger | The standalone app based on official debugger of React Native, and includes React Inspector / Redux DevTools |
| 82 | [cs01/gdbgui](https://github.com/cs01/gdbgui) | 10351 | TypeScript | debugger | Browser-based frontend to gdb (gnu debugger). Add breakpoints, view the stack, visualize data structures, and more in C, C++, Go, Rust, and  |
| 83 | [faisalman/ua-parser-js](https://github.com/faisalman/ua-parser-js) | 10196 | JavaScript | exploit-dev | UAParser.js: The Essential Web Development Tool for User-Agent Detection. Detect Browsers, OS, Devices, Bots, Apps, AI Crawlers, and more. R |
| 84 | [gruns/icecream](https://github.com/gruns/icecream) | 10108 | Python | debugger | 🍦 Never use print() to debug again. |
| 85 | [yeoman/yeoman](https://github.com/yeoman/yeoman) | 10104 | - | exploit-dev | Yeoman - a set of tools for automating development workflow |
| 86 | [google/go-cloud](https://github.com/google/go-cloud) | 9910 | Go | exploit-dev | The Go Cloud Development Kit (Go CDK): A library and tools for open cloud development in Go. |
| 87 | [alufers/mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger) | 9647 | HTML | topic:reverse-engineering | Automagically reverse-engineer REST APIs via capturing traffic |
| 88 | [checkstyle/checkstyle](https://github.com/checkstyle/checkstyle) | 9596 | Java | exploit-dev | Checkstyle is a development tool to help programmers write Java code that adheres to a coding standard. By default it supports the Google Ja |
| 89 | [platformio/platformio-core](https://github.com/platformio/platformio-core) | 9524 | Python | topic:firmware | Your Gateway to Embedded Software Development Excellence :alien: |
| 90 | [Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | 9501 | C# | topic:reverse-engineering | Unity il2cpp reverse engineer |
| 91 | [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) | 9434 | C | topic:reverse-engineering,emulator | Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, PowerPC, RiscV, S390x, TriCore, X86) |
| 92 | [Tikam02/DevOps-Guide](https://github.com/Tikam02/DevOps-Guide) | 9361 | HTML | debugger |  DevOps Guide - Development to Production all configurations with basic notes to debug efficiently. |
| 93 | [Next-Flip/Momentum-Firmware](https://github.com/Next-Flip/Momentum-Firmware) | 9263 | C | topic:firmware | 🐬 Feature-rich, stable and customizable Flipper Firmware |
| 94 | [facebook/chisel](https://github.com/facebook/chisel) | 9178 | Python | debugger | Chisel is a collection of LLDB commands to assist debugging iOS apps. |
| 95 | [angr/angr](https://github.com/angr/angr) | 9152 | Python | binary-analysis | A powerful and user-friendly binary analysis platform! |
| 96 | [mandiant/flare-vm](https://github.com/mandiant/flare-vm) | 9124 | PowerShell | reverse-engineering,topic:reverse-engineering | A collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering enviro |
| 97 | [capstone-engine/capstone](https://github.com/capstone-engine/capstone) | 9084 | C | disassembler,topic:reverse-engineering | Capstone disassembly/disassembler framework for ARM, ARM64 (ARMv8), Alpha, BPF, Ethereum VM, HPPA, LoongArch, M68K, M680X, Mips, MOS65XX, PP |
| 98 | [didi/VirtualAPK](https://github.com/didi/VirtualAPK) | 9048 | Java | android-re | A powerful and lightweight plugin framework for Android |
| 99 | [kivy/python-for-android](https://github.com/kivy/python-for-android) | 8931 | Python | android-re | Turn your Python application into an Android APK |
| 100 | [amitshekhariitbhu/Android-Debug-Database](https://github.com/amitshekhariitbhu/Android-Debug-Database) | 8694 | Java | debugger | A library for debugging android databases and shared preferences - Make Debugging Great Again |
| 101 | [avast/retdec](https://github.com/avast/retdec) | 8647 | C++ | decompiler | RetDec is a retargetable machine-code decompiler based on LLVM. |
| 102 | [firerpa/lamda](https://github.com/firerpa/lamda) | 8586 | Python | topic:reverse-engineering | Android Full-Stack Device Control Platform: WebRTC/H.264 remote desktop, UI/OCR/image-matching automation, one-click MITM, built-in Frida, p |
| 103 | [NomicFoundation/hardhat](https://github.com/NomicFoundation/hardhat) | 8513 | TypeScript | debugger | Hardhat is a development environment to compile, deploy, test, and debug your Ethereum software.  |
| 104 | [EpicGames/raddebugger](https://github.com/EpicGames/raddebugger) | 8460 | C | debugger | A native, user-mode, multi-process, graphical debugger. |
| 105 | [hugsy/gef](https://github.com/hugsy/gef) | 8394 | Python | topic:reverse-engineering,debugger | GEF (GDB Enhanced Features) - a modern experience for GDB with advanced debugging capabilities for exploit devs & reverse engineers on Linux |
| 106 | [Ralim/IronOS](https://github.com/Ralim/IronOS) | 8381 | C | topic:firmware | Open Source Soldering Iron firmware |
| 107 | [django-commons/django-debug-toolbar](https://github.com/django-commons/django-debug-toolbar) | 8380 | Python | debugger | A configurable set of panels that display various debug information about the current request/response. |
| 108 | [crosspoint-reader/crosspoint-reader](https://github.com/crosspoint-reader/crosspoint-reader) | 8329 | C | topic:firmware | Open-source e-reader firmware |
| 109 | [hediet/vscode-debug-visualizer](https://github.com/hediet/vscode-debug-visualizer) | 8172 | TypeScript | debugger | An extension for VS Code that visualizes data during debugging. |
| 110 | [SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill) | 8088 | Shell | reverse-engineering | Claude Code skill to support Android app's reverse engineering |
| 111 | [deepseek-ai/open-infra-index](https://github.com/deepseek-ai/open-infra-index) | 8078 | - | exploit-dev | Production-tested AI infrastructure tools for efficient AGI development and community-driven innovation |
| 112 | [nodemcu/nodemcu-firmware](https://github.com/nodemcu/nodemcu-firmware) | 7950 | C | topic:firmware | Lua based interactive firmware for ESP8266, ESP8285 and ESP32 |
| 113 | [JakeWharton/hugo](https://github.com/JakeWharton/hugo) | 7880 | Java | debugger | Annotation-triggered method call logging for your debug builds. |
| 114 | [vladikoff/chromeos-apk](https://github.com/vladikoff/chromeos-apk) | 7836 | JavaScript | android-re | ☢️  Run Android Apps in Chrome OS OR Chrome in OS X, Linux and Windows. |
| 115 | [acheong08/EdgeGPT](https://github.com/acheong08/EdgeGPT) | 7831 | Python | topic:reverse-engineering | Reverse engineered API of Microsoft's Bing Chat AI |
| 116 | [gaogaotiantian/viztracer](https://github.com/gaogaotiantian/viztracer) | 7754 | Python | debugger | A debugging and profiling tool that can trace and visualize python code execution |
| 117 | [j-hc/revanced-magisk-module](https://github.com/j-hc/revanced-magisk-module) | 7679 | Shell | android-re | Extensive ReVanced builder. Builds both modules and APKs. Updated daily. |
| 118 | [microsoft/azuredatastudio](https://github.com/microsoft/azuredatastudio) | 7678 | TypeScript | exploit-dev | Azure Data Studio is a data management and development tool with connectivity to popular cloud and on-premises databases. Azure Data Studio  |
| 119 | [wuchangming/spy-debugger](https://github.com/wuchangming/spy-debugger) | 7618 | JavaScript | debugger | 微信调试，各种WebView样式调试、手机浏览器的页面真机调试。便捷的远程调试手机页面、抓包工具，支持：HTTP/HTTPS，无需USB连接设备。 |
| 120 | [labring/laf](https://github.com/labring/laf) | 7550 | TypeScript | exploit-dev | Laf is a vibrant cloud development platform that provides essential tools like cloud functions, databases, and storage solutions. It enables |
| 121 | [Blazity/next-enterprise](https://github.com/Blazity/next-enterprise) | 7458 | TypeScript | exploit-dev | 💼 An enterprise-grade Next.js boilerplate for high-performance, maintainable apps. Packed with features like Tailwind CSS, TypeScript, ESLin |
| 122 | [de4dot/de4dot](https://github.com/de4dot/de4dot) | 7429 | C# | unpacker | .NET deobfuscator and unpacker. |
| 123 | [Col-E/Recaf](https://github.com/Col-E/Recaf) | 7427 | Java | topic:reverse-engineering | The modern Java bytecode editor |
| 124 | [Abdess/retrobios](https://github.com/Abdess/retrobios) | 7368 | Python | topic:firmware | Source-verified BIOS and firmware packs for RetroArch, Batocera, Recalbox, Lakka, RetroPie, EmuDeck, RetroBat, RetroDECK, RomM, BizHawk, ROC |
| 125 | [mfussenegger/nvim-dap](https://github.com/mfussenegger/nvim-dap) | 7277 | Lua | debugger | Debug Adapter Protocol client implementation for Neovim |
| 126 | [rehan-remade/universal-modder](https://github.com/rehan-remade/universal-modder) | 7267 | Python | reverse-engineering,topic:reverse-engineering | Point Claude at any game. Skills, tools and the fal MCP that let Claude Code mod almost any PC game you own: recon, reverse engineering, fal |
| 127 | [symfony/debug](https://github.com/symfony/debug) | 7166 | PHP | debugger | Provides tools to ease debugging PHP code |
| 128 | [ayoubfaouzi/al-khaser](https://github.com/ayoubfaouzi/al-khaser) | 7153 | C++ | debugger | Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection.  |
| 129 | [AllThingsSmitty/must-watch-javascript](https://github.com/AllThingsSmitty/must-watch-javascript) | 7137 | - | debugger | JavaScript talks you have to see 👀 on functional programming, performance, frameworks, React, debugging, leveling up, and more! |
| 130 | [albertan017/LLM4Decompile](https://github.com/albertan017/LLM4Decompile) | 7129 | Python | reverse-engineering,topic:reverse-engineering | Reverse Engineering: Decompiling Binary Code with Large Language Models |
| 131 | [ProxymanApp/Proxyman](https://github.com/ProxymanApp/Proxyman) | 6998 | - | debugger | The best-in-class HTTP Debugger for macOS. Capture HTTP/HTTPS from macOS, iOS, Android with a few clicks ✅ |
| 132 | [DroidPluginTeam/DroidPlugin](https://github.com/DroidPluginTeam/DroidPlugin) | 6971 | Java | android-re | A plugin framework on android,Run any third-party apk without installation, modification or repackage |
| 133 | [AloneMonkey/MonkeyDev](https://github.com/AloneMonkey/MonkeyDev) | 6798 | Objective-C | topic:reverse-engineering | CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps,  Without Jailbreak. |
| 134 | [shiaho777/web-to-app](https://github.com/shiaho777/web-to-app) | 6791 | Kotlin | android-re | The most full featured web-to-app toolkit on Android, a complete APK workshop that runs entirely on your phone |
| 135 | [RMerl/asuswrt-merlin](https://github.com/RMerl/asuswrt-merlin) | 6758 | - | topic:firmware | Enhanced version of Asus's router firmware (Asuswrt) (legacy code base) |
| 136 | [aws/aws-sam-cli](https://github.com/aws/aws-sam-cli) | 6738 | Python | debugger | CLI tool to build, test, debug, and deploy Serverless applications using AWS SAM |
| 137 | [google/perfetto](https://github.com/google/perfetto) | 6633 | C++ | pe-parser | Production-grade client-side tracing, profiling, and analysis for complex software systems. |
| 138 | [hect0x7/JMComic-APK](https://github.com/hect0x7/JMComic-APK) | 6565 | Python | android-re | 防迷路 \| 禁漫天堂APK \| 禁漫APP安卓安装包 \| jm天堂 \| 回家 \| GitHub Actions \| JMComic3 \| JMComic2 |
| 139 | [sigalor/whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng) | 6504 | JavaScript | reverse-engineering,topic:reverse-engineering | Reverse engineering WhatsApp Web. |
| 140 | [CodingGay/BlackDex](https://github.com/CodingGay/BlackDex) | 6460 | C++ | android-re,unpacker | BlackDex is an Android unpack(dexdump) tool, it supports Android 5.0~12 and need not rely to any environment. BlackDex can run on any Androi |
| 141 | [davecgh/go-spew](https://github.com/davecgh/go-spew) | 6425 | Go | debugger | Implements a deep pretty printer for Go data structures to aid in debugging |
| 142 | [dwisiswant0/apkleaks](https://github.com/dwisiswant0/apkleaks) | 6345 | Python | topic:reverse-engineering,android-re | Scanning APK file for URIs, endpoints & secrets. |
| 143 | [androguard/androguard](https://github.com/androguard/androguard) | 6343 | Python | reverse-engineering,topic:reverse-engineering | Reverse engineering and pentesting for Android applications  |
| 144 | [snare/voltron](https://github.com/snare/voltron) | 6340 | Python | debugger | A hacky debugger UI for hackers |
| 145 | [tianocore/edk2](https://github.com/tianocore/edk2) | 6330 | C | topic:firmware | EDK II |
| 146 | [swig/swig](https://github.com/swig/swig) | 6329 | SWIG | exploit-dev | SWIG is a software development tool that connects programs written in C and C++ with a variety of high-level programming languages. |
| 147 | [Archmage83/tvapk](https://github.com/Archmage83/tvapk) | 6300 | Java | android-re | 收集各大AndroidTV的apk应用，可免费看vip和国外电影电视。如大家有也可以贡献一下。 |
| 148 | [donnemartin/dev-setup](https://github.com/donnemartin/dev-setup) | 6277 | Python | exploit-dev | macOS development environment setup:  Easy-to-understand instructions with automated setup scripts for developer tools like Vim, Sublime Tex |
| 149 | [PaddlePaddle/PaddleX](https://github.com/PaddlePaddle/PaddleX) | 6272 | Python | exploit-dev | All-in-One Development Tool based on PaddlePaddle |
| 150 | [mandiant/capa](https://github.com/mandiant/capa) | 6229 | Python | topic:reverse-engineering | The FLARE team's open-source tool to identify capabilities in executable files. |
| 151 | [RMerl/asuswrt-merlin.ng](https://github.com/RMerl/asuswrt-merlin.ng) | 6229 | C | topic:firmware | Third party firmware for Asus routers (newer codebase) |
| 152 | [google/ios-webkit-debug-proxy](https://github.com/google/ios-webkit-debug-proxy) | 6201 | C | debugger | A DevTools proxy (Chrome Remote Debugging Protocol) for iOS devices (Safari Remote Web Inspector). |
| 153 | [qilingframework/qiling](https://github.com/qilingframework/qiling) | 6129 | Python | topic:reverse-engineering | A True Instrumentable Binary Emulation Framework |
| 154 | [Coding-Solo/godot-mcp](https://github.com/Coding-Solo/godot-mcp) | 6046 | JavaScript | debugger | MCP server for interfacing with Godot game engine. Provides tools for launching the editor, running projects, and capturing debug output. |
| 155 | [rmusser01/Infosec_Reference](https://github.com/rmusser01/Infosec_Reference) | 6005 | CSS | topic:reverse-engineering | An Information Security Reference That Doesn't Suck; https://rmusser.net/git/admin-2/Infosec_Reference for non-MS Git hosted version. |
| 156 | [singwhatiwanna/dynamic-load-apk](https://github.com/singwhatiwanna/dynamic-load-apk) | 5995 | Java | android-re | DL : dynamic load framework in android |
| 157 | [kuafuai/DevOpsGPT](https://github.com/kuafuai/DevOpsGPT) | 5965 | HTML | exploit-dev | Multi agent system for AI-driven software development. Combine LLM with DevOps tools to convert natural language requirements into working s |
| 158 | [cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) | 5960 | JavaScript | malware-analysis | Cuckoo Sandbox is an automated dynamic malware analysis system |
| 159 | [0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering) | 5957 | C++ | reverse-engineering | Reverse engineering focusing on x64 Windows. |
| 160 | [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) | 5930 | Java | decompiler | JPEXS Free Flash Decompiler (FFDec) is open-source Flash SWF decompiler and editor. Extract and edit ActionScript, images, sounds, shapes, f |
| 161 | [secfigo/Awesome-Fuzzing](https://github.com/secfigo/Awesome-Fuzzing) | 5921 | - | exploit-dev | A curated list of fuzzing resources ( Books, courses - free and paid, videos, tools, tutorials and vulnerable applications to practice on )  |
| 162 | [HexFiend/HexFiend](https://github.com/HexFiend/HexFiend) | 5901 | Objective-C | hex-editor | A fast and clever hex editor for macOS |
| 163 | [square/PonyDebugger](https://github.com/square/PonyDebugger) | 5847 | Objective-C | debugger | Remote network and data debugging for your native iOS app using Chrome Developer Tools |
| 164 | [coze-dev/coze-loop](https://github.com/coze-dev/coze-loop) | 5768 | Go | debugger | Next-generation AI Agent Optimization Platform: Cozeloop addresses challenges in AI agent development by providing full-lifecycle management |
| 165 | [ReagentX/imessage-exporter](https://github.com/ReagentX/imessage-exporter) | 5670 | Rust | topic:reverse-engineering | Export iMessage data + run iMessage Diagnostics |
| 166 | [HuolalaTech/page-spy-web](https://github.com/HuolalaTech/page-spy-web) | 5635 | TypeScript | debugger | A remote debugging platform you'll definitely find useful. Lightweight, cross-platform, out-of-box debugging tool |
| 167 | [dsasmblr/game-hacking](https://github.com/dsasmblr/game-hacking) | 5605 | - | reverse-engineering,topic:reverse-engineering | Tutorials, tools, and more as related to reverse engineering video games. |
| 168 | [lief-project/LIEF](https://github.com/lief-project/LIEF) | 5590 | C++ | topic:reverse-engineering | LIEF - Library to Instrument Executable Formats (C++, Python, Rust) |
| 169 | [allure-framework/allure2](https://github.com/allure-framework/allure2) | 5561 | HTML | exploit-dev | Allure Report is a flexible, lightweight multi-language test reporting tool. It provides clear graphical reports and allows everyone involve |
| 170 | [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) | 5553 | Java | reverse-engineering,topic:reverse-engineering | Ghidra MCP Server — 200+ MCP tools for AI-powered reverse engineering. GUI plugin + headless server, lazy tool loading, convention enforceme |
| 171 | [armbian/build](https://github.com/armbian/build) | 5464 | Shell | topic:firmware | The official build framework for the Armbian Linux distribution. This repository contains the complete toolchain and scripts required to com |
| 172 | [davinci1010/pinduoduo_backdoor](https://github.com/davinci1010/pinduoduo_backdoor) | 5444 | - | android-re | 拼多多apk内嵌提权代码，及动态下发dex分析 |
| 173 | [CreditTone/hooker](https://github.com/CreditTone/hooker) | 5323 | JavaScript | reverse-engineering,topic:reverse-engineering | 🔥🔥 hooker is a Frida-based reverse engineering toolkit for Android. It offers a user-friendly CLI, universal scripts, auto hook generation,  |
| 174 | [mentebinaria/retoolkit](https://github.com/mentebinaria/retoolkit) | 5312 | Inno Setup | topic:reverse-engineering | Reverse Engineer's Toolkit |
| 175 | [Naituw/IPAPatch](https://github.com/Naituw/IPAPatch) | 5294 | Objective-C | topic:reverse-engineering | Patch iOS Apps, The Easy Way, Without Jailbreak. |
| 176 | [timschneeb/GalaxyBudsClient](https://github.com/timschneeb/GalaxyBudsClient) | 5285 | C# | topic:reverse-engineering,topic:firmware | Unofficial Galaxy Buds Manager for Windows, macOS, Linux, and Android |
| 177 | [laravel/telescope](https://github.com/laravel/telescope) | 5232 | PHP | debugger | An elegant debug assistant for the Laravel framework. |
| 178 | [KnuffApp/Knuff](https://github.com/KnuffApp/Knuff) | 5215 | Objective-C | debugger | The debug application for Apple Push Notification Service (APNs). |
| 179 | [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics) | 5212 | - | forensics | ⭐️ A curated list of awesome forensic analysis tools and resources |
| 180 | [niklashigi/apk-mitm](https://github.com/niklashigi/apk-mitm) | 5125 | TypeScript | topic:reverse-engineering,android-re | 🤖 A CLI application that automatically prepares Android APK files for HTTPS inspection |
| 181 | [alphaSeclab/awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering) | 5113 | - | reverse-engineering,topic:reverse-engineering | Reverse Engineering Resources About All Platforms(Windows/Linux/macOS/Android/iOS/IoT) And Every Aspect! (More than 3500 open source tools a |
| 182 | [deathmarine/Luyten](https://github.com/deathmarine/Luyten) | 5111 | Java | decompiler | An Open Source Java Decompiler Gui for Procyon |
| 183 | [atom0s/Steamless](https://github.com/atom0s/Steamless) | 5088 | C# | unpacker | Steamless is a DRM remover of the SteamStub variants.  The goal of Steamless is to make a single solution for unpacking all Steam DRM-packed |
| 184 | [pret/pokered](https://github.com/pret/pokered) | 4983 | Assembly | disassembler,topic:reverse-engineering | Disassembly of Pokémon Red/Blue |
| 185 | [aloshdenny/reverse-SynthID](https://github.com/aloshdenny/reverse-SynthID) | 4963 | Python | reverse-engineering | reverse engineering Gemini's SynthID detection |
| 186 | [Kodezi/Chronos](https://github.com/Kodezi/Chronos) | 4963 | Java | debugger | Kodezi Chronos is a debugging-first language model that achieves state-of-the-art results on SWE-bench Lite (80.33%) and 67% real-world fix  |
| 187 | [preactjs/wmr](https://github.com/preactjs/wmr) | 4910 | JavaScript | exploit-dev | 👩‍🚀 The tiny all-in-one development tool for modern web apps. |
| 188 | [charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool) | 4856 | Python | decompiler,android-re,unpacker | the fastest and most powerful android decompiler(native tool working without Java VM) for the APK, DEX, ODEX, OAT, JAR, AAR, and CLASS file. |
| 189 | [R3nzTheCodeGOD/R3nzSkin](https://github.com/R3nzTheCodeGOD/R3nzSkin) | 4854 | C++ | topic:reverse-engineering | Skin changer for League of Legends (LOL) |
| 190 | [HotCakeX/Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security) | 4780 | C# | exploit-dev | Harden Windows Safely, Securely using Official Supported Microsoft methods and proper explanation \| Always up-to-date and works with the lat |
| 191 | [Integuru-AI/Integuru](https://github.com/Integuru-AI/Integuru) | 4777 | Python | reverse-engineering | The first AI agent that builds permissionless integrations through reverse engineering platforms' internal APIs. |
| 192 | [microsoft/perfview](https://github.com/microsoft/perfview) | 4766 | C# | pe-parser | PerfView is a CPU and memory performance-analysis tool |
| 193 | [kaitai-io/kaitai_struct](https://github.com/kaitai-io/kaitai_struct) | 4702 | Shell | topic:reverse-engineering | Kaitai Struct: declarative language to generate binary data parsers in C++ / C# / Go / Java / JavaScript / Lua / Nim / Perl / PHP / Python / |
| 194 | [vaibhavpandeyvpz/apkstudio](https://github.com/vaibhavpandeyvpz/apkstudio) | 4678 | C++ | reverse-engineering,topic:reverse-engineering,android-re | Open-source, cross platform Qt6 based IDE for reverse-engineering Android application packages. It features a friendly IDE-like layout inclu |
| 195 | [CalebFenton/simplify](https://github.com/CalebFenton/simplify) | 4671 | Java | topic:reverse-engineering,unpacker | Android virtual machine and deobfuscator |
| 196 | [johnno1962/InjectionIII](https://github.com/johnno1962/InjectionIII) | 4653 | Objective-C | topic:reverse-engineering | Re-write of Injection for Xcode in (mostly) Swift |
| 197 | [zrax/pycdc](https://github.com/zrax/pycdc) | 4648 | C++ | disassembler,decompiler | C++ python bytecode disassembler and decompiler |
| 198 | [ReVanced/revanced-patches-template](https://github.com/ReVanced/revanced-patches-template) | 4612 | Kotlin | topic:reverse-engineering | 👋🧩Template repository for ReVanced Patches |
| 199 | [firefox-devtools/debugger](https://github.com/firefox-devtools/debugger) | 4607 | - | debugger | The faster and smarter Debugger for Firefox DevTools 🔥🦊🛠 |
| 200 | [tokio-rs/console](https://github.com/tokio-rs/console) | 4605 | Rust | debugger | a debugger for async rust! |
| 201 | [cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) | 4556 | JavaScript | debugger | Chrome Debugging Protocol interface for Node.js |
| 202 | [kdzwinel/betwixt](https://github.com/kdzwinel/betwixt) | 4556 | JavaScript | debugger | :zap: Web Debugging Proxy based on Chrome DevTools Network panel. |
| 203 | [gbdev/awesome-gbdev](https://github.com/gbdev/awesome-gbdev) | 4528 | - | exploit-dev | A curated list of Game Boy development resources such as tools, docs, emulators, related projects and open-source ROMs. |
| 204 | [cirosantilli/linux-kernel-module-cheat](https://github.com/cirosantilli/linux-kernel-module-cheat) | 4518 | Python | debugger | The perfect emulation setup to study and develop the Linux kernel, kernel modules, QEMU, gem5 and x86_64, ARMv7 and ARMv8 userland and barem |
| 205 | [firmianay/CTF-All-In-One](https://github.com/firmianay/CTF-All-In-One) | 4509 | C | topic:reverse-engineering | CTF竞赛权威指南 |
| 206 | [qwerty472123/wxappUnpacker](https://github.com/qwerty472123/wxappUnpacker) | 4505 | - | unpacker | wxml被“编译“后”压缩“一下多好！😀 |
| 207 | [RPISEC/Malware](https://github.com/RPISEC/Malware) | 4502 | - | malware-analysis | Course materials for Malware Analysis by RPISEC |
| 208 | [extremecoders-re/pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) | 4499 | Python | topic:reverse-engineering | PyInstaller Extractor |
| 209 | [JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | 4495 | Python | topic:reverse-engineering | This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF, PE and Mach-O format on |
| 210 | [lennylxx/ipv6-hosts](https://github.com/lennylxx/ipv6-hosts) | 4486 | Python | topic:reverse-engineering | Fork of https://code.google.com/archive/p/ipv6-hosts/, focusing on automation |
| 211 | [orhun/binsider](https://github.com/orhun/binsider) | 4478 | Rust | topic:reverse-engineering | Analyze ELF binaries like a boss 😼🕵️‍♂️ |
| 212 | [iosre/iOSAppReverseEngineering](https://github.com/iosre/iOSAppReverseEngineering) | 4437 | - | reverse-engineering | The world’s 1st book of very detailed iOS App reverse engineering skills :) |
| 213 | [SteamClientHomebrew/Millennium](https://github.com/SteamClientHomebrew/Millennium) | 4437 | C++ | topic:reverse-engineering | An open-source framework for Steam Client themes and plugins |
| 214 | [jsbin/jsbin](https://github.com/jsbin/jsbin) | 4424 | JavaScript | debugger | Collaborative JavaScript Debugging App |
| 215 | [JetBrains/fernflower](https://github.com/JetBrains/fernflower) | 4422 | Java | decompiler,topic:reverse-engineering | Decompiler from Java bytecode to Java, used in IntelliJ IDEA. |
| 216 | [yagiz/Bagel](https://github.com/yagiz/Bagel) | 4419 | Swift | debugger | a little native network debugging tool for iOS |
| 217 | [Tencent/GT](https://github.com/Tencent/GT) | 4394 | Java | debugger | GT (Great Tit) is a portable debugging tool for bug hunting and performance tuning on smartphones anytime and anywhere just as listening mus |
| 218 | [zyantific/zydis](https://github.com/zyantific/zydis) | 4388 | C | disassembler | Fast and lightweight x86/x86-64 disassembler and code generation library |
| 219 | [php-debugbar/php-debugbar](https://github.com/php-debugbar/php-debugbar) | 4383 | PHP | debugger | Debug bar for PHP |
| 220 | [auchenberg/vscode-browser-preview](https://github.com/auchenberg/vscode-browser-preview) | 4372 | TypeScript | debugger | A real browser preview inside your editor that you can debug. |
| 221 | [redpanda-data/console](https://github.com/redpanda-data/console) | 4335 | TypeScript | debugger | Redpanda Console is a developer-friendly UI for managing your Kafka/Redpanda workloads. Console gives you a simple, interactive approach for |
| 222 | [x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide) | 4332 | C++ | debugger | Advanced usermode anti-anti-debugger. Forked from https://bitbucket.org/NtQuery/scyllahide |
| 223 | [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) | 4331 | Python | decompiler | A cross-version Python bytecode decompiler |
| 224 | [JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton) | 4327 | C++ | binary-analysis,reverse-engineering,topic:reverse-engineering | Triton is a dynamic binary analysis library. Build your own program analysis tools, automate your reverse engineering, perform software veri |
| 225 | [puremourning/vimspector](https://github.com/puremourning/vimspector) | 4325 | Vim Script | debugger | vimspector - A multi-language debugging system for Vim |
| 226 | [Triple-T/gradle-play-publisher](https://github.com/Triple-T/gradle-play-publisher) | 4323 | Kotlin | android-re | GPP is Android's unofficial release automation Gradle Plugin. It can do anything from building, uploading, and then promoting your App Bundl |
| 227 | [GDRETools/gdsdecomp](https://github.com/GDRETools/gdsdecomp) | 4320 | C++ | reverse-engineering | Godot reverse engineering tools |
| 228 | [Pimzino/spec-workflow-mcp](https://github.com/Pimzino/spec-workflow-mcp) | 4304 | TypeScript | exploit-dev | A Model Context Protocol (MCP) server that provides structured spec-driven development workflow tools for AI-assisted software development,  |
| 229 | [ConsenSysDiligence/mythril](https://github.com/ConsenSysDiligence/mythril) | 4271 | Python | symbolic-execution | Mythril is a symbolic-execution-based securty analysis tool for EVM bytecode. It detects security vulnerabilities in smart contracts built f |
| 230 | [wux1an/wxapkg](https://github.com/wux1an/wxapkg) | 4247 | Vue | topic:reverse-engineering | 跨平台微信小程序反编译 GUI 工具，.wxapkg 文件扫描 + 解密 + 解包工具 |
| 231 | [lando/lando](https://github.com/lando/lando) | 4245 | - | exploit-dev | A development tool for all your projects that is fast, easy, powerful and liberating |
| 232 | [0xor0ne/awesome-list](https://github.com/0xor0ne/awesome-list) | 4217 | - | topic:reverse-engineering | Cybersecurity oriented awesome list |
| 233 | [fwupd/fwupd](https://github.com/fwupd/fwupd) | 4190 | C | topic:firmware | A system daemon to allow session software to update firmware |
| 234 | [HJLebbink/asm-dude](https://github.com/HJLebbink/asm-dude) | 4176 | C# | disassembler | Visual Studio extension for assembly syntax highlighting and code completion in assembly files and the disassembly window |
| 235 | [ericc-ch/copilot-api](https://github.com/ericc-ch/copilot-api) | 4148 | TypeScript | topic:reverse-engineering | Turn GitHub Copilot into OpenAI/Anthropic API compatible server. Usable with Claude Code! |
| 236 | [CocoaDebug/CocoaDebug](https://github.com/CocoaDebug/CocoaDebug) | 4133 | Swift | debugger | iOS Debugging Tool 🚀 |
| 237 | [pedrovgs/AndroidWiFiADB](https://github.com/pedrovgs/AndroidWiFiADB) | 4133 | Java | debugger | IntelliJ/AndroidStudio plugin which provides a button to connect your Android device over WiFi to install, run and debug your applications w |
| 238 | [HyperDbg/HyperDbg](https://github.com/HyperDbg/HyperDbg) | 4130 | C | topic:reverse-engineering,debugger | State-of-the-art native debugging tools |
| 239 | [alexandreborges/malwoverview](https://github.com/alexandreborges/malwoverview) | 4130 | Python | malware-analysis | Malwoverview is a first response tool for threat hunting across VirusTotal, Hybrid Analysis, URLHaus, Polyswarm, Malshare, Alien Vault, Malp |
| 240 | [openai/transformer-debugger](https://github.com/openai/transformer-debugger) | 4123 | Python | debugger |  |
| 241 | [Joshua-Riek/ubuntu-rockchip](https://github.com/Joshua-Riek/ubuntu-rockchip) | 4108 | Shell | topic:firmware | Ubuntu for Rockchip RK35XX Devices |
| 242 | [rumboalla/apkupdater](https://github.com/rumboalla/apkupdater) | 4040 | Kotlin | android-re | APKUpdater is an open source tool that simplifies the process of finding updates for your installed apps. |
| 243 | [APKLab/APKLab](https://github.com/APKLab/APKLab) | 4007 | TypeScript | reverse-engineering,topic:reverse-engineering,android-re | Android Reverse-Engineering Workbench for VS Code |
| 244 | [cea-sec/miasm](https://github.com/cea-sec/miasm) | 3989 | Python | reverse-engineering,topic:reverse-engineering | Reverse engineering framework in Python |
| 245 | [DaveWoodCom/XCGLogger](https://github.com/DaveWoodCom/XCGLogger) | 3981 | Swift | debugger | A debug log framework for use in Swift projects. Allows you to log details to the console (and optionally a file), just like you would have  |
| 246 | [rizinorg/rizin](https://github.com/rizinorg/rizin) | 3952 | C | reverse-engineering,topic:reverse-engineering | UNIX-like reverse engineering framework and command-line toolset. |
| 247 | [AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) | 3947 | JavaScript | topic:reverse-engineering | pull decrypted ipa from jailbreak device |
| 248 | [tox-dev/tox](https://github.com/tox-dev/tox) | 3943 | Python | exploit-dev | Command line driven CI frontend and development task automation tool. |
| 249 | [a0rtega/pafish](https://github.com/a0rtega/pafish) | 3941 | C | topic:reverse-engineering,malware-analysis | Pafish is a testing tool that uses different techniques to detect virtual machines and malware analysis environments in the same way that ma |
| 250 | [danvk/source-map-explorer](https://github.com/danvk/source-map-explorer) | 3930 | TypeScript | debugger | Analyze and debug space usage through source maps |
| 251 | [newliver666/apk-reverse](https://github.com/newliver666/apk-reverse) | 3929 | Python | reverse-engineering,android-re | Suitable for Android APK reverse engineering analysis |
| 252 | [Aefyr/SAI](https://github.com/Aefyr/SAI) | 3907 | Java | android-re | Android split APKs installer |
| 253 | [Ly0n/awesome-robotic-tooling](https://github.com/Ly0n/awesome-robotic-tooling) | 3903 | - | exploit-dev | Tooling for professional robotic development in C++ and Python with a touch of ROS, autonomous driving and aerospace. |
| 254 | [dendibakh/perf-ninja](https://github.com/dendibakh/perf-ninja) | 3892 | C++ | pe-parser | This is an online course where you can learn and master the skill of low-level performance analysis and tuning. |
| 255 | [danielkrupinski/Osiris](https://github.com/danielkrupinski/Osiris) | 3886 | C++ | topic:reverse-engineering | Cross-platform game hack for Counter-Strike 2 with Panorama-based GUI. |
| 256 | [trailofbits/manticore](https://github.com/trailofbits/manticore) | 3856 | Python | symbolic-execution | Symbolic execution tool |
| 257 | [fastmonkeys/stellar](https://github.com/fastmonkeys/stellar) | 3851 | Python | exploit-dev | Fast database snapshot and restore tool for development |
| 258 | [danluu/debugging-stories](https://github.com/danluu/debugging-stories) | 3845 | - | debugger | A collection of debugging stories. PRs welcome (sorry for the backlog) :-) |
| 259 | [ax/apk.sh](https://github.com/ax/apk.sh) | 3842 | Shell | reverse-engineering,topic:reverse-engineering,android-re | Makes reverse engineering Android apps easier, automating repetitive tasks like pulling, decoding, rebuilding and patching an APK. |
| 260 | [cilium/pwru](https://github.com/cilium/pwru) | 3840 | C | debugger | Packet, where are you? -- eBPF-based Linux kernel networking debugger |
| 261 | [blacktop/ipsw](https://github.com/blacktop/ipsw) | 3794 | Go | topic:firmware | iOS/macOS Research Swiss Army Knife |
| 262 | [dekuNukem/Nintendo_Switch_Reverse_Engineering](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering) | 3789 | C | reverse-engineering | A look at inner workings of Joycon and Nintendo Switch |
| 263 | [JJTech0130/pypush](https://github.com/JJTech0130/pypush) | 3786 | Python | topic:reverse-engineering | Python APNs and iMessage client |
| 264 | [denji/awesome-http-benchmark](https://github.com/denji/awesome-http-benchmark) | 3781 | - | debugger | HTTP(S) benchmark tools, testing/debugging, & restAPI (RESTful) |
| 265 | [Mouseww/anything-analyzer](https://github.com/Mouseww/anything-analyzer) | 3766 | TypeScript | topic:reverse-engineering | 全能协议分析工具：浏览器抓包 + MITM 代理 + 指纹伪装 + AI 分析 + MCP Server 无缝对接 AI Agent/IDE   \|  All-in-one protocol analysis toolkit — built-in browser capture, |
| 266 | [kasketis/netfox](https://github.com/kasketis/netfox) | 3756 | Swift | debugger | A lightweight, one line setup, iOS / OSX network debugging library! 🦊 |
| 267 | [Tyrrrz/YoutubeExplode](https://github.com/Tyrrrz/YoutubeExplode) | 3739 | C# | topic:reverse-engineering | Abstraction layer over YouTube's internal API |
| 268 | [schemaspy/schemaspy](https://github.com/schemaspy/schemaspy) | 3732 | HTML | topic:reverse-engineering | Database documentation built easy |
| 269 | [blackmagic-debug/blackmagic](https://github.com/blackmagic-debug/blackmagic) | 3721 | - | debugger | In-application debugger for ARM Cortex and RISC-V processors. |
| 270 | [momo5502/sogen](https://github.com/momo5502/sogen) | 3715 | C++ | topic:reverse-engineering | 🪅 Windows & Linux userspace emulator  |
| 271 | [e-m-b-a/emba](https://github.com/e-m-b-a/emba) | 3703 | Shell | topic:reverse-engineering,topic:firmware | EMBA - The firmware security analyzer |
| 272 | [dendibakh/perf-book](https://github.com/dendibakh/perf-book) | 3673 | TeX | pe-parser | The book "Performance Analysis and Tuning on Modern CPU" |
| 273 | [httptoolkit/httptoolkit](https://github.com/httptoolkit/httptoolkit) | 3654 | - | debugger | HTTP Toolkit is a beautiful & open-source tool for debugging, testing and building with HTTP(S) on Windows, Linux & Mac  :tada:  Open an iss |
| 274 | [openwrt-xiaomi/xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher) | 3643 | Python | topic:firmware | Firmware patcher for Xiaomi routers |
| 275 | [dembrandt/dembrandt](https://github.com/dembrandt/dembrandt) | 3628 | TypeScript | topic:reverse-engineering | Extract any website’s design system into tokens in seconds: logo, colors, typography, borders & more. One command. |
| 276 | [openai/openai-realtime-console](https://github.com/openai/openai-realtime-console) | 3614 | JavaScript | debugger | React app for inspecting, building and debugging with the Realtime API |
| 277 | [icedland/iced](https://github.com/icedland/iced) | 3589 | Rust | disassembler | Blazing fast and correct x86/x64 disassembler, assembler, decoder, encoder for Rust, .NET, Java, Python, Lua |
| 278 | [mxschmitt/action-tmate](https://github.com/mxschmitt/action-tmate) | 3589 | JavaScript | debugger | Debug your GitHub Actions via SSH by using tmate to get access to the runner system itself. |
| 279 | [pret/pokeemerald](https://github.com/pret/pokeemerald) | 3576 | C | topic:reverse-engineering | Decompilation of Pokémon Emerald |
| 280 | [HanaokaYuzu/Gemini-API](https://github.com/HanaokaYuzu/Gemini-API) | 3574 | Python | topic:reverse-engineering | ✨ Reverse-engineered Python API for Google Gemini web app |
| 281 | [joernio/joern](https://github.com/joernio/joern) | 3566 | Scala | binary-analysis | Open-source code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code property graphs. Discord https://discord.gg/ |
| 282 | [open-goal/jak-project](https://github.com/open-goal/jak-project) | 3565 | Common Lisp | topic:reverse-engineering | Reviving the language that brought us the Jak & Daxter Series |
| 283 | [kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2) | 3564 | Python | topic:reverse-engineering | Malware Configuration And Payload Extraction |
| 284 | [vaib25vicky/awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security) | 3561 | - | topic:reverse-engineering | An effort to build a single place for all useful android and iOS security related stuff. All references and tools belong to their respective |
| 285 | [V33RU/awesome-connected-things-sec](https://github.com/V33RU/awesome-connected-things-sec) | 3557 | - | topic:reverse-engineering | A Curated list of Security Resources for all connected things |
| 286 | [evolutionary-architecture/evolutionary-architecture-by-example](https://github.com/evolutionary-architecture/evolutionary-architecture-by-example) | 3549 | C# | unpacker | Navigate the complex landscape of .NET software architecture with our step-by-step, story-like guide. Unpack the interplay between modular m |
| 287 | [ReVanced/revanced-patcher](https://github.com/ReVanced/revanced-patcher) | 3522 | Kotlin | topic:reverse-engineering | 💉 ReVanced Patcher used to patch Android applications |
| 288 | [JusticeRage/Gepetto](https://github.com/JusticeRage/Gepetto) | 3483 | Python | reverse-engineering,topic:reverse-engineering | IDA plugin which queries language models to speed up reverse-engineering |
| 289 | [commaai/opendbc](https://github.com/commaai/opendbc) | 3481 | Python | topic:reverse-engineering | a Python API for your car |
| 290 | [microsoft/tensorwatch](https://github.com/microsoft/tensorwatch) | 3477 | Jupyter Notebook | debugger | Debugging, monitoring and visualization for Python Machine Learning and Data Science |
| 291 | [limboemu/limbo](https://github.com/limboemu/limbo) | 3465 | Java | android-re | Limbo is a QEMU-based emulator for Android. It currently supports x86, ARM, PowerPC, and Sparc emulation  for Intel x86 and ARM android devi |
| 292 | [dotnet/cli](https://github.com/dotnet/cli) | 3460 | - | exploit-dev | The .NET Core command-line (CLI) tools, used for building .NET Core apps and libraries through your development flow (compiling, NuGet packa |
| 293 | [google/OpenSK](https://github.com/google/OpenSK) | 3451 | Rust | topic:firmware | OpenSK is an open-source implementation for security keys written in Rust that supports both FIDO U2F and FIDO2 standards. |
| 294 | [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | 3436 | Python | reverse-engineering | Agent skills for solving CTF challenges - web exploitation, binary pwn, crypto, reverse engineering, forensics, OSINT, and more |
| 295 | [decalage2/oletools](https://github.com/decalage2/oletools) | 3430 | Python | binary-analysis,malware-analysis,forensics | oletools - python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware anal |
| 296 | [EntySec/Ghost](https://github.com/EntySec/Ghost) | 3426 | Python | debugger | Ghost Framework is an Android post-exploitation framework that exploits the Android Debug Bridge to remotely access an Android device. |
| 297 | [xdebug/xdebug](https://github.com/xdebug/xdebug) | 3416 | PHP | debugger | Xdebug — Step Debugger and Debugging Aid for PHP |
| 298 | [ran-j/PS2Recomp](https://github.com/ran-j/PS2Recomp) | 3410 | C++ | topic:reverse-engineering | Playstation 2 Static Recompiler & Runtime Tool to make native PC ports |
| 299 | [web-infra-dev/rsbuild](https://github.com/web-infra-dev/rsbuild) | 3398 | TypeScript | exploit-dev | Fast, extensible build tool for modern web development |
| 300 | [sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) | 3386 | Java | forensics | Autopsy® is a digital forensics platform and graphical interface to The Sleuth Kit® and other digital forensics tools. It can be used by law |
