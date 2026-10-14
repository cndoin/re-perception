# 能力差距矩阵与候选项目对照（capability gap matrix）

> 目标：**从数学基础往上，从零逆向任何东西（含系统、硬件、应用生态接口）**
> 生成方式：GitHub Search API，18 个功能域，sort=stars 取 Top，
> **每域去重后均 >= 50 个候选**（实际合计 3288 个），此表为各域 Top 12。
> 用途：第 4/5 步「货比三家 → 选星最多且最适配的接入」。


## A 反编译/伪代码

- **现状**：只有 `disasm`（指令级）+ `semantics`（函数行为画像），没有 IR 提升与伪代码生成。
- **缺口 / 拟接入**：这是**最大缺口**：把指令转成中间表示再结构化为 if/while/赋值，是「看懂程序」的分水岭。参照 A 域三强（jadx / ILSpy / Ghidra 的 pcode），先做 x86/ARM 的轻量 IR + 控制流结构化（结构化算法参照 Cifuentes 的 dcc），再谈反混淆与类型恢复。


候选对照（144 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [skylot/jadx](https://github.com/skylot/jadx) | 50895 | Java | Dex to Java decompiler |
| [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) | 26598 | C# | .NET Decompiler with support for PDB generation, ReadyToRun, Metadata (&more) - cross-platform! |
| [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) | 15670 | Java | A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More) |
| [java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui) | 15212 | Java | A standalone Java Decompiler GUI |
| [avast/retdec](https://github.com/avast/retdec) | 8646 | C++ | RetDec is a retargetable machine-code decompiler based on LLVM. |
| [Col-E/Recaf](https://github.com/Col-E/Recaf) | 7428 | Java | The modern Java bytecode editor |
| [jindrapetrik/jpexs-decompiler](https://github.com/jindrapetrik/jpexs-decompiler) | 5931 | Java | JPEXS Free Flash Decompiler (FFDec) is open-source Flash SWF decompiler and editor. Extract and  |
| [deathmarine/Luyten](https://github.com/deathmarine/Luyten) | 5111 | Java | An Open Source Java Decompiler Gui for Procyon |
| [charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool) | 4855 | Python | the fastest and most powerful android decompiler(native tool working without Java VM) for the AP |
| [zrax/pycdc](https://github.com/zrax/pycdc) | 4648 | C++ | C++ python bytecode disassembler and decompiler |
| [JetBrains/fernflower](https://github.com/JetBrains/fernflower) | 4422 | Java | Decompiler from Java bytecode to Java, used in IntelliJ IDEA. |
| [rocky/python-uncompyle6](https://github.com/rocky/python-uncompyle6) | 4331 | Python | A cross-version Python bytecode decompiler |

## B IR/数据流/污点

- **现状**：`lib_code` 有 CFG/函数指纹/XREF，但无 def-use 链、无可达性传播。
- **缺口 / 拟接入**：污点传播与 def-use 是「这个输入最终流到哪个 API」的答案来源，也是反混淆与漏洞挖掘的地基。纯 stdlib 可实现：支配树 + worklist 迭代数据流。


候选对照（216 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [orhun/binsider](https://github.com/orhun/binsider) | 4478 | Rust | Analyze ELF binaries like a boss 😼🕵️‍♂️ |
| [joernio/joern](https://github.com/joernio/joern) | 3566 | Scala | Open-source code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code  |
| [RevylAI/greenlight](https://github.com/RevylAI/greenlight) | 2444 | Go | Pre-submission compliance scanner for the Apple App Store and Google Play. Scans code, privacy m |
| [BinaryAnalysisPlatform/bap](https://github.com/BinaryAnalysisPlatform/bap) | 2264 | OCaml | Binary Analysis Platform |
| [JonathanSalwan/Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection) | 927 | LLVM | Playing with the Tigress software protection. Break some of its protections and solve their reve |
| [llnl/rose](https://github.com/llnl/rose) | 693 | C | ROSE is an open-source compiler framework engineered by LLNL supporting program analysis and tra |
| [mohitmishra786/reversingBits](https://github.com/mohitmishra786/reversingBits) | 661 | HTML | A comprehensive collection of cheatsheets for reverse engineering, binary analysis, and assembly |
| [lkimuk/ReArk](https://github.com/lkimuk/ReArk) | 622 | C++ | An intelligent reverse engineering and AI-assisted analysis tool for HarmonyOS NEXT (HAP/APP/ABC |
| [B2R2-org/B2R2](https://github.com/B2R2-org/B2R2) | 552 | F# | B2R2 is a fully managed binary analysis framework written in F#. It provides a rich set of algor |
| [carbonblack/binee](https://github.com/carbonblack/binee) | 531 | Go | Binee: binary emulation environment |
| [danleh/wasabi](https://github.com/danleh/wasabi) | 409 | WebAssembly | A dynamic analysis framework for WebAssembly programs. |
| [h311d1n3r/Cerberus](https://github.com/h311d1n3r/Cerberus) | 407 | C++ | A C++ tool to unstrip Rust/Go binaries (ELF and PE) |

## C 调试信息与类型

- **现状**：有 `symbols`（demangle + Go pclntab），无 PDB 解析、无 DWARF 解析、无类型/结构体恢复。
- **缺口 / 拟接入**：Windows 样本丢掉 PDB 等于放弃源码级信息（行号/变量/结构体）。优先做 DWARF（ELF，文档公开且与 cpptrace/btfparse 同思路）与简易 PDB MSF 流解析。


候选对照（64 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [getsentry/pdb](https://github.com/getsentry/pdb) | 467 | Rust | A parser for Microsoft PDB (Program Database) debugging information |
| [Sfedfcv/redesigned-pancake](https://github.com/Sfedfcv/redesigned-pancake) | 268 | - | Skip to content github / docs Code Issues 80 Pull requests 35 Discussions Actions Projects 2 Sec |
| [trailofbits/btfparse](https://github.com/trailofbits/btfparse) | 30 | C++ | A C++ library that parses debug information encoded in BTF format |
| [X-TOOL-S/crispy-winner](https://github.com/X-TOOL-S/crispy-winner) | 28 | - | # Git Credential Manager  [![Build Status](https://github.com/GitCredentialManager/git-credentia |
| [denman2328/Help](https://github.com/denman2328/Help) | 26 | - | ------------------ System Information ------------------ Time of this report: 8/10/2013, 08:36:2 |
| [ramikg/tdinfo-parser](https://github.com/ramikg/tdinfo-parser) | 14 | Python | Turbo/Borland debug information parser for IDA |
| [dovnel/Win-7](https://github.com/dovnel/Win-7) | 14 | - | ------------------ System Information ------------------ Time of this report: 9/2/2015, 19:28:59 |
| [Camus777/Minecraft](https://github.com/Camus777/Minecraft) | 11 | - | ----------------- System Information ------------------ Time of this report: 1/8/2014, 14:32:23  |
| [zolutal/dsviz](https://github.com/zolutal/dsviz) | 11 | Python | A tool for visualizing structures from debug info |
| [thewebdeveloper2017/ilearnmacquarie20178](https://github.com/thewebdeveloper2017/ilearnmacquarie20178) | 9 | - | <!DOCTYPE html> <html  dir="ltr" lang="en" xml:lang="en"> <head>   <!-- front -->   <meta name=" |
| [haseebalam/python-twitter-api](https://github.com/haseebalam/python-twitter-api) | 9 | - | software # distributed under the License is distributed on an "AS IS" BASIS, # WITHOUT WARRANTIE |
| [Luciana45/minecraft](https://github.com/Luciana45/minecraft) | 8 | - | ------------------ System Information ------------------ Time of this report: 8/20/2013, 21:40:5 |

## D 反混淆(OLLVM/平坦化)

- **现状**：有 `obfstr`（栈字符串 + XOR 循环，但 XOR 分支 CLI 未接出）。
- **缺口 / 拟接入**：现代加固主力是控制流平坦化 + 不透明谓词 + 虚拟化，这类样本不解平坦化反编译出来的全是 dispatcher。可做：支配关系识别 dispatcher、边折叠还原基本块顺序。


候选对照（313 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [CalebFenton/simplify](https://github.com/CalebFenton/simplify) | 4672 | Java | Android virtual machine and deobfuscator |
| [JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton) | 4327 | C++ | Triton is a dynamic binary analysis library. Build your own program analysis tools, automate you |
| [mandiant/flare-floss](https://github.com/mandiant/flare-floss) | 4183 | Python | FLARE Obfuscated String Solver - Automatically extract obfuscated strings from malware. |
| [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) | 2960 | TypeScript | Deobfuscate obfuscator.io, unminify and unpack bundled javascript |
| [rockbruno/swiftshield](https://github.com/rockbruno/swiftshield) | 2548 | Swift | 🔒 Swift Obfuscator that protects iOS apps against reverse engineering attacks. |
| [vmoranv/jshookmcp](https://github.com/vmoranv/jshookmcp) | 2042 | TypeScript | A search-first, profile-aware reverse-engineering workspace for AI agents — 735 tools across 36  |
| [KasperskyLab/hrtng](https://github.com/KasperskyLab/hrtng) | 1945 | C++ | IDA Pro plugin with a rich set of features: decryption, deobfuscation, patching, lib code recogn |
| [JustasMasiulis/lazy_importer](https://github.com/JustasMasiulis/lazy_importer) | 1928 | C++ | library for importing functions from dlls in a hidden, reverse engineer unfriendly way |
| [java-deobfuscator/deobfuscator](https://github.com/java-deobfuscator/deobfuscator) | 1764 | Java | The real deal |
| [vtil-project/VTIL-Core](https://github.com/vtil-project/VTIL-Core) | 1603 | C++ | Virtual-machine Translation Intermediate Language |
| [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) | 1594 | - | A curated list of IDA x64DBG, Ghidra and OllyDBG plugins.  |
| [JonathanSalwan/VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | 1532 | Roff | Playing with the VMProtect software protection. Automatic deobfuscation of pure functions using  |

## E 加壳与脱壳

- **现状**：`identify`/`triage` 能报壳厂/加壳启发式（含 APK 加固），但只识别不脱。
- **缺口 / 拟接入**：静态解包可覆盖的部分应当做：UPX（NRV 解压可用纯 Python 实现）、NSIS / Inno Setup / 7z SFX（本质是容器解析，见 J 域）。VMProtect / Themida 明说不支持 —— 只标注，不冒充能脱（诚实边界）。


候选对照（108 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11691 | JavaScript | Program for determining types of files for Windows, Linux and MacOS. |
| [CodingGay/BlackDex](https://github.com/CodingGay/BlackDex) | 6460 | C++ | BlackDex is an Android unpack(dexdump) tool, it supports Android 5.0~12 and need not rely to any |
| [Bioruebe/UniExtract2](https://github.com/Bioruebe/UniExtract2) | 4440 | AutoIt | Universal Extractor 2 is a tool to extract files from any type of archive or installer. |
| [horsicq/DIE-engine](https://github.com/horsicq/DIE-engine) | 3307 | C++ | DIE engine |
| [UnderminersTeam/UndertaleModTool](https://github.com/UnderminersTeam/UndertaleModTool) | 2078 | C# | The most complete tool for modding, decompiling and unpacking Undertale (and other GameMaker gam |
| [redballoonsecurity/ofrak](https://github.com/redballoonsecurity/ofrak) | 2076 | Python | OFRAK: unpack, modify, and repack binaries. |
| [NotPrab/.NET-Deobfuscator](https://github.com/NotPrab/.NET-Deobfuscator) | 1522 | - | Lists of .NET Deobfuscator and Unpacker (Open Source) |
| [ergrelet/unlicense](https://github.com/ergrelet/unlicense) | 1495 | Python | Dynamic unpacker and import fixer for Themida/WinLicense 2.x and 3.x. |
| [dscharrer/innoextract](https://github.com/dscharrer/innoextract) | 1385 | C++ | A tool to unpack installers created by Inno Setup |
| [SychicBoy/NETReactorSlayer](https://github.com/SychicBoy/NETReactorSlayer) | 1272 | C# | An open source (GPLv3) deobfuscator and unpacker for Eziriz .NET Reactor |
| [strazzere/android-unpacker](https://github.com/strazzere/android-unpacker) | 1181 | C | Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0 |
| [WithSecureLabs/python-exe-unpacker](https://github.com/WithSecureLabs/python-exe-unpacker) | 1018 | Python | A helper script for unpacking and decompiling EXEs compiled from python code. |

## F 文件系统镜像

- **现状**：`fsx` 只能按签名检出 squashfs/jffs2/cramfs/UBI，明确标注「检不冒充提」。
- **缺口 / 拟接入**：固件逆向 80% 的工作是「把文件系统完好取出」。SquashFS（含 LZO/xz/zstd 压缩）与 CramFS 解析可纯 Python 实现，是最高性价比的一跃。


候选对照（102 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [plougher/squashfs-tools](https://github.com/plougher/squashfs-tools) | 932 | C | tools to create and extract Squashfs filesystems |
| [DC-SWAT/DreamShell](https://github.com/DC-SWAT/DreamShell) | 568 | C | Operating system for the Sega Dreamcast, NAOMI and NAOMI 2 |
| [zszszszsz/.config](https://github.com/zszszszsz/.config) | 362 | Shell | # # Automatically generated file; DO NOT EDIT. # OpenWrt Configuration # CONFIG_MODULES=y CONFIG |
| [Gregwar/fatcat](https://github.com/Gregwar/fatcat) | 329 | C++ | FAT filesystems explore, extract, repair, and forensic tool |
| [malus-security/iextractor](https://github.com/malus-security/iextractor) | 225 | C++ | Automate extraction from iOS firmware files (.ipsw) |
| [nlitsme/extfstools](https://github.com/nlitsme/extfstools) | 143 | C++ | Tools for extracting files from ext2,3,4 filesystem images |
| [firmadyne/extractor](https://github.com/firmadyne/extractor) | 65 | Python | Kernel and filesystem extractor |
| [citruz/dmgwiz](https://github.com/citruz/dmgwiz) | 60 | Rust | Extract filesystem data from DMG files |
| [ReFirmLabs/qnx6-extractor](https://github.com/ReFirmLabs/qnx6-extractor) | 45 | Python | extractor for QNX6 filesystem format. |
| [jimmikaelkael/eromdir](https://github.com/jimmikaelkael/eromdir) | 31 | C | PS2 erom dump files extractor. The goal this program is to allow to list files from an Encrypted |
| [jkbenaim/efsextract](https://github.com/jkbenaim/efsextract) | 19 | C | Extract files from SGI CD images (EFS file system) |
| [marostcs/konzole](https://github.com/marostcs/konzole) | 19 | - | 09:17:02 Steam Console Client (c) Valve Corporation 09:17:02 -- type 'quit' to exit -- 09:17:02  |

## G 固件/硬件/引导

- **现状**：`fsx` 有 U-Boot image / DTB / TRX / Android boot.img 等 24 条签名。
- **缺口 / 拟接入**：缺口是**分区表与 bootloader 语义**：GPT/MBR 分区、UBI/UBIFS、以及 bootloader 环境变量。这一步做成后，「从零逆向一块固件」链路才闭合。


候选对照（149 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | 86074 | Java | Ghidra is a software reverse engineering (SRE) framework |
| [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) | 49836 | C++ | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware ana |
| [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | 41644 | PowerShell | Reverse Engineering / Authorized Penetration Testing / Security Research Skill Router Pack AI-po |
| [The-Art-of-Hacking/h4cker](https://github.com/The-Art-of-Hacking/h4cker) | 29735 | Jupyter Notebook | This repository is maintained by Omar Santos (@santosomar) and includes thousands of resources r |
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 25869 | Java | A tool for reverse engineering Android apk files |
| [radareorg/radare2](https://github.com/radareorg/radare2) | 25017 | C | UNIX-like reverse engineering framework and command-line toolset |
| [rizinorg/cutter](https://github.com/rizinorg/cutter) | 19998 | C++ | Free and Open Source Reverse Engineering Platform powered by rizin |
| [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) | 15670 | Java | A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More) |
| [mytechnotalent/Reverse-Engineering](https://github.com/mytechnotalent/Reverse-Engineering) | 14622 | Assembly | A FREE comprehensive reverse engineering tutorial covering x86, x64, 32-bit/64-bit ARM, 8-bit AV |
| [OWASP/mastg](https://github.com/OWASP/mastg) | 13246 | Python | The OWASP Mobile Application Security Testing Guide (MASTG) is a comprehensive manual for mobile |
| [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | 12773 | Python | AI-powered reverse engineering assistant that bridges IDA Pro with language models through MCP. |
| [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | 11046 | Python | Exploit Development and Reverse Engineering with GDB & LLDB Made Easy |

## H 二进制差分/相似性

- **现状**：有 `sim`（函数级指纹差分）与 `diff`（字节差分）。
- **缺口 / 拟接入**：缺函数调用图级匹配（BinDiff/Diaphora 的核心：图同构近似匹配），升级 `sim` 到「指纹 + 调用图邻域」二级匹配，准确率会有量级提升。


候选对照（213 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) | 4426 | Python | Diaphora, the most advanced Free and Open Source program diffing tool. |
| [google/bindiff](https://github.com/google/bindiff) | 3205 | Java | Quickly find differences and similarities in disassembled code |
| [google/binexport](https://github.com/google/binexport) | 1212 | C++ | Export disassemblies into Protocol Buffers |
| [clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff) | 812 | Python | Python Command-Line Ghidra Binary Diffing Engine |
| [sayantann11/all-classification-templetes-for-ML](https://github.com/sayantann11/all-classification-templetes-for-ML) | 303 | Python | Classification - Machine Learning This is ‘Classification’ tutorial which is a part of the Machi |
| [ubfx/BinDiffHelper](https://github.com/ubfx/BinDiffHelper) | 297 | Java | Ghidra Extension to integrate BinDiff for function matching |
| [thetacom/hexabyte](https://github.com/thetacom/hexabyte) | 294 | Python | A modern, modular, and robust TUI hex editor. |
| [google/vxsig](https://github.com/google/vxsig) | 288 | C++ | Automatically generate AV byte signatures from sets of similar binaries. |
| [Lil-Ran/build-bindiff-for-ida-9](https://github.com/Lil-Ran/build-bindiff-for-ida-9) | 247 | - | Use GitHub Actions to build BinDiff 8 and BinExport 12 for various IDA Pro 9.x on Windows, macOS |
| [quarkslab/qbindiff](https://github.com/quarkslab/qbindiff) | 246 | Python | Quarkslab Bindiffer but not only ! |
| [vul337/jTrans](https://github.com/vul337/jTrans) | 197 | Python | Official code of jTrans: Jump-Aware Transformer for Binary Code Similarity Detection |
| [joshterrill/post-patch-postmortem](https://github.com/joshterrill/post-patch-postmortem) | 170 | Python | a CLI tool for analyzing Microsoft Patch Tuesday security updates. Fetches patch data from MSRC, |

## I Android/DEX 深水

- **现状**：`apk` 已解 AXML + 权限/组件/导出面/DEX 摘要，DEX 只做摘要、resources.arsc 只申报存在。
- **缺口 / 拟接入**：用户明确要求的核心场景「APK 里调用了什么接口」需要把 DEX 落到 **方法级**：method_ids → 类/方法名 → 常量池里的字符串与 URL → 汇总成调用面。这一步做完才是真正的 APK 接口地图。


候选对照（243 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 25869 | Java | A tool for reverse engineering Android apk files |
| [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) | 15670 | Java | A Java 8+ Jar & Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger & More) |
| [alphaSeclab/awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering) | 5113 | - | Reverse Engineering Resources About All Platforms(Windows/Linux/macOS/Android/iOS/IoT) And Every |
| [charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool) | 4855 | Python | the fastest and most powerful android decompiler(native tool working without Java VM) for the AP |
| [Jermic/Android-Crack-Tool](https://github.com/Jermic/Android-Crack-Tool) | 2941 | - | 🐞Android crack tool For Mac |
| [user1342/Awesome-Android-Reverse-Engineering](https://github.com/user1342/Awesome-Android-Reverse-Engineering) | 2734 | - | A curated list of awesome Android Reverse Engineering training, resources, and tools. |
| [MG1937/ASC](https://github.com/MG1937/ASC) | 2339 | Python | ASC is a super FAST and lightweight Android decompiler designed for Agents/Mobile Researchers. G |
| [Juude/droidReverse](https://github.com/Juude/droidReverse) | 2021 | Shell | reverse engineering tools for android（android 逆向工程工具集） |
| [suifei/fridare](https://github.com/suifei/fridare) | 947 | Go | 强大的 Frida 重打包工具，用于 iOS 和 Android。轻松修改 Frida 特征，增强隐蔽性，绕过检测。简化逆向工程和安全测试。Powerful Frida repackaging |
| [n0mi1k/apk2url](https://github.com/n0mi1k/apk2url) | 880 | Shell | An OSINT tool to quickly extract IP and URL endpoints from APKs by disassembling and decompiling |
| [1N3/ReverseAPK](https://github.com/1N3/ReverseAPK) | 872 | Shell | Quickly analyze and reverse engineer Android packages |
| [neocanable/garlic](https://github.com/neocanable/garlic) | 856 | C | The world's fastest apk (android)/java open source decompiler |

## J 分发包格式

- **现状**：有 ZIP/APK/IPA/ISO(tar/gzip/cpio 成员)，无 deb/rpm/msi/cab/xz(容器)/7z SFX。
- **缺口 / 拟接入**：分发包是「最容易拿到的一类样本」，且多为容器套娃（deb=ar+tar+xz）。做成统一「容器递归展开」层，复用到 E/F 两域。


候选对照（136 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [electron-userland/electron-builder](https://github.com/electron-userland/electron-builder) | 14669 | TypeScript | A complete solution to package and build a ready for distribution Electron app with “auto update |
| [goreleaser/nfpm](https://github.com/goreleaser/nfpm) | 2670 | Go | nFPM is Not FPM - a simple deb, rpm, apk, ipk, and arch linux packager written in Go |
| [activescott/lessmsi](https://github.com/activescott/lessmsi) | 1766 | C# | A tool to view and extract the contents of an Windows Installer (.msi) file. |
| [sbt/sbt-native-packager](https://github.com/sbt/sbt-native-packager) | 1606 | Scala | sbt Native Packager |
| [javapackager/JavaPackager](https://github.com/javapackager/JavaPackager) | 1196 | Java | Gradle/Maven plugin to package Java applications as native Windows, MacOS, or Linux executables  |
| [openSUSE/open-build-service](https://github.com/openSUSE/open-build-service) | 1084 | Ruby | Build and distribute Linux packages from sources in an automatic, consistent and reproducible wa |
| [patrickjaja/claude-desktop-extra](https://github.com/patrickjaja/claude-desktop-extra) | 673 | JavaScript | Unofficial Linux packages for Claude Desktop AI assistant with automated updates. |
| [tcurdt/jdeb](https://github.com/tcurdt/jdeb) | 542 | Java | This library provides an Ant task and a Maven plugin to create Debian packages from Java builds  |
| [kaltura/platform-install-packages](https://github.com/kaltura/platform-install-packages) | 533 | Shell | Official deployment packages to install the Kaltura platform on a server or cluster environments |
| [termux/termux-create-package](https://github.com/termux/termux-create-package) | 508 | Python | Python script to create Termux packages easily. |
| [crabnebula-dev/cargo-packager](https://github.com/crabnebula-dev/cargo-packager) | 489 | Rust | Rust executable packager, bundler and updater. |
| [zszszszsz/.config](https://github.com/zszszszsz/.config) | 362 | Shell | # # Automatically generated file; DO NOT EDIT. # OpenWrt Configuration # CONFIG_MODULES=y CONFIG |

## K 协议/流量/PCAP

- **现状**：有 `netaddr`/`endpoints` 静态抽取 URL/IP/域名，无抓包文件解析、无 protobuf 无 schema 解码。
- **缺口 / 拟接入**：移动/ IoT 应用的私有协议常用 protobuf/MessagePack，「无 schema 解码 + 字段语义推断」是把二进制流量变成可读接口文档的关键能力。


候选对照（285 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [GyulyVGC/sniffnet](https://github.com/GyulyVGC/sniffnet) | 41494 | Rust | Comfortably monitor your network traffic 🕵️‍♂️ |
| [secdev/scapy](https://github.com/secdev/scapy) | 12601 | Python | Scapy: the Python-based interactive packet manipulation program & library. |
| [kubeshark/kubeshark](https://github.com/kubeshark/kubeshark) | 12095 | Go | eBPF-powered network observability for Kubernetes. Indexes L4/L7 traffic with full K8s context,  |
| [wader/fq](https://github.com/wader/fq) | 10610 | Go | fq - jq for binary formats. Tool, language and decoders for working with binary formats. |
| [gcla/termshark](https://github.com/gcla/termshark) | 10036 | Go | A terminal UI for tshark, inspired by Wireshark |
| [zeek/zeek](https://github.com/zeek/zeek) | 8098 | C++ | Zeek is a powerful network analysis framework that is much different from the typical IDS you ma |
| [arkime/arkime](https://github.com/arkime/arkime) | 7533 | C | Arkime is an open source, large scale, full packet capturing, indexing, and database system. |
| [bee-san/pyWhat](https://github.com/bee-san/pyWhat) | 7330 | Python | 🐸   Identify anything. pyWhat easily lets you identify emails, IP addresses, and more. Feed it a |
| [emanuele-f/PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | 4905 | Java | No-root network monitor, firewall and PCAP dumper for Android |
| [pavel-odintsov/fastnetmon](https://github.com/pavel-odintsov/fastnetmon) | 3713 | C++ | Very fast DDoS sensor with sFlow/Netflow/IPFIX/SPAN support |
| [odedshimon/BruteShark](https://github.com/odedshimon/BruteShark) | 3404 | C# | Network Analysis Tool |
| [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) | 3245 | C | the TCPdump network dissector |

## L Web/JS/WASM

- **现状**：`identify` 认得出 WASM 与 JS，但无反混淆/无 WASM 反编译。
- **缺口 / 拟接入**：WASM 是栈机 + 显式类型，反编译到伪代码比原生还容易（有完整的类型信息），而 JS 反混淆（字符串数组 + 控制流）有成熟参考实现。


候选对照（152 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [j4k0xb/webcrack](https://github.com/j4k0xb/webcrack) | 2960 | TypeScript | Deobfuscate obfuscator.io, unminify and unpack bundled javascript |
| [relative/synchrony](https://github.com/relative/synchrony) | 1253 | TypeScript | javascript-obfuscator cleaner & deobfuscator |
| [kuizuo/js-deobfuscator](https://github.com/kuizuo/js-deobfuscator) | 1183 | JavaScript | An automated JavaScript deobfuscation tool based on Babel AST, with an online playground, CLI, a |
| [ben-sb/javascript-deobfuscator](https://github.com/ben-sb/javascript-deobfuscator) | 1154 | TypeScript | General purpose JavaScript deobfuscator |
| [ben-sb/obfuscator-io-deobfuscator](https://github.com/ben-sb/obfuscator-io-deobfuscator) | 807 | TypeScript | A deobfuscator for scripts obfuscated by Obfuscator.io |
| [IndAlok/rzweb](https://github.com/IndAlok/rzweb) | 764 | TypeScript | A complete browser-based reverse engineering platform built on Rizin, running entirely client-si |
| [HumanSecurity/restringer](https://github.com/HumanSecurity/restringer) | 610 | JavaScript | A Javascript Deobfuscator |
| [vicnaum/bun-demincer](https://github.com/vicnaum/bun-demincer) | 222 | JavaScript | Decompiler, deminifier and deobfuscator for Bun-compiled standalone JavaScript binaries |
| [LostMyCode/javascript-deobfuscator](https://github.com/LostMyCode/javascript-deobfuscator) | 191 | JavaScript | A deobfuscator for JavaScript codes generated by Obfuscator.io |
| [geeksonsecurity/illuminatejs](https://github.com/geeksonsecurity/illuminatejs) | 157 | TypeScript | IlluminateJS is a static JavaScript deobfuscator |
| [willnode/deobfuscator](https://github.com/willnode/deobfuscator) | 152 | JavaScript | Online Javascript Deobfuscator Tool |
| [1-3-7/disrobe](https://github.com/1-3-7/disrobe) | 149 | Rust | Static decompiler, deobfuscator, and unpacker for reverse engineering and malware analysis: Pyth |

## M Apple/Mach-O 生态

- **现状**：有 Mach-O 结构解析、`plist`、`archs`（胖二进制）。
- **缺口 / 拟接入**：缺 **Objective-C 运行时元数据**（classlist/selrefs 里的类名与方法名）与 dyld_shared_cache 解析。前者直接给出 iOS 应用的类/方法调用面，是 Apple 生态版的「接口地图」。


候选对照（270 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [OWASP/mastg](https://github.com/OWASP/mastg) | 13246 | Python | The OWASP Mobile Application Security Testing Guide (MASTG) is a comprehensive manual for mobile |
| [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11691 | JavaScript | Program for determining types of files for Windows, Linux and MacOS. |
| [majd/ipatool](https://github.com/majd/ipatool) | 11659 | Go | Command-line tool that allows you to search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS  |
| [AloneMonkey/MonkeyDev](https://github.com/AloneMonkey/MonkeyDev) | 6799 | Objective-C | CaptainHook Tweak、Logos Tweak and Command-line Tool、Patch iOS Apps,  Without Jailbreak. |
| [Naituw/IPAPatch](https://github.com/Naituw/IPAPatch) | 5295 | Objective-C | Patch iOS Apps, The Easy Way, Without Jailbreak. |
| [below/HelloSilicon](https://github.com/below/HelloSilicon) | 5009 | Assembly | An introduction to ARM64 assembly on Apple Silicon Macs |
| [AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) | 3947 | JavaScript | pull decrypted ipa from jailbreak device |
| [nygard/class-dump](https://github.com/nygard/class-dump) | 3586 | Objective-C | Generate Objective-C headers from Mach-O files. |
| [vaib25vicky/awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security) | 3561 | - | An effort to build a single place for all useful android and iOS security related stuff. All ref |
| [nabla-c0d3/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2) | 3322 | Objective-C | Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS |
| [ivRodriguezCA/RE-iOS-Apps](https://github.com/ivRodriguezCA/RE-iOS-Apps) | 2917 | - | A completely free, open source and online course about Reverse Engineering iOS Applications. |
| [aozhimin/iOS-Monitor-Platform](https://github.com/aozhimin/iOS-Monitor-Platform) | 2622 | - | :books: iOS 性能监控 SDK —— Wedjat（华狄特）开发过程的调研和整理 |

## N .NET 反编译

- **现状**：`dotnet` 只读 CLR 头与元数据流/程序集名。
- **缺口 / 拟接入**：IL 是栈式字节码且有完整元数据，**反编译到 C# 的性价比极高**（dnSpy/ILSpy 已证明）。这一项几乎是「投入产出比最高」的缺口。


候选对照（222 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) | 26598 | C# | .NET Decompiler with support for PDB generation, ReadyToRun, Metadata (&more) - cross-platform! |
| [SamboyCoding/Cpp2IL](https://github.com/SamboyCoding/Cpp2IL) | 2983 | C# | Work-in-progress tool to reverse unity's IL2CPP toolchain. |
| [uxmal/reko](https://github.com/uxmal/reko) | 2613 | C# | Reko is a binary decompiler. |
| [ErikEJ/EFCorePowerTools](https://github.com/ErikEJ/EFCorePowerTools) | 2514 | C# | Entity Framework Core Power Tools - reverse engineering, migrations and model visualization in V |
| [ValveResourceFormat/ValveResourceFormat](https://github.com/ValveResourceFormat/ValveResourceFormat) | 2498 | C# | Source 2 Viewer is an all-in-one tool to browse VPK archives, view, extract, and decompile Sourc |
| [Washi1337/AsmResolver](https://github.com/Washi1337/AsmResolver) | 1127 | C# | A library for creating, reading and editing PE files and .NET modules. |
| [OpenRakis/Spice86](https://github.com/OpenRakis/Spice86) | 661 | C# | Reverse engineer and rewrite real mode DOS programs!  |
| [B2R2-org/B2R2](https://github.com/B2R2-org/B2R2) | 552 | F# | B2R2 is a fully managed binary analysis framework written in F#. It provides a rich set of algor |
| [mysticmind/reversemarkdown-net](https://github.com/mysticmind/reversemarkdown-net) | 405 | HTML | ReverseMarkdown.Net is a Html to Markdown converter library in C#. |
| [codemerx/CodemerxDecompile](https://github.com/codemerx/CodemerxDecompile) | 399 | C# | The first standalone .NET decompiler for Mac, Linux and Windows |
| [yukiarrr/Il2cppSpy](https://github.com/yukiarrr/Il2cppSpy) | 360 | Python | Unity IL2CPP Disassembler (for apk) |
| [ioncodes/dnpatch](https://github.com/ioncodes/dnpatch) | 329 | C# | .NET Patcher library using dnlib |

## O 序列化/IDL 推断

- **现状**：`identify` 认 SQLite，无 protobuf/MessagePack/CBOR/Avro/Thrift。
- **缺口 / 拟接入**：同 K 域：应用中大量配置/通信走序列化二进制，「无 schema 推断出字段结构」对接口逆向是直接可用的能力。


候选对照（94 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [SoftbearStudios/bitcode](https://github.com/SoftbearStudios/bitcode) | 675 | Rust | A binary encoder/decoder for Rust |
| [mongodb/bson-rust](https://github.com/mongodb/bson-rust) | 461 | Rust | Encoding and decoding support for BSON in Rust |
| [winddpan/CodableWrapper](https://github.com/winddpan/CodableWrapper) | 389 | Swift | @CodingKey("encoder", "decoder") var cool: Bool = true |
| [creationix/rx](https://github.com/creationix/rx) | 382 | TypeScript | RX encoder, decoder, and CLI data tool |
| [NeuroJSON/jsonlab](https://github.com/NeuroJSON/jsonlab) | 320 | MATLAB | JSONLab: compact, portable, robust JSON/binary-JSON encoder/decoder for MATLAB/Octave |
| [laurencelundblade/QCBOR](https://github.com/laurencelundblade/QCBOR) | 241 | C | Comprehensive, powerful, commercial-quality CBOR encoder/ decoder that is still suited for small |
| [christophhagen/BinaryCodable](https://github.com/christophhagen/BinaryCodable) | 125 | Swift | A binary encoder for Swift Codable types |
| [toby/serde-bencode](https://github.com/toby/serde-bencode) | 78 | Rust | Serde backed Bencode encoding/decoding library for Rust. |
| [daangn/urlpack](https://github.com/daangn/urlpack) | 61 | TypeScript | Pure JavaScript toolkit for data URLs (MessagePack, Base58 and Base62) |
| [loopholelabs/polyglot](https://github.com/loopholelabs/polyglot) | 57 | Go | A high-performance serialization framework used for encoding and decoding arbitrary datastructur |
| [Pipelex/kajson](https://github.com/Pipelex/kajson) | 54 | Python | Powerful universal JSON encoder/decoder for Python objects with support for pydantic v2. |
| [fumoboy007/msgpack-swift](https://github.com/fumoboy007/msgpack-swift) | 45 | Swift | An efficient, full-featured, and compliant MessagePack implementation for Swift. / msgpack.org[S |

## P 符号执行/SMT

- **现状**：无任何符号执行能力。
- **缺口 / 拟接入**：完整符号执行需要重写 SMT 求解器，代价巨大。务实路线：**约束求解外包给可选外部 SMT（z3），本地只做路径探索与约束生成**，或用「具体值 + 轻量传播」的折叠求值覆盖大部分常量还原场景。


候选对照（96 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton) | 4327 | C++ | Triton is a dynamic binary analysis library. Build your own program analysis tools, automate you |
| [ConsenSysDiligence/mythril](https://github.com/ConsenSysDiligence/mythril) | 4271 | Python | Mythril is a symbolic-execution-based securty analysis tool for EVM bytecode. It detects securit |
| [cea-sec/miasm](https://github.com/cea-sec/miasm) | 3989 | Python | Reverse engineering framework in Python |
| [klee/klee](https://github.com/klee/klee) | 2983 | C++ | KLEE Symbolic Execution Engine |
| [BinaryAnalysisPlatform/bap](https://github.com/BinaryAnalysisPlatform/bap) | 2264 | OCaml | Binary Analysis Platform |
| [illera88/Ponce](https://github.com/illera88/Ponce) | 1633 | C++ | IDA 2016 plugin contest winner! Symbolic Execution just one-click away! |
| [JonathanSalwan/VMProtect-devirtualization](https://github.com/JonathanSalwan/VMProtect-devirtualization) | 1532 | Roff | Playing with the VMProtect software protection. Automatic deobfuscation of pure functions using  |
| [ksluckow/awesome-symbolic-execution](https://github.com/ksluckow/awesome-symbolic-execution) | 1502 | - | A curated list of awesome symbolic execution resources including essential research papers, lect |
| [pschanely/CrossHair](https://github.com/pschanely/CrossHair) | 1337 | Python | An analysis tool for Python that blurs the line between testing and type systems. |
| [AliveToolkit/alive2](https://github.com/AliveToolkit/alive2) | 1181 | C++ | Automatic verification of LLVM optimizations |
| [wisk/medusa](https://github.com/wisk/medusa) | 1089 | C++ | An open source interactive disassembler |
| [AngoraFuzzer/Angora](https://github.com/AngoraFuzzer/Angora) | 957 | C++ | Angora is a mutation-based fuzzer.  The main goal of Angora is to increase branch coverage by so |

## Q 更多指令集(MIPS/RISC-V/PPC)

- **现状**：只支持 x86/x86-64/ARM64/Thumb。
- **缺口 / 拟接入**：**硬伤**：路由器/摄像头/工控固件几乎全是 MIPS 与 RISC-V。不做这个，「从零逆向硬件」就是空话。MIPS（R3000 子集）与 RISC-V（RV32IMC）表驱动解码器可控在千行内。


候选对照（169 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | 86076 | Java | Ghidra is a software reverse engineering (SRE) framework |
| [WerWolv/ImHex](https://github.com/WerWolv/ImHex) | 55127 | C++ | 🔍 A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when workin |
| [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) | 49836 | C++ | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware ana |
| [radareorg/radare2](https://github.com/radareorg/radare2) | 25017 | C | UNIX-like reverse engineering framework and command-line toolset |
| [horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | 11691 | JavaScript | Program for determining types of files for Windows, Linux and MacOS. |
| [pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | 11046 | Python | Exploit Development and Reverse Engineering with GDB & LLDB Made Easy |
| [capstone-engine/capstone](https://github.com/capstone-engine/capstone) | 9084 | C | Capstone disassembly/disassembler framework for ARM, ARM64 (ARMv8), Alpha, BPF, Ethereum VM, HPP |
| [zrax/pycdc](https://github.com/zrax/pycdc) | 4648 | C++ | C++ python bytecode disassembler and decompiler |
| [zyantific/zydis](https://github.com/zyantific/zydis) | 4388 | C | Fast and lightweight x86/x86-64 disassembler and code generation library |
| [cea-sec/miasm](https://github.com/cea-sec/miasm) | 3989 | Python | Reverse engineering framework in Python |
| [icedland/iced](https://github.com/icedland/iced) | 3589 | Rust | Blazing fast and correct x86/x64 disassembler, assembler, decoder, encoder for Rust, .NET, Java, |
| [horsicq/DIE-engine](https://github.com/horsicq/DIE-engine) | 3307 | C++ | DIE engine |

## R 仿真执行/脱壳基座

- **现状**：无任何 CPU 仿真。
- **缺口 / 拟接入**：仿真是动态脱壳与混淆还原的终极手段，但自研完整 emulator 代价极高。务实做法：先做「受控解释器」——只对选定函数做指令级解释 + 内存读写追踪（unicorn 同思路但仅覆盖必要指令子集）。


候选对照（148 个候选中 Star 前 12）：

| 项目 | ★ | 语言 | 简介 |
|---|---:|---|---|
| [unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn) | 9435 | C | Unicorn CPU emulator framework (ARM, AArch64, M68K, Mips, Sparc, PowerPC, RiscV, S390x, TriCore, |
| [AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) | 6798 | C | AFL++ is a state-of-the-art fuzzer, and #1 in benchmarks. It was originally based on AFL. Today  |
| [qilingframework/qiling](https://github.com/qilingframework/qiling) | 6129 | Python | A True Instrumentable Binary Emulation Framework |
| [JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton) | 4327 | C++ | Triton is a dynamic binary analysis library. Build your own program analysis tools, automate you |
| [BinaryAnalysisPlatform/bap](https://github.com/BinaryAnalysisPlatform/bap) | 2264 | OCaml | Binary Analysis Platform |
| [QBDI/QBDI](https://github.com/QBDI/QBDI) | 1827 | C++ | A Dynamic Binary Instrumentation framework based on LLVM. |
| [lcgamboa/picsimlab](https://github.com/lcgamboa/picsimlab) | 669 | C++ | PICSimLab - Programmable IC Simulator Laboratory ⚠️ Please note: The official distribution of th |
| [AlexAltea/unicorn.js](https://github.com/AlexAltea/unicorn.js) | 604 | JavaScript | Unicorn CPU emulator framework port for JavaScript |
| [zeropointdynamics/zelos](https://github.com/zeropointdynamics/zelos) | 420 | Python | A comprehensive binary emulation and instrumentation platform. |
| [zszszszsz/.config](https://github.com/zszszszsz/.config) | 362 | Shell | # # Automatically generated file; DO NOT EDIT. # OpenWrt Configuration # CONFIG_MODULES=y CONFIG |
| [aengelke/instrew](https://github.com/aengelke/instrew) | 292 | C | A high performance LLVM-based dynamic binary instrumentation framework |
| [RPCS3/rpcs3-binaries-win](https://github.com/RPCS3/rpcs3-binaries-win) | 291 | - | Repository for Windows x64 binaries |

---

> 归档（archived）项目已排除；本轮候选总数 3124，各域 Top 的 Star 门槛与「能否用纯标准库复刻」是下一轮筛选的两个硬指标。
