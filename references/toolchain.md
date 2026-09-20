# 工具矩阵与安装速查

## 1. 按场景速查：我该用什么工具？

| 场景 | 第一选择 | 备选 |
|---|---|---|
| 看一个 exe 是什么 | Detect It Easy (DiE) / pestudio | `file`、CFF Explorer |
| 反编译 Windows 程序 | **Ghidra**（免费）/ IDA Pro + Hex-Rays | Binary Ninja、radare2+Cutter、dogbolt.org |
| 调试 Windows 程序 | **x64dbg** | WinDbg（内核/崩溃）、OllyDbg |
| 调试 Linux 程序 | **GDB + pwndbg/gef/peda** | strace、ltrace、radare2 |
| 调试 macOS/iOS | **LLDB** | Hopper（静态）、dtrace |
| 跨平台 Hook | **Frida** | DynamoRIO、Intel Pin |
| 符号执行 | **angr + Z3** | Triton、KLEE |
| 恶意样本行为 | Cuckoo / CAPE 沙箱 | Any.run、Noriben、Sysmon |
| 反编译 APK | **jadx** | apktool（smali）、JEB、MobSF |
| Android Hook | Frida / LSPosed | Xposed、Objection |
| Android 抓包 | Burp / mitmproxy | Charles、Postern |
| iOS 砸壳 | frida-ios-dump | bagbak |
| iOS 类结构 | class-dump | Hopper、IDA |
| 反编译 .NET | **dnSpyEx** | ILSpy、dotPeek、de4dot（去混淆） |
| 反编译 Java | **CFR / FernFlower / BCV 多引擎对比** | Procyon、Recaf、javap |
| Java 线上诊断 | **arthas** | JFR、JVisualVM、BTrace |
| 反编译 pyc | pycdc | uncompyle6、xdis |
| 解 Electron 应用 | `npx asar extract app.asar` | — |
| 分析 WASM | wasm2wat / wasm-decompile | Chrome DevTools、Ghidra WASM 插件 |
| 解固件 | **binwalk** + unsquashfs | FMK、EMBA、FACT |
| 模拟固件 | QEMU / firmadyne / FirmAE | Qiling |
| 十六进制分析 | **ImHex** | 010 Editor、HxD |
| 协议分析 | Wireshark + Scapy | Netzob、tshark、mitmproxy |
| 游戏内存 | Cheat Engine + ReClass.NET | x64dbg |
| Unity IL2CPP | **Il2CppDumper** | Il2CppInspector、Cpp2IL |

## 2. 静态分析工具矩阵

| 类别 | 工具 | 定位 |
|---|---|---|
| 商业王者 | IDA Pro + Hex-Rays | 交互分析 + F5 反编译，业界金标准 |
| 开源王者 | **Ghidra** | NSA 开源，SLEIGH 支持几十种架构，自带反编译器，支持 headless 批处理 |
| 新锐 | Binary Ninja | 三层 IR + 极佳 Python API，自动化舒服 |
| 轻量商业 | Hopper | macOS/Linux 便宜好用 |
| 开源命令行 | **radare2 / rizin** + Cutter(GUI) | 全免费、脚本化强、支持极多架构 |
| 交叉验证 | **dogbolt.org** | 并排对比 Hex-Rays/Ghidra/Binja/angr 的反编译输出，**强烈推荐** |

### Ghidra headless 批处理（批量样本必用）
```bash
./support/analyzeHeadless ./projects MyProject \
  -import ./samples/target.bin \
  -postScript MyAnalysis.java \
  -deleteProject
```

### 符号恢复（让「无名世界」变「有名世界」）
| 技术 | 说明 |
|---|---|
| FLIRT 签名（IDA） | 用预生成 `.sig` 识别静态链接进来的库函数（OpenSSL、zlib…） |
| `sigmake` | 自己从 `.lib`/`.a` 生成签名文件 |
| Lumina（IDA） | 云端哈希数据库，自动拉取他人已命名的符号 |
| bindiff / diaphora | 对比相似二进制，把旧版本已知符号迁移到新版本 |

## 3. 动态分析工具矩阵

### 插桩框架
| 框架 | 定位 |
|---|---|
| **Frida** | 事实标准：JS 脚本、跨平台、`Interceptor.attach/replace`、`Stalker` 指令级追踪、`Java.perform`、免 root 用 `frida-gadget` |
| DynamoRIO | 工业级 DBI，性能分析/污点追踪 |
| Intel Pin | Intel 官方 DBI，学术圈常用 |
| Unicorn | 纯 CPU 模拟器（无 OS），可单跑一段函数 |
| Qiling | 基于 Unicorn 的全系统模拟框架，能跑整个 ELF/PE 并处理系统调用 |
| Triton | 动态符号执行 + 污点分析 |

### 沙箱（恶意样本必做）
| 工具 | 说明 |
|---|---|
| Cuckoo Sandbox | 经典开源自动化沙箱，产出行为报告 + 网络 IOC |
| CAPE | Cuckoo 增强分支，**擅长自动脱壳**与 payload 提取 |
| Any.run / Hybrid Analysis | 在线交互式沙箱（⚠️ 上传样本等于公开，敏感样本别传） |
| Noriben | 轻量 Windows 行为记录（Procmon + Python） |
| Sysmon + Windows 事件日志 | 生产环境行为采集 |

## 4. 符号执行：把「猜」变成「算」

```python
import angr, claripy
proj = angr.Project("./crackme", auto_load_libs=False)
flag = claripy.BVS("flag", 8 * 16)
st = proj.factory.full_init_state(stdin=flag)
sim = proj.factory.simgr(st)
sim.explore(find=0x400B45, avoid=0x400B60)
if sim.found:
    print(sim.found[0].posix.dumps(0))
```

| 工具 | 用途 |
|---|---|
| angr | Python 符号执行框架，默认 Z3 求解 |
| Z3 | 微软 SMT 求解器，可单独解约束 |
| KLEE | 基于 LLVM（需源码或 bitcode） |
| Triton | 动态符号执行 + 污点分析 |

⚠️ **正确用法**：先用静态分析缩小范围，只对关键校验函数做符号执行。
对整个程序跑必然路径爆炸。

## 5. 安装源速查

| 工具 | 官方地址 |
|---|---|
| Ghidra | https://github.com/NationalSecurityAgency/ghidra/releases |
| radare2 | https://github.com/radareorg/radare2 |
| rizin | https://github.com/rizinorg/rizin |
| Frida | https://frida.re/docs/installation/ （`pip install frida-tools`） |
| x64dbg | https://x64dbg.com |
| jadx | https://github.com/skylot/jadx/releases |
| apktool | https://apktool.org/docs/install/ |
| Il2CppDumper | https://github.com/Perfare/Il2CppDumper |
| frida-ios-dump | https://github.com/AloneMonkey/frida-ios-dump |
| class-dump | https://github.com/nygard/class-dump |
| dnSpyEx | https://github.com/dnSpyEx/dnSpy |
| ILSpy | https://github.com/icsharpcode/ILSpy |
| de4dot | https://github.com/de4dot/de4dot |
| CFR | https://www.benf.org/other/cfr/ |
| pycdc | https://github.com/zrax/pycdc |
| pyinstxtractor | https://github.com/extremecoders-re/pyinstxtractor |
| uncompyle6 | https://github.com/rocky/python-uncompyle6 |
| binwalk | https://github.com/ReFirmLabs/binwalk |
| ImHex | https://github.com/WerWolv/ImHex |
| wabt (wasm2wat) | https://github.com/WebAssembly/wabt |
| angr | https://github.com/angr/angr |
| capstone | https://www.capstone-engine.org/ |
| unicorn | https://www.unicorn-engine.org/ |
| qiling | https://github.com/qilingframework/qiling |
| androguard | https://github.com/androguard/androguard |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| objection | https://github.com/sensepost/objection |
| pwndbg | https://github.com/pwndbg/pwndbg |
| scapy | https://scapy.net/ |
| QEMU | https://www.qemu.org/download/ |
| mitmproxy | https://mitmproxy.org/ |
| dogbolt（在线多引擎对比） | https://dogbolt.org |

## 6. 学习路线

**阶段 1 · 打地基（1–2 月）**：C 与指针 → 汇编（x86-64 或 ARM64 先啃一个，配合 Compiler Explorer 对照 C 与汇编）→ 编译链接装载（《程序员的自我修养》）→ 进程/虚拟内存/系统调用。

**阶段 2 · 工具与手感（1–2 月）**：
- 《Reverse Engineering for Beginners》Dennis Yurichev — https://beginners.re/ （免费，有中文版）
- 《The IDA Pro Book》Chris Eagle
- 《加密与解密》（段钢）、《逆向工程核心原理》（李承远）

**阶段 3 · 动手练**：crackmes.one、pwnable.kr、**microcorruption**（嵌入式逆向神站）、picoCTF、Flare-On、OWASP MASTG CrackMes、Mobile Hacking Lab。

**阶段 4 · 专项深入**：二进制漏洞（pwndbg/ROP/堆/fuzzing）、恶意代码（沙箱/YARA/ATT&CK/Volatility）、移动（MASTG/Frida/加固原理）、IoT（binwalk/QEMU/UART-JTAG/SDR）、协议（PRE 论文/Wireshark dissector 开发）。

## 7. 持续关注的信息源

- 学术论文：USENIX Security、IEEE S&P、CCS、NDSS
- 会议：Black Hat、DEF CON、**REcon**（逆向专项）、OffensiveCon
- 标准：OWASP MASTG/MASVS、MITRE ATT&CK/CAPEC、NIST
- 社区：GitHub 各工具仓库、看雪学院、安全客、先知社区
