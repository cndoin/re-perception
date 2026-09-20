# -*- coding: utf-8 -*-
"""
lib_tools.py —— 外部工具链探测 + 分析计划生成。

设计原则：
  - 脚本自身零依赖，但逆向真正干活要靠外部工具。doctor 负责把「本机有什么」
    探测清楚，plan 负责把「下一步该敲什么命令」排出来。
  - 探测只读环境变量与 PATH（shutil.which），不执行任何外部程序，因此永远安全、飞快。
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys

# ---------------------------------------------------------------- 外部工具清单

TOOLS: list[dict] = [
    # 通用识别 / 反汇编 / 反编译
    {"cmd": "file",        "cat": "identify",  "desc": "文件类型识别（Unix）", "url": "https://www.gnu.org/software/file/"},
    {"cmd": "strings",     "cat": "identify",  "desc": "字符串提取", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "xxd",         "cat": "identify",  "desc": "十六进制转储", "url": "https://www.gnu.org/software/vim/"},
    {"cmd": "objdump",     "cat": "disasm",    "desc": "反汇编（binutils）", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "readelf",     "cat": "disasm",    "desc": "ELF 结构查看", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "nm",          "cat": "disasm",    "desc": "符号表查看", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "objcopy",     "cat": "disasm",    "desc": "目标文件改写/脱壳辅助", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "radare2",     "cat": "disasm",    "desc": "开源逆向框架 r2", "url": "https://github.com/radareorg/radare2"},
    {"cmd": "rizin",       "cat": "disasm",    "desc": "radare2 社区分支", "url": "https://github.com/rizinorg/rizin"},
    {"cmd": "r2",          "cat": "disasm",    "desc": "radare2 别名", "url": "https://github.com/radareorg/radare2"},
    {"cmd": "analyzeHeadless", "cat": "disasm", "desc": "Ghidra 无头批处理", "url": "https://github.com/NationalSecurityAgency/ghidra/releases"},
    {"cmd": "ghidraRun",   "cat": "disasm",    "desc": "Ghidra GUI", "url": "https://github.com/NationalSecurityAgency/ghidra/releases"},

    # 动态 / 调试
    {"cmd": "gdb",         "cat": "dynamic",   "desc": "Linux 调试器", "url": "https://www.gnu.org/software/gdb/"},
    {"cmd": "lldb",        "cat": "dynamic",   "desc": "macOS/iOS 调试器", "url": "https://lldb.llvm.org/"},
    {"cmd": "strace",      "cat": "dynamic",   "desc": "系统调用跟踪", "url": "https://strace.io/"},
    {"cmd": "ltrace",      "cat": "dynamic",   "desc": "库调用跟踪", "url": "https://man7.org/linux/man-pages/man1/ltrace.1.html"},
    {"cmd": "frida",       "cat": "dynamic",   "desc": "跨平台 Hook 框架（CLI）", "url": "https://frida.re/docs/installation/"},
    {"cmd": "frida-ps",    "cat": "dynamic",   "desc": "Frida 进程枚举", "url": "https://frida.re/docs/installation/"},
    {"cmd": "qemu-system-x86_64", "cat": "dynamic", "desc": "QEMU 全系统模拟（固件）", "url": "https://www.qemu.org/download/"},
    {"cmd": "qemu-arm",    "cat": "dynamic",   "desc": "QEMU 用户态模拟", "url": "https://www.qemu.org/download/"},

    # Android
    {"cmd": "jadx",        "cat": "android",   "desc": "DEX → Java 反编译（质量最高）", "url": "https://github.com/skylot/jadx/releases"},
    {"cmd": "jadx-gui",    "cat": "android",   "desc": "jadx 图形界面", "url": "https://github.com/skylot/jadx/releases"},
    {"cmd": "apktool",     "cat": "android",   "desc": "APK 资源/smali 双向转换", "url": "https://apktool.org/docs/install/"},
    {"cmd": "aapt2",       "cat": "android",   "desc": "Android 资源与清单查看", "url": "https://developer.android.com/tools/aapt2"},
    {"cmd": "apkanalyzer", "cat": "android",   "desc": "APK 静态分析（cmdline-tools）", "url": "https://developer.android.com/tools/apkanalyzer"},
    {"cmd": "adb",         "cat": "android",   "desc": "Android 调试桥", "url": "https://developer.android.com/tools/adb"},

    # iOS
    {"cmd": "class-dump",  "cat": "ios",       "desc": "导出 ObjC 类结构（macOS）", "url": "https://github.com/nygard/class-dump"},
    {"cmd": "otool",       "cat": "ios",       "desc": "Mach-O 结构查看（macOS/Xcode）", "url": "https://www.unix.com/man-page/osx/1/otool/"},
    {"cmd": "codesign",    "cat": "ios",       "desc": "签名查看与重签（macOS）", "url": "https://www.unix.com/man-page/osx/1/codesign/"},
    {"cmd": "ideviceinstaller", "cat": "ios", "desc": "iOS 设备安装管理", "url": "https://github.com/libimobiledevice/libimobiledevice"},

    # .NET / Java / Python
    {"cmd": "ilspycmd",    "cat": "dotnet",    "desc": "ILSpy 命令行反编译", "url": "https://github.com/icsharpcode/ILSpy"},
    {"cmd": "dotnet",      "cat": "dotnet",    "desc": ".NET SDK", "url": "https://dotnet.microsoft.com/download"},
    {"cmd": "monodis",     "cat": "dotnet",    "desc": "Mono 反汇编", "url": "https://www.mono-project.com/"},
    {"cmd": "java",        "cat": "java",      "desc": "JRE/JDK", "url": "https://adoptium.net/"},
    {"cmd": "javap",       "cat": "java",      "desc": "字节码反汇编", "url": "https://docs.oracle.com/en/java/javase/"},
    {"cmd": "cfr",         "cat": "java",      "desc": "CFR 反编译器", "url": "https://www.benf.org/other/cfr/"},
    {"cmd": "procyon",     "cat": "java",      "desc": "Procyon 反编译器", "url": "https://github.com/mstrobel/procyon"},
    {"cmd": "pycdc",       "cat": "python",    "desc": "pyc 反编译器", "url": "https://github.com/zrax/pycdc"},
    {"cmd": "uncompyle6",  "cat": "python",    "desc": "pyc 反编译器（≤3.8）", "url": "https://github.com/rocky/python-uncompyle6"},
    {"cmd": "pyinstxtractor", "cat": "python", "desc": "PyInstaller 解包", "url": "https://github.com/extremecoders-re/pyinstxtractor"},

    # Web / WASM / 打包
    {"cmd": "node",        "cat": "web",       "desc": "Node.js（asar 解包/JS 执行）", "url": "https://nodejs.org/"},
    {"cmd": "npx",         "cat": "web",       "desc": "npx（asar extract）", "url": "https://nodejs.org/"},
    {"cmd": "wasm2wat",    "cat": "web",       "desc": "WASM → WAT（wabt）", "url": "https://github.com/WebAssembly/wabt"},
    {"cmd": "wasm-objdump", "cat": "web",      "desc": "WASM 反汇编", "url": "https://github.com/WebAssembly/wabt"},

    # 固件 / 文件 / 协议
    {"cmd": "binwalk",     "cat": "firmware",  "desc": "固件拆解与雕刻", "url": "https://github.com/ReFirmLabs/binwalk"},
    {"cmd": "unsquashfs",  "cat": "firmware",  "desc": "SquashFS 解包", "url": "https://github.com/plougher/squashfs-tools"},
    {"cmd": "tshark",      "cat": "network",   "desc": "Wireshark 命令行", "url": "https://www.wireshark.org/"},
    {"cmd": "mitmproxy",   "cat": "network",   "desc": "交互式 HTTPS 代理", "url": "https://mitmproxy.org/"},
    {"cmd": "openssl",     "cat": "network",   "desc": "加密/证书分析", "url": "https://www.openssl.org/"},
    {"cmd": "7z",          "cat": "archive",   "desc": "通用解包", "url": "https://www.7-zip.org/"},
    {"cmd": "unzip",       "cat": "archive",   "desc": "ZIP 解包", "url": "https://infozip.sourceforge.net/"},

    # 游戏
    {"cmd": "Il2CppDumper", "cat": "game",     "desc": "Unity IL2CPP 符号还原", "url": "https://github.com/Perfare/Il2CppDumper"},

    # 符号还原（strip 后找回可读名字，成本最低的收益）
    {"cmd": "c++filt",     "cat": "symbol",   "desc": "C++ 符号 demangle（binutils）", "url": "https://www.gnu.org/software/binutils/"},
    {"cmd": "llvm-cxxfilt", "cat": "symbol",  "desc": "LLVM C++ 符号 demangle", "url": "https://llvm.org/docs/CommandGuide/llvm-cxxfilt.html"},
    {"cmd": "swift-demangle", "cat": "symbol", "desc": "Swift 符号 demangle", "url": "https://github.com/apple/swift"},
    {"cmd": "rustfilt",    "cat": "symbol",   "desc": "Rust 符号 demangle", "url": "https://github.com/luser/rustfilt"},
    {"cmd": "rustc",       "cat": "symbol",   "desc": "Rust 工具链（含 rust-demangle 能力）", "url": "https://www.rust-lang.org/tools/install"},
    {"cmd": "go",          "cat": "symbol",   "desc": "Go 工具链（读取 buildinfo 里的模块与版本）", "url": "https://go.dev/dl/"},

    # 脱壳 / 修补
    {"cmd": "upx",         "cat": "unpack",   "desc": "UPX 加解壳（最常见的压缩壳）", "url": "https://upx.github.io/"},
    {"cmd": "patchelf",    "cat": "unpack",   "desc": "ELF interpreter/RPATH 改写", "url": "https://github.com/NixOS/patchelf"},
    {"cmd": "retdec-decompiler", "cat": "unpack", "desc": "RetDec 开源反编译器", "url": "https://github.com/avast/retdec"},

    # 二进制比对（先比对再逆，能省掉大量重复劳动）
    {"cmd": "bindiff",     "cat": "diff",     "desc": "Google BinDiff 二进制比对", "url": "https://github.com/google/bindiff"},
    {"cmd": "radiff2",     "cat": "diff",     "desc": "radare2 二进制 diff", "url": "https://github.com/radareorg/radare2"},
    {"cmd": "rabin2",      "cat": "identify", "desc": "radare2 二进制信息提取", "url": "https://github.com/radareorg/radare2"},
    {"cmd": "rahash2",     "cat": "identify", "desc": "radare2 哈希/熵计算", "url": "https://github.com/radareorg/radare2"},

    # 雕刻 / 内存取证
    {"cmd": "foremost",    "cat": "carve",    "desc": "文件雕刻", "url": "https://forensicswiki.xyz/wiki/index.php?title=Foremost"},
    {"cmd": "scalpel",     "cat": "carve",    "desc": "文件雕刻（可自定义头尾）", "url": "https://github.com/sleuthkit/scalpel"},
    {"cmd": "bulk_extractor", "cat": "carve", "desc": "批量特征提取（邮箱/URL/信用卡号）", "url": "https://github.com/simsong/bulk_extractor"},
    {"cmd": "vol",         "cat": "memory",   "desc": "Volatility3 内存取证", "url": "https://github.com/volatilityfoundation/volatility3"},
    {"cmd": "volatility3", "cat": "memory",   "desc": "Volatility3（旧名）", "url": "https://github.com/volatilityfoundation/volatility3"},

    # 规则匹配
    {"cmd": "yara",        "cat": "yara",     "desc": "YARA 规则匹配", "url": "https://virustotal.github.io/yara/"},
    {"cmd": "yara64",      "cat": "yara",     "desc": "YARA（Windows 版）", "url": "https://virustotal.github.io/yara/"},

    # 固件解包补充
    {"cmd": "unblob",      "cat": "firmware", "desc": "递归固件/嵌套格式拆解", "url": "https://github.com/onekey-sec/unblob"},
    {"cmd": "ubi_reader",  "cat": "firmware", "desc": "UBI/UBIFS 镜像提取", "url": "https://github.com/jrspruitt/ubi_reader"},
    {"cmd": "jefferson",   "cat": "firmware", "desc": "JFFS2 镜像提取", "url": "https://github.com/sviehb/jefferson"},
    {"cmd": "cpio",        "cat": "archive",  "desc": "cpio initramfs 解包", "url": "https://www.gnu.org/software/cpio/"},
    {"cmd": "sqlite3",     "cat": "archive",  "desc": "SQLite 命令行（查应用数据库）", "url": "https://sqlite.org/cli.html"},

    # 环境 / 编排（Windows 上跑 Linux 工具链的桥）
    {"cmd": "docker",      "cat": "env",      "desc": "容器（跑 Linux 逆向工具链）", "url": "https://www.docker.com/"},
    {"cmd": "wsl",         "cat": "env",      "desc": "WSL（跑 Linux 逆向工具链）", "url": "https://learn.microsoft.com/windows/wsl/"},
    {"cmd": "uv",          "cat": "env",      "desc": "极速 Python 包管理（装 ReVa 等）", "url": "https://github.com/astral-sh/uv"},
    {"cmd": "git",         "cat": "env",      "desc": "拉取开源源码做对照", "url": "https://git-scm.com/"},
    {"cmd": "curl",        "cat": "env",      "desc": "下载样本/依赖", "url": "https://curl.se/"},
    {"cmd": "claude",      "cat": "ai",       "desc": "Claude Code CLI（MCP 客户端，可驱动 Ghidra/IDA）", "url": "https://github.com/anthropics/claude-code"},
]

# AI 辅助层不一定是可执行文件，常以「安装目录环境变量 + MCP 客户端」形式存在。
# 这里只读环境变量，不启动任何进程。
ENV_PROBES = [
    ("GHIDRA_INSTALL_DIR", "Ghidra 安装目录（ReVa / GhidraMCP / analyzeHeadless 依赖）",
     "https://github.com/NationalSecurityAgency/ghidra/releases"),
    ("IDADIR", "IDA Pro 安装目录（ida-pro-mcp 依赖）",
     "https://github.com/mrexodia/ida-pro-mcp"),
    ("IDAPATH", "IDA Pro 安装路径（部分版本使用此变量）",
     "https://github.com/mrexodia/ida-pro-mcp"),
    ("JAVA_HOME", "JDK 根目录（Ghidra 12 需要 JDK 21+）",
     "https://github.com/NationalSecurityAgency/ghidra/releases"),
    ("ANDROID_HOME", "Android SDK（apkanalyzer / aapt2 依赖）",
     "https://developer.android.com/tools"),
]

# Python 模块（用 find_spec 探测，不真正 import，快且不触发副作用）
PYMODULES = [
    ("pefile", "PE 文件解析", "https://github.com/erocarrera/pefile"),
    ("capstone", "反汇编引擎", "https://www.capstone-engine.org/"),
    ("angr", "符号执行框架", "https://github.com/angr/angr"),
    ("androguard", "Android 静态分析", "https://github.com/androguard/androguard"),
    ("frida", "Frida Python 绑定", "https://frida.re/docs/installation/"),
    ("uncompyle6", "pyc 反编译（≤3.8）", "https://github.com/rocky/python-uncompyle6"),
    ("xdis", "跨版本字节码反汇编", "https://github.com/rocky/xdis"),
    ("scapy", "报文构造与解析", "https://scapy.net/"),
    ("yara", "YARA 规则匹配", "https://github.com/VirusTotal/yara-python"),
    ("lief", "多格式二进制解析", "https://github.com/lief-project/LIEF"),
    ("keystone", "汇编引擎", "https://www.keystone-engine.org/"),
    ("unicorn", "CPU 模拟器", "https://www.unicorn-engine.org/"),
    ("qiling", "全系统模拟框架", "https://github.com/qilingframework/qiling"),
    ("mcp", "MCP 协议库（驱动 Ghidra/IDA 的 AI 辅助层）", "https://github.com/modelcontextprotocol/python-sdk"),
]

# AI 辅助层的三类接入形态，doctor 只做「是否具备条件」的静态推断，不联网、不启动服务。
AI_STACK = [
    {"id": "ghidra_mcp", "kind": "mcp-server", "desc": "Ghidra MCP 服务（ReVa / GhidraMCP）：让 LLM 直接驾驶反编译器",
     "url": "https://github.com/cyberkaida/reverse-engineering-assistant",
     "requires": ["GHIDRA_INSTALL_DIR"], "alt": "https://github.com/LaurieWired/GhidraMCP"},
    {"id": "ida_mcp", "kind": "mcp-server", "desc": "IDA Pro MCP 服务（ida-pro-mcp）",
     "url": "https://github.com/mrexodia/ida-pro-mcp", "requires": ["IDADIR"]},
    {"id": "mcp_client", "kind": "client", "desc": "MCP 客户端（Claude Code / Cursor 等）用来发起分析",
     "url": "https://modelcontextprotocol.io", "requires": ["claude"]},
    {"id": "local_llm", "kind": "model", "desc": "本地模型（Ollama）：样本不能外传时用",
     "url": "https://ollama.com", "requires": ["ollama"]},
]


def doctor() -> dict:
    """探测本机可用工具。只读 PATH/模块元数据，不执行外部程序。"""
    present, missing = [], []
    for t in TOOLS:
        path = shutil.which(t["cmd"])
        item = {k: t[k] for k in ("cmd", "cat", "desc", "url")}
        if path:
            item["path"] = path
            present.append(item)
        else:
            missing.append(item)

    mods = []
    for name, desc, url in PYMODULES:
        try:
            spec = importlib.util.find_spec(name)
        except Exception:
            spec = None
        mods.append({"module": name, "desc": desc, "url": url, "available": spec is not None})

    cats: dict[str, dict] = {}
    for item in present + missing:
        c = cats.setdefault(item["cat"], {"present": 0, "total": 0})
        c["total"] += 1
        if "path" in item:
            c["present"] += 1

    # 环境变量探测：AI 辅助层与 Java/IDA 类工具的启用前提
    env_probes = []
    for name, desc, url in ENV_PROBES:
        val = os.environ.get(name) or ""
        ok = bool(val) and os.path.isdir(val)
        env_probes.append({"name": name, "desc": desc, "url": url,
                           "value": val or None, "dir_exists": ok})

    # AI 辅助层可用性推断：require 里的每一项，命中「环境变量目录存在」或「PATH 里有该命令」即算满足
    present_cmds = {t["cmd"] for t in present}
    env_ok = {e["name"] for e in env_probes if e["dir_exists"]}
    ai_stack = []
    for a in AI_STACK:
        satisfied = [r for r in a["requires"] if r in env_ok or r in present_cmds]
        ready = len(satisfied) == len(a["requires"])
        ai_stack.append({
            "id": a["id"], "kind": a["kind"], "desc": a["desc"], "url": a["url"],
            "requires": a["requires"], "satisfied": satisfied,
            "ready": ready,
            "how": "已具备条件" if ready else "需先配置：" + "、".join(a["requires"]),
        })
    if "alt" in AI_STACK[0]:
        ai_stack[0]["alt"] = AI_STACK[0]["alt"]

    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "python_exe": sys.executable,
        "tool_count": len(TOOLS),
        "present_count": len(present),
        "present": present,
        "missing": missing,
        "python_modules": mods,
        "coverage_by_category": cats,
        "env_probes": env_probes,
        "ai_stack": ai_stack,
        "ai_ready_count": sum(1 for a in ai_stack if a["ready"]),
        "note": "missing 里的工具并非必须：脚本自身零依赖即可完成识别/字符串/熵/结构解析，"
                "外部工具用于反编译与动态分析等更深的环节。",
    }


# ---------------------------------------------------------------- 分析计划

FORMAT_PLAN: dict[str, list[dict]] = {
    "pe": [
        {"stage": "1 指纹", "title": "建立行为地图",
         "commands": ['re.py triage "{t}" --json', 're.py imports "{t}" --json'],
         "note": "导入表 = 行为目录：Crypt* 说明有加密、WinInet/winhttp 说明有网络、RegSetValueEx 说明写注册表。PDB 路径会泄露源码目录结构。"},
        {"stage": "2 静态全景", "title": "反编译与入口定位",
         "commands": ["ghidraRun（导入后自动分析，从 entry → main/WinMain 顺 xref 追）",
                      "analyzeHeadless <proj> <projname> -import \"{t}\" -postScript X.java（批量）",
                      "rizin/radare2: r2 -A \"{t}\" 然后 afl / pdf @ main"],
         "note": "先找 main/WinMain，再从导入表里的可疑 API 反向查交叉引用（谁调用了 CreateRemoteThread）。"},
        {"stage": "3 行为观测", "title": "隔离环境里跑一遍",
         "commands": ["Procmon + API Monitor 记录文件/注册表/进程行为",
                      "Noriben（轻量行为记录）", "沙箱（Cuckoo/CAPE）出报告"],
         "note": "恶意样本必须在断网虚拟机里跑，不要连生产网络。"},
        {"stage": "4 定点突破", "title": "Hook 关键函数看真实数据",
         "commands": ["x64dbg 下断点（优先硬件断点，避免被 0xCC 扫描发现）",
                      "frida -l hook.js -f \"{t}\"（Interceptor.attach 打印参数与返回值）"],
         "note": "加密/压缩的东西静态一定看不全，必须在运行时截获解密后的明文。"},
        {"stage": "5 对抗处理", "title": "脱壳/过反调试（按需）",
         "commands": ["先 re.py entropy \"{t}\" 看熵曲线定位加密段",
                      "UPX: upx -d \"{t}\"（仅压缩壳，一行解决）",
                      "其余：找 OEP → dump → Scylla 修 IAT → 重建 PE"],
         "note": "VMP/Themida 一类虚拟机壳等于逆向一个自制 CPU，成本极高，先评估是否值得。"},
        {"stage": "6 建模验证", "title": "写出等价实现",
         "commands": ["写解析器/客户端/算法 → 输入输出对齐即算理解完成"],
         "note": "复现即理解：写不出来说明还有隐藏分支没覆盖。"},
    ],
    "elf": [
        {"stage": "1 指纹", "title": "结构与安全机制",
         "commands": ['re.py triage "{t}" --json', "checksec --file=\"{t}\"",
                      "readelf -d \"{t}\" | grep NEEDED", "nm -D \"{t}\" | head -50"],
         "note": "先看静态链接还是动态链接：Go/Rust 默认静态链接，二进制巨大但符号特征明显。"},
        {"stage": "2 静态全景", "title": "反汇编/反编译",
         "commands": ["objdump -d --no-show-raw-insn \"{t}\" > disasm.txt",
                      "Ghidra/IDA/Binary Ninja 自动分析",
                      "Go 二进制：Ghidra 的 golang_loader_assist.py 恢复符号",
                      "Rust 二进制：nm \"{t}\" | rustfilt 还原符号"],
         "note": "Go 的函数名与类型元数据完整保留（pclntab），是最友好的编译型二进制之一。"},
        {"stage": "3 动态", "title": "跟踪与 Hook",
         "commands": ["strace -f -o trace.txt \"{t}\"", "ltrace \"{t}\"",
                      "gdb + pwndbg/gef 下断点", "frida 插桩"],
         "note": "strace 能一眼看清文件/网络/进程行为，是 Linux 下性价比最高的第一步。"},
        {"stage": "4 建模验证", "title": "写等价实现",
         "commands": ["校验算法 → 用 Z3/angr 解约束（只对关键校验函数，别对整个程序跑）"],
         "note": "符号执行要先用静态分析缩小范围，否则路径爆炸。"},
    ],
    "macho": [
        {"stage": "1 指纹", "title": "结构与依赖",
         "commands": ['re.py triage "{t}" --json', "otool -L \"{t}\"", "otool -l \"{t}\" | head -80",
                      "codesign -dv --verbose=4 \"{t}\""],
         "note": "Mach-O 是 Load Command 驱动，所有信息（段/依赖/符号/签名/加密标记）都在 LC 里。"},
        {"stage": "2 静态", "title": "反编译与类结构",
         "commands": ["class-dump -H \"{t}\" -o headers/（ObjC 元数据一键导出）",
                      "Hopper / IDA / Ghidra"],
         "note": "ObjC 元数据极其丰富，Swift 则差很多。"},
        {"stage": "3 动态", "title": "调试与 Hook",
         "commands": ["lldb \"{t}\"", "frida -l hook.js -f \"{t}\"", "fs_usage 看文件行为"],
         "note": "macOS 上 SIP 会限制注入，必要时关闭 SIP 或用 entitlements 重签。"},
    ],
    "apk": [
        {"stage": "1 指纹", "title": "APK 结构与加固判定",
         "commands": ['re.py triage "{t}" --json',
                      "aapt2 dump badging \"{t}\"", "apkanalyzer dex packages \"{t}\"",
                      "apkanalyzer manifest print \"{t}\""],
         "note": "Android 的对抗集中在加固壳，不在字节码本身。看 lib/ 与 assets/ 下的可疑文件。"},
        {"stage": "2 静态", "title": "DEX → Java",
         "commands": ["jadx -d out/ \"{t}\"（首选，质量最高）",
                      "apktool d \"{t}\" -o smali/（需要改 smali 重打包时用）",
                      "MobSF（一站式自动扫描，有 Web UI）"],
         "note": "多引擎交叉验证：jadx / JEB / dex2jar+CFR 对同一方法对比，谁更可信一目了然。"},
        {"stage": "3 对抗（若加固）", "title": "脱壳思路",
         "commands": ["Frida + frida-dexdump：内存中扫 DEX 魔数并 dump",
                      "Hook ClassLoader / dvmDexFileOpen 等加载点",
                      "Xposed/LSPosed 模块在 ART 层拦截"],
         "note": "抽取型加固在运行时必然把 DEX 还原到内存，这是它的命门。"},
        {"stage": "4 动态", "title": "Hook 与抓包",
         "commands": ["frida -U -f <pkg> -l hook.js（Java.perform Hook Java 方法）",
                      "objection explore（交互式）",
                      "抓包：mitmproxy/Burp + 证书装入系统区或 Magisk 模块过 SSL Pinning"],
         "note": "SSL Pinning 绕过只对自己拥有或书面授权的应用做。"},
        {"stage": "5 Native 层", "title": "so 逆向（如有）",
         "commands": ["Ghidra/IDA 打开 lib/<abi>/*.so", "优先看 JNI_OnLoad 与 RegisterNatives 注册的表"],
         "note": "从 RegisterNatives 能直接拿到 Java 方法与 native 函数的对应关系。"},
    ],
    "dex": [
        {"stage": "1 静态", "title": "直接反编译",
         "commands": ["jadx -d out/ \"{t}\"", "re.py strings \"{t}\" --min 8 --json"],
         "note": "裸 DEX 通常是脱壳产物，直接上 jadx。"},
        {"stage": "2 验证", "title": "完整性检查",
         "commands": ["对比 header 里的 file_size 与实际大小；checksum 不匹配说明被改动过"],
         "note": "脱壳 dump 出来的 DEX 头部常常需要手工修复。"},
    ],
    "jar": [
        {"stage": "1 静态", "title": "字节码反编译",
         "commands": ["CFR / FernFlower / Procyon 多引擎对比（BCV）",
                      "javap -p -c <Class> 看字节码",
                      "re.py strings \"{t}\" --json"],
         "note": "Java 保留常量池与局部变量表，混淆器（ProGuard/Allatori）才决定真实难度。"},
        {"stage": "2 线上诊断", "title": "运行时观察（自有服务）",
         "commands": ["arthas：不改代码不重启，直接 watch/trace 线上方法"],
         "note": "对自家 Java 服务，arthas 比反编译更快得到答案。"},
    ],
    "pyc": [
        {"stage": "1 定版本", "title": "确认 Python 版本（关键前提）",
         "commands": ['re.py info "{t}" --json（看 python_version 字段）',
                      "python -c \"import importlib.util;print(importlib.util.MAGIC_NUMBER)\" 对照"],
         "note": "版本不匹配是 pyc 反编译失败的第一大原因。"},
        {"stage": "2 反编译", "title": "还原源码",
         "commands": ["pycdc \"{t}\"", "uncompyle6 \"{t}\"（≤3.8）", "xdis + 手工读字节码兜底"],
         "note": "解不出就退回字节码：dis 模块能看指令流。"},
    ],
    "wasm": [
        {"stage": "1 边界", "title": "导入/导出接口是明处",
         "commands": ["wasm2wat \"{t}\" -o out.wat", "wasm-objdump -x \"{t}\"",
                      're.py info "{t}" --json（直接列出 imports/exports）'],
         "note": "WASM 的导入导出接口与 JS 胶水层是天然的 Hook 点。"},
        {"stage": "2 分析", "title": "反编译与动态",
         "commands": ["wasm-decompile \"{t}\"", "Chrome DevTools 调试 + 在边界 Hook"],
         "note": "无符号但结构清晰，配合胶水层的函数名能推断语义。"},
    ],
    "zip": [
        {"stage": "1 拆解", "title": "看包内结构",
         "commands": ['re.py info "{t}" --json', "unzip -l \"{t}\""],
         "note": "ZIP 是容器：APK/JAR/docx/whl/Electron asar 都可能是它，先看 subtype。"},
        {"stage": "2 分支", "title": "按子类型继续",
         "commands": ["apk → 走 Android 流程", "jar → 走 Java 流程",
                      "含 app.asar → npx asar extract app.asar out/（Electron 一行解开）"],
         "note": "Electron 应用解开后全是明文 JS，难度极低。"},
    ],
    "firmware": [
        {"stage": "1 识别", "title": "是什么镜像",
         "commands": ['re.py identify "{t}" --json', 're.py entropy "{t}" --json',
                      "binwalk \"{t}\"", "file \"{t}\""],
         "note": "熵曲线能区分压缩段与明文段；加密固件整体熵接近 8，binwalk 扫不出东西。"},
        {"stage": "2 拆解", "title": "提取文件系统",
         "commands": ["binwalk -Me \"{t}\"（递归提取）", "unsquashfs <squashfs 镜像>",
                      're.py carve "{t}" --out carved/（脚本自带的魔数雕刻兜底）'],
         "note": "binwalk 抽不出来的用 carve 按魔数硬扫。"},
        {"stage": "3 审计", "title": "快速挖硬编码",
         "commands": ['re.py strings "{t}" --min 6 --json | 找 口令/密钥',
                      "grep -rE '(password|passwd|admin|root)' 提取目录",
                      "找私钥：grep -rl 'BEGIN.*PRIVATE KEY'",
                      "看 /etc/shadow、.htpasswd、启动脚本"],
         "note": "固件三大命门：默认凭证、硬编码密钥、未签名更新。"},
        {"stage": "4 模拟", "title": "跑起来看行为",
         "commands": ["qemu-arm -L <sysroot> ./bin/xxx（用户态跑单个二进制）",
                      "firmadyne / FirmAE（全系统模拟）"],
         "note": "能模拟运行就拿到了最真实的证据。"},
    ],
    "sqlite": [
        {"stage": "1 结构", "title": "看 schema",
         "commands": ['re.py info "{t}" --json（列出表/索引/视图/行数）',
                      "sqlite3 \"{t}\" .schema"],
         "note": "先看 schema 再谈数据。"},
        {"stage": "2 取证", "title": "已删除数据",
         "commands": ["从 freelist / 未分配区恢复字符串（undark / sqlite-recover）"],
         "note": "删除只是标记，页面里的记录往往还在。"},
    ],
    "unknown": [
        {"stage": "1 兜底", "title": "未知格式的标准起手式",
         "commands": ['re.py identify "{t}" --json', 're.py entropy "{t}" --json',
                      're.py strings "{t}" --min 4 --json',
                      're.py carve "{t}"（看里面有没有嵌入的已知格式）'],
         "note": "私有格式：先用多样本差分找出长度/偏移字段，再用 ImHex pattern 建模。"},
        {"stage": "2 差分", "title": "造样本做实验",
         "commands": ['re.py diff sampleA sampleB --json（改一个字节看输出怎么变）'],
         "note": "差分实验是破解私有格式最有效的武器。"},
    ],
}

# 格式 → 计划 key 的映射
PLAN_ROUTE = {
    "pe": "pe", "mz": "pe",
    "elf": "elf",
    "macho32": "macho", "macho64": "macho", "macho32be": "macho", "macho64be": "macho", "fat": "macho",
    "zip": "zip", "apk": "apk",
    "dex035": "dex", "dex037": "dex", "dex038": "dex", "dex039": "dex",
    "jar": "jar", "class": "jar",
    "pyc": "pyc", "wasm": "wasm", "sqlite": "sqlite",
    "squashfs": "firmware", "cramfs": "firmware", "cramfsbe": "firmware",
    "jffs2": "firmware", "jffs2be": "firmware", "romfs": "firmware",
    "ubifs": "firmware", "uimage": "firmware", "androidboot": "firmware",
    "trx": "firmware", "dtb": "firmware",
}


# ---------------------------------------------------------------- 加速层
#
# 这一层来自对当前开源生态与论文结论的归纳，核心思想是三条：
#   1) 复用优先 —— 先确认「这段代码是不是别人已经写过的」，
#      是的话直接拿源码/带符号的官方版本对照，比从零逆快一个数量级。
#   2) 比对优先 —— 有旧版本就 diff，把名字、注释、结构体移植过来，
#      省掉逆向里最耗时的「重新命名」劳动（BinDiff/Diaphora 的核心价值）。
#   3) AI 只做初筛 —— LLM 擅长命名与解释，但会被对抗样本欺骗，
#      已有研究表明攻击者可在二进制字符串里埋提示注入来误导 LLM 逆向流水线
#      （arXiv:2605.30667）。所以 AI 输出一律当作「待验证线索」，不许当结论。

ACCEL_SYMBOLS: dict[str, list[str]] = {
    "pe": ['rabin2 -I "{t}"（看编译器、架构、是否 strip）',
           're.py strings "{t}" --categorize --json | 找 version/source_path 类',
           'c++filt < syms.txt（C++ 名还原，strip 后仍可能残留）',
           'ilspycmd -p -o out "{t}"（若为 .NET 程序集，元数据是完整的）',
           'upx -d "{t}"（确认是不是最常见的 UPX 压缩壳）'],
    "elf": ['c++filt < syms.txt（C++ 名还原）',
            'go version -m "{t}"（Go 二进制直接吐出模块名与版本）',
            'strings "{t}" | rustfilt（Rust 名还原 + panic 消息定位）',
            'readelf -p .comment "{t}"（编译器版本）',
            're.py strings "{t}" --categorize --json'],
    "macho": ['otool -Iv "{t}" | c++filt（符号表）',
              'class-dump "{t}" -H -o out（ObjC 类结构一键导出）',
              'swift-demangle（Swift 名还原）'],
    "apk": ['jadx -d out "{t}"（先拿到近乎源码的 Java）',
            'aapt2 dump badging "{t}"（版本与包名，用于找官方原版对照）',
            're.py strings "{t}" --categorize --json（找第三方 SDK 特征）'],
    "dex": ['jadx -d out "{t}"',
            're.py strings "{t}" --categorize --json'],
    "jar": ['javap -p -c -constants "{t}"（常量池是明牌）',
            'cfr "{t}" --outputdir out（多引擎交叉验证：cfr/procyon/jadx）'],
    "pyc": ['re.py info "{t}" --json（先确认 magic 对应的精确 Python 版本）',
            'pycdc "{t}"（版本对了才有意义）'],
    "wasm": ['wasm2wat "{t}" -o out.wat',
             'wasm-objdump -x "{t}"（导出接口暴露功能边界）'],
    "zip": ['re.py identify "{t}" --json（先确定容器 subtype）',
            'unzip -l "{t}"'],
    "firmware": ['binwalk -E "{t}"（熵分布找压缩/加密区）',
                 'unblob "{t}"（递归拆嵌套格式）',
                 'binwalk -Me "{t}"（递归提取）'],
    "sqlite": ['sqlite3 "{t}" .schema（表结构即数据模型）',
               're.py carve "{t}"（freelist 里可能残留已删记录）'],
    "unknown": ['re.py diff A B --json（造样本做差分实验）',
                're.py entropy "{t}" --json（高熵区即压缩/加密区）'],
}


def _accel_steps(key: str, short: str) -> list[dict]:
    """生成「加速层」步骤。这些步骤的目标是用最小成本砍掉最大工作量。"""
    sym_cmds = ACCEL_SYMBOLS.get(key, ACCEL_SYMBOLS["unknown"])
    return [
        {"stage": "加速 1", "id": "reuse", "title": "复用优先：先确认它是不是别人写过的代码",
         "commands": [
             're.py strings "{t}" --categorize --json  # 找 version / url / email / 路径类',
             're.py imports "{t}" --json  # 导入表 = 用了哪些库',
             '# 拿到组件名+版本后，优先去拉同版本源码/官方带符号二进制对照',
             '# 纯函数级匹配可用腾讯科恩 BinaryAI：https://github.com/Tencent/BinaryAI',
         ],
         "note": "逆向前先花 5 分钟做成分识别。命中开源组件 = 直接拿到源码，"
                 "这是投入产出比最高的一步，跳过它等于放弃最大的加速机会。"},
        {"stage": "加速 2", "id": "diff", "title": "版本比对：有旧版本就别从零逆",
         "commands": [
             '# 有同软件的旧版/官方版时：',
             'radiff2 -C old new          # radare2 快速比对',
             'bindiff old.i64 new.i64     # Google BinDiff（Ghidra/IDA/BinaryNinja 均有）',
             '# IDA 用户可用 Diaphora：https://github.com/joxeankoret/diaphora',
             're.py diff old new --json   # 本工具自带的字节级差分（找改动区间）',
         ],
         "note": "把旧版本的函数名、注释、结构体移植过来，能省掉逆向里最耗时的"
                 "「重新命名」。补丁比对（找 1-day）更是标准打法。"},
        {"stage": "加速 3", "id": "symbols", "title": "符号与类型恢复：strip 了也能救回一部分",
         "commands": sym_cmds,
         "note": "不同类型有不同的「符号富矿」：Go 的 buildinfo、Rust 的 panic 消息、"
                 "ObjC 的元数据、.NET 的元数据表、Java 的常量池。先找富矿再啃汇编。"},
        {"stage": "加速 4", "id": "ai", "title": "AI 辅助层：批量命名与初筛（只作线索，必须复核）",
         "commands": [
             '# Ghidra 用户：ReVa（推荐，抗上下文腐烂）/ GhidraMCP / GhidrAssistMCP',
             '#   https://github.com/cyberkaida/reverse-engineering-assistant',
             '# IDA 用户：ida-pro-mcp  https://github.com/mrexodia/ida-pro-mcp',
             '# 用法：让模型按功能批量重命名 + 加注释，人只做审核',
         ],
         "note": "LLM 最成熟的能力是「函数重命名与解释」，能摊掉大量重复劳动；"
                 "但已有研究证明攻击者可在二进制字符串里埋提示注入，误导 LLM 反编译流水线"
                 "（arXiv:2605.30667）。因此：AI 结论一律回工具里复核，"
                 "不要让它单独下安全结论。"},
    ]


def build_plan(ident: dict, tools: dict | None = None, goal: str = "auto") -> dict:
    """根据识别结果 + 本机可用工具，排出下一步该做什么。"""
    fmt = ident.get("format", "unknown")
    detail = ident.get("detail") or {}
    sub = (detail.get("subtype") or "") if isinstance(detail, dict) else ""

    key = PLAN_ROUTE.get(fmt, "unknown")
    if fmt == "zip" and sub == "apk":
        key = "apk"
    if fmt == "zip" and sub == "jar":
        key = "jar"
    if fmt == "unknown":
        key = "unknown"

    # 命令里用文件名而不是绝对路径：用户通常在目标所在目录操作，
    # 绝对路径会让每行命令长到没法读。
    short = os.path.basename(ident.get("path") or "") or "<目标>"
    steps = []
    for st in FORMAT_PLAN.get(key, FORMAT_PLAN["unknown"]):
        steps.append({
            "stage": st["stage"], "title": st["title"], "note": st["note"],
            "commands": [c.replace("{t}", short) for c in st["commands"]],
        })

    # 目标导向的前置建议
    goal_tips = {
        "understand": "先回答「它是什么、做什么、和谁通信」，再决定要不要深挖。",
        "behavior": "优先行为层：先跑起来看它干了什么，别一开始死磕汇编。",
        "algorithm": "定位关键函数 → 用 Z3/angr 解约束 → 写出输入输出一致的等价实现。",
        "protocol": "先抓包拿样本 → 差分找长度/校验字段 → 识别序列化框架 → 写解析器。",
        "malware": "隔离环境！先沙箱跑一遍拿 IOC，再回到静态确认机制。",
    }
    goal = goal if goal in goal_tips else "understand"

    # 关键提醒（来自对各类型「命门」的经验）
    hooks = {
        "pe": "命门：导入表 + 字符串 + 运行时内存必定解密。",
        "elf": "命门：动态链接符号表 / Go 的 pclntab / Rust 的 panic 消息。",
        "macho": "命门：ObjC 元数据极其丰富，class-dump 一键导出。",
        "apk": "命门：DEX 语义完整 + 内存 dump 破壳 + Frida 无孔不入。",
        "dex": "命门：DEX 语义完整，jadx 一把梭。",
        "jar": "命门：常量池 + 局部变量表保留，多引擎反编译交叉验证。",
        "pyc": "命门：版本匹配 + 解开打包。",
        "wasm": "命门：导入/导出接口与 JS 胶水层在明处。",
        "zip": "命门：先确定 subtype，容器内部才是目标。",
        "firmware": "命门：binwalk 一刀 + 默认凭证 + 未签名更新 + UART 直出 root shell。",
        "sqlite": "命门：schema 与 freelist 残留。",
        "unknown": "命门：多样本差分找长度/偏移字段。",
    }
    return {
        "target": ident.get("path"),
        "format": fmt,
        "route": key,
        "goal": goal,
        "goal_tip": goal_tips.get(goal),
        "key_insight": hooks.get(key),
        "packer": ident.get("detail", {}).get("packer_signals") if isinstance(ident.get("detail"), dict) else None,
        "steps": steps,
        "accel": [dict(a, commands=[c.replace("{t}", short) for c in a["commands"]])
                  for a in _accel_steps(key, short)],
        "install_hints": _missing_hints(tools, key),
    }


def _missing_hints(tools: dict | None, key: str) -> list[dict]:
    """按当前任务方向，从 doctor 结果里挑出最该补的工具（最多 5 个）。"""
    if not tools:
        return []
    have = {t["cmd"] for t in tools.get("present", [])}
    want = {
        "pe": ["analyzeHeadless", "ghidraRun", "radare2", "frida", "rizin"],
        "elf": ["objdump", "readelf", "gdb", "frida", "radare2"],
        "macho": ["otool", "class-dump", "lldb", "frida"],
        "apk": ["jadx", "apktool", "aapt2", "adb", "frida"],
        "dex": ["jadx", "apktool"],
        "jar": ["cfr", "java", "javap", "procyon"],
        "pyc": ["pycdc", "uncompyle6"],
        "wasm": ["wasm2wat", "wasm-objdump"],
        "zip": ["unzip", "7z", "node"],
        "firmware": ["binwalk", "unsquashfs", "qemu-system-x86_64"],
        "sqlite": [],
        "unknown": ["binwalk", "radare2", "xxd"],
    }.get(key, [])
    out = []
    for cmd in want:
        if cmd in have:
            continue
        meta = next((t for t in tools.get("missing", []) if t["cmd"] == cmd), None)
        if meta:
            out.append({"cmd": cmd, "desc": meta["desc"], "url": meta["url"]})
        if len(out) >= 5:
            break
    return out
