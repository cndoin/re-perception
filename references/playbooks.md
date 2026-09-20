# 分类型作战手册

每类一个「命门」——最容易突破的地方。先看命门，再展开。

---

## 1. Windows PE（exe / dll / sys）

**命门：导入表（行为地图）+ 字符串 + 运行时内存必定解密。**

### 结构要点
- DOS Header → `e_lfanew`@0x3C → `PE\0\0` → COFF → Optional Header → 节表 → 节
- Optional Header 魔数：`0x10B`=PE32，`0x20B`=PE32+
- **RVA/VA/FileOffset 换算是基本功，换算错了全盘皆错**：
  ```
  VA = ImageBase + RVA
  FileOffset = RVA - Section.VirtualAddress + Section.PointerToRawData
  ```
  （Section 需满足 `VirtualAddress ≤ RVA < VirtualAddress + VirtualSize`）

### Data Directory 里最有价值的几项
| 索引 | 内容 | 为什么重要 |
|---|---|---|
| 0 | 导出表 | 这个 DLL 对外提供哪些函数 |
| 1 | **导入表** | 依赖哪些库函数 = 行为地图 |
| 2 | 资源 | 图标、对话框、**嵌入的 PE**、版本信息 |
| 5 | 重定位表 | 脱壳后重建必需 |
| 6 | **调试目录** | **PDB 路径，泄露源码目录结构** |
| 9 | TLS | **TLS Callback 在 main 之前执行**，常用于反调试 |
| 14 | CLI Header | .NET 程序集入口（非零即为托管程序） |

### 快速判断
- 导入 `WinInet.dll` / `winhttp.dll` / `libcurl` → 有网络行为
- 导入 `CryptEncrypt` / `BCrypt*` → 有加密
- 导入 `RegSetValueEx` → 写注册表
- 导入 `CreateRemoteThread` + `WriteProcessMemory` → 进程注入
- 导入 `IsDebuggerPresent` → 有反调试
- **PDB 路径存在** → 拿到源码目录树，等于白送一半情报

### 加壳与脱壳
| 壳类型 | 原理 | 例子 | 难度 |
|---|---|---|---|
| 压缩壳 | 整段压缩，运行解压 | UPX、ASPack | **低**（`upx -d` 一行） |
| 加密壳 | 加密代码段 + 反调试 + IAT 保护 | ASPack、Armadillo | 中 |
| 虚拟机壳 | 原指令翻译成私有字节码，由自定义 VM 执行 | VMProtect、Themida | **极高**（等于逆向一个自制 CPU） |

**OEP 脱壳法通用流程：**
```
1. 找 OEP：压缩壳看最后的跨节跳转；通用法是对代码段下「写入断点」，
   壳解密完写回后执行到的第一条即为原代码；32 位可用 ESP 定律
2. 在 OEP 处 dump 内存映像（Scylla / OllyDumpEx）
3. 修复 IAT（Scylla / ImportREC 扫描内存中的函数调用重建导入表）
4. 重建 PE：修节对齐、修 .reloc、修 OEP、去掉壳的节
5. 验证：能正常跑 + 反汇编器能看到正常导入表 = 成功
```

### 签名
Authenticode（PE 属性证书 + 时间戳），位于 Data Directory[4]。
`re.py identify` 会输出 `cert_size`，非零说明带签名。

---

## 2. Linux ELF（bin / so / core）

**命门：动态链接符号表 / Go 的 `pclntab` / Rust 的 panic 消息。**

### 关键差异（与 PE 相比）
- **双视图**：Program Header 给内核加载器看（Segment），Section Header 给链接器/分析工具看（Section）
- 加壳软件常把 Section Header 抹掉恶心 `readelf` —— 此时只能靠 Program Header 定位

### 一条龙命令
```bash
file target.bin                      # 是否 stripped
readelf -h target.bin                # 头信息
readelf -d target.bin | grep NEEDED  # 依赖库
objdump -R target.bin                # 重定位项 = 用到的外部函数
nm -D target.bin                     # 动态符号
checksec --file=target.bin           # RELRO/Canary/NX/PIE
strace -f -o trace.txt ./target      # 行为观测（性价比最高的一步）
```

### Go 二进制
```bash
go version -m binary                 # 官方支持，读内嵌 buildinfo
strings binary | grep -E '^go1\.'    # 版本
```
- **函数名完整保留**（含包路径）：`net/http.(*Client).do`
- 金矿：`runtime.pclntab` / `.gopclntab`（函数表）、`runtime._type`（类型元数据）
- Go 1.17+ 改为寄存器 ABI（RAX/RBX/RCX/RDI/RSI/R8–R11），旧栈式 ABI0 仅用于汇编
- **必用工具：Ghidra 的 `golang_loader_assist.py`（自动恢复函数名与类型）**

### Rust 二进制
- 单态化导致代码膨胀（`Vec<T>` 每个 T 一份）
- 救命稻草：**panic 消息里含源码文件路径**（`src/main.rs:42`）
- `nm binary | rustfilt` 还原 mangled 符号

---

## 3. macOS / iOS（Mach-O / IPA）

**命门：ObjC 元数据极其丰富 + class-dump 一键导出 + 砸壳后一切照旧。**

### 结构
- **Load Command 驱动**：段、依赖库、符号表、签名、加密标记全是一条条 LC
- 胖二进制（Fat）magic `0xCAFEBABE` —— 与 Java class 同 magic，靠后续字段消解

### 关键 Load Command
| LC | 作用 |
|---|---|
| `LC_SEGMENT_64` | 段与节 |
| `LC_SYMTAB` | 符号表 |
| `LC_LOAD_DYLIB` | 依赖库 |
| `LC_ENCRYPTION_INFO_64` | **cryptid ≠ 0 表示被 FairPlay 加密** |
| `LC_UUID` | dSYM 配对用的 UUID |
| `LC_MAIN` | 入口偏移 |
| `LC_CODE_SIGNATURE` | 代码签名 |
| `LC_DYLD_CHAINED_FIXUPS` | macOS 12+ 取代旧 bind opcodes |

### 砸壳流程（iOS，需越狱）
```bash
otool -l binary | grep -A4 LC_ENCRYPTION_INFO   # 看 cryptid
# 设备上装 frida-server（源 https://build.frida.re）
frida-ios-dump <BundleID>                        # 产出 cryptid=0 的 IPA
```
产出可直接扔给 Hopper/IDA，之后流程与 macOS 一致。

### 静态
```bash
class-dump -H binary -o headers/    # ObjC 类结构一键导出（近乎源码骨架）
otool -L binary                     # 依赖库
codesign -dv --verbose=4 binary     # 签名信息
```

⚠️ Swift 的元数据远比 ObjC 少，难度高一个档。

---

## 4. Android（APK）

**命门：DEX 语义完整 + 内存 dump 破壳 + Frida 无孔不入。**

### APK 结构
```
app.apk
├── AndroidManifest.xml      # AXML（二进制 XML，不是明文）
├── classes.dex / classes2.dex ...
├── resources.arsc           # 资源索引表
├── res/  assets/            # assets 常被加固壳用来放加密 DEX
├── lib/arm64-v8a/*.so       # Native 层
└── META-INF/ + APK Signing Block   # v1 / v2 / v3 签名
```

### 静态
```bash
aapt2 dump badging app.apk        # 包名/版本/权限/SDK
apkanalyzer dex packages app.apk  # 类方法统计
jadx -d out/ app.apk              # DEX → Java（质量最高，首选）
apktool d app.apk -o out/         # 资源 + smali（需要改代码重打包时用）
```

### 加固识别（本技能包已内置厂商特征库）
`re.py info app.apk --json` 会输出 `apk.packer_hits` 与启发式判断。
常见指纹：

| 文件 | 厂商 |
|---|---|
| `libjiagu.so` / `libjiagu_64.so` | 360 加固 |
| `libdexjni.so` / `libdexhelper.so` | 腾讯乐固 |
| `libexec.so` / `libexecmain.so` / `libsecexe.so` | 梆梆加固 |
| `libsecshell.so` / `libmobisec.so` | 阿里聚安全 |
| `libkwscmm.so` / `libijiami.so` | 爱加密 |
| `libddog.so` | 通付盾 |

**抽取型加固的启发式**：`classes.dex` 极小（<100KB）+ assets 里有多个 >200KB 文件
→ DEX 被加密，运行时才还原到内存。

### 脱壳思路
DEX 在运行时必然以明文形式存在于内存 → **扫内存里的 DEX 魔数并 dump**：
```bash
frida-dexdump -U -f <pkg>
# 或 Hook ClassLoader / ART 加载点
```

### Native 层（.so）
- 优先看 `JNI_OnLoad` 与 `RegisterNatives` 注册表
  → **直接拿到 Java 方法与 native 函数的对应关系**

### 抓包与 SSL Pinning
1. 改 `network_security_config.xml` 加用户 CA（需能重打包，仅自有/授权 App）
2. 把 CA 装进系统证书区（需 root）
3. **Magisk 模块（推荐）**：AlwaysTrustUserCerts / MagiskTrustUserCerts

---

## 5. .NET / C# / VB.NET

**命门：元数据完整保留，dnSpy 近乎还原源码。**

- 判据：PE 的 Data Directory[14]（CLI Header）非零
- 工具：**dnSpyEx**（可调试 + 修改 IL）、ILSpy、`ilspycmd`、dotPeek
- 混淆处理：`de4dot` 去常见混淆器
- 看 IL：`ildasm` / `monodis`
- ⚠️ **NativeAOT / ReadyToRun 是例外**：已编译为机器码，退化为原生二进制难度

---

## 6. Java / JVM

**命门：常量池 + 局部变量表保留，多引擎反编译交叉验证。**

- 反编译器：CFR、FernFlower（IntelliJ 内置）、Procyon、Recaf
- **多引擎对比（BCV）**是标准做法：同一个方法谁的输出最合理就用谁
- 混淆器（ProGuard / Allatori / Zelix）才决定真实难度
- **对自家服务：arthas 比反编译更快得到答案**
  ```
  watch com.xxx.Service method '{params, returnObj}' -x 3
  trace com.xxx.Service method
  ```
  不改代码、不重启，直接看运行中的类。

---

## 7. Python

**命门：版本匹配 + 解开打包。**

### pyc
- **版本不匹配是反编译失败的第一大原因**
- `re.py info x.pyc` 直接给出推定版本（本机已实测验证 3.13/3.14 的 magic）
- 工具：`pycdc`（支持面最广）、`uncompyle6`（≤3.8）、`xdis` + 手工读字节码兜底

### PyInstaller 打包
```bash
pyinstxtractor app.exe          # 产出 app.exe_extracted/
# 注意：PyInstaller 的 pyc 常常缺 magic 头，必须补回
#   补 = 本版本 magic(4B) + bit field + mtime + size
pycdc 补好的.pyc
```
- Nuitka（编译成 C）难度远高于 PyInstaller

---

## 8. Web / JS / WASM / Electron

**命门：代码必然下发到客户端；能执行就能观察。**

### 前端 JS
- **source map 是第一大漏**：`.js.map` 直接还原原始目录结构
- 混淆：先美化（Prettier），再定位关键函数，最后用 DevTools 下断点看真实值
- 常见混淆：字符串数组 + 移位函数、控制流平坦化、自执行解密函数
  → **直接在 Console 里调用解密函数拿到明文**，比静态推演快得多

### WASM
```bash
wasm2wat module.wasm -o out.wat
wasm-decompile module.wasm
```
- **导入/导出接口与 JS 胶水层是明处**，从边界 Hook
- 无符号但结构清晰

### Electron
```bash
npx asar extract app.asar out/     # 一行解开
```
解开后全是明文 JS，难度极低。

---

## 9. 网络协议（PRE）

**命门：长度字段 + 不变字节 + 加密必然在某处被解密。**

### 流程
```
1. 抓包拿样本（Wireshark / mitmproxy）
2. 多样本对齐（MSA 多序列比对）：找不变字节与变化字节
3. 猜字段：改一个字节看输出怎么变 → 定位长度/校验和/序号
4. 识别序列化框架（省 80% 功夫）
5. 写解析器验证
```

### 序列化框架识别
| 框架 | 特征 |
|---|---|
| protobuf | 字段号 + wire type，`protoc --decode_raw` 可无 schema 猜结构 |
| JSON/XML | 明文，直接看 |
| MessagePack | 紧凑二进制，首字节是类型标记 |
| TLV | 类型-长度-值三段循环 |

```bash
protoc --decode_raw < packet.bin     # 神器：无 schema 也能猜出结构
```

### 加密流量
- 让客户端吐 `SSLKEYLOGFILE`：
  Wireshark → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
- 或直接 Hook 加解密 API（`SSL_write` / `SSL_read` / `CryptEncrypt`）拿明文

---

## 10. 固件 / IoT

**命门：binwalk 一刀 + 默认凭证 + 未签名更新 + UART 直出 root shell。**

### 拆解
```bash
binwalk firmware.bin           # 识别
binwalk -Me firmware.bin       # 递归提取
unsquashfs fs.squashfs
# 常见文件系统：squashfs(hsqs)、jffs2(0x1985)、cramfs、romfs、UBIFS
# initramfs 常是 gzip 压缩的 cpio
```
`binwalk` 扫不出东西且整体熵接近 8.0 → **固件是加密的**，先找解密例程或 OTA 明文包。

### 审计清单
```bash
grep -rE '(password|passwd|admin|root)' extracted/
grep -rl 'BEGIN.*PRIVATE KEY' extracted/       # 找私钥
cat extracted/etc/shadow extracted/.htpasswd   # 找凭证
```

### 模拟运行
```bash
qemu-arm -L <sysroot> ./bin/xxx      # 用户态跑单个交叉编译二进制
firmadyne / FirmAE                   # 全系统模拟
```

---

## 11. 私有文件格式

**命门：多样本差分 + 长度/偏移字段 + pattern 建模。**

```
1. 收集多个样本（内容不同）
2. 逐字节对比 → 不变的字节是结构，变化的字节是数据
3. 定位长度字段：改长度值看解析怎么崩
4. 定位偏移字段：通常是文件开头的小端/大端整数
5. 用 ImHex pattern（.hexpat）建模并验证
6. 写出能读全部样本的解析器 = 完成
```

**常见魔数速查**（`re.py magic` 可查全表）：

| 魔数 | 格式 |
|---|---|
| `4D 5A` | PE / DOS |
| `7F 45 4C 46` | ELF |
| `CF FA ED FE` | Mach-O 64 |
| `CA FE BA BE` | Java class / Mach-O Fat |
| `64 65 78 0A` | DEX |
| `50 4B 03 04` | ZIP 系 |
| `00 61 73 6D` | WASM |
| `1F 8B` | gzip |
| `FD 37 7A 58 5A 00` | xz |
| `28 B5 2F FD` | zstd |
| `68 73 71 73` | SquashFS |
| `27 05 19 56` | U-Boot uImage |
| `53 51 4C 69 74 65` | SQLite |

---

## 12. 游戏（Unity / Unreal）

**命门：Unity IL2CPP 的 `global-metadata.dat` 保留全部符号。**

### Unity
- Mono 后端：`Assembly-CSharp.dll` 直接 dnSpy，难度极低
- IL2CPP 后端：
  ```bash
  Il2CppDumper binary global-metadata.dat output/
  ```
  产出 `dump.cs`（近乎源码骨架）、IDA/Ghidra 脚本、`il2cpp.h`

### Unreal
- UE4/5 蓝图 → C++ 编译，靠反射元数据（`.uasset` / pak）
- pak 解包：UnrealPak / FModel
- 名称表（`Names` / `Objects`）是主要线索来源

### 内存分析
Cheat Engine + ReClass.NET 重建结构体；先找指针链基址。

⚠️ 反作弊绕过属于本文档明确不覆盖的范围（见 legal.md）。

---

## 13. 数据库与取证

**命门：schema 与 freelist 残留。**

### SQLite
```bash
re.py info app.db --json      # 直接列出表/索引/视图/行数
sqlite3 app.db .schema
```
- 删除只是标记，页面里的记录往往还在
- 恢复：undark（开源）/ sqlite-recover（商业）
- 应用私有加密数据库（如微信 EnMicroMsg.db、SQLCipher）→ 先找密钥派生入口
  （通常在 native 层，Hook 拿 key）

### 文件系统取证
- file carving：不依赖文件系统按特征恢复（`re.py carve` 已内置）
- 工具：Autopsy / Volatility（内存取证）/ PhotoRec
