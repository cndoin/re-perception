# 贡献指南

感谢你愿意改进这个项目。请先读完本页，再动手。

## 项目定位

一个**零第三方依赖**（仅 Python 标准库）的逆向工程工具箱，作为 Agent Skill
分发。两条硬约束，任何 PR 都不能破：

1. **不许引入第三方依赖。** 自检用例 `t_no_third_party` 会扫描所有脚本的
   import，一旦发现非标准库模块就直接失败。需要新能力时，用标准库自己
   实现，或做成「可选的外部工具探测」（`lib_tools.py` 的机制）。
2. **不许静默失败。** 「失败被上报为成功」是本项目最不能接受的一类缺陷。
   典型反面例子：解压失败后继续用压缩数据解析、并在结果里报 `ok: true`。
   遇到可选功能不可用时，必须在返回值里留下可观测的错误字段。

## 环境要求

- Python 3.10+（开发与验证使用 3.13）
- 无需安装任何 pip 包

```bash
# 拿到仓库后进 scripts/ 目录即可，无需安装任何东西
cd reverse-engineering/scripts

# 全量自检（约 110 秒，88 个用例）
python selftest.py

# 只跑名字含关键字的用例
python selftest.py --only 符号

# 静态体检（语法/静默吞异常/可变默认参数/硬编码路径等）
python _dev/_lint.py

# 端到端：把 26 个子命令在真实系统 PE 上全跑一遍
python _dev/_e2e.py
```

**提交前这三条必须全绿**，否则 CI 会拒绝。

## 目录约定

```
scripts/
  re.py              CLI 唯一入口（26 个子命令：21 分析 + 5 编排）
  lib_*.py           按职责拆分的分析库
  _quirk.py          dbghelp 已知缺陷清单（**参考文档**，须随发布分发）
  selftest.py        自检用例集
  _dev/              开发脚手架，不随发布分发
```

`_` 前缀**不代表**「可以随便挪」。判断标准是「有没有被运行时/用户需要」，
不是文件名，也不是「有没有被 import」：

- `_quirk.py` **没有任何生产模块 import 它** —— 它是 dbghelp 已知缺陷的
  参考文档，被 `README.md` / `CHANGELOG.md` 引用，用户读技能时需要它，
  因此**必须随发布分发**，不能挪进 `_dev/`。
- `_dev/` 下的东西才真的不分发（见 `_dev/_install.py` 的 `_EXCLUDE_DIRS`）。

`_dev/_lint.py` 有专门的护栏（护栏 9/10）会在你误挪时报警；护栏 9 的判据
是**导入方的身份**，别改成「被导入模块在 `_dev/`」—— 那样护栏会整体失效
（负向测试能当场抓到）。

## 提交规范

Conventional Commits 前缀，`subject` 用英文，`body` 用中文详述：

```
fix: 修复 funcs 在指令预算用尽时报 function_count=0 的误导性输出

改了什么：lib_code.analyze() 在 truncated 时补出 partial 与 truncated_note
为什么改：预算耗尽时 function_count=0 看似"确实没有函数"，实际只扫了前
          100 条指令，属于把截断结果伪装成完整结论
影响范围：funcs / sim / semantics 三个子命令的 JSON 输出新增两个字段，
          字段是新增的，不破坏既有调用方
```

一个主题一个提交，别把无关改动糊在一起。提交信息必须能回答三件事：
**改了什么 / 为什么原来那样是错的 / 影响范围**。「fix bug」等于没写。

## 修 bug 的流程

1. **先复现，再动手。** 写出能稳定复现的最小输入。如果复现不了，说明你
   还没找到根因。
2. **先证明，再断言。** 不要凭一个样本就归纳规律。曾经有过一次教训：
   从单个样本 `QE$ADVObject` 推断出「函数头 `$Ax` 会输出 `__unaligned`」，
   加进引擎后差异数从 67 暴涨到 142，最后靠对照实验（`QE$AAA@XZ` 无 hat
   对比 `QE$AAAPE$AAVObject` 才有 hat）才证伪。
3. **每个修复配一个回归用例。** 加在 `selftest.py` 的 `cases` 列表里。
4. **别用「归一化」掩盖问题。** 如果引擎输出和参考实现不一致，先去查是
   谁错了。把 `>` `>` 强制压成 `>>` 这种「归一化」会把真 bug 一起藏掉。

## 关于符号还原（MSVC）

这是本项目最复杂的部分，改动前请先读 `references/research.md`。要点：

- 首选验证参照是 `dbghelp!UnDecorateSymbolName`（Windows 自带，用
  `ctypes` 调用）。但它**自身有至少 6 个已知缺陷**，清单在
  `scripts/_quirk.py` 的模块 docstring 里（该文件是参考文档，不是运行时
  模块 —— 没有任何代码 import 它）。
- 因此「与 dbghelp 逐字一致」**不是**正确性标准。目标是与正确语义一致，
  并明确记录哪些差异是 dbghelp 的错。
- C++/CX 的 `^` 帽（hat）扩展 `$AA`–`$AD` 在 LLVM 里**完全没有**，是本
  项目自行逆向出来的，见 `references/research.md`。

## 报告安全问题

请勿开公开 issue。见 [SECURITY.md](SECURITY.md) 的披露流程。
