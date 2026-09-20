# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [1.3.8] — 2026-09-20

「每一个工具都要单独验一遍」：再挖 7 处静默缺陷，其中 6 处是**静默丢结果**，
1 处是把**虚拟地址当成文件偏移**的功能性失效。

这一轮换了做法：不再只靠静态审计，而是造了一版「工具体检矩阵」
（`scripts/_dev/_matrix.py`），把 **26 个子命令 × 12 种样本格式**实跑一遍，
逐条检查退出码 / Traceback / JSON 可解析性 / `ok` 键 / null 字段五类契约。
首份报告里 26 个子命令只覆盖了 14 个 —— 探针把文件路径塞给了 `case`
这类取值是 `{init,status,...}` 的**动作型**子命令，argparse 判非法选项后
直接退出，于是这些命令**一次都没真正跑到**，却报了 12 处「工具坏了」。
这是本版第一个被修的东西，也是本版最值得记的一条：**体检工具自己也会
说谎，必须用它是否真的覆盖了来判断它可信不可信。** 修完覆盖 26/26。

### 修复

- **P0 · `obfstr` 的 XOR 加密串在 PE 上永远恢复不出来**（`lib_obfstr.py`）

  `xor_loops_to_strings` 第 507 行把 `lp["data_ref"]` 直接喂给
  `Reader.read()`。而 `data_ref` 来自指令的 `mem_ref`，是**虚拟地址**
  （`lib_x86.py:849-855`）；`Reader.read` 是**文件偏移**语义
  （`lib_formats.py:54-61`）。PE 的 image_base 通常是 0x140000000，远超文件
  长度 → `read()` 越界返回空 → 一条 XOR 串都出不来，而函数照样返回
  `warnings: []`。新增 `make_vma2off(ident)` 按节表换算后再读。

  顺带修掉两处同源坐标错误：输出里的 `offset` 字段填的其实是 VMA（用户拿
  它去跳转必然扑空），现在 `offset` 给真实文件偏移、VMA 另给 `vma` 字段；
  `data_ref` 为 `None`（循环体里是寄存器间接取数）时原本静默 `continue`，
  现在计数并告警。

  Mach-O 的节表目前**没有输出地址字段**（`lib_formats.py:1338-1339` 只有
  seg/name/size/offset），无法建映射 —— 这种情况明确报「给不出映射」，
  不假装成功。

- **P0 · `xref` 的 `unresolved_calls` 是编造的数字**（`lib_code.py`）

  原实现 `sum(1 for f in funcs for i in [0] if any(c is None for c in [None]))`
  是没写完的占位脚手架 —— `any(c is None for c in [None])` 恒为 True，于是
  该值恒等于**函数总数**。notepad.exe 上真实输出是 308，一个跟真数字并排
  放着、看不出是编的值。现在拆成两个如实口径：`unresolved_calls`
  （`target` 与 `mem_ref` 都为 None，真·无从下手）与 `indirect_calls`
  （留有 IAT/thunk 线索，下游可还原）。实测 notepad.exe：
  `unresolved_calls=0`、`indirect_calls=1373`。

  > 这里纠正过一次自己：第一版把所有 `target is None` 的调用都算「未解析」，
  > 得出 1373 这个吓人的数字。逐条核过发现这 1373 条**全部带 `mem_ref`**，
  > 是 MSVC 调 API 的标准写法，下游能还原成 API 名。把「可还原」报成
  > 「没解析出来」是方向相反的另一种编造，所以要拆开。

- **P1 · `_as_vma_int` 把十进制地址当十六进制解析**（`lib_semantics.py:557`）

  两个分支都写成 `int(v, 16)`，十进制串 `"4096"` 被解析成 `16534` 且
  **不抛异常** —— 静默得到错误的 VMA，后面按这个地址查名全部落空。

- **P1 · `_walk` 撞到遍历预算返回半个函数体**（`lib_code.py`）

  调用方无法区分「走完了」和「没走完」，照单全收 → `insn_count` /
  `bb_count` / `calls` 全是偏小的假数字，还没有任何提示。现在返回
  `(body, hit_limit)` 二元组，`analyze()` 会在输出里给出
  `functions_truncated` 与对应说明。`max_functions` 触顶时原本直接
  `break` 不留痕（用户会把 `function_count` 读成全文件的函数总数），
  现在登记 `skipped_seeds` 并给出 `function_seed_truncated`。

- **P1 · `bytes` 叶子承诺了要报，实际静默不命中**（`lib_rules.py`）

  注释写着「但要报出来（不能静默当成不命中）」，实现却只有一个裸
  `return False`。现在真的往 `errors` 里登记。

- **P1 · 常量签名扫描每个分块只报第一处**（`lib_libscan.py`）

  `buf.find()` 只返回第一次出现的位置，同一 1MB 分块里存在的第二份、
  第三份常量表永远扫不到。改为取全部命中位置，并按 `(签名, 偏移)` 去重
  （分块留有 64 字节重叠，同一位置会被相邻两块各命中一次）。

- **P1 · `_data_spans` 裸 `except` 吞异常**（`lib_libscan.py`）

  取数据节失败时静默 `return []`，于是常量签名一条也扫不到 → 所有依赖
  `characteristic:` 的规则大面积静默漏报，报告上却写着「样本干净」。
  现在留痕并向上抛出，与本文件另一处的既有约定一致。

### 未改但有结论

- `lib_symbols.py` 三个 `guard()` 的 `depth` 只增不减，名字与实际语义不符。
  查证后确认三个解析器类都是**每个符号新建实例**（`_Ita(body)` /
  `_Msvc(s)` / `_RV0(body)`），不存在跨符号累积；且每次 `guard()` 调用都
  对应一次递归进入，累计次数 ≥ 当前深度，照样挡得住无限递归。因此判定为
  **非用户可见缺陷**，只订正了文档，不改行为（避免后来者按错误前提再加
  一层守卫，反而引进真 bug）。

### 新增

- 回归用例 **92 → 97**，新增 5 个（每一项都做了反向验证：撤回复修必须变红）：
  `unresolved_calls` 不是函数数、VMA→文件偏移换算、`_as_vma_int` 十进制
  分支、`bytes` 叶子必须报错、函数截断与丢弃种子留痕。
- `scripts/_dev/_matrix.py`：工具体检矩阵（26 子命令 × 12 格式）。
- `scripts/_dev/_probe138.py`：修复前后行为对比探针。

### 门禁

lint 生产 0 处违规 ／ 未定义名 0 处 ／ 自检 97/97 ／ e2e 36/36 ／
体检矩阵 26/26 覆盖且硬性故障 0 处。

## [1.3.7] — 2026-09-20

开源前全量复查：再挖出 2 个 P0「假成功」+ 5 个静默降级。

这一轮不是加功能，是把「要开源了，每个角落都看一遍」这条要求真正执行完。
派了一组审计子代理逐文件找**静默失败**，命中 7 处；另有 1 处是修复过程中
我自己引入、被回归用例当场抓住的（见最后一条）。

### 修复

- **P0 · `capability` 在非 x86 上把「没做」报成「没有」**：

  `cmd_capability` 里 `idx = res.pop("_idx", None)`，之后所有语义层代码
  都以 `if idx is not None` 为条件。而 `lib_disasm.analyze_file` 对非 x86
  架构走线性反汇编分支，返回 `ok: True` **但不带 `_idx`**
  （`lib_disasm.py:295-309`）。于是语义层（resolve_thunks /
  summarize_functions）与字符串 VMA 映射**整段跳过**，api / 字符串类特征
  全空 → 规则必然大面积漏报，而输出仍是 `ok: true` + `capabilities: []`，
  **一个 warning 都没有**。

  用户读到的是「这个样本没有这些能力」，真相是「压根没做函数识别」——
  这正是该函数自己注释里点名要防的那句话（"把没命中读成没这个能力"），
  结果它自己就踩了。现在 `idx is None`，以及 idx 在但识别出 0 个函数，
  都会产出显式告警并进 `--json` 的 `warnings`。`semantics` 子命令
  同一处缺陷一并修掉。

- **P0 · `imports` 在 PE 解析失败时仍报 `ok: true`**：

  原代码写死 `out = {..., "ok": True}`，随后
  `out["modules"] = [... for m in det.get("imports", [])]`。PE 头畸形时
  `parse_pe` 在 `lib_formats.py:1001-1007` 的 except 里把异常吞掉，
  `detail` 只剩 `parse_ok: False` + `errors`，**连 `imports` 键都没有**，
  于是返回 `ok: true / modules: [] / function_count: null`。
  用户读到「这文件没有导入表」，真相是「压根没解析成功」。

  `identify` / `info` 也是写死的 `d["ok"] = True`，与 `triage`
  （`not bool(errors)`）口径不一致——三处三种写法。现在统一到新增的
  `_ident_ok()` 助手：从顶层 `errors` + `detail.errors` 推导，
  且 `parse_ok=False` 却没记 errors 的分支也判失败（防御以后有人加
  只设 flag 不记原因的代码）。失败时 `errors` 一并输出。

- **P1 · pclntab 扫描窗口截断 = 假阴性「不是 Go」**：

  `find_pclntab` 默认只扫前 32MB。文件更大而 pclntab 落在窗口之外时返回
  空列表，`recover_go_symbols` 直接 `return None, []` —— 与「不是 Go
  程序」在返回值上**完全一样**。现在窗口小于文件且没找到候选时给出告警，
  明确说「不能据此断定不是 Go 程序」。与 1.3.5 修的 AXML 截断同族。

- **P1 · 熵分析「声称采样」却根本没采样**：

  `entropy_profile` 的 else 分支写着「整体熵由采样估算」并设
  `sampled=True`，**一行采样代码都没有** —— `overall_entropy` 保持
  `None`，报告里就印出「整体熵：**None**」。这比不做更糟：读者会以为
  那个数字是采样结果。现在真的做等距采样（64 段），并给出
  `sampled_bytes` / `sampled_ratio` 与一句说清覆盖范围的 note。

- **P1 · `truncated` 在 semantics / capability 里被丢掉**：

  `lib_code.analyze` 在 `--max-insns` 触顶时会给 `truncated` +
  `truncated_note`；`cmd_funcs` 正确透传，但 `cmd_semantics` 与
  `cmd_capability` 都没带出去 —— 命中的能力只覆盖已解码的那一段，
  却没有任何标记。现在两个子命令都透传。

- **P2 · `semantics` 的 warning 被第二次赋值静默覆盖**：

  `out["warning"]` 先被 `_libscan_error` 写、再被 `_string_map_error` 写。
  两个都挂时用户只看到后者，前者凭空消失。改成累加后拼接。

- **P2 · 病态文件能把 I/O 放大到几十 GB**：

  逐节算熵时每节上限 8MB，但**没有合计上限**：ELF 可声明 4096 个节、
  Mach-O 可声明 1024×64 个节，逐个读 8MB 就是几十 GB 的读放大，
  一个 256MB 的构造文件足以把这个工具挂死。现在加了 64MB 合计预算；
  预算耗尽时该节熵置 `null`（**不是 0.0** —— 0.0 会被读成
  「这节是常量字节」，那是另一个假结论），并在 `notes` 里交代
  有几个节没算。顺带修了 `lib_names` 里一处 `Reader` 未用 `with`
  的句柄泄漏。

### 我自己引入、被回归用例抓住的那一条

第一版采样写的是「64 段 × 每段 1MB」，没考虑段长 > 段间距时相邻段会
**互相重叠**：3MB 的文件采样出 56MB，`sampled_ratio` 算出 1794%。
回归用例里加了「采样字节数不得超过文件本身」这条断言，当场变红。
现在段长取 `min(1MB, 段间距)`。

### 验证

- 新增 4 条回归用例：`t_imports_ok_false_on_parse_error`、
  `t_capability_warns_without_function_index`、
  `t_entropy_sampled_really_samples`、
  `t_names_go_pclntab_scan_truncated_reports`。每条都带**反向验证**
  （正常场景不能被误伤）。
- 4 条全部做了「撤回修复 → 用例必须变红」的反向确认：
  **撤销后仍然绿的守卫等于没有守卫**。
- 全量自检 **92/92 通过**（88 → 92）；`_lint` 生产 0 处；
  `_undefined` 0 处。

### 文档

用例数 88 → 92 散落在 7 处（README × 2、SKILL × 2、CONTRIBUTING、
Makefile、PR 模板），全部对齐；耗时标注 110s → 155s。

## [1.3.6] - 2026-09-20

整理：安装器的 WorkBuddy 路径解析错误 + 三处过期文档数字。

### 修复

- **`workbuddy` 运行时的目标路径解析错误（假成功）**：
  `personal_dir("workbuddy")` 返回 `os.path.dirname(SELF_ROOT)`，即
  「技能自己的上一级目录」。两层后果，第二层更严重：
  1) 把仓库 clone 到 `~/projects/re-clone` 后跑 `--auto`，会往
     `~/projects/reverse-engineering` 再复制一份 —— 那不是任何运行时
     读技能的路径；
  2) 这一步还被上报成「[成功] 复制 → …」。装到一个永远不会被读的位置
     却报成功，是本项目最忌讳的假成功。
  现固定返回 `<home>/.workbuddy/skills`，并让「技能已在此位置」走幂等
  分支（回报已就绪、不复制），杜绝自己复制进自己。

### 文档

- 修正三处过期用例数：`README.md` 快速开始仍写「81 个用例，约 170 秒」、
  `.github/PULL_REQUEST_TEMPLATE.md` 仍写 81。这两处 ossaudit 未覆盖，
  属于上一轮只改 CONTRIBUTING.md 时留下的漏网。

### 新增用例（87 → 88）

- `安装：workbuddy 不复制到技能上级` —— 断言目标必须是
  `<home>/.workbuddy/skills`，且不得退化为技能上级目录。
  已做负向验证：撤回修复即变红。

## [1.3.5] - 2026-09-20

收尾：修复两处「静默截断」缺陷 —— 它们与已修的 `function_count: 0` 同源，
都是把「没做完的工作」呈现成「做完的结论」。

### 修复

- **`lib_code.match_functions` 比对预算触顶后不标注**：`cmp_count` 超过
  `max_pairs * 50` 就 `break`，返回值里没有任何标记。调用方看到
  `match_rate_a` 偏低会读成「两个二进制只有 12% 像」，实际是「比到一半
  就停了」。现新增 `partial` 与 `truncated_note`，与 `funcs` 子命令的
  既有契约一致；预算充足时两个字段不会出现（避免标记退化成恒真噪音）。
- **`lib_formats._axml_strings` 扫描窗口截断后退化成「无权限」**：
  扫描窗口被硬截到 1 MB，若 `AndroidManifest.xml` 的中央目录条目落在
  1 MB 之后，循环走完 `find` 返回 -1 → `pool` 为空 → 返回 **`{}`**，
  连 `_note` 都没有。调用方会读成「这个 APK 不申请任何权限」。
  注意此处原本已谨慎处理 inflate 失败（注释明写「不要 pass」），
  唯独漏了窗口截断这一路。现改为返回带原因的 `_error`。

### 新增用例（85 → 88）

- `稳定性：差分比对截断如实标注` —— 双向验证：触顶必须标 `partial`，
  充足时不得误标。
- `稳定性：AXML 截断窗口不伪装成空` —— 大文件无 manifest 必须报 `_error`；
  小文件无 manifest 仍应安静返回 `{}`（不得误报）。

两条用例都做过**负向验证**：把修复临时撤回后，它们会变红 ——
证明它们真的在守，而不是永不拦截的门。

## [1.3.4] — 2026-09-20

**跨运行时安装**：让同一份技能能装进 Claude Code / Codex CLI / Hermes /
OpenClaw / Cursor / Gemini CLI，并**装完能自证可用**。

### 新增

- **`scripts/_dev/_install.py` 跨运行时安装器**。各家技能目录不同
  （`~/.claude` vs `~/.codex` vs `~/.hermes` vs `~/.openclaw`…），
  目录找错就静默不生效。安装器按**各官方文档**的路径建表，支持：
  - `--auto`：只读探测本机装了哪些运行时，只装这些
  - `--verify`：回去检查 SKILL.md 可达、frontmatter 合规、入口脚本在
  - 幂等（重复装不报错）、已存在时**拒绝覆盖**、`--force` 先备份
  - 复制时**裁剪** `_dev/` `_ref/` `.github/` `.git/` `*.pyc`
- **`INSTALL.md`**：各运行时目录对照表、手工装法、常见错误对照、
  Windows 符号链接陷阱说明。
- **4 个安装用例**（自检 81 → 85）：路径合规、验证器能识别坏安装、
  复制可用且裁剪、不覆盖用户已有技能。

### 修复

- **`os.symlink` 的假成功**。实测在 Windows 上 `os.symlink()` 会
  **返回成功但造出一个不可解析的目录**（`islink()` 为假、读不到 SKILL.md）。
  旧实现只看有没有抛异常，于是把不可用的安装上报为成功 —— 正是本项目
  最忌的"失败被上报为成功"。改为**建完验证链接真能读到 SKILL.md**，
  读不到就清掉残骸并退回复制（`--mode auto`）或明确报错（`--mode link`）。
- **安装器无法在测试中隔离**。`personal_dir()` 直接读 `~`，
  测试会把用例真的装进开发者的 `~/.claude`。新增 `RE_SKILL_HOME`
  环境变量覆盖家目录（同时支持绿色/便携安装）。
- **裁剪只匹配顶层目录名**。`_dev/` 和 `_ref/` 实际在 `scripts/` 之下，
  只比对顶层名字会原样拷贝进去。改为**任意层级**匹配。
- **`t_no_third_party` 漏扫 `_dev/`**。本地模块集只收 `scripts/*.py`，
  于是自研脚手架模块被当成第三方依赖误报；扫描范围也只有 17 个文件，
  脚手架坏了查不出来。现在收全 32 个（`scripts/` + `_dev/`）。

## [1.3.3] — 2026-09-20

**仓库整理与最终检查**：把项目从"文件躺在磁盘上"变成"一个自洽的 git 仓库"。

### 新增

- **git 仓库初始化 + 首次提交**。此前项目不是仓库，导致 README 的
  clone 说明无法执行、也无法提交/推送/打标签 —— 这是 1.3.2 审计里
  唯一剩下的高危项。
- **`.gitattributes`** —— 显式 `eol=lf`。仓库的 `.editorconfig` 要求 LF，
  而 Windows 上 git 默认 `autocrlf=true` 会把文本转成 CRLF，两者打架会让
  diff 出现整文件差异。锁死行尾后不会再有这种噪声。

### 清理

- **移除 6 个零引用的历史快照**（约 150 KB）：`_msvc_new` / `_msvc_old` /
  `_msvc_test` / `_msvc_score` / `_lib_symbols_before_splice` /
  `_corpus_build2`。这些是 MSVC 引擎开发期的拼接工作流产物，引擎并入
  `lib_symbols.py` 后已无任何引用。`_dev/README.md` 里保留了归档说明。
- **移除编译产物**：`scripts/selftest.pyc`（234 KB，本不该进源码目录）、
  两处 `__pycache__/`。
- **`.gitignore` 补充分析产物后缀**：`*.re-report.json` / `*.re-cfg.json` /
  `*.re-funcs.txt` / `*.re-strings.txt`。

### 文档修复（漂移）

本轮又抓到一批文档与代码不一致 —— 都是"代码在长、文档没跟"：

| 位置 | 问题 |
|---|---|
| `README.md` 目录结构 | 只列 12 个模块，实际 **17 个**（漏 `lib_agent` / `lib_names` / `lib_obfstr` / `lib_rules` / `lib_x86`） |
| `SKILL.md` 模块表 | 漏 `lib_symbols`（最复杂的模块）/ `lib_names` / `lib_obfstr` / `lib_agent` / `_quirk` |
| `scripts/_dev/README.md` | 漏 `_adversarial` / `_deepaudit` / `_fuzz` / `_fuzzlib` / `_ossaudit` 五个脚本 |

### 审计器增强

`_ossaudit.py` 新增**反向检查：生产模块是否被文档覆盖**。

旧版只查"文档引用的文件在不在"（防多余），不查"存在的文件有没有被文档提到"
（防缺失）—— 而上面那批漏列正是这个盲区。现在两个方向都查。
新检查**上线即命中**：`_dev/README.md` 还在描述我删掉的文件。

### 验证

| 项目 | 结果 |
|---|---|
| 全量自检 | 81/81 |
| 静态体检 | 生产 0 处 / 脚手架 18 处，退出码 0 |
| 未定义名 | 0 处 |
| 开源合规自审 | **0 项**（1.3.2 结束时为 1 项） |
| `git clone` 后自检 | 62 文件 / 1.16 MB，81/81 通过 |

### 提交历史

按主题拆成 4 个提交（不是一个大 commit），便于 review 与单点 revert：

```
ea128e8  test: 开发脚手架与自审工具
fa30046  docs: 开源标配文件与合规文档
cf235b3  docs: 技能定义与逆向方法论参考
0da58c3  feat: 逆向工程工具箱核心引擎（零第三方依赖）
```

## [1.3.2] — 2026-09-20

**开源准备专项**：把项目从"能跑"推到"能开源"。这一轮的核心不是加功能，
而是**让项目对自己的缺陷说实话** —— 过程中发现三道门禁存在"永不拦截"
的结构性问题，以及一个用户一上手就会踩到的真实 bug。

### 修复

- **`report` 默认输出位置在受保护目录下必然失败**。
  默认写到"目标文件旁边"，于是 `re.py report C:/Windows/System32/notepad.exe`
  直接以退出码 4 失败 —— 这是新用户最可能敲的第一条命令。
  现在：优先目标旁边，写不进去则退到当前工作目录，并在返回值里加
  `writable_fallback` + `note` **标明发生了降级**（不静默换位置 ——
  否则 AI 按预期路径读文件会读到空，属于本项目最忌的假成功）。
  踩坑记录：第一版用 `os.access(dir, W_OK)` 预测可写性，**在 Windows 上无效**
  —— 它只看只读属性位、不查 ACL，System32 会被判成可写。改成真写一次再回退。

- **`_ossaudit.py` 永远返回 0**。它被打包成 CI 门禁，但无论报出多少条
  高危都算通过。这不是"检查不严"，是**审计器自己在犯"失败被上报为成功"**。
  现在：有高危项退出 1。

- **`_lint.py` 永远返回 0**，且把生产文件与 `_dev/` 脚手架的告警混在一张
  账单里（"合计 26 处"），导致 `SKILL.md` 里"期望 0 处"这句话永远是假的，
  数字失去信号价值。现在：生产/脚手架分账，生产侧有告警退出 1。
  这个改动立刻抓到一处真实残留 —— 我们自己的测试把
  `notepad.exe.re-report.md` 写进了 `scripts/`（护栏 11 生效）。

- **`selftest.py --only <无匹配关键字>` 静默通过**。旧行为打印
  "通过 0/0" 并返回 0 —— 一个用例都没跑，在 CI 里等于一道永不拦截的门。
  现在：无匹配时打印可用前缀提示并返回 2。

- **两处 lint 守卫的漏检**（上一轮遗留，本轮验证时补上）：
  ① `check_file` 遇 `SyntaxError` 直接 `return`，导致 9 条 AST 级守卫
  全部跳过（含文本级的硬编码路径检查）—— 一个语法错误就能让整个文件免检；
  ② `main()` 只扫 `scripts/`，不扫 `scripts/_dev/`，
  于是 `_corpus_*.py` 里的本机路径一路漂到开源前。

### 文档

- **数字全面校对**：README / CONTRIBUTING / SKILL.md / `_dev/README.md`
  写的"46 个用例""18 个子命令"全部过期，实际是 **81 个用例 / 26 个子命令**。
  这不是排版问题 —— 数字过期会让人对项目的成熟度判断失真。
- 澄清 **26 = 21 分析命令 + 5 编排命令**（`require` `flow` `case` `result`
  `toolgraph`），此前文档只说"21 个"或"18 个"，都对但都不完整。
- README 新增「门禁的退出码契约」与「一键跑门禁（Makefile）」两节。

### 许可证

- **`LICENSE` 回归标准 MIT 全文**，去掉附加的「使用限制与免责声明」章节。
  原形态在 OSI 定义下**已不是开源许可证**（含使用领域限制），会让企业法务
  直接拒用。限制内容移到新文件 **`USE-POLICY.md`**，并明确标注
  "本文件不是许可证、不修改 LICENSE 授予的任何权利"——
  许可证管代码授权，使用政策管用途提醒，两件事不混。

### 新增（开源标配）

- `SECURITY.md` —— 漏洞披露政策，含本项目特有的威胁模型（解析器内存耗尽 /
  栈溢出 / 无界读取 / 路径穿越 / **假成功**，后者按严重级别等同 RCE）。
- `CODE_OF_CONDUCT.md` —— 基于 Contributor Covenant 2.1，加入逆向领域
  专属条款（不接受破解/免杀类贡献，不贴未授权专有代码）。
- `USE-POLICY.md` —— 使用政策（非许可证）。
- `.github/workflows/ci.yml` —— 三平台 × 多 Python 版本矩阵；
  **刻意不装任何依赖**，装了反而掩盖"零依赖"被破坏的问题。
- `.github/ISSUE_TEMPLATE/`（bug / feature）+ `config.yml`
  + `PULL_REQUEST_TEMPLATE.md`（PR 模板把退出码契约写进自检清单）。
- `Makefile` —— `make check` / `make all` / `make help`。
- `.editorconfig` —— 统一缩进与换行（`Makefile` 单独指定真实制表符）。
- `scripts/_dev/_ossaudit.py` —— 开源合规自审器：实测 CATALOG 条目 /
  CLI 子命令 / 用例数 / 工具表，再据此核对文档数字、失效链接、失效脚本引用、
  敏感信息与缺失文件。**先量事实、再判合规**，不靠手写常量。

### 审计器自身的修复

审计器也是代码，也会撒谎。本轮修掉它自己的 3 个问题：

- 脚本引用检查漏了 `scripts/_dev/` 这个基准，导致 `_lint.py` 被误报
  "引用不存在的脚本"（文件确实存在）。
- 命令表行数检查要求标题后紧跟空行+表格，一插入说明段落就误报"表格 0 行"——
  改成从标题扫到下一个标题，不再用排版约束反向限制解析。
- 敏感信息扫描用裸正则扫原始文本，把 `_lint.py` 里**解释这个坑**的注释
  当成本机路径泄漏 —— 与 `_lint.py` 自己早已实现的豁免逻辑不一致。
  现在同样跳过注释与 docstring。

### 验证

| 项目 | 结果 |
|---|---|
| 全量自检 | 81/81 通过 |
| 端到端（26 子命令 / 真实 PE） | 36/36 通过（修复前 34/35，`report` 因权限失败） |
| `_lint.py` | 生产 0 处 / 脚手架 25 处，退出码 0 |
| `_undefined.py` | 0 处问题（44 个文件） |
| `_ossaudit.py` | 18 项 → **1 项**（仅剩"非 git 仓库"） |

### 已知限制

- **项目尚未成为 git 仓库**，因此无法提交 / 推送 / 打标签 / 被 `git clone`。
  README 里的 `git clone <repo>` 示例在初始化仓库前无法执行。
  这是当前唯一的开源阻塞项。

## [1.3.1] — 2026-09-20

**稳定性专项**：一次针对「失败被上报为成功」与「畸形输入打崩引擎」的系统性
普查。缺陷不是靠读代码找出来的 —— 先用两个新写的审计器把问题**逼出来**，
再逐个修、逐个补回归。子命令与用例数不变（26 / 81），自检用例 **74 → 81**。

### 为什么做这一轮

前一轮（1.3.0）结束时 74 个用例全绿、`_lint` 与 `_undefined` 也都是 0 处。
但"全绿"只说明**已写的检查**没发现问题，不说明没有问题 —— 语法级与文本级
的检查器看不见语义级缺陷。于是补了两个维度：

- **`_dev/_deepaudit.py`（静态）**：AST 层面扫 7 类语义缺陷 ——
  可选值下标、无保护除法、无保护类型转换、负下标/越界切片、自递归无深度
  参数、循环内无界增长、`makedirs` 与写文件同处一个 `try`、函数同时返回
  `None` 与空集合。**只报告不修改**——自动修会掩盖判断，也会把作者的意图
  一起改掉。
- **`_dev/_adversarial.py`（动态）**：8 组对抗输入 —— 深嵌套规则、
  零分母路径、极端路径名、极端地址、两万条 `jmp` 长链、case 目录 7 种
  破坏方式、超长/纯符号/emoji 意图、畸形 JSON。断言的不是"有输出"，
  而是**要么受控拒绝、要么如实上报失败**。

结果是 7 个真缺陷，全部是 74 个用例漏掉的：

### 修复

**一、两层守卫叠加导致外层变死代码（两处）**

同一个错误被内外两层各守一次，内层先 `except Exception: return {}` 吞掉，
外层那段"记录错误"的处理于是**永远走不到**。

- `lib_semantics.string_vma_map` —— 内层 `return {}`，而 `re.py:594` 的
  `res["_string_map_error"] = ...` 成了死代码。表现为"字符串交叉引用少了
  一半"，看着像"没找到"，实际是引擎坏了。
- `lib_libscan.scan_const_tables` —— 内层 `return hits` 返回**部分结果**，
  AES / CRC32 签名静默丢失，`lib_rules.py:726` 的 `errs_out.append("const-sigs: ...")`
  同样成了死代码。

两处都改成向上抛（`scan_const_tables` 抛 `RuntimeError` 并在消息里写明
"已扫到 N 条、结果不完整"），让外层的错误处理重新活过来。

**二、不支持的架构静默兜底到 x86 解码器**

`lib_disasm.backend()` 对 MIPS / PPC / RISC-V 返回 x86-64 后端，产出
**语法合法、语义完全错误**的指令，且 `ok=True`。新增 `UnsupportedArch`
异常，两个调用点都改成 `ok: false` + `unsupported_arch: true`。
判断依据：一个说得通但完全错误的结论，比一个明确的报错危险一百倍。

**三、case 目录只防了"读不到"，没防"形状不对"（两处崩溃）**

`manifest.json` / `index.json` / `journal.jsonl` 是**外部可变状态**，
原代码只处理了"文件缺失 / 解析出 None"：

- `index.json` 写成 `{"artifacts": "x"}` → 字符串是真值，`or {}` 不生效，
  `case_load` 里 `art.get('sha256')` 直接 `AttributeError`。
- `artifacts` 的某个条目写成 `123` → `case_status` 里 `e.get(...)` 崩。

新增 `_case_index()` 统一归一化形状（顶层非 dict、`artifacts` 非 dict、
条目非 dict 一律降级并记录告警），接到 `case_save` / `case_status` /
`case_load` 三个调用点。`case_status` 在索引损坏时返回 `ok: false` +
`reason`，不再"不吭声地给个不完整结果"。顺带修掉一个 `flow` 相关缺陷：
失效条目同时出现在 `have` 和 `stale` 里，导致 `flow` 会跳过本该重跑的步骤。

**四、两处无界资源消耗**

- **`case_journal` 把整个追加文件读进内存再切片**。改成
  `collections.deque(maxlen=...)` 流式读取，精确统计 `total`，
  新增 `truncated` 字段 —— 原来调用者无法区分"这就是全部"和"被截了"。
- **YAML 解析无体积与深度上限**。深缩进规则文件能把调用栈打爆；
  更隐蔽的是**解析耗时正比于字节数**（缩进是空白也要逐字符扫）——
  实测一个 95 MB 的纯缩进文件在 `_strip_comment` 里空转近 10 秒才轮到
  结构校验。两手都加：
  - `_YAML_MAX_BYTES = 32 MB` 预检（正常规则文件是几十 KB 量级，
    三个数量级的余量）；
  - `_strip_comment` 增加"无引号且无 `#` 直接返回"的快速路径
    （用 C 实现的 `in` 判断，不等价于逐字符 Python 循环）；
  - `parse_block` 加 `_YAML_MAX_DEPTH = 200`。
    95 MB 输入现在 **0.000s** 拒绝，1000 层深嵌套 **0.022s** 拒绝
    （原 9.85s）。

**五、规则特征树深度守卫（原本只有步数上限）**

`match_rules` 只有 `max_calls` 步数上限，但**递归深度与循环步数是两个
正交的轴** —— `not: not: not: ...` 能在极少步数内把栈打爆。
发现 `Rule._validate` 已有 `depth > 32` 的构建期检查（这是实际生效的那层），
于是补上 `_MAX_EVAL_DEPTH = 200` 的运行期兜底并让内部递归统一走计数入口。
两层都保留：未来任何新入口（如某个 loader 直接塞特征树）都可能绕过 `Rule`。

**六、工具目录结构不变量（启动期校验）**

`CATALOG` 是手写字面量，下游有几十处 `e["field"]` 直接取键。少写一个字段
**不会在 import 时报错**，只会在某个特定意图被检索到的那一刻抛 `KeyError`
—— "平时看着好好的，用户一句话就崩"。新增 `_validate_catalog()` 在
import 时校验必填字段、字段类型、元素类型、`cost`/`stage` 枚举、重名，
以及 `flags` 的两种合法形状。

写这个守卫的第一版就把 6 个条目的 `flags` 写法差异照出来了：6 条用
`[["--min", "6"]]`（选项 + 示例值），15 条用 `["--json"]`。核实后确认
两种都是刻意的（`build_command` 分别渲染成 `--min 6` 和 `--json`），
于是把它**写进文档并纳入校验**，而不是"统一"掉 —— 那 6 条的示例值正是
为了让命令模板能直接跑。

### 新增自检（74 → 81）

每条都对应上面一次修复，注释里写明**原来的错法**：否则后来者看到一个
"多余"的断言，很容易在重构时顺手删掉，缺陷就悄悄回来了。

- `稳定性：YAML 资源上限` —— 体积与深度都必须抛 `YamlError`，
  且断言"不是 `RecursionError`"（靠解释器兜底说明没拦住）；
  含 10 项注释剥离快速路径与慢路径的逐字节等价。
- `稳定性：工具目录结构不变量` —— 12 种畸形目录必须拦截，
  且**真实目录不能误伤**（守卫过严会让技能直接 import 失败）。
- `稳定性：不吞异常（string_vma_map）` —— 必须抛，不能静默返回 `{}`。
- `稳定性：不支持架构明确报错` —— 5 种架构明确报错，x86-64/arm64 未误伤。
- `稳定性：case 索引形状容错` —— 7 种畸形 `index.json` 受控，
  且损坏时 `status` 必须如实报 `ok: false`。
- `稳定性：journal 有界读取` —— 5000 行文件验证 `limit` / `total` /
  `truncated` 三者语义。
- `稳定性：规则特征树深度守卫` —— 构建期边界（15 层通过 / 30 层拦截，
  实测口径：每级 `not` 吃 2 层 depth）+ 子进程验证运行期兜底
  确实拦住了绕过 `Rule` 的深树。

### 验证

| 关卡 | 结果 |
|---|---|
| `selftest.py` | **81/81 通过**（原 74，新增 7） |
| `_dev/_lint.py` | 合计 0 处 |
| `_dev/_undefined.py` | 0 处问题 |
| `py_compile` 全量 | OK |
| `_dev/_adversarial.py` | 失败 0 项 |
| `_dev/_deepaudit.py` | 只报告；剩余命中已逐条复核为可接受 |

顺带清理了 15 个一次性脚手架脚本（`_patch_*.py` / `_v_*.py` /
`_reg_*.py` 等）。

## [1.3.0] — 2026-09-19

新增**工具编排层**：把"选工具 / 排顺序 / 记状态 / 判失败"从模型脑子里
搬进确定性代码。子命令 **21 → 26**，自检 **64 → 74** 个用例。

### 为什么做这一层

AWS Well-Architected `AGENTPERF06-BP01` 给出的经验是：LLM 的候选工具集
一旦超过 **10–15 个**，工具选择质量就会明显下降（~50 个工具时准确率
84–95%，~200 个时掉到 41–83%，~740 个时接近 0）。本工具包当时有 21 个
分析子命令，正好落在"开始变差"的区间。

但比"挑错工具"更贵的浪费是**重试语义搞错**：把"跑完了但结果本来就是空的"
当成失败反复重试（参数怎么换结果都是空的），同时又把真正因为上限截断
而少拿数据的情况放过。这类判断必须由契约写死，不能靠模型猜。

调查结论：**凡是"看几个字段就能决定"的事，都不该让模型决定。**

### 新增

- **`lib_agent.py`（约 2200 行）：编排层核心**
  - **`require`** —— 按自然语言意图检索工具。21 条目录条目，每条带
    `summary / answers / keywords / args / flags / needs / produces /
    cost / stage / formats`。打分顺序：整句命中（+4.0，噪声最少的强信号）
    → 命令名命中（+5.0）→ `answers` 命中（+3.0×权重）→ `keywords`
    （+2.0×权重）→ 摘要（+1.0）→ 阶段匹配（+1.5）→ 格式匹配（±）
    → 成本惩罚（`heavy` −0.5）。
    - **中文 n-gram 切分**：`str.isalnum()` 对汉字返回 `True`，
      整句会被当成一个词元，永远匹配不上 2 字关键词。改为生成 2/3/4 字
      n-gram，并把匹配改成**双向子串**。
    - **泛词降权**：`_GENERIC_TOKENS`（"函数/文件/代码/里面/在哪"…）
      权重降到 0.35。对标 capa 的教训——在函数粒度上用公用助记符做合取
      等于没有约束。
    - **失败即闭合**：空意图 / 完全没命中时返回空候选 + 可读原因 + hint，
      **不兜底返回全表**（那是 fail-open，等于把问题原样退回给模型）。
  - **`flow`** —— 19 步 DAG（`batch` + `deps` + `why` + `yields`）。
    同批次无依赖、可并发。有 `--case` 时读 `case status` 自动跳过已完成步骤。
  - **`case`** —— 目标级落盘目录（`manifest.json` + `index.json` +
    `journal.jsonl` + `artifacts/`）。原子写（tmp + `os.replace`）；
    每条记录带 `target_fingerprint`（size + mtime）与 `payload_sha1`；
    **过期默认拒绝返回数据**，要旧数据须显式 `--allow-stale`。
    目录名来自 AI，经 `_safe_artifact_name` 去路径分隔符（防穿越）。
  - **`result`** —— 字段白名单摘要（不是随机截断）+ 6 类错误归类。
    `kind / handling / retryable / next_action` 四件套直接告诉 AI 该怎么做。
  - **`toolgraph`** —— 手写先验转移表（如 `triage→symbols 0.80`）
    + 从 case 流水统计的在线学习。`weights_source` 明确区分
    `"prior"` 与 `"prior+learned"`，不把手写意图伪装成实测数据。
    遵循 AutoTool（arXiv:2511.14650）的自我修正——全局图是错的，
    所以**只统计同一目标内相邻命令**的共现。

- **`references/ai-calling-protocol.md`** —— 完整调用协议：
  五步标准流程、意图速查表、9 条硬性纪律、以及每条设计选择背后的依据。

### 修复

编排层的测试用例在编写过程中**抓出 4 个真实缺陷**（这正是加用例的意义）：

- **`result` 把失败上报为成功**（最严重）。顶层 `ok` 被写死为 `True`，
  即使它转述的上游结果是 `ok:false`。管道用法
  （`re.py triage x --json | re.py result --stdin`）下上游一崩，
  调用方看到 `ok` 就继续走，实际上手上什么都没有。现在 `ok` 跟随被转述
  结果的成败；而退出码仍表示"`result` 自己干得怎么样"，两者分离，
  脚本才能区分"`result` 挂了"和"上游挂了"。
- **`case_status` 把过期条目同时列进 `have` 和 `stale`**。`flow` 正是拿
  `have` 决定"哪些步骤可跳过"，于是它会跳过一条数据已失效的命令，
  AI 拿旧结论继续往下走且无任何报错。现在过期条目从 `have` 中摘出。
- **`case_load` 拒绝过期时不给机器可读标志**。只返回 `stale_reason`
  自然语言字符串，AI 无法一眼分清"被过期拦下"和"压根没存过"。
  现在补 `stale: true`。
- **`_write_json` 可能删掉无关的残留文件**。`os.makedirs` 在 `try` 内，
  它一失败就走到清理分支无条件 `os.remove(tmp)`，删的是**上一轮**留下的
  `.tmp`。现在只清理本次调用真正创建的文件。

同一轮静态体检还发现并修掉 3 处静默吞异常（本项目最忌讳的缺陷类），
新增 `_note_swallowed` 登记机制，吞掉的异常会出现在
`classify_error` 返回的 `swallowed` 字段里——**"没报错"与"没出问题"
必须能区分开**。

### 变更

- `re.py` 子命令 21 → 26，新增 `require / flow / case / result / toolgraph`。
- 工具目录 `CATALOG` 精修（检索准确率 top-1 **84%**、top-3 **100%**，
  19 条中文口语意图实测）：
  - `capability` 接管行为类问题（"这程序是干什么的"、"有没有加密算法"、
    "有没有反调试"）——它才是回答"能干什么"的命令；
  - `triage` 收窄为"从哪开始/体检/摸底"；
  - `entropy` 补齐口语说法（"熵高不高"、"文件被加了什么壳"）；
  - `obfstr` **移除**裸词 `加密/解密/c2`——它会抢走能力类问题；
  - `semantics` 的 `反调试` 收窄为 `反调试在哪`（**定位**归语义，
    **判定**归 capability）。

## [1.2.0] — 2026-09-19

新增**符号恢复层**与**混淆串恢复层**，并把"顶尖逆向工程师怎么干活"的调研
沉淀为可执行的路线图。

到此，一条完整的"省事 → 省力 → 硬啃"链路成型：
`identify/triage（有什么）→ symbols（叫什么）→ obfstr（藏了什么）→
semantics（每个函数干嘛）→ capability（具备哪些能力）`。

调研产出见 [`references/top-tier-tools.md`](references/top-tier-tools.md)：
按「省事层 / 省力层 / 硬啃层」拆解顶级逆向工程师的真实工作流，
逐个拆解 IDA / Ghidra / Binary Ninja / radare2 的看家本领与算法，
并把每一项按 **✅已有 / 🟢可自研 / 🟡可做子集 / 🔴不做** 四档定级 ——
这份表就是后续功能开发的排期依据。

### 新增

- **`lib_names.py`：符号恢复的统一入口**
  - 接通 `lib_symbols.demangle`。**此前它是一段 3000 余行、四方言全支持
    却没有任何生产代码调用的死代码**——能力一直存在，只是外面看不见。
  - 四方言 demangle：Itanium（GCC/Clang）、MSVC、Rust v0、Rust legacy。
  - **Go `pclntab` 符号恢复**：识别 4 种 magic（Go 1.20+ `0xFFFFFFF1`、
    1.18–1.19 `0xFFFFFFF0`、1.16–1.17 `0xFFFFFFFA`、≤1.15 `0xFFFFFFFB`），
    解析 1.20+ 头部，从 functab 还原函数名（含 `main.main` 这类
    名字表偏移为 0 的函数）。
  - 聚合 PE 导出表 / 导入表 / ELF 符号表 / Mach-O 符号表，
    每条符号带 `raw / demangled / dialect / changed / source`。
- **CLI `symbols` 子命令**（第 20 个）：默认只显示 demangle 后**发生变化**
  的符号（这才是增量信息），`--all` 看全量，`--no-demangle` / `--no-go`
  可关掉对应阶段。
- **`lib_obfstr.py`：FLOSS 风格静态混淆串恢复**
  - **栈字符串**：识别 `mov byte/word/dword/qword [rsp+disp], imm` 序列并
    按偏移重排还原；覆盖逐字节、宽字节（`dword` 立即数一次 4 字符）、
    `rbp` 基址三种形态。
  - **XOR 解密循环定位**：不猜密钥，而是**先找后向跳转定出循环体**，
    再在循环体内找「带立即数的 `xor`」+「同时有内存读和内存写」的
    结构性证据，用循环自己的密钥去解循环自己引用的数据。
- **CLI `obfstr` 子命令**（第 21 个）：`--no-stack` / `--no-xor` 可单跑一路
  （**互斥校验，同时开会报 usage 错误**）。

### 修复

- **Go `pclntab` 在非 Go 目标上疯狂误报** —— 在 `notepad.exe` 上扫到 3 个
  候选（`faffffff` / `fbffffff`，其实只是 x86 指令字节），
  还会打出"发现 Go 表但解析失败"这种误导性告警。
  改为**头部自洽性校验**：`minLC ∈ {1,2,4}`、`ptrSize ∈ {4,8}`、
  `4 ≤ nfunc ≤ 3_000_000`、`funcnameOff != 0`、`pclnOff != 0`、
  `funcnameOff < pclnOff`、`pclnOff ≤ 64MB`，任一不满足即否决；
  版本不支持的候选**只报一条**提示，不再刷屏。
- **`pclntab` 解析漏掉第一个函数名** —— functab 首项的名字表偏移可以是 `0`，
  而原实现写的是 `if entry == 0 or foff == 0: continue`，于是
  **`main.main` 永远找不回来**（真实 Go 二进制里它偏偏就在偏移 0）。
  现在只跳过 `entry == 0`，`foff` 改为做可读性检查。
  *这个 bug 是靠合成 fixture 断言 6/6 才暴露的——手工看输出看不出少了一个。*
- **`dword` 立即数被当成 2 字节** —— 尺寸表按 `"qword"/"dword"/"word"/"byte"`
  顺序遍历时，`"word" in "dword"` 恒真，`dword` 走到了 `word` 分支，
  还原出 `C:\x00\x00Wi...` 这种断裂串。
  改为显式 **最长优先** 的有序键表，不再依赖字典序。
- **XOR 解出错误密钥** —— 真串用密钥 `0x41`，用 `0x43` 却解出
  `jvvr8--ocnucpg` 也"看着挺像英文"。根因是判据只数 "100% 可打印"，
  而多个密钥都能满足。
  改为**字符频率似然表**（`etaoinshrdlu` 权重 1.00、数字 0.85、
  结构符 `.:/\\_-?` 0.90 等）取最高分，并要求分数 ≥ 0.72。
- **XOR 在真实 PE 上打出 20–29 条垃圾**（`s.HLN:os>HLN`、`tttttttttttt`、
  `A7kifv-iiTkh`）。依次试了三层修法：
  1. 字母数字占比 ≥ 0.75 —— **不够**，垃圾串的占比同样高；
  2. 禁止 ≥6 个相同字符连续 —— **不够**，只挡住 `ttttttt` 这类；
  3. 要求含强特征令牌（`://`、`.exe`、`SOFTWARE`、`Mozilla` 等）——
     **差点走错**：一开始留了"≥5 个连续字母"作弱兜底，结果 28 条垃圾里
     放过了 25 条。
  结论是**阈值法这条路根本不通**，最终改为**结构性消除**：
  定位解密循环、用循环自己的密钥解它自己引用的数据。
  效果：notepad.exe（43,946 条指令）与 kernel32（60,000 条指令）上
  **误报为 0**，同时注入的合成循环（key=`0x4A`）被正确命中。
  这三层失败的完整链条已写进代码注释，免得后人再走一遍。
- **循环检测首版恒返回 0** —— 算法从 `xor` 出发试图反推循环边界，很脆。
  倒过来：**先遍历所有后向跳转**（跳转本身就定义了循环），再检查循环体。

### 变更

- `VERSION` 由 `1.1.2` 升至 `1.2.0`；子命令 19 → 21 个。
- selftest 用例数 58 → 64。新增 6 个：
  `符号：四方言 demangle`、`符号：Go pclntab 合成解析`、
  `符号：CLI symbols 契约`、`混淆串：栈字符串恢复`、
  `混淆串：XOR 解密循环`、`混淆串：CLI obfstr 契约`。
  `CLI 鲁棒性：畸形目标不崩` 的扫描面同步纳入两个新子命令。
- `SKILL.md`：补 `symbols` / `obfstr` 的意图映射与专节说明
  （含 XOR 循环那一段的实测数字）。

### 测试记录（供后续对照）

- 全量自检 **64/64 通过，0 跳过，0 失败，142.48s**。
- Go pclntab 因本机**没有任何 Go 二进制**（扫遍 704 个 exe 确认）而
  无法实机验证，改用**合成 pclntab fixture** 对齐：
  合成表恢复 6/6 函数名、版本判定正确、非 Go 目标 0 误报。
  —— 宁可对着合成数据断言，也不发一段没被跑过的代码。

## [1.1.0] — 2026-09-19

新增**能力识别层**：把静态结构（导入表/字符串/指令）折算成"这样本能做什么"，
并映射到 ATT&CK。至此分析链路补齐为
`triage（有什么）→ semantics（每个函数在干嘛）→ capability（具备哪些能力）`。

### 新增

- **`lib_rules.py`：capa 风格能力规则引擎**（自研，零依赖）
  - **自带 YAML 子集解析器**（不能引 PyYAML，零依赖是硬约束）：
    支持标量/列表/映射/多文档，正确处理 `::` 与 `://` 不作为键分隔符、
    相对缩进、引号内 `#`；对锚点 `&`/`*`、块标量 `|`/`>`、流式集合 `{`/`[`
    等未支持的语法**一律报错**，绝不静默降级。
  - 规则模型与校验：`meta`（name/namespace/scope/authors/description/att_ck）
    + `features` 逻辑树（`and`/`or`/`not`/`optional`/`match`），
    未知特征类型、空节点、超深树、重名规则均在加载期报出。
  - 特征提取：文件级（section/import/export/string/os/arch/format/characteristic）
    与函数级（api/number/string/mnemonic/characteristic/tag/loop/nzxor）。
  - 匹配引擎：函数作用域能看见文件级特征、`match:` 规则依赖（带成环检测）、
    步数上限防失控。
  - **`ENGINE_CHARACTERISTICS` 白名单**：规则引用了引擎不可能产出的
    characteristic 会**在加载期直接失败**——这类拼写错误否则会让规则
    永远不命中且不报错。
- **`rules/`：能力规则库（4 类 20 条，19 条带 ATT&CK 映射）**
  - `process.yml`：创建进程、创建远程线程（注入）、进程镂空、创建服务
  - `crypto.yml`：使用 AES、使用 RC4、密钥/配置解密例程、哈希计算、Base64
  - `network.yml`：HTTP 连接、原始套接字、DNS 查询、下载并执行、读取主机信息
  - `anti-analysis.yml`：反调试、反虚拟机、反沙箱、加壳、时间规避、反射式加载
- **CLI `capability` 子命令**（第 19 个）：输出按 namespace 分组的能力清单，
  每条命中带**地址证据**与 ATT&CK 映射，可回退 `disasm`/`cfg` 复核。
  支持 `--rule` 只跑指定规则（名字不存在则报错并列出可用规则，不静默少跑）。
- **新增 8 个自检用例**（`--only 能力规则`）：规则库加载、YAML 子集解析器、
  API 名归一化、特征字段形态、实机端到端匹配、CRT 误报守卫、
  CLI 契约、无死 characteristic。
- `lib_libscan` 新增 **RC4 KSA 初始化序列**常量签名（`rc4_ksa`）。

### 修复（规则引擎从「0 命中」与「全命中」两个极端拉回可用）

以下每个 bug 都会造成**静默失效**（不报错、只是结果错），是本次修复的重点：

- **API 名归一化不认 `!` 分隔符** —— `_norm_api` 只按 `.` 切分，而语义层
  `iat_map` 产出的是 `kernel32!Sleep`，导致特征侧存成 `|kernel32!sleep`、
  规则侧给 `kernel32|sleep`，两边永远对不上。**这是"20 条规则全部 0 命中"
  的直接原因。** 同时修正了先替换 `!` 再去扩展名会让 `KERNEL32.dll!Func`
  切出 `kernel32.dll` 的顺序错误。
- **语义层输出字段名读错** —— 读 `s["apis"]`，实际字段是 `api_calls`，
  于是所有 api 特征为空。
- **指令助记符字段名读错** —— 读 `ins.mnemonic`，实际是 `ins.mnem`，
  于是 `mnemonic` 特征恒为空集。
- **立即数读取形态错误** —— 按 `operands` 列表读，实际 `imm`/`disp` 是
  指令自身的标量字段，于是 `number` 特征恒为空集。
- **文件级字符串特征恒空** —— `identify()` 不填 `strings_sample`，
  改为拿不到时显式补一次字符串扫描（失败留痕，不静默）。
- **arch 推断依赖人读的 label 文案** —— 改为优先读 `ident.arch`/`bits`
  结构化字段，label 只作兜底。
- **`build_features` 指令遍历是 O(函数数²)** —— 每个函数线性扫全部函数找
  `_offs`；notepad 看不出问题，静态链接的大二进制会直接卡死。改为先建
  VMA→`_offs` 索引。
- **多文档 YAML 静默丢规则** —— `---` 分隔的 4 条规则只留下最后 1 条。
  加 `split_documents()` + 多文档解析，并在文件产不出规则时报警。
- **消除三处误报（规则从"全命中"拉回准）**：`反调试检测` 曾命中 notepad.exe
  的 CRT 样板（`__report_gsfailure` / `_CrtDbgReport`）、`使用 RC4` 曾命中 3 个
  普通函数、`密钥或配置解密例程` 曾命中 **83/308 个函数**。根因统一是
  "函数粒度上用公用助记符做合取等于没有约束"。规则已按"能签名就签名、
  要组合就组合意图明确的行为、占比阈值配绝对下限"重写，
  并在 `SKILL.md` 记入「写能力规则时的铁律」。
- **规则引用了引擎不产出的 `characteristic`**（`loop` 实为
  `features.loop`、`nzxor` 从未产出、`rc4-ksa` 拼写不一致）——
  现已接通语义层字段，并加加载期校验堵住同类问题。

### 变更

- selftest 用例数 46 → 54。

## [1.1.2] — 2026-09-19

**稳定性与 bug 全量测试**（用户要求"测试每一个工具和项目的稳定性以及有没有 bug"）。
新增两个压测工具，跑了 **408 次 CLI 调用 + 约 2100 次库调用**。

### 新增

- **`scripts/_dev/_fuzz.py`：CLI 级稳定性压测**（408 次调用，0 缺陷）。
  19 个子命令 × 21 类恶意目标（空文件 / 全 FF / 全零 / MZ 无 PE 头 /
  `e_lfanew` 越界 / 节表全垃圾 / 节数谎报 0xFFFF / 随机 128K /
  超长单行 / NUL 串海 / 畸形 ELF·Mach-O·ZIP·DEX·WASM·SQLite·pyclass / 
  目录当目标 / 不存在的文件 / 缺参数）。四条判据：
  退出码必须 ∈ {0,2,3,4}、**不得漏 Python Traceback**、`--json` 必须有顶层
  `ok`、必须超时内返回、不得污染工作目录。**全部通过。**
- **`scripts/_dev/_fuzzlib.py`：库级 fuzz**（约 2100 次调用）。
  绕过 CLI 的 `except` 兜底，直接轰解析器 —— 因为 CLI 兜底会把
  "预期内的目标非法"和"我们自己写崩了"压成同一个退出码，
  真 bug 常藏在"畸形输入 → 内部状态不一致 → 后续假设被打破"。
  自带**慢调用检测**（超 5s 记录，慢 ≠ 崩溃但要从可用性角度评估）。

### 修复

- **`match_rules` 对非法参数抛无信息量的 `TypeError`** —— 它是公开 API，
  规则加载失败时调用方很容易把 `None` 传下来，原实现在
  `_Ctx.__init__` 里 `{r.name: r for r in rules}` 直接抛
  `TypeError: 'NoneType' object is not iterable`，看不出是"规则没加载到"
  还是"引擎坏了"；且会被上层 `except` 吞掉，最终表现为"0 条命中"。
  现在显式校验并返回可读 `reason`，同时保留 `hits` 字段（调用方不会 KeyError）。
- **`capability` 在规则集为空时静默报 0 命中** —— 现在把
  `match_rules` 的 `reason` 提升为 `warnings`，
  避免用户把"规则没生效"误读成"样本没有这些能力"。

### 新增自检（56 → 58）

- `能力规则：match_rules 参数校验` —— 5 种非法参数（None/str/int/dict/空表）
  都必须给出可读原因且保留 `hits`。
- `CLI 鲁棒性：畸形目标不崩` —— 39 组（子命令 × 畸形目标）组合，
  断言退出码受控且无 Traceback。**已反向验证能抓到回归。**

### 测试记录（供后续对照）

- **规模增长是线性的**，无算法级爆炸：`analyze_file` 在
  4K/16K/64K/256K/1M 上分别 0.04s/0.10s/0.33s/2.70s/7.32s。
- **CLI 层已有内部工作量上限**，所以库层"1MB 要 7.6s"并不会传导到用户：
  4MB 二进制上 disasm 0.5s / funcs 3.0s / capability 2.6s /
  semantics 0.6s / report 1.1s / triage 1.2s，全部 < 3s。
- `--budget-seconds` **只存在于 triage / strings**；其余子命令靠
  `--max-insns` / `--limit` 控制。
- 复跑方式：`python _dev/_fuzz.py`（CLI 级）、`python _dev/_fuzzlib.py`（库级）。
  两者都以退出码 0 表示"无缺陷"。



**全量代码体检**（用户要求"确保代码都没有问题"）。这一轮的重点不是加功能，
而是把「检查能力本身不可靠」的问题找出来并堵住 —— 体检器谎报覆盖比不检查更危险。

### 新增

- **`scripts/_dev/_undefined.py`：手写 AST 未定义名检查器**（约 250 行）。
  `py_compile` 只查语法、`import` 只跑模块顶层，**两者都发现不了函数体里写错
  一个变量名**——而这正是本项目历史上真实出过的 bug 类型（`errs_out` 未声明、
  `n = 0` 被误删），只有跑到那条分支才 `NameError`。零依赖约束下装不了
  pyflakes，因此自行实现：先收集作用域内**全部**绑定再判定（`x = 1` 写在
  `print(x)` 之后是合法的，边遍历边判会误报），覆盖函数参数
  （`posonlyargs`/`args`/`kwonlyargs`/`vararg`/`kwarg`）、推导式、
  `global`/`nonlocal`、以及 `__file__` 等解释器注入名。
- **`_lint.py` 护栏 11：测试残留物** —— 生产目录出现 `*.re-report.md` 等
  运行产物即报错（排除白名单）。
- **2 个新自检用例**（54 → 56）：
  - `--help 覆盖全部子命令`：从 `re.py` 解析真实注册项，与 `--help` epilog
    逐条比对。**已反向验证**：临时删掉 epilog 里 `capability` 一行，
    用例立刻 FAIL 并点名该子命令；还原后 PASS。
  - `report 默认输出不污染 cwd`：在独立工作目录里跑 `report`（不带 `--out`），
    断言该目录保持干净、报告落到目标文件旁边。

### 修复

- **`_lint.py` 谎报检查覆盖范围（文档与实现不一致）** —— docstring 第 5 条
  「未定义名字」**从未实现**，`grep` 证实代码里根本没有对应逻辑，
  体检器一直以"0 处"冒充已检查。现已接入 `_undefined.py`，
  并在 docstring 中标注【已修 bug】。
- **`report` 默认把报告写进当前工作目录** —— 原为 `os.getcwd()`。
  看着合理，实则是个地雷：`selftest` 统一用 `cwd=scripts/` 跑 CLI，
  于是**每次自检都在源码目录里生成 `sample_pe64.exe.re-report.md`**，
  测试残留被当成交付物发布出去（真实发生过，本轮清理掉后才定位到根因）。
  现改为写到**目标文件同级目录**：位置可预知，且不污染工作目录。
- **`selftest.py` 的 `report` 探针未指定 `--out`** —— 即上一条的实际触发者。
  已改为显式输出到临时目录。
- **`--help` 漏列 2 个子命令** —— `re.py` 模块 docstring 即 epilog，
  清单是手写的、与 `add_parser()` 无强制关联，此前停在 `sim`（18 条），
  漏掉 `semantics` 与 `capability`。子命令能用但帮助里看不到，
  等于这两个能力对使用者不存在。已补全并加不变量测试守住。
- **脚手架里的 3 处未定义名（新检查器首战即抓到的真实缺陷）** ——
  `_msvc_old.py` / `_msvc_new.py` 是 MSVC demangle 引擎的开发脚手架，
  从 `lib_symbols.py` 切出来时把两个常量留在了原文件：
  - `_Fail`（异常类）：两文件共 22 处 `raise _Fail`，**但从未定义**。
    真跑到那些分支时抛的是 `NameError`，而调用方清一色
    `except Exception` 会把它一并吞掉 —— 表现为"这条符号解析不出来"，
    实为代码跑不起来。
  - `_MAX_DEPTH`：`guard()` 的递归防护引用了它，同样未定义，
    于是**深度防护形同虚设**（一触发就 NameError 而非正常中断）。
  两者均已在各自文件中定义（`_MAX_DEPTH = 200`，与 `lib_symbols.py` 同值）。

### 变更

- 10 处 `except ... : pass/continue` 全部逐个审阅：9 处本就带 `# lint:ok`
  理由，另 2 处（AXML 字符串池单条坏串）补上理由注释。
  **结论：无静默失败**——每一处都是"单条坏数据跳过、不影响其余"或
  "必须抛出才算通过"的反向断言，属于刻意且有记录的行为。
- 版本 1.1.0 → 1.1.1；selftest 用例数 54 → 56；`_lint.py` 合计 0 处。
- 删除混入 `scripts/` 的测试残留 `sample_pe64.exe.re-report.md`。

## [1.0.0] — 2026-09-19

首个可开源版本。零第三方依赖的逆向工程工具箱 + Agent Skill。

### 新增

- **CLI（18 个子命令）**：`doctor` / `identify` / `strings` / `entropy` /
  `imports` / `info` / `triage` / `carve` / `diff` / `plan` / `report` /
  `magic` / `disasm` / `funcs` / `cfg` / `xref` / `sim` / `semantics`。
  统一 `--json` 契约，统一退出码（0 成功 / 2 用法 / 3 目标不可读 / 4 分析出错）。
- **多格式解析**：PE（含 Rich 头、节熵、覆盖层、加壳启发式）、ELF
  （checksec）、Mach-O、APK（DEX / ABI / 加固特征 / AXML 字符串池）、
  JAR、DEX、pyc（版本校验）、WASM、SQLite、Java class、固件容器。
- **反汇编**：自研 x86 / x86-64（含 VEX / EVEX / 段前缀）、ARM64、Thumb
  解码器，支持 RIP 相对寻址与内存操作数还原。
- **代码分析**：函数识别与指纹、控制流图 CFG、交叉引用 XREF、函数级
  二进制差分（`sim`）、函数语义摘要（调了哪些 API / 什么行为）。
- **符号还原**：MSVC（含 C++/CX `^` 帽扩展）、Itanium、Rust 三代名字修饰
  的解码引擎；MSVC 部分为自研实现，非 LLVM 移植。
- **常量与签名识别**：库函数指纹、密码学常量（AES S-box 等）、
  编译器特征串。
- **分析流水线**：`plan` 按格式产出分析计划，`report` 生成 Markdown 报告，
  含合规提醒。
- **自检体系**：46 个用例（`selftest.py`），覆盖合成样本、真实系统文件、
  指令向量、模糊测试、性能基线、契约一致性、零依赖约束。

### 修复（相对开发期版本）

- **`_cstr` 长度上限双重陷阱**：读长度与解析上限是两个独立参数，此前
  只传了前者，导致长导出名被截断成 256 字节。修正后语料最长符号
  256 → 1341，放弃解析数 265 → 0。
- **C++/CX 帽 `$AC` / `$AD` 无法解析**：根因是 `_is_member_ptr()` 只硬编码
  了 `$AA` / `$AB`，改为查完整的 `_HAT_CV` 表。
- **嵌套模板 `> > >` 空格错位**：`_Out._flush_pend` 在待补 `>` 多于一个时
  偏移算错，改为写前快照 `base = len(self.s)`。
- **APK 清单解压失败被静默吞掉**：解压失败后继续拿**压缩数据**解析，产出
  垃圾结果却报 `parse_ok`，属于「失败被上报为成功」。现改为立即返回
  `_error` 并在报告中显式告警。
- **`ins_at()` 把解码崩溃伪装成「该地址无指令」**：改为记录异常并提供
  `ins_at_errors()`，让调用方能区分两种情况。
- **`funcs` 指令预算用尽时输出误导性的 `function_count: 0`**：预算被
  argparse 前缀缩写意外压低后，结果看似「确实没有函数」。现新增
  `partial` 与 `truncated_note` 字段显式标注为片段结果。
- **`doctor` / `magic` 的 JSON 缺 `ok` 字段**：与其他 16 个子命令契约不一致。
  已补齐，并新增 `t_json_ok_contract` 用例防止再次漂移。
- **`_quirk.canon` 里的归一化掩盖真 bug**：`re.sub(r">\s*>", ">>", s)` 把
  真实的空格问题压平了。删除后得分不变，反证引擎本身正确。
  （勘误：`canon()` 及整个 `_quirk.py` 的代码部分此后已删除 —— 它从无调用方。
  该文件现为纯参考文档，只保留 dbghelp 缺陷清单。）
- **`selftest` 的依赖检查误报标准库**：`import os, sys, json` 解析出
  `mod='os,'`（带逗号）导致查表失败。改为逗号拆分 + `as` / 相对导入处理。
- **`Reader.__init__` 半构造对象泄漏句柄**：`open()` 失败时会留下已构造
  的对象。改为包装成带原因的 `OSError`。

### 已知限制

- 反汇编为线性扫描，不跟随间接跳转；数据内嵌代码段可能被误判为指令。
  用 `--section` 与 `funcs` 的覆盖率指标交叉判断。
- 与 `dbghelp!UnDecorateSymbolName` 的输出存在**刻意的**差异——dbghelp
  自身有至少 6 个已证实的缺陷，本项目不做「向缺陷对齐」。清单见
  `scripts/_quirk.py`。
- 加壳判定为启发式，命中不等于确诊，需要动态验证。
- 尚缺：capa 风格的能力规则引擎、Go `pclntab` 符号恢复、栈字符串与
  加密字符串解码、FLIRT 签名匹配、`symbols` 子命令。
