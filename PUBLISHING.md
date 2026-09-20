# 开源发布指南 · Publishing to GitHub

> 这份文档是给**维护者**看的操作手册，不是给使用者看的。
> 目标是：把这个项目干净、合规、有吸引力地发布到 GitHub。
> 每一步都写清了「做什么」和「为什么」。

---

## 0. 当前状态自检

发布前先确认这几件事都成立：

```bash
cd scripts

python re.py --version          # 应输出 1.3.8
python selftest.py              # 97/97 全绿
python _dev/_lint.py            # 生产 0 处告警
python _dev/_undefined.py       # 0 处问题
python _dev/_e2e.py             # 36/36
python _dev/_ossaudit.py        # 0 项
```

`_dev/_ossaudit.py` 是项目自带的**开源合规自审**，会交叉核对文档里的数字
（用例数、子命令数）与实际是否一致 —— 它报 0 项，才说明文档没有漂移。

---

## 1. 发布前必须决定的事（维护者决策项）

### 1.1 Git 作者邮箱会公开

提交作者**当前是一个真实的 QQ 邮箱**（维护者的私人地址，此处不复制出来，
请自己用 `git log --format='%an <%ae>'` 查看）。

**一旦推送到公共仓库，这个邮箱会永久出现在提交历史里**，是垃圾邮件与
社工的常见来源。发布前建议二选一：

```bash
# 查看当前作者
git log --format='%an <%ae>' | sort -u

# 方案 A：改用 GitHub 的 noreply 邮箱（推荐）
git config user.name "going-ahead"
git config user.email "<你的GitHub用户ID>+going-ahead@users.noreply.github.com"

# 方案 B：保持现状
```

已有提交若要改写作者，需要在推送**之前**做（推送后再改会污染他人克隆）：

```bash
# 只改写全部提交的作者信息（谨慎，会重写历史）
git filter-branch --env-filter '
export GIT_AUTHOR_EMAIL="356803749+going-ahead@users.noreply.github.com"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
' --tag-name-filter cat -- --all
```

> 若仓库还没推送过，最省事的做法是：先配好 `user.email`，再用
> `git commit --amend --reset-author`（仅对最后一次提交）或重建仓库。

### 1.2 LICENSE 的版权署名

`LICENSE` 当前是：

```
MIT License

Copyright (c) 2026 寇豆码 and contributors
```

请确认这个署名是你想要的公开身份。若要用真名/公司名，现在改最方便。

> 之前讨论过的「增加使用限制条款」被推迟了。**本项目的建议是保持标准 MIT**：
> 任何使用限制都应通过 `USE-POLICY.md`（明确声明「非许可证」）表达。
> 在 MIT 上打补丁会造成许可证语义混乱 —— `USE-POLICY.md` 里已经写明了
> 这个立场，法务需要严格条款时应换许可证而不是改 MIT。

### 1.3 仓库名与可见性

建议：**`reverse-engineering-skill`** 或 **`re-skill`**（简洁、可检索）。
不建议用 `reverse-engineering` 单词名 —— GitHub 上同名仓库多，且不利于
「这是一个 AI 技能」的定位。

---

## 2. 仓库元数据（决定别人能不能搜到你）

推到 GitHub 后，在仓库 **Settings** 页填写：

**Description**（一句话，会显示在搜索结果里）：

```
Agent Skill: give any AI agent a real reverse engineer's workflow for any unknown
file — PE/ELF/Mach-O/APK/DEX/pyc/WASM/firmware. Zero third-party deps, pure stdlib.
```

**Topics**（最多 20 个，选高检索量的）：

```
reverse-engineering  agent-skills  skill  claude-code  codex  malware-analysis
disassembler  pe  elf  macho  apk  dex  firmware  security  static-analysis
binary-analysis  python  no-dependencies  infosec  tooling
```

**其他设置：**

- ✅ **Website** —— 留空或指向 README（不要放失效链接）
- ✅ 勾选 **Releases**、**Packages**（发布时用）
- ❌ 不要勾 **Wiki**（文档已在仓库内，双份必漂移）
- ✅ **Issues** 开启，并按 `.github/ISSUE_TEMPLATE/` 的模板走

---

## 3. 推送流程

```bash
cd <项目目录>

# 1) 确认工作区干净
git status

# 2) 配好作者身份（见 1.1）
git config user.name  "going-ahead"
git config user.email "你的邮箱"

# 3) 关联远程（用你自己的仓库地址）
git remote add origin https://github.com/<你的账号>/<仓库名>.git

# 4) 首推
git branch -M main          # 可选：把 master 改名为 main
git push -u origin main
```

> ⚠️ 推送前**再确认一次** `git log --format='%an <%ae>'` 里没有不想公开的邮箱。

---

## 4. 首发 Release（强烈建议做）

有 Release 的项目显得「可交付」，而且给使用者一个明确的版本锚点。

```bash
git tag -a v1.3.8 -m "1.3.8 — 逐工具体检，再挖 7 处静默缺陷"
git push origin v1.3.8
```

然后在 GitHub 上 **Draft a new release**：

- **Tag**：`v1.3.8`
- **Title**：`1.3.8 — 逐工具体检，再挖 7 处静默缺陷`
- **Describe**：把 `CHANGELOG.md` 里 `[1.3.8]` 整段粘过去

> 本项目的 CHANGELOG 是按 Keep a Changelog 格式写的，直接可当 Release Notes。
> 这是它写那么详细的原因之一。

---

## 5. CI 会在推送后自动跑

`.github/workflows/ci.yml` 已配好，推送即触发：

| Job | 平台 | 作用 |
|---|---|---|
| `selftest` | ubuntu / windows / macos × py3.10 / py3.13 | 全量自检 + lint + 未定义名 |
| `e2e` | **windows-latest** | 26 个子命令跑真实系统二进制 |
| `no-third-party` | ubuntu | 独立一道门，防止混进 pip 包 |

**首次推送后务必去 Actions 页看结果。** 本地绿不等于 CI 绿 —— 本项目的
`_e2e.py` 依赖 Windows 的 `System32` 样本，这也是它被固定在
`windows-latest` 上的原因（改回 Linux 会永久变红，CI 文件里已写明）。

---

## 6. 发布后建议做的三件事

1. **开一个 `good first issue`** —— 标注哪些地方欢迎新手贡献（比如新增
   `rules/*.yml` 规则、补充 `references/` 的论文索引）。有好入门任务的项目
   更容易收到第一批外部 PR。

2. **在 README 顶部放实拍输出** —— 一段真实的 `triage` 输出比任何形容词都
   有说服力。**注意不要放任何真实恶意样本的信息**，用系统文件
   （notepad.exe / ntdll.dll）做演示。

3. **明确回答「凭什么信这个工具」** —— 本项目已有的两个数字最有说服力，
   建议放在 README 显眼处：

   - MSVC demangle 在 **61,248 条真实系统 DLL 导出符号**上实测 99.89% 一致；
   - **97 个自检用例 + 36 项端到端**，且每个回归用例都做了「撤回修复必须
     变红」的反向验证。

---

## 7. 双语文档一览（本次新增）

| 文件 | 语言 | 说明 |
|---|---|---|
| `README.md` | 中文 | 主 README |
| `README.en.md` | English | 英文主 README |
| `INSTALL.md` / `INSTALL.en.md` | 中 / 英 | 装到各 AI 运行时 + 目录对照表 |
| `CONTRIBUTING.md` / `CONTRIBUTING.en.md` | 中 / 英 | 贡献指南（含两条硬约束与修 bug 流程） |
| `SECURITY.md` / `SECURITY.en.md` | 中 / 英 | 漏洞披露（含「失败被上报为成功」的定级说明） |
| `USE-POLICY.md` / `USE-POLICY.en.md` | 中 / 英 | 使用政策（明确非许可证） |
| `CODE_OF_CONDUCT.md` / `CODE_OF_CONDUCT.en.md` | 中 / 英 | 行为准则 |
| `CHANGELOG.md` | 中 | 更新日志（Release Notes 直接复用） |

`SKILL.md` 保持中文 —— 它是给 AI 读的技能定义，而 AI 无语言障碍；
英文翻译反而会给技能增加维护负担且容易与主文件漂移。

---

## 8. 发布检查清单

- [ ] `python re.py --version` 输出与 `CHANGELOG.md` 最新条目一致
- [ ] 五道门禁全绿（见第 0 节）
- [ ] `_dev/_ossaudit.py` 报 0 项（文档无漂移）
- [ ] 提交作者邮箱已确认可公开（见 1.1）
- [ ] `LICENSE` 版权署名已确认（见 1.2）
- [ ] 仓库 description 与 topics 已填（见第 2 节）
- [ ] 已打 tag 并写 Release Notes（见第 4 节）
- [ ] 推送后 Actions 三平台全绿（见第 5 节）
- [ ] 工作区无未提交改动、无临时文件（`git status` 干净）

---

## 9. 常见坑

| 坑 | 后果 | 规避 |
|---|---|---|
| 提交里带真实恶意样本 | 仓库被封、法律风险 | `.gitignore` 已排除常见样本扩展名；提交前 `git status` 逐项确认 |
| 文档数字与实际不符 | 使用者发现后失去信任 | `_ossaudit.py` 会拦；改数字后跑一次 |
| 在 MIT 上叠加使用限制 | 许可证语义混乱 | 限制写进 `USE-POLICY.md`，不改 `LICENSE` |
| 推送后才想改作者邮箱 | 需要重写历史，影响他人克隆 | 推送**前**决定（见 1.1） |
| 把 `_dev/` 脚手架当发布物 | 使用者困惑、体积虚增 | 安装器已自动裁剪；发布压缩包也用安装器的复制逻辑 |
