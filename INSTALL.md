# 安装到各 AI 运行时

本技能遵循 **Agent Skills 开放标准**（`SKILL.md` + YAML frontmatter），
所以同一份文件可以装进 Claude Code、Codex CLI、Hermes、OpenClaw、
Cursor、Gemini CLI 等运行时 —— **无需改动内容**。

各家唯一不同的是**技能目录**。目录找错，装完也不会被加载，
所以下面的路径全部来自各自官方文档，不是推测。

## 一句话装法（推荐）

仓库自带安装器，自动处理目录差异、幂等、备份与自验：

```bash
cd <SKILL>/scripts

# 1) 看看本机装了哪些运行时（只读探测，不启动任何东西）
python _dev/_install.py --auto --verify

# 2) 装到所有探测到的运行时（个人级）
python _dev/_install.py --auto

# 3) 或指定运行时
python _dev/_install.py --runtime claude-code --runtime codex --runtime hermes --runtime openclaw

# 4) 装到某个项目（团队共享，随仓库提交）
python _dev/_install.py --runtime claude-code --scope project --project-root /path/to/repo

# 5) 装完回验（真的回去检查 SKILL.md 可达、frontmatter 合规、入口脚本在）
python _dev/_install.py --runtime claude-code --verify
```

`--list` 可随时查看全部运行时的目录对照表。

> **装完必须重开一次新会话。** 多数运行时的技能在会话启动时扫描，
> 中途装进去的本轮不会加载。

## 目录对照表（官方约定）

| 运行时 | 个人级 | 项目级 | 说明 |
|---|---|---|---|
| **Claude Code** | `~/.claude/skills/` | `.claude/skills/` | Anthropic，SKILL.md 的发起者 |
| **Codex CLI** | `$CODEX_HOME/skills/`<br>（默认 `~/.codex/skills/`） | `.codex/skills/` | OpenAI；受 `CODEX_HOME` 影响 |
| | | `.agents/skills/` | Codex 的跨工具可移植约定 |
| **Hermes** | `~/.hermes/skills/` | —— | Nous Research，支持 `references/` `scripts/` `assets/` |
| **OpenClaw** | `~/.openclaw/skills/` | `.openclaw/skills/` | 注意是 `.openclaw` 不是 `.claude` |
| **Cursor** | —— | `.cursor/skills/` | 目前**仅项目级** |
| **Gemini CLI** | `~/.gemini/skills/` | `.gemini/skills/` | Google |
| **WorkBuddy** | `~/.workbuddy/skills/` | —— | 本技能自带的技能根 |

Windows 上把 `~` 换成 `%USERPROFILE%`，例如
`%USERPROFILE%\.claude\skills\reverse-engineering\SKILL.md`。

## 手工装法（不依赖安装器）

任何支持 SKILL.md 的运行时，手工安装都是同一件事：
**把整个技能目录放到它的技能目录下，且 `SKILL.md` 正好在目录根部**。

```bash
# 例：Claude Code
mkdir -p ~/.claude/skills
cp -r <SKILL> ~/.claude/skills/reverse-engineering

# 例：OpenClaw（注意目录名不同）
mkdir -p ~/.openclaw/skills
cp -r <SKILL> ~/.openclaw/skills/reverse-engineering

# 例：仓库级共享（Claude Code / OpenClaw / Codex 都支持各自的项目级目录）
cp -r <SKILL> /path/to/repo/.claude/skills/reverse-engineering
```

**用符号链接代替复制**（开发期改一处即生效）：

```bash
ln -s <SKILL> ~/.claude/skills/reverse-engineering
```

⚠️ **Windows 注意**：普通用户默认无建符号链接权限。实测发现
`os.symlink()` 在本机会「返回成功但造出一个不可解析的目录」——
所以安装器会**验证链接真的能读到 SKILL.md**，读不到就自动退回复制。
手工建链接后请务必确认 `~/.claude/skills/reverse-engineering/SKILL.md` 真的能打开。

## 常见错误

| 症状 | 原因 | 解法 |
|---|---|---|
| 装完不生效 | 没重开会话 | 开新会话 |
| 装完不生效 | 目录找错（用了 `.claude` 去装 OpenClaw） | 用上表核对 |
| 装完不生效 | 目录套了两层：`skills/reverse-engineering/reverse-engineering/SKILL.md` | 把内层内容提到外层 |
| 装完不生效 | 文件不叫 `SKILL.md`（大小写敏感，Linux/macOS 尤其） | 改名 |
| `FileNotFoundError: re.py` | 只拷了 `SKILL.md`，没拷 `scripts/` | 拷**整个目录**，脚本是技能的一部分 |

## 各运行时的能力差异

技能内容本身是通用的，但运行时对以下特性支持不一，本技能**不依赖**它们：

- `allowed-tools`（预授权工具）：实验性字段，本技能未使用
- Codex 的 `openai.yaml`：本技能未提供，Codex 会忽略
- Claude Code 的 `context: fork`（子代理隔离）：本技能未使用

因此本技能在任何一家上都是**同样的行为**：AI 读 `SKILL.md` 决定何时调用，
然后按文档调用 `scripts/re.py`。

## 前置条件

- **Python 3.10+**，仅标准库 —— **不需要 `pip install` 任何东西**
- 外部工具（Ghidra / jadx / Frida 等）可选，`re.py doctor` 会告诉你本机有哪些
- 装完自测：`python <技能目录>/scripts/selftest.py`（期望 **97/97** 全绿）
