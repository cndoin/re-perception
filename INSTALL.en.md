# Installing into AI Runtimes

This skill follows the **Agent Skills open standard** (`SKILL.md` plus YAML
frontmatter), so one and the same file installs into Claude Code, Codex CLI,
Hermes, OpenClaw, Cursor, Gemini CLI and others — **with no content changes**.

The only thing that differs between runtimes is the **skills directory**. Get the
directory wrong and the skill will not load, even though the install "succeeded",
so every path below comes from the respective project's official documentation
rather than from guesswork.

---

## The one-liner (recommended)

The repository ships an installer that handles directory differences,
idempotency, backups and self-verification:

```bash
cd <SKILL>/scripts

# 1) See which runtimes are present locally (read-only probe, starts nothing)
python _dev/_install.py --auto --verify

# 2) Install into every detected runtime (personal scope)
python _dev/_install.py --auto

# 3) Or name the runtimes explicitly
python _dev/_install.py --runtime claude-code --runtime codex --runtime hermes --runtime openclaw

# 4) Install into a specific project (shared with the team, committed to the repo)
python _dev/_install.py --runtime claude-code --scope project --project-root /path/to/repo

# 5) Verify afterwards (actually goes back and checks that SKILL.md is reachable,
#    the frontmatter is valid, and the entry script is present)
python _dev/_install.py --runtime claude-code --verify
```

`--list` prints the full runtime-to-directory table at any time.

> **Start a new session after installing.** Most runtimes scan skills at session
> startup, so a skill installed mid-session will not load until the next one.

---

## Directory reference (official conventions)

| Runtime | Personal scope | Project scope | Notes |
|---|---|---|---|
| **Claude Code** | `~/.claude/skills/` | `.claude/skills/` | Anthropic, the originator of SKILL.md |
| **Codex CLI** | `$CODEX_HOME/skills/`<br>(default `~/.codex/skills/`) | `.codex/skills/` | OpenAI; affected by `CODEX_HOME` |
| | | `.agents/skills/` | Codex's cross-tool portable convention |
| **Hermes** | `~/.hermes/skills/` | — | Nous Research; supports `references/` `scripts/` `assets/` |
| **OpenClaw** | `~/.openclaw/skills/` | `.openclaw/skills/` | Note: `.openclaw`, **not** `.claude` |
| **Cursor** | — | `.cursor/skills/` | Currently **project scope only** |
| **Gemini CLI** | `~/.gemini/skills/` | `.gemini/skills/` | Google |
| **WorkBuddy** | `~/.workbuddy/skills/` | — | The skill root this project was developed against |

On Windows, replace `~` with `%USERPROFILE%`, for example
`%USERPROFILE%\.claude\skills\reverse-engineering\SKILL.md`.

---

## Manual installation (without the installer)

For any runtime that supports SKILL.md, manual installation is the same thing:
**put the entire skill directory under that runtime's skills directory, with
`SKILL.md` sitting at the root of that directory.**

```bash
# Example: Claude Code
mkdir -p ~/.claude/skills
cp -r <SKILL> ~/.claude/skills/reverse-engineering

# Example: OpenClaw (note the different directory name)
mkdir -p ~/.openclaw/skills
cp -r <SKILL> ~/.openclaw/skills/reverse-engineering

# Example: repository-level sharing (Claude Code / OpenClaw / Codex all support
# their own project-scope directories)
cp -r <SKILL> /path/to/repo/.claude/skills/reverse-engineering
```

**Use a symlink instead of a copy** (so edits during development take effect
immediately):

```bash
ln -s <SKILL> ~/.claude/skills/reverse-engineering
```

⚠️ **Windows note.** Regular users have no symlink privilege by default.
In testing, `os.symlink()` on this platform "returned success while producing an
unresolvable directory" — which is why the installer **verifies that the link can
actually read `SKILL.md`** and falls back to copying if it cannot. If you create
a link by hand, always confirm that
`~/.claude/skills/reverse-engineering/SKILL.md` really opens.

---

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| Installed but never activates | Session not restarted | Start a new session |
| Installed but never activates | Wrong directory (used `.claude` for OpenClaw) | Check against the table above |
| Installed but never activates | Directory nested one level too deep: `skills/reverse-engineering/reverse-engineering/SKILL.md` | Move the inner contents up one level |
| Installed but never activates | File is not named `SKILL.md` (case-sensitive, especially on Linux/macOS) | Rename it |
| `FileNotFoundError: re.py` | Only `SKILL.md` was copied, not `scripts/` | Copy the **whole directory**; the scripts are part of the skill |

---

## Runtime capability differences

The skill content itself is portable, but runtimes differ in support for the
following features — and this skill **does not depend on any of them**:

- `allowed-tools` (pre-authorized tools): an experimental field, unused here
- Codex's `openai.yaml`: not provided; Codex will ignore its absence
- Claude Code's `context: fork` (sub-agent isolation): unused here

So behaviour is **identical** across runtimes: the AI reads `SKILL.md` to decide
when to invoke the skill, then calls `scripts/re.py` as documented.

---

## Prerequisites

- **Python 3.10+**, standard library only — **no `pip install` of any kind**
- External tools (Ghidra / jadx / Frida and friends) are optional; `re.py doctor`
  reports which ones your machine has
- Verify after installing:
  `python <skill-dir>/scripts/selftest.py` (expect **97/97** green)
