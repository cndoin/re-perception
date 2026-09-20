# Reverse Engineering Toolbox — an Agent Skill

Give any AI agent the workflow of a **real reverse engineer** for **any** unknown
file: identify → fingerprint → static → dynamic → targeted breakthrough →
model & verify → document.

- **Zero third-party dependencies** — pure Python standard library, works the
  moment you unpack it. No `pip install`, no build, no virtualenv.
- **Targets every major platform** — Windows PE / Linux ELF / macOS–iOS Mach-O /
  Android APK / iOS IPA / .NET / Java / Python pyc / Web·WASM·Electron /
  firmware / private formats / SQLite.
- **Bounded memory, speed first** — streaming scans; string extraction on a
  100 MB file takes roughly one second.
- **Read-only analysis** — never writes to the target, never patches it, never
  generates registration codes.
- **Ships with its own test harness** — 97 self-test cases + 36 end-to-end
  integration checks; all must pass before a commit is allowed.

> ⚠️ **Authorized use only.** Only reverse-engineer targets you own or have
> written authorization to analyze. See [USE-POLICY.md](USE-POLICY.md) for the
> authorization policy and [LICENSE](LICENSE) (MIT) for the legal terms.

**中文文档：** [README.md](README.md) ・ [INSTALL.md](INSTALL.md) ・
[CONTRIBUTING.md](CONTRIBUTING.md) ・ [SECURITY.md](SECURITY.md) ・
[USE-POLICY.md](USE-POLICY.md) ・ [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ・
[PUBLISHING.md](PUBLISHING.md)

---

## Table of contents

- [Install into your AI runtime](#install-into-your-ai-runtime)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Concepts worth knowing](#concepts-worth-knowing)
- [Self-testing and gates](#self-testing-and-gates)
- [Symbol recovery (MSVC / Itanium / Rust)](#symbol-recovery-msvc--itanium--rust)
- [Repository layout](#repository-layout)
- [Compliance](#compliance)
- [Contributing](#contributing)

---

## Install into your AI runtime

This skill follows the **Agent Skills open standard** — a single `SKILL.md` with
YAML frontmatter. The same file drops into **Claude Code / Codex CLI / Hermes /
OpenClaw / Cursor / Gemini CLI** without modification. Only the *skills
directory* differs between runtimes:

```bash
cd scripts
python _dev/_install.py --auto --verify      # detect which runtimes exist locally
python _dev/_install.py --auto               # install into all detected runtimes
```

| Runtime | Personal scope | Project scope |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex CLI | `$CODEX_HOME/skills/` (default `~/.codex/skills/`) | `.codex/skills/` |
| Hermes | `~/.hermes/skills/` | — |
| OpenClaw | `~/.openclaw/skills/` | `.openclaw/skills/` |
| Cursor | — (project scope only) | `.cursor/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `.gemini/skills/` |

On Windows, `~` means `%USERPROFILE%`. Full instructions, manual installation and
a troubleshooting table live in **[INSTALL.md](INSTALL.md)**.

> After installing, **start a new session**. Most runtimes scan skills at session
> startup, so a skill installed mid-session will not load until the next one.

---

## Quick start

```bash
# Python 3.10+ is the only requirement. Nothing to install.
cd reverse-engineering/scripts     # the scripts/ directory at the repository root

python re.py doctor --json                  # which external tools are available here
python re.py triage some-unknown-file --json   # first thing to run on an unknown target
python re.py plan some-unknown-file --json     # what to do next
python re.py report some-unknown-file --out report.md   # Markdown report
```

> Just `cd scripts` and run — no installation, no build step, no virtualenv.
> If you got the project via `git clone`, enter `scripts/` after cloning.

When an **agent** calls this tool, always pass `--json`. Exit codes `0 / 2 / 3 / 4`
mean success / usage error / target unreadable / analysis error. Under `--json`
every subcommand emits a top-level `ok` field, and a self-test case guards that
contract.

**A note on exit code `1`.** It is *never* a legal outcome of this CLI — it means
an uncaught exception escaped. That is a bug, not a result. The same philosophy
runs through the whole codebase: a failure must never be reported as a success.

---

## Commands

There are **26 subcommands** in two layers: **21 analysis commands** (the table
below, schedulable by the orchestration layer) and **5 orchestration/state
commands** (`require` `flow` `case` `result` `toolgraph`, used by an agent for
routing and caching).

| Command | Purpose |
|---|---|
| `doctor` | Probe the local toolchain (83 external tools) |
| `identify` | Format identification + structural parsing (PE/ELF/Mach-O/DEX/ZIP/pyc/WASM/SQLite/class/firmware headers) |
| `strings` | Streaming string extraction (filter by category/regex, UTF-16 aware) |
| `entropy` | Overall entropy + block entropy curve (locate encrypted/compressed regions) |
| `imports` | Import table / dependent libraries (the behaviour map) |
| `info` | Deep structural parsing |
| `triage` | **One-shot first pass** (identify + entropy + strings + IOCs + packer detection) |
| `carve` | Carve embedded files by magic number (firmware / overlay analysis) |
| `diff` | Byte-level diff of two files (version comparison / reversing private formats) |
| `plan` | Generate a step-by-step analysis plan, trimmed to the local toolchain |
| `report` | Produce a Markdown analysis report |
| `magic` | Magic-number lookup |
| `disasm` | Disassembly (x86 / x86-64 / ARM64 / Thumb) |
| `funcs` | Function identification + fingerprints + XREF |
| `cfg` | Control-flow graph for a single function |
| `xref` | Cross references (who calls whom) |
| `sim` | Function-level similarity diff between two binaries |
| `semantics` | Per-function semantic summary (which APIs it calls, what it does) |
| `capability` | Capability detection (capa-style rule library → behaviour + ATT&CK mapping) |
| `symbols` | Symbol recovery (C++/MSVC/Rust demangle + Go pclntab) |
| `obfstr` | Obfuscated string recovery (stack strings + XOR decryption loops) |
| `require` | Look up which subcommands fit an intent (the agent's routing entry point) |
| `flow` | Staged workflow: what to run now (parallelizable batches shown together) |
| `case` | Analysis state directory: persist results, reuse them, detect staleness |
| `result` | Result summary + error classification (prevents useless retries) |
| `toolgraph` | Tool transition graph: what to run after this one |

---

## Concepts worth knowing

Three design decisions shape everything above.

**1. Never report a failure as a success.** This is the single most important rule
in the project, and defects in this class are treated as vulnerabilities. A
malformed PE that fails to parse must not come back as `ok: true` with zero
imports; a truncated scan must not look like a completed one; a stat that was
never computed must not be printed as `0`. Where a value genuinely cannot be
computed, the field is reported as `null` **with an explanation** — never as a
plausible-looking wrong number.

**2. A gate that never blocks is not a gate.** Every check tool is judged by its
exit code, not by its prose. A self-test that silently runs zero cases is a
failure, not a pass. The tool-matrix harness in `scripts/_dev/_matrix.py` carries
an explicit guard for this: if it manages to run zero groups, it fails loudly
instead of reporting "no problems".

**3. Verify by evidence, not by assertion.** Every claim about behaviour in this
repository is expected to be backed by an actual file path and line number, or by
a runnable check. Recommendations are not accepted because they sound right.

---

## Self-testing and gates

```bash
python selftest.py                     # full self-test (97 cases, ~155 s)
python selftest.py --only 性能          # run one category only
python _dev/_lint.py                   # static audit (syntax / swallowed exceptions / hardcoded paths)
python _dev/_e2e.py                    # end-to-end: all 26 subcommands against real PE files
python _dev/_ossaudit.py               # open-source compliance self-audit
```

Coverage runs along three axes: **correctness** (synthetic samples plus real
system files), **robustness** (empty files, truncation, bit-flip mutation, garbage
input) and **performance** (100 MB streaming scan). Two further hard constraints
are enforced: **zero third-party dependencies** and the **`ok` field contract**
for `--json`.

### Exit-code contracts for the gates

| Command | Exit code | Meaning |
|---|---|---|
| `selftest.py` | `0` all green / `1` failures present / `2` `--only` matched nothing | Silently running zero cases is an error, not a pass |
| `_dev/_lint.py` | `0` zero findings in production files / `1` findings present | Warnings in `_dev/` scaffolding are listed separately and do not affect the exit code |
| `_dev/_undefined.py` | `0` clean / `1` problems | A zero-dependency pyflakes |
| `_dev/_ossaudit.py` | `0` no high-severity items / `1` high-severity items present | Open-source compliance self-audit |

### Running all gates at once

Where `make` exists (Linux / macOS / WSL):

```bash
make check     # lint + undefined names + full self-test (required before every commit)
make all       # check + end-to-end + compliance audit (required before a release)
make help      # list every target
```

Native Windows environments usually lack `make`; just run the corresponding
`python xxx.py` commands above. The `Makefile` contains no logic — only command
aliases.

---

## Symbol recovery (MSVC / Itanium / Rust)

`lib_symbols.py` implements three demanglers with no external dependencies:

| Dialect | Prefix | Coverage |
|---|---|---|
| Itanium C++ ABI | `_Z` | GCC/Clang: nested names, templates, substitution tables, member CV/ref qualifiers, operators, thunks, typeinfo/vtable/guard/TLS |
| MSVC | `?` | Windows C++ / drivers / COM: full LLVM grammar, back-references, thunks, RTTI, C++/CX hat pointers |
| Rust legacy / v0 | `_ZN…17h` / `_R` | legacy hash stripping; v0 punycode idents, generics, lifetimes, const generics |

The MSVC path is aligned character-for-character against
`dbghelp!UnDecorateSymbolName` and measured on **61,248 real exported symbols
from system DLLs**:

```
valid samples            61205
  exact character match  51337  (83.88%)
  including dbghelp quirks 61138  (99.89%)
  still mismatched          67  (0.11%)
  gave up                    0  (0.00%)
  correct rate (w/ quirks)      99.89%
  end-to-end coverage           99.82%  (of all input)
```

"dbghelp quirks" are defects in dbghelp itself, each confirmed with a minimal
reproducing case (no space before CV, duplicated trailing `__ptr64` on
variables, dropped `const` on pointer return values, and so on). The complete
list with minimal cases lives in `scripts/_quirk.py` (reference documentation;
no code imports it). **All 67 mismatches are attributable to dbghelp defects
rather than grammar gaps in this engine** — this project deliberately does not
"align to a defect", and the reasoning is recorded in that file's module
docstring.

> C++/CX hat pointers (`^`), the `$AA`–`$AD` extensions, do not exist in LLVM at
> all. They were reverse-engineered for this project as a 2-bit CV ladder. See
> `references/research.md`.

---

## Repository layout

```
reverse-engineering/
├── SKILL.md                     # skill entry point (this is what the AI reads; Chinese)
├── INSTALL.md / INSTALL.en.md   # installation into each AI runtime (zh / en)
├── README.md                    # Chinese README (primary)
├── README.en.md                 # English README (this file)
├── PUBLISHING.md / .en.md       # open-source publishing guide (maintainer manual, zh / en)
├── CONTRIBUTING.md / .en.md     # contribution guide (zh / en)
├── SECURITY.md / SECURITY.en.md # vulnerability disclosure (zh / en)
├── USE-POLICY.md / .en.md       # usage policy (zh / en; explicitly NOT a license)
├── CODE_OF_CONDUCT.md / .en.md  # code of conduct (zh / en)
├── LICENSE                      # MIT (standard text, no additional restrictions)
├── CHANGELOG.md                 # changelog
├── Makefile                     # command entry points (make test / lint / check)
├── .editorconfig                # editor configuration
├── .github/
│   ├── workflows/ci.yml         # CI: three platforms × multiple Python versions
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── references/
│   ├── workflow.md              # general methodology: five-layer model / hypothesis-driven / SOP / ABI / anti-debugging
│   ├── playbooks.md             # 13 target classes: pressure points, toolchains, pitfalls
│   ├── toolchain.md             # tool matrix, install sources, learning path
│   ├── ecosystem.md             # open-source ecosystem map: four-layer stack / project comparison / decision tree
│   ├── research.md              # paper index, organised by "where you're stuck"
│   ├── ai-calling-protocol.md   # how an AI picks tools: intent lookup / summary layer / orchestration
│   ├── top-tier-tools.md        # tools and habits of top reverse engineers, with an "AI reachability" column
│   └── legal.md                 # compliance red lines (CN / US / EU + self-check list)
├── rules/                       # capability rule library (capa-style, loaded by `capability`)
│   ├── anti-analysis.yml        # anti-debugging / anti-analysis
│   ├── crypto.yml               # AES and similar crypto constants and APIs
│   ├── network.yml              # HTTP / network communication
│   └── process.yml              # process creation / WMI / shell
├── assets/
│   ├── frida-templates.js       # Frida hook templates (native / Android / iOS / plaintext capture / unpacking)
│   └── notes-template.md        # analysis notes template
└── scripts/
    ├── re.py                    # CLI entry point (26 subcommands)
    ├── lib_formats.py           # magic-number library + per-format parsers
    ├── lib_analyze.py           # strings / entropy / IOCs / diffing / carving
    ├── lib_disasm.py            # disassembly dispatcher
    ├── lib_x86.py               # x86 / x86-64 decoder
    ├── lib_arm.py               # ARM64 / Thumb decoder
    ├── lib_code.py              # function identification / CFG / XREF
    ├── lib_semantics.py         # function semantic profiling
    ├── lib_libscan.py           # library-function and crypto-constant identification
    ├── lib_symbols.py           # MSVC / Itanium / Rust demangling engine
    ├── lib_names.py             # symbol recovery (Go pclntab / symbol table / exports)
    ├── lib_obfstr.py            # obfuscated string recovery (stack strings + XOR loops)
    ├── lib_rules.py             # capability rule engine (built-in YAML subset parser + matcher)
    ├── lib_agent.py             # orchestration: intent→command lookup / workflow / state / transition graph
    ├── lib_tools.py             # toolchain probing + analysis plans
    ├── _quirk.py                # known dbghelp defects (reference doc, not a runtime module)
    ├── selftest.py              # self-test suite (97 cases, incl. 5 installation cases)
    └── _dev/                    # development scaffolding (not shipped in releases)
        └── _install.py          # cross-runtime installer (--auto detect / --verify re-check)
```

---

## Compliance

Only reverse-engineer targets you own or have written authorization to analyze.
Analyze malware in an isolated environment. Decompiled output, recovered source
code and extracted keys must never be redistributed.

- Legal terms: [LICENSE](LICENSE) (standard MIT, no field-of-use restriction)
- Authorization and compliance policy: [USE-POLICY.md](USE-POLICY.md) (**not** a license)
- Compliance red lines (CN / US / EU + self-check list): `references/legal.md`
- Vulnerability disclosure: [SECURITY.md](SECURITY.md)

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Two constraints are non-negotiable:

1. **Zero third-party dependencies.** Python 3.10+, standard library only. The
   `t_no_third_party` test will reject a pull request that breaks this.
2. **Never disguise a failure as a success, and never disguise a skip or a
   truncation as a pass.** A new check must be able to go red; adding a guard
   requires showing that withdrawing the fix makes the test fail.

Every fix is expected to come with a regression case in `selftest.py`, and commit
messages must answer three questions: what changed, why the original code was
wrong, and what the blast radius is.
