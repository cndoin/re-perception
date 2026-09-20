# Contributing

Thank you for considering a contribution. This project has unusually strict
standards in one specific direction, and reading this first will save us both a
round trip.

## Two hard constraints

**1. Zero third-party dependencies.** Python 3.10+, standard library only. The
`t_no_third_party` test enforces this and will reject a pull request that adds an
import outside the standard library. This is not nostalgia — it is what makes
"download the repository, run it immediately" true, on every platform, with no
packaging story to maintain.

**2. Never disguise a failure as a success.** Do not report a skip or a
truncation as a pass. Do not print a plausible-looking number for a value you did
not actually compute. Where something genuinely cannot be determined, say so
explicitly and, where a field is involved, let it be `null` with a note explaining
why. Defects in this class are treated as equivalent in severity to a remote code
execution flaw.

This second rule has a corollary that catches people out: **a guard that cannot
go red is not a guard.** When you add a check, demonstrate that removing the fix
makes it fail. A test that passes whether or not the code is correct is worse than
no test, because it manufactures false confidence.

## Setting up

Nothing to install:

```bash
git clone <repository-url>
cd reverse-engineering/scripts
python re.py --version
```

## Before you commit

```bash
cd scripts
python selftest.py             # full self-test (97 cases, ~155 s) — must be all green
python _dev/_lint.py           # static audit — must report zero production findings
python _dev/_undefined.py      # undefined-name check — must be clean
python _dev/_e2e.py            # end-to-end across all 26 subcommands
```

With `make` available:

```bash
make check     # lint + undefined names + full self-test
make all       # check + end-to-end + compliance audit
```

**Do not commit with a red gate.** If a gate fails, investigate; do not
re-run until it goes green, and do not disable the check.

## Fixing a bug

1. **Read the actual source lines.** The project's standing rule is that no claim
   about behaviour is accepted without a file path and line number. A report that
   "sounds right" is not evidence.
2. **Write the regression case first, in your head.** What exact input made the
   old code produce a wrong answer? Encode that input as a test in
   `selftest.py`'s `cases` list.
3. **Prove the test can fail.** Temporarily withdraw your fix and confirm the new
   test goes red. If it stays green, the test is not guarding anything.
4. **Fix the root cause, not the symptom.** If the immediate symptom appears in
   three places, find the one cause. The repository has repeatedly found that
   fixing a symptom in one place leaves two silent copies of the same defect.
5. **Keep the test suite honest.** If the fix changes a count (test cases, number
   of subcommands), update `README.md`, `README.en.md`, `SKILL.md`,
   `CONTRIBUTING.md`, `INSTALL.md`, `Makefile` and the PR template. The
   compliance audit (`_dev/_ossaudit.py`) cross-checks several of these and will
   flag drift.

## Commit messages

Commit messages must answer three questions. A message saying only "fix bug"
does not count as a message.

1. **What changed** — the concrete edit.
2. **Why the original code was wrong** — the actual defect, with file and line,
   and the consequence a user would have experienced.
3. **Blast radius** — which subcommands or API outputs change. Call out
   **breaking changes** explicitly (field renames, exit-code changes). New fields
   are not breaking, but say so.

Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes
(`fix:` / `feat:` / `perf:` / `docs:` / `test:` / `chore:`) for the subject line.
Write the body in whatever language you are most precise in; Chinese is common in
this repository.

Example:

```
fix(obfstr): XOR 加密串在 PE 上永远恢复不出来

改了什么
  新增 lib_obfstr.make_vma2off(ident)，按节表把虚拟地址换算成文件偏移。

为什么原来那样是错的
  xor_loops_to_strings 第 507 行把 lp["data_ref"] 直接喂给 Reader.read()。
  data_ref 来自指令的 mem_ref，是虚拟地址；而 Reader.read 是文件偏移语义。
  PE 的 image_base 通常是 0x140000000，远超文件长度，read() 越界返回空，
  于是一条 XOR 明文都出不来，函数却照样返回 warnings: []。

影响范围
  - obfstr 子命令：XOR 串恢复由 100% 失效变为可用。
  - 新增 vma 字段；offset 字段语义由"虚拟地址"更正为"文件偏移"。
```

## Pull requests

Use the template in `.github/PULL_REQUEST_TEMPLATE.md`. The self-check list in it
is not decorative; each item corresponds to a real failure this project has
shipped and had to fix.

Keep pull requests focused. One logical change per pull request is much easier to
review and far easier to revert in isolation.

## Adding a new module

Prefer extending an existing `lib_*.py` over adding a new file. The module
boundaries are deliberate:

- `lib_formats.py` — format detection and structural parsing
- `lib_analyze.py` — data-oriented analysis (strings, entropy, IOCs, diffing)
- `lib_disasm.py` / `lib_x86.py` / `lib_arm.py` — decode layers
- `lib_code.py` — function-level structure (functions, CFG, XREF)
- `lib_semantics.py` / `lib_libscan.py` — how code behaves, what it looks like
- `lib_symbols.py` / `lib_names.py` — names, from mangling and from symbol tables
- `lib_rules.py` — the rule engine
- `lib_agent.py` — orchestration and state

If a new file is genuinely justified, say why in the pull request.

## Adding rules

Rules live in `rules/*.yml` and use a YAML subset parsed by the engine itself
(`lib_rules.py`) — no PyYAML. When adding a rule:

- State the evidence basis in the rule, not just the conclusion.
- Include a `characteristic:` anchor tied to a specific constant or instruction
  shape where possible. Rules that fire on weak signals produce the false
  positives that make users distrust the whole rule library.

## Reporting issues

Please include:

- The exact command you ran (including flags).
- The target's format and, if it is safe to share, its size and a hash.
- The full output, including the exit code.
- `python re.py --version` and your Python version.

If the issue is a **silent wrong answer** — a plausible-looking incorrect value, a
missing warning, an `ok: true` that should have been `ok: false` — say so
explicitly. Those reports are the most valuable kind and get prioritized.

## Security

Do not open a public issue for a security-relevant defect. Follow
[SECURITY.md](SECURITY.md).
