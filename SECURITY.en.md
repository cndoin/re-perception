# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security-relevant defect.**

Send a private report to the maintainers, including:

- A description of the issue and its impact.
- A minimal reproduction: the exact command, the target file (or a synthetic
  equivalent that triggers the same path), and the observed output.
- Your Python version and the output of `python re.py --version`.

You can expect an acknowledgement, an assessment of severity, and a coordinated
disclosure timeline. Credit will be given in the changelog unless you prefer
otherwise.

## What counts as a security issue here

This is an offline, read-only analysis tool. It does not execute the target, does
not write to it, and does not open network connections on its own. The traditional
remote-code-execution surface is therefore small. But this project treats a
specific class of defect as **equivalent in severity to RCE**:

**A failure reported as a success.**

Concretely, any of the following is a security issue:

- A malformed or hostile input that causes the tool to report `ok: true` while
  having produced no meaningful result.
- A truncated or budget-limited scan that is presented as a completed one, so a
  user concludes "the sample is clean" when in fact it was never fully examined.
- A value that was never computed being printed as a plausible-looking number
  (as opposed to `null` with an explanation).
- A warning that the code claims to emit but does not, leaving the user to read a
  silent degradation as a clean result.
- A gate or check that cannot fail — one that reports success after running zero
  cases.

The reason for this severity is the domain. A reverse engineer uses this output
to decide whether a binary is safe to run, what a malicious sample does, and
whether an evasive technique is present. A confidently wrong answer is worse than
a missing one, because it stops the investigation.

## What is explicitly out of scope

- **The analyzer does not sandbox the target.** Analyzing malware is inherently
  risky. This tool performs static, read-only analysis precisely so that you do
  not have to execute anything, but you are responsible for handling the sample
  safely and for working in an isolated environment.
- **Upstream tool invocations.** When a subcommand shells out to Ghidra, jadx,
  Frida or similar, defects in those tools are theirs to fix. If this project
  invokes them unsafely — for example by building a shell command from a
  filename without quoting — that *is* in scope, and please report it.
- **Authorization.** Whether you are permitted to analyze a given target is your
  responsibility. See [USE-POLICY.md](USE-POLICY.md) and `references/legal.md`.

## Hard constraints that back these claims

Two properties are enforced by the test suite, so a regression fails CI rather
than shipping quietly:

- **Zero third-party dependencies.** `t_no_third_party` rejects any import
  outside the Python standard library, which keeps the supply chain empty.
- **The `ok` field contract.** A dedicated test asserts that every subcommand
  emitting `--json` output also emits a truthful top-level `ok`.

## Supported versions

Fixes land on the current release line. The version reported by
`python re.py --version` is the version you should cite in a report.
