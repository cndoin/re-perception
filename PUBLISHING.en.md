# Publishing to GitHub

> This document is an operations manual for **maintainers**, not for users.
> Its goal: publish this project to GitHub cleanly, compliantly and
> attractively. Every step states both *what to do* and *why*.

---

## 0. Pre-flight check

Confirm all of the following before publishing:

```bash
cd scripts

python re.py --version          # should print 1.3.8
python selftest.py              # 97/97 green
python _dev/_lint.py            # zero findings in production files
python _dev/_undefined.py       # zero problems
python _dev/_e2e.py             # 36/36
python _dev/_ossaudit.py        # zero items
```

`_dev/_ossaudit.py` is the project's own **open-source compliance audit**. It
cross-checks the numbers quoted in the documentation (test-case count, subcommand
count) against reality — only when it reports zero items can you be sure the docs
have not drifted.

---

## 1. Decisions to make before publishing

### 1.1 The Git author email becomes public

Commits are currently authored with **a real personal mailbox** (the maintainer's
own address; it is deliberately not reproduced here — inspect it with
`git log --format='%an <%ae>'`).

**Once pushed to a public repository, this address is permanently in the commit
history** and is a well-known source of spam and social engineering. Choose one:

```bash
# See the current author
git log --format='%an <%ae>' | sort -u

# Option A: switch to GitHub's noreply address (recommended)
git config user.name "going-ahead"
git config user.email "<your-github-user-id>+going-ahead@users.noreply.github.com"

# Option B: keep it as-is
```

Rewriting existing commits is only practical **before** the first push (doing it
afterwards disrupts everyone else's clones):

```bash
git filter-branch --env-filter '
export GIT_AUTHOR_EMAIL="356803749+going-ahead@users.noreply.github.com"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
' --tag-name-filter cat -- --all
```

> If the repository has never been pushed, the simplest path is: set
> `user.email` first, then use `git commit --amend --reset-author` for the last
> commit, or simply recreate the repository.

### 1.2 The copyright line in LICENSE

`LICENSE` currently reads:

```
MIT License

Copyright (c) 2026 寇豆码 and contributors
```

Confirm this is the public identity you want. If you would rather use a real name
or a company name, now is the cheapest moment to change it.

> A previously discussed "additional use restriction" was deferred. **This
> project's recommendation is to keep plain MIT.** Any use restriction belongs in
> `USE-POLICY.md`, which explicitly states it is *not* a license. Bolting terms
> onto MIT creates legal ambiguity — `USE-POLICY.md` already records this
> position: a scenario needing stricter terms should choose a different license
> rather than patch MIT.

### 1.3 Repository name and visibility

Suggested: **`reverse-engineering-skill`** or **`re-skill`** — short and
searchable. Avoid a bare `reverse-engineering`: many repositories share that
name, and it obscures the "this is an agent skill" positioning.

---

## 2. Repository metadata (determines whether people find you)

After pushing, fill in the **Settings** page:

**Description** (one line, shown in search results):

```
Agent Skill: give any AI agent a real reverse engineer's workflow for any unknown
file — PE/ELF/Mach-O/APK/DEX/pyc/WASM/firmware. Zero third-party deps, pure stdlib.
```

**Topics** (up to 20; prefer high-traffic ones):

```
reverse-engineering  agent-skills  skill  claude-code  codex  malware-analysis
disassembler  pe  elf  macho  apk  dex  firmware  security  static-analysis
binary-analysis  python  no-dependencies  infosec  tooling
```

**Other settings:**

- ✅ **Website** — leave empty or point at the README; do not link something dead
- ✅ Enable **Releases** and **Packages**
- ❌ Do **not** enable the **Wiki** (documentation lives in-repo; two copies
  will always drift)
- ✅ Keep **Issues** enabled, driven by the templates in `.github/ISSUE_TEMPLATE/`

---

## 3. Pushing

```bash
cd <project-dir>

# 1) Confirm the working tree is clean
git status

# 2) Set your identity (see 1.1)
git config user.name  "going-ahead"
git config user.email "your-address"

# 3) Add the remote (your own repository URL)
git remote add origin https://github.com/<account>/<repo>.git

# 4) First push
git branch -M main          # optional: rename master to main
git push -u origin main
```

> ⚠️ Immediately before pushing, check `git log --format='%an <%ae>'` once more
> for any address you do not want public.

---

## 4. Cut a release (strongly recommended)

A repository with releases reads as "deliverable", and it gives users a stable
anchor point.

```bash
git tag -a v1.3.8 -m "1.3.8 — per-tool verification, seven more silent defects found"
git push origin v1.3.8
```

Then on GitHub use **Draft a new release**:

- **Tag**: `v1.3.8`
- **Title**: `1.3.8 — per-tool verification, seven more silent defects found`
- **Describe**: paste the whole `[1.3.8]` block from `CHANGELOG.md`

> The changelog follows Keep a Changelog, so it doubles as release notes
> verbatim. That level of detail is one reason it is written the way it is.

---

## 5. CI runs automatically after the push

`.github/workflows/ci.yml` is already configured and triggers on push:

| Job | Platform | Purpose |
|---|---|---|
| `selftest` | ubuntu / windows / macos × py3.10 / py3.13 | Full self-test + lint + undefined names |
| `e2e` | **windows-latest** | All 26 subcommands against real system binaries |
| `no-third-party` | ubuntu | A separate gate so a pip package cannot sneak in |

**Check the Actions tab after the first push.** Green locally does not imply green
in CI — `_e2e.py` deliberately depends on Windows `System32` samples, which is
exactly why it is pinned to `windows-latest` (moving it back to Linux makes it
permanently red; the workflow file says so in a comment).

---

## 6. Three things worth doing after publishing

1. **Open a `good first issue`.** Mark the areas that welcome newcomers — adding
   a rule to `rules/*.yml`, or expanding the paper index in `references/`.
   Projects with an obvious on-ramp receive their first external pull request
   much sooner.

2. **Put real output near the top of the README.** One genuine `triage`
   transcript outperforms any number of adjectives. **Do not include information
   from real malware** — demonstrate with system files (notepad.exe / ntdll.dll).

3. **Answer "why should I trust this tool" head-on.** Two existing numbers are
   the strongest material; consider promoting them in the README:

   - MSVC demangling measured at 99.89% agreement across **61,248 real exported
     symbols from system DLLs**;
   - **97 self-test cases + 36 end-to-end checks**, where every regression case
     was reverse-validated (withdrawing the fix must make it fail).

---

## 7. Bilingual documentation inventory (added in this pass)

| File | Language | Purpose |
|---|---|---|
| `README.md` | 中文 | Main README |
| `README.en.md` | English | English main README |
| `INSTALL.md` / `INSTALL.en.md` | both | Installing into each AI runtime + directory table |
| `CONTRIBUTING.md` / `CONTRIBUTING.en.md` | both | Contribution guide (two hard constraints, bug-fix flow) |
| `SECURITY.md` / `SECURITY.en.md` | both | Disclosure policy, incl. the severity rule for silent failures |
| `USE-POLICY.md` / `USE-POLICY.en.md` | both | Use policy (explicitly not a license) |
| `CODE_OF_CONDUCT.md` / `CODE_OF_CONDUCT.en.md` | both | Code of conduct |
| `CHANGELOG.md` | 中文 | Changelog, reused verbatim as release notes |

`SKILL.md` deliberately stays in Chinese only. It is the skill definition the AI
reads, and an AI has no language barrier; an English mirror would add maintenance
burden and drift away from the primary file.

---

## 8. Release checklist

- [ ] `python re.py --version` matches the newest `CHANGELOG.md` entry
- [ ] All five gates green (section 0)
- [ ] `_dev/_ossaudit.py` reports zero items (no doc drift)
- [ ] Commit author email confirmed safe to publish (1.1)
- [ ] `LICENSE` copyright line confirmed (1.2)
- [ ] Repository description and topics filled in (section 2)
- [ ] Tag created and release notes written (section 4)
- [ ] Actions green on all three platforms after the push (section 5)
- [ ] Working tree clean, no stray files (`git status`)
- [ ] `OWNER/REPO` placeholders in `.github/ISSUE_TEMPLATE/config.yml` replaced
      with the real account/repo name — otherwise two contact links 404, and
      nobody notices until someone clicks them

---

## 9. Common pitfalls

| Pitfall | Consequence | Avoidance |
|---|---|---|
| Committing real malware samples | Repository takedown, legal exposure | `.gitignore` already excludes common sample extensions; confirm each file in `git status` |
| Documentation numbers out of sync | Users lose trust on discovery | `_ossaudit.py` catches it; re-run after changing any number |
| Layering a use restriction onto MIT | Ambiguous licensing | Put restrictions in `USE-POLICY.md`, leave `LICENSE` alone |
| Deciding to change the author email after pushing | Requires history rewriting, disrupting clones | Decide **before** pushing (1.1) |
| Shipping `_dev/` scaffolding | User confusion, inflated size | The installer trims it; use the installer's copy logic for release archives too |
