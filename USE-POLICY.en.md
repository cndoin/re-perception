# Use Policy (not a license)

> **This file is not a license, and it neither modifies nor limits any right
> granted by [LICENSE](LICENSE).**
>
> `LICENSE` is standard MIT. It grants you the full right to use, modify,
> distribute, sublicense and sell this software, with no restriction on the
> purpose of use. This file is the maintainers' good-faith advisory and
> compliance guidance to **users**, and is documentation rather than contractual
> terms. If all you need is the legal terms, read `LICENSE` and stop there.

## Why this page exists

What this tool does is **reverse engineering**. The capability itself is neutral,
but how you apply it may be constrained by law. The MIT license does not — and
should not — decide whether your purpose is lawful. That judgement is yours to
make. This page collects the relevant reminders in one place, kept separate from
the license:

**The license governs "the authorization of the code". This document addresses
"what you do with it". The two must not be conflated.**

## Reminders

1. **Analyze only targets you are entitled to analyze.** Work on software and
   systems you own, or for which you hold written authorization from the rights
   holder. Reverse-engineering third-party software may violate its license
   agreement and may be unlawful where you are.

2. **Comply with local law.** This includes, without limitation, the
   Cybersecurity Law, the Data Security Law, the Personal Information Protection
   Law and the Copyright Law of the People's Republic of China, as well as the
   EU Digital Services Act and the US DMCA where applicable. Circumventing
   technical protection measures (DRM) is restricted in most jurisdictions. See
   `references/legal.md` for detail.

3. **Do not use this for malicious purposes** — including developing malware,
   evading security controls, violating others' privacy or intellectual property,
   or conducting network attacks.

4. **Handling of samples.** Malware must be analyzed in an isolated environment.
   Decompiled output, recovered source code, and extracted keys or credentials
   must not be redistributed.

5. **Vulnerability disclosure.** If you find a security vulnerability, use a
   proper channel (a vendor SRC, CNCERT/CNNVD, or the affected party's security
   team) and do not publish details until the vendor has shipped a fix. This
   project's own disclosure process is in [SECURITY.md](SECURITY.md).

## On the "no keygen, no patching" design constraint

This toolbox **performs read-only analysis only**: it does not modify target
files, does not generate keygens or crack patches, and provides no
anti-detection capability. This is a deliberate design choice — the line between
analysis capability and cracking capability is drawn here, and the omission is
the point. See [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

*If your legal team needs an explicit field-of-use restriction, please do not
cite this file as its basis — the MIT license contains no field-of-use
restriction and this project does not claim to add one. A scenario requiring
stricter terms should choose a different license rather than bolting one onto
this MIT.*
