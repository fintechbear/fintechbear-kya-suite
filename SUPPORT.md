# Support

Thanks for using FintechBear KYA ("Know Your Agent"), the open-source Rust SDK
for AI-agent delegated-authority verification. This document explains where to
get help and what is in scope.

FintechBear is the maintainer of this open-source project. It has no affiliation
with and no endorsement from Google, Visa, Mastercard, Skyfire, or any payment
network or standards body.

## Before you ask

Most questions are answered by the documentation:

- [README.md](README.md) - what the SDK does, what it does not do, install, and a
  working Quick Start.
- [docs/demo.md](docs/demo.md) - the recommended primary demo walkthrough with
  real captured output (`cargo run -p kya-examples --example demo`).
- [docs/quickstart.md](docs/quickstart.md) - a step-by-step quick start.
- [docs/api-usage.md](docs/api-usage.md) - the public facade surface, task by task.
- [docs/architecture.md](docs/architecture.md) - the five-stage model and crate layering.
- [docs/known-limitations.md](docs/known-limitations.md) - what the SDK cannot establish.
- [docs/supported-protocols.md](docs/supported-protocols.md) - supported capabilities and the AP2 status.
- [AGENTS.md](AGENTS.md) - the engineering constitution and its 22 rules.

## How to get help

- **Questions and usage help:** open a [GitHub Discussion](https://github.com/fintechbear/fintechbear-kya-suite/discussions)
  if discussions are enabled, or a non-security GitHub issue using the
  "Question / usage help" path in the issue chooser.
- **Bug reports:** open a GitHub issue using the **Bug report** template. Include
  the crate and version, your platform and Rust toolchain version, and a minimal
  reproduction.
- **Feature requests:** open a GitHub issue using the **Feature request**
  template. Describe the problem you are trying to solve, not only a proposed
  API.

## Security issues are different

Do **not** open a public issue, pull request, or discussion for a security
problem. Report suspected vulnerabilities privately per
[SECURITY.md](SECURITY.md) (preferred: a private GitHub security advisory).

## Scope of support

This is an early `v0.1.0` work in progress, not a release. It ships the
offline-evaluable stages (A identity, B real Ed25519 / JWS-EdDSA verification,
C static policy) plus the fail-closed trait seams for stages D and E. It does
**not** ship a concrete online authority or a concrete execution path, has not
been independently audited, carries no certification, and is not declared
production-safe. Support is best-effort and community-driven; the timelines in
[SECURITY.md](SECURITY.md) are good-faith targets, not contractual commitments.

## Contributing

If you would like to contribute a fix or an improvement, read
[CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) first. All
participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
