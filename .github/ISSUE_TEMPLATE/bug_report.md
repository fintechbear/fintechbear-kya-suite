---
name: Bug report
about: Report a defect in the FintechBear KYA SDK (NOT a security vulnerability)
title: "[bug] "
labels: ["bug"]
assignees: []
---

<!--
Do NOT use this template for a security vulnerability. Report suspected
vulnerabilities privately per SECURITY.md (a private GitHub security advisory).
-->

## Is this a security issue?

- [ ] No. (If yes, stop and follow SECURITY.md instead of filing here.)

## Description

<!-- A clear and concise description of the bug. -->

## Affected crate and version

<!-- e.g. kya-crypto 0.1.0, or the git commit SHA you built from. -->

## Reproduction

Steps to reproduce, ideally a minimal code sample:

```rust
// Minimal reproduction.
```

## Expected behavior

<!-- What you expected to happen. For this SDK, note that a fail-closed Deny is
often the correct, expected behavior. -->

## Actual behavior

<!-- What actually happened. Include the exact typed error or ErrorCode if one
was returned, and any panic message. -->

## Environment

- OS and version:
- Rust toolchain (`rustc --version`):
- On Windows, did you source `vcvars64.bat` before building crypto-linked crates? (yes/no)

## Additional context

<!-- Anything else that helps. Do NOT include live secrets, private keys, or
third-party data. Test keys in this SDK are deterministic synthetic seeds. -->
