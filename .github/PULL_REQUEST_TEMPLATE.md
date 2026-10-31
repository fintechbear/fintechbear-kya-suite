<!--
Thanks for contributing to FintechBear KYA. This is a security-critical
financial-authorization SDK; please read AGENTS.md (the engineering constitution
and its 22 rules) and CONTRIBUTING.md before opening a pull request.

Do NOT open a pull request for a security vulnerability. Report it privately per
SECURITY.md.
-->

## Summary

<!-- What does this change do, and why? -->

## Related issues

<!-- e.g. Closes #123. Omit if none. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (requires a major version bump per Rule 21)
- [ ] Documentation only
- [ ] Tests / tooling / CI only

## Security-relevant?

- [ ] This change touches identity, verification, policy, decision, or
      authorization code.
- [ ] If checked: I added or updated a security regression test that locks in
      the secure behavior (Rule 17), and I did not weaken, skip, or delete any
      existing test to make CI pass (Rule 22).

## Invariants (confirm all that apply)

- [ ] No `From<PolicyOutcome> for Decision` was added; `Decision` stays
      `Allow` / `Deny` only, and the only bridge is the fail-closed
      `kya_client::authorize`.
- [ ] Every crate still begins with `#![forbid(unsafe_code)]`; no `unsafe` added.
- [ ] No `unwrap` / `expect` / panicking index in security-critical production
      paths (tests may use them).
- [ ] Money stays integer minor units + explicit ISO-4217; no floats; checked
      arithmetic; cross-currency rejected.
- [ ] Public typed errors remain `#[non_exhaustive]` and implement
      `Display` + `std::error::Error`.
- [ ] No secrets, keys, or signatures are logged or committed.
- [ ] Compatibility and security claims are truthful and evidence-backed
      (Rule 20): no invented certification, audit, affiliation, or endorsement.

## Quality gates (Rule 16)

Confirm the full gate set passes locally (on Windows, source `vcvars64.bat`
first for crypto-linked crates):

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo test --doc --workspace`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`

## Notes for reviewers

<!-- Anything a reviewer should look at first, tradeoffs, or follow-ups. -->
