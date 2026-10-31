# AGENTS.md: The FintechBear KYA Engineering Constitution

This document is the authoritative engineering constitution for the FintechBear
KYA SDK. Every contributor and every automated agent working in this repository
MUST comply with it. The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY
are to be interpreted as described in RFC 2119.

This is a security-critical financial-authorization SDK. When any rule here
conflicts with convenience, speed, or passing CI, this document wins.

---

## 1. Core security distinction (read this first)

A valid cryptographic signature is **NOT** sufficient to authorize a financial
transaction. A signature proves authenticity and integrity of some bytes. It
says nothing about whether the delegating mandate is still valid, whether a
budget is exhausted, or whether the request is a replay.

Offline verification **cannot** establish current revocation state, cumulative
budget state, or global replay state. Those facts are global and mutable, and
establishing them requires trustworthy authoritative evidence obtained online.
Any code that treats an offline "looks fine" as "authorized" is a defect.

---

## 2. The five non-interchangeable stages

Authorization is decomposed into five stages. They MUST NOT be conflated,
reordered into a shortcut, or collapsed into one another.

- **Stage A — Identity.** Resolve who the agent and issuer claim to be.
  (`kya-core::identity`.)
- **Stage B — Signature verification.** Verify the cryptographic authenticity
  of the signed mandate/request. Trait seam only in this SDK
  (`kya-core::verification`). Passing stage B is NOT authorization.
- **Stage C — Static policy evaluation.** Deterministic, offline scope and
  limit checks (`kya-core::policy`), producing a `PolicyOutcome`. A `Passed`
  outcome is NOT authorization.
- **Stage D — Online authoritative authorization.** Revocation, cumulative
  budget, and global replay state, established via an authority
  (`kya-client::OnlineAuthorizer`). This is the only stage that can yield an
  `Allow`.
- **Stage E — Execution enforcement.** The integration layer enforces that only
  an authorized `Decision` is ever executed.

The only bridge from a stage-C `PolicyOutcome` to a final `Decision` is the
fail-closed `kya_client::authorize` function. There MUST NOT be a
`From<PolicyOutcome> for Decision` implementation anywhere in the SDK.

---

## 3. The twenty-two rules

### Rule 1 — Clean Code, SOLID, DRY, KISS, YAGNI
Code MUST be readable and single-purpose. Follow SOLID. Do not repeat logic
(DRY). Prefer the simplest design that works (KISS). Do not build for
hypothetical futures (YAGNI).

### Rule 2 — Clean Architecture and strict dependency boundaries
Dependencies MUST point inward toward the domain core. `kya-core` MUST NOT
depend on `kya-protocol`, `kya-client`, HTTP, databases, cloud SDKs, or payment
providers. `kya-protocol` and `kya-client` MAY depend on `kya-core`. Library
crates MUST NOT depend on examples.

### Rule 3 — Idiomatic Rust with strong type safety
Make illegal states unrepresentable. Use newtypes and enums instead of raw
strings and integers for domain concepts. Prefer `Result` over sentinels.

### Rule 4 — No unsafe Rust by default
Every crate MUST begin with `#![forbid(unsafe_code)]`, and the workspace sets
`unsafe_code = "forbid"`. Any exception requires an ADR and explicit review.

### Rule 5 — No panic from untrusted input
Code paths that process attacker-controlled input MUST NOT panic. Parsing,
verification, and policy code MUST return typed errors, never `panic!`, on
malformed input.

### Rule 6 — No unwrap/expect in security-critical production paths
Security-critical production code MUST NOT use `unwrap`, `expect`, or indexing
that can panic. Clippy is configured to warn on `unwrap_used`/`expect_used`;
tests MAY use them for brevity.

### Rule 7 — Explicit, typed error handling
Errors MUST be typed enums, `#[non_exhaustive]`, implementing `Display` and
`std::error::Error`. No stringly-typed errors in public APIs.

### Rule 8 — Exact monetary arithmetic; no financial floats
Money MUST be represented as integer minor units plus an explicit ISO-4217
currency. `f32`/`f64` MUST NOT appear in monetary logic. Arithmetic MUST be
checked and fail closed on overflow; cross-currency operations MUST be rejected.

### Rule 9 — Deny by default and fail closed
The default answer is deny. Any error, timeout, unknown state, or
approval-required signal MUST resolve to `Deny`. `Allow` requires explicit
authoritative approval.

### Rule 10 — Standard cryptography; no invented algorithms
Cryptographic verification MUST use standard, reviewed primitives and libraries.
Inventing cryptographic algorithms or constructions is forbidden.

### Rule 11 — Explicit trust anchors and issuer verification
Trust MUST be explicit and allow-listed. There is no implicit or wildcard trust.
Issuers MUST be verified against configured trust anchors.

### Rule 12 — No silent authorization fallback
There MUST be no code path that upgrades a non-authoritative result to an
authorization. The absence of `From<PolicyOutcome> for Decision` is a deliberate
enforcement of this rule.

### Rule 13 — Minimal, reviewed dependencies
Dependencies MUST be minimal and justified. Prefer `std` for the v0.1
foundation. New dependencies require review and SHOULD be pinned.

### Rule 14 — Comprehensive unit and integration testing
Every module with logic MUST have unit tests. Cross-crate behavior SHOULD have
integration tests. The fail-closed bridge and monetary arithmetic MUST be
tested.

### Rule 15 — Negative, property-based, and fuzz testing
Security-sensitive parsers and verifiers MUST have negative tests (malformed and
adversarial input) and SHOULD have property-based and fuzz tests as they mature.

### Rule 16 — Strict formatting, Clippy, and CI quality gates
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, `cargo test --workspace --all-features`, and
`cargo doc --workspace --no-deps` MUST all pass. CI enforces these gates.

### Rule 17 — Security regression tests for security-sensitive changes
Any change to identity, verification, policy, decision, or authorization code
MUST add or update tests that lock in the secure behavior to prevent regression.

### Rule 18 — Secure logging and secrets management
Secrets, keys, and signatures MUST NOT be logged. Secrets MUST NOT be committed;
`.gitignore` excludes common secret file patterns. Logs MUST avoid leaking
sensitive payloads.

### Rule 19 — Documented threat modeling and trust boundaries
Threat models and trust boundaries MUST be documented and kept current as the
design evolves.

### Rule 20 — Honest protocol compatibility and security claims
Compatibility and security claims MUST be truthful and evidence-backed. Do not
claim certification, independent audit, or protocol compatibility without
evidence.

### Rule 21 — API stability and semantic versioning
Public APIs MUST follow semantic versioning. Breaking changes require a major
version bump. Error enums are `#[non_exhaustive]` to permit additive evolution.

### Rule 22 — No weakening tests to make CI pass
Tests MUST NOT be deleted, skipped, or loosened merely to make CI green. Fix the
code, not the test. A failing security test is a blocker, not a nuisance.

---

## 4. Crate boundaries at a glance

| Crate          | Role                                             | May depend on            |
|----------------|--------------------------------------------------|--------------------------|
| `kya-core`     | Domain types, money, trait seams, policy, decision | nothing in-repo; std   |
| `kya-protocol` | Language-independent wire/protocol surface       | `kya-core`               |
| `kya-client`   | Stage D authorization + integration seams        | `kya-core`, `kya-protocol` |

`kya-core` performs no I/O. Concrete crypto, HTTP, DB, and cloud code live
outside the core, behind traits.
