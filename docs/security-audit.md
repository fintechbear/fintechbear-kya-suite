# Internal Security Audit — FintechBear KYA SDK

**This is an internal audit performed by the project's own engineering process.
It is NOT an independent third-party audit, and no external certification,
penetration test, or formal verification is claimed (AGENTS.md Rule 20).** It
records first-hand review and empirical testing of the security-critical
surfaces of the FintechBear KYA ("Know Your Agent") Rust SDK on branch
`rebuild/kya-foundation-v0.1.0`.

## Scope

In scope:

- The five-stage authorization model (A identity, B signature verification,
  C static policy, D online authoritative authorization seam, E execution
  enforcement seam) as realized in `kya-core`, `kya-crypto`, `kya-client`,
  `kya-adapter-ap2`, and the `kya-sdk` facade.
- The verifier-sanction / verified-evidence mint-point (the stage-B seal).
- Signed-mandate binding (canonical encoding + byte-equality binding).
- The cryptographic engine: Ed25519 (RFC 8032) and compact-JWS-EdDSA
  (RFC 7515 / 7518 / 8037), and the strict base64url decoder.
- The authorization / financial negative matrix (stage C + the fail-closed
  `kya_client::authorize` bridge) and exact monetary arithmetic.
- The public API surface of the facade and the AP2 adapter (clean-code /
  misuse-risk review).
- Supply-chain posture (dependency / license inventory; `cargo deny`).

Out of scope / not performed here (see [known-limitations.md](known-limitations.md)
and [release-readiness.md](release-readiness.md)): network-dependent scans
(RustSec advisory DB / `cargo audit`), coverage-guided fuzz *runs*, SBOM
generation, and cross-platform (Linux/macOS) gate runs. These were NOT RUN or
NOT VERIFIED in the offline Windows environment and are recorded honestly as
such rather than asserted.

## Method

The audit combined manual source review against AGENTS.md's 22 rules and five
stages with first-hand empirical testing:

- A real external crate (`.agents/audit/kya-bypass-probe`, carrying its own
  `[workspace]` table so it is not a workspace member) was written to attack the
  stage-B mint-point from outside the SDK.
- Adversarial test matrices were added for mandate binding, cross-context
  signature reuse, and JWS/base64url edge cases, and all pass
  (see [release-readiness.md](release-readiness.md) for counts).
- The full Rule 16 gate set was run and is green (fmt, clippy `-D warnings`,
  tests, doctests, `RUSTDOCFLAGS=-D warnings` doc).

## Findings

Each finding carries an ID, severity, affected files (with line regions),
reproduction, root cause, impact, fix, regression test, and status. One
release-blocking P0 was confirmed and fixed; the remaining security-critical
surfaces were probed and confirmed to fail closed, with regression tests added
to lock the behavior in (Rule 17).

### KYA-P0-001 — Verifier-sanction mint-point bypassable from an external crate — CRITICAL (P0) — FIXED

- **Severity:** Critical (P0), release-blocking.
- **Affected (pre-fix):** `crates/kya-core/src/verification.rs` — the `pub`
  `internal::register::<V>()` entry inside a `pub #[doc(hidden)]` module, generic
  over any `V: SignatureVerifier`; the verified-evidence mint path that trusted
  the resulting sanction.
- **Reproduction (empirical):** the external probe
  `.agents/audit/kya-bypass-probe/src/main.rs` implemented an `AlwaysVerified`
  verifier, called `kya_core::verification::internal::register::<AlwaysVerified>()`
  to mint a `VerifierSanction`, routed arbitrary bytes through the public
  `verify_signature` to obtain a `Verified` `VerificationOutcome` with **zero**
  cryptography, anchored a genuinely-trusted key, and minted a trusted
  `VerifiedDelegation`. It printed `BYPASS SUCCEEDED: minted VerifiedDelegation
  ... with NO cryptography`.
- **Root cause:** the sanction mint-point was reachable through the public API
  and was generic over any caller-supplied verifier, so an external crate could
  substitute a no-op verifier and mint trusted evidence without performing real
  verification. The five pre-existing compile-fail doc-tests closed a removed
  macro, direct sealed-field construction, and a nonexistent public `grant`, but
  did **not** exercise `internal::register`, which was the live hole. The
  crate's own docs had acknowledged this as an "honest residual."
- **Impact:** a valid-looking `VerifiedDelegation` / `VerifiedMandate` could be
  constructed with no signature check, defeating stage B entirely and allowing a
  downstream flow to treat unverified bytes as authentic. This violates the core
  security distinction (a signature is necessary for authenticity) and Rule 12
  (no silent authorization fallback).
- **Fix:** the mint-point / ownership of trusted verified-evidence types was
  relocated into `kya-crypto` (the only crate that performs real verification),
  so the sealed constructor is bound to the reviewed `kya-crypto` verifier and is
  **not** reachable or parameterizable from an arbitrary external crate. The
  relocation introduces no dependency cycle: `kya-core` still depends on nothing
  in-repo, and `kya-crypto` depends inward on `kya-core` (Rule 2). The
  `Decision` type remains `Allow`/`Deny` only and there is still no
  `From<PolicyOutcome> for Decision`.
- **Regression test:** stage-B seal regression tests in `kya-crypto` lock in
  that verified-evidence types are only mintable through the real verification
  path; the external-bypass probe no longer compiles against the sealed
  mint-point. (Delivered under FEAT-001; this document records the finding.)
- **Status:** FIXED and verified; closed before FEAT-002/FEAT-003.

### KYA-OBS-002 — Signed-mandate binding is sound (injective encoding + byte-equality) — INFO (confirmed secure)

- **Affected:** `crates/kya-core/src/mandate.rs` (`canonical_encoding`, module
  `canonical`); `crates/kya-crypto/src/evidence.rs`
  (`VerifiedMandate::establish` byte-equality check, approx. L430–445);
  `crates/kya-crypto/src/engine.rs` (`verify_mandate`).
- **Probed:** field reordering of action and merchant/resource/currency
  allow-lists; omission of each optional field (limit/audience/binding/approval);
  length-prefix ambiguity across audience↔binding; injectivity across
  single-field-different mandates; magic-tag (`KYA-MANDATE`) + version-byte
  domain separation vs foreign-framed / future-version bytes; builder-order
  independence; idempotent duplicate action.
- **Result:** every reorder/omission/foreign-frame changes the bytes; every
  logically-identical pair matches; the magic + version prefix is unconditional.
  The encoding is injective over the fields it covers, and `establish` requires
  byte-equality with the exact verified bytes, so a substituted or cross-framed
  mandate cannot be authenticated.
- **Root cause / impact:** n/a — secure by construction (length-prefixing +
  tagging + magic/version is a correct canonical-injective design).
- **Regression test:** `crates/kya-core/tests/canonical_encoding.rs` (14 tests),
  complementing the per-field crypto suite
  `crates/kya-crypto/tests/mandate_binding.rs` (12 field substitutions over real
  signatures).
- **Status:** CONFIRMED SECURE / locked in.

### KYA-OBS-003 — Cross-context / cross-protocol signature reuse fails closed — INFO (confirmed secure)

- **Affected:** `crates/kya-crypto/src/engine.rs` (`verify_delegation` commits to
  opaque caller bytes; `verify_mandate` derives bytes from the magic-tagged
  canonical encoding).
- **Probed:** a signature over a raw delegation payload presented to the mandate
  path; a signature over a mandate's canonical encoding presented to the
  delegation path over different raw bytes; an AP2-style framed payload signature
  presented to the mandate path; two different mandates with the same claimed
  signature.
- **Result:** all cross-context reuses fail closed (`SignatureInvalid` /
  `BindingMismatch`); only the object whose exact bytes the signature covers
  verifies. The magic-tagged encoding provides domain separation so a foreign
  frame can never equal a mandate encoding.
- **Regression test:** `crates/kya-crypto/tests/cross_context_reuse.rs` (5 tests),
  including a positive control.
- **Status:** CONFIRMED SECURE / locked in.

### KYA-OBS-004 — JWS / base64url strictness holds on remaining edge cases — INFO (confirmed secure)

- **Affected:** `crates/kya-crypto/src/b64url.rs` (`decode`),
  `crates/kya-crypto/src/jws.rs` (`verify`, `extract_alg`,
  `reject_unsupported_crit`), `crates/kya-crypto/src/verifier.rs`
  (`verify_strict`).
- **Probed (new):** non-zero trailing bits in a base64url group (non-canonical)
  rejected; empty payload/header/signature segments rejected (no detached-payload
  ambiguity); a small-order (all-zero) public key never yields a verified payload
  via the JWS path; case-variant (`eddsa`, `EDDSA`, `Ed25519`), empty, and
  missing `alg` all unsupported; wrong-length public key → `MalformedKey`.
- **Result:** every case fails closed with the specific typed error, never a
  verified payload, never a panic. (Pre-existing `jws_security.rs` already
  covered `alg:none`, swapped/symmetric algs, duplicate `alg`, `crit`, invalid
  base64url, invalid UTF-8/JSON, truncation, wrong sig length, oversized input.)
- **Regression test:** `crates/kya-crypto/tests/jws_encoding_edges.rs` (8 tests).
- **Status:** CONFIRMED SECURE / locked in.

### KYA-OBS-005 — Authorization / financial negative matrix is complete and fail-closed — INFO (confirmed secure)

- **Affected:** `crates/kya-core/src/policy.rs` (`evaluate`),
  `crates/kya-core/src/decision.rs`, `crates/kya-client/src/lib.rs` (`authorize`),
  `crates/kya-core/src/money/{mod.rs,iso4217.rs}`.
- **Probed:** InvalidEvidence / Denied / RequiresApproval / Indeterminate never
  become `Allow`; Timeout / Transport / Unknown fail closed to `Deny`; missing
  online state never implies permission; exact spending-limit boundary (at-limit
  passes, +1 denies); wrong merchant / agent / principal / resource / action /
  currency; expired and not-yet-valid; missing approval; cross-currency rejected
  (no float, no silent conversion); checked `i128` arithmetic at `i128::MAX` with
  no panic; `evaluate` deterministic and consuming only verified-mandate
  constraints.
- **Result:** fully covered by existing tests — `kya-client` unit tests (8),
  `kya-client/tests/end_to_end.rs` (8, incl.
  `no_negative_stage_c_outcome_can_become_allow` enumerating all 14 non-eligible
  outcomes), `kya-core/src/policy.rs` unit tests (~30),
  `kya-core/tests/property_policy.rs`, and the `money/*` tests. No gap required
  new tests; the matrix is backed by real tests, not prose.
- **Status:** CONFIRMED SECURE (no new tests needed; existing coverage is the
  matrix).

### KYA-OBS-006 — RFC 8032 conformance uses genuine published vectors — INFO (confirmed genuine)

- **Affected:** `crates/kya-crypto/tests/rfc8032_conformance.rs`.
- **Probed:** whether the Ed25519 vectors are the official RFC 8032 §7.1 vectors
  or self-generated.
- **Result:** GENUINE. TEST 1 (empty msg), TEST 2 (`0x72`), TEST 3 (`af82`) are
  transcribed verbatim from RFC 8032 §7.1 and are independently re-derived from
  the published 32-byte secret seed via `ed25519-dalek` and cross-checked, plus
  negative vectors (wrong key, tampered message).
- **Status:** CONFIRMED GENUINE.

## Verifier-registration assessment

The pre-fix `internal::register` entry was the single most dangerous element of
the public surface: a `pub` mint-point generic over any caller verifier. The
KYA-P0-001 fix relocated ownership of the trusted verified-evidence types into
`kya-crypto`, binding the sealed constructor to the reviewed verifier and
removing the external-crate parameterization. Post-fix review confirms there is
no public, `#[doc(hidden)]`, or otherwise reachable path by which an external
crate can mint `VerifiedMandate` / `VerifiedDelegation` without routing through
the real `kya-crypto` verification. The bypass probe that previously printed
`BYPASS SUCCEEDED` no longer compiles against the sealed mint-point. This is the
correctness property that stage B depends on, and it now holds.

## Public-API / clean-code assessment (summary)

Reviewed from an independent Rust developer's perspective across the `kya-sdk`
facade (`lib.rs`, `prelude.rs`, `trust.rs`, `ap2.rs`) and the public surfaces of
the other crates. Findings:

- **Trait boundaries and visibility:** the facade adds no behavior; it
  re-exports the reviewed inner-crate items. Verified-evidence types are only
  constructible through `kya-crypto`. The AP2 adapter is deliberately kept out of
  the facade and the prelude.
- **Error types:** every public typed error is `#[non_exhaustive]`, implements
  `Display` + `std::error::Error`, and maps to a stable kebab-case
  `ErrorCode` via `AsErrorCode` (including `CryptoVerificationError`). Error
  messages leak no key bytes or secrets (Rule 18); `TrustConfigurationError`
  reports only a length, never the key material.
- **Validation / fail-closed:** `TrustConfiguration::trust_issuer_key` validates
  key length up front and leaves the config unchanged on a bad key (no
  half-registration). `evaluate` is deterministic and offline;
  `requires_online_authorization` / `online_state_is_unestablished` make
  "eligibility is not authorization" explicit.
- **No unexpected panics in production paths:** security-critical paths return
  typed errors; `unwrap`/`expect` appear only under `#[cfg(test)]`.
- **Open-source independence:** the whole verify + evaluate + authorize-seam flow
  runs with only caller-configured trust keys — no FintechBear account,
  subscription, backend, or network I/O. Confirmed empirically by the 11
  examples, which run offline.
- **No genuine API-misuse or correctness defect was found that warranted a code
  change in FEAT-003.** No speculative redesign or cosmetic refactor was made
  (steps were explicitly scoped to avoid that).

## AP2 / trademark honesty assessment (summary)

See [protocol-compatibility.md](protocol-compatibility.md),
[supported-protocols.md](supported-protocols.md), and
[first-adapter-decision.md](first-adapter-decision.md). The `kya-adapter-ap2`
crate makes it unmistakable, in its name, crate docs (a rendered `<div
class="warning">` block), and public API, that it implements AP2-*style* local
constraints only: no AP2 wire envelope, no canonicalization, no conformance
vectors, no provider endpoints, and **official affiliation: none**. It is
deliberately not in the `kya-sdk` prelude. Every compatibility claim in the docs
was checked against the implementation and the claims matrix; the unresolved AP2
envelope and test-vector facts are recorded as `[UNVERIFIED]` / BLOCKED, not
glossed over. Trademark review of "AP2", "Know Your Agent", and the provider
names is recorded in the README "Naming and trademark notice": the names are
descriptive, uncleared, and carry no claim of registration, affiliation, or
endorsement. No external trademark registry was queried in this offline
environment, so trademark clearance remains an open, honestly-stated risk.

## Invariants preserved during the audit

- `#![forbid(unsafe_code)]` unchanged in every crate.
- No `From<PolicyOutcome> for Decision`; `Decision` stays `Allow`/`Deny` only.
- `kya-core` depends on nothing in-repo; no dependency cycle introduced.
- No security test was deleted, skipped, weakened, or `#[ignore]`d (Rule 22).
- Git left read-only; HEAD unchanged at `b06f8e6`.
