# Security Invariants

This document enumerates the security invariants the FintechBear KYA SDK intends
to hold. Each invariant is phrased so that a regression test could lock it in
(AGENTS.md Rules 14, 15, 17), and each is mapped to the authorization stage it
governs and the AGENTS.md rule(s) it enforces.

An invariant marked **(enforced)** is backed by current code in the repository.
An invariant marked **(design intent)** is a rule the design commits to and that
future code (for example the AP2 adapter) must satisfy; it is not a claim that
code already enforces it. This labelling is required by AGENTS.md Rule 20. The
concrete cryptographic invariants (INV-8, INV-11, INV-18 through INV-21) are
realized by the `kya-crypto` engine; see
[cryptographic-architecture.md](cryptographic-architecture.md).

## Invariants

### INV-1 — A signature is never, by itself, an authorization. (enforced)
- **Stage(s):** B, C, D. **Rules:** section 1, Rule 12.
- A verified signature (stage B) and an `EligibleForOnlineAuthorization` static
  outcome (stage C) do not and cannot produce an `Allow`. Only the stage-D
  authority, through the bridge, can.
- **Testable as:** no code path turns `VerificationStatus::Verified` or
  `PolicyOutcome::EligibleForOnlineAuthorization` into `Decision::Allow` without
  an authority approval.

### INV-2 — There is no `From<PolicyOutcome> for Decision`. (enforced)
- **Stage(s):** C to D boundary. **Rules:** section 2, Rule 12.
- The only bridge from a static outcome to a decision is
  `kya_client::authorize`. The coercion is absent at the type level.
- **Testable as:** a compile-level/structural check that no such `impl` exists;
  the only function producing a `Decision` from a `PolicyOutcome` is `authorize`.

### INV-3 — Deny-by-default and fail-closed. (enforced)
- **Stage(s):** D. **Rules:** Rule 9.
- In `authorize`: any outcome other than
  `PolicyOutcome::EligibleForOnlineAuthorization` denies without contacting the
  authority (this covers `InvalidEvidence`, `Denied`, `RequiresApproval`, and
  `Indeterminate`); `Approved` maps to `Allow`; `Denied` and `ApprovalRequired`
  map to `Deny`; any authorizer error, timeout, or uninterpretable response maps
  to `Deny`. The `Decision` type has no `Unknown` variant.
- **Testable as:** the existing `kya-client` tests
  (`denied_outcome_never_contacts_authority`,
  `approval_required_is_not_auto_authorized`,
  `authorizer_error_fails_closed_to_deny`, `explicit_denial_maps_to_deny`,
  `passed_outcome_can_be_authorized`,
  `requires_approval_outcome_never_contacts_authority`,
  `invalid_evidence_outcome_fails_closed_without_contacting_authority`,
  `indeterminate_outcome_fails_closed_without_contacting_authority`). Each would
  fail if the behaviour regressed.

### INV-4 — The authority is never contacted when static policy already rejected. (enforced)
- **Stage(s):** C to D. **Rules:** Rule 9, Rule 1 (KISS; no wasted side effects).
- A rejected `PolicyOutcome` short-circuits to `Deny` before any `await` on the
  authorizer.
- **Testable as:** `denied_outcome_never_contacts_authority` (asserts the
  authorizer's `contacted` flag stays false).

### INV-5 — `ApprovalRequired` is never silently upgraded to an allow. (enforced)
- **Stage(s):** D. **Rules:** Rule 9, Rule 12.
- `AuthorityVerdict::ApprovalRequired` maps to `Deny` with
  `ReasonCode::ApprovalRequired`; it stays denied until an explicit `Approved`
  arrives out of band.
- **Testable as:** `approval_required_is_not_auto_authorized`.

### INV-6 — Trust is explicit, allow-listed, and deny-by-default. (enforced)
- **Stage(s):** A. **Rules:** Rule 11.
- `TrustAnchors::new` trusts nothing; `is_trusted` is true only for an issuer
  that was deliberately added; there is no wildcard or implicit trust.
- **Testable as:** `identity::tests::trust_is_explicit_and_deny_by_default`.

### INV-7 — Untrusted input never panics; it yields typed errors. (enforced)
- **Stage(s):** A, B, C. **Rules:** Rules 5, 6, 7.
- Identity construction, signature verification, and policy evaluation return
  typed, `#[non_exhaustive]` error enums (`IdentityError`, `VerificationError`,
  `ReasonCode`-carrying outcomes) on malformed or adversarial input, and avoid
  `unwrap`/`expect`/panicking indexing in production paths.
- **Testable as:** negative tests feeding empty/oversized identifiers, malformed
  keys/signatures, and out-of-scope/over-limit requests, asserting typed errors
  rather than panics.

### INV-8 — Signature verification is binary; a non-match is not an error, and an error is not a pass. (enforced)
- **Stage(s):** B. **Rules:** Rules 7, 9, 10.
- `SignatureVerifier::verify` returns `Ok(Verified)` or `Ok(Invalid)` for a
  genuine match/non-match, and `Err(VerificationError)` only for malformed input
  or an unsupported algorithm. There is no third "maybe" that could be read as a
  pass. The concrete `kya_crypto::Ed25519SignatureVerifier` now realizes this
  contract against a reviewed RFC 8032 implementation: a 32-byte key / 64-byte
  signature that genuinely matches is `Verified`, a genuine non-match is
  `Invalid`, and wrong-length key or signature bytes are `MalformedKey` /
  `MalformedSignature` — never a panic, never a silent pass.
- **Testable as (enforced):** `kya-crypto/tests/rfc8032_conformance.rs` (official
  RFC 8032 §7.1 vectors), and `verifier.rs::{verifies_a_genuine_signature,
  rejects_tampered_message_as_invalid, wrong_length_key_is_malformed_key,
  wrong_length_signature_is_malformed_signature,
  does_not_panic_on_arbitrary_inputs}`.

### INV-9 — Money is exact integer minor units with an explicit currency; no floats. (enforced)
- **Stage(s):** C. **Rules:** Rule 8.
- Monetary values use integer minor units plus an ISO-4217 currency; arithmetic
  is checked and fails closed on overflow; cross-currency operations are
  rejected. No `f32`/`f64` appears in monetary logic.
- **Testable as:** the existing `money` tests exercising checked-overflow
  rejection, negative-result rejection, and currency-mismatch rejection.

### INV-10 — Static policy enforces the full twelve-check matrix against the mandate, on verified evidence. (enforced)
- **Stage(s):** C. **Rules:** Rules 3, 8, 9.
- `kya_core::policy::evaluate` takes a `VerifiedDelegation` (the only source of
  established agent/issuer identity, mintable solely through real cryptographic
  verification), the mandate, the untrusted `TransactionIntent`, and an injected
  `now`. It deterministically and deny-leaningly checks, each with a distinct
  `ReasonCode`: verified agent identity (the verified agent must equal the
  mandate's agent and the intent's claimed agent), trusted delegation issuer
  (verified issuer equals mandate issuer), principal, validity window
  (`[nbf, exp)` against the injected `now`, no system clock), required audience,
  exact transaction binding (anti-substitution), authorized action, merchant
  allow-list, resource allow-list, currency allow-list, per-transaction spending
  limit (exact `i128` via `Money::try_cmp`, cross-currency rejected fail-closed),
  and human-approval requirement (surfaced as `RequiresApproval`, never a silent
  pass). An intent's own identity fields are treated as **claims** to be checked
  against the evidence, never as evidence. The only passing outcome is
  `EligibleForOnlineAuthorization`, which is **not** an authorization.
- **Testable as:** the `policy` unit tests covering every check and boundary
  (agent/issuer/evidence, principal, validity nbf/exp boundaries, audience,
  binding substitution, action, merchant, resource, currency, limit including
  0 / 1 / limit-exactly / limit+1 / `i128::MAX`, cross-currency fail-closed, and
  approval-required).

### INV-10b — Verified identity versus untrusted claims. (enforced)
- **Stage(s):** C. **Rules:** section 1, Rule 3.
- The stage-C evaluator can only be called with a `VerifiedDelegation` for the
  established agent/issuer identity; a self-asserted identity cannot be fed in as
  "verified" because `VerifiedDelegation` has no constructor other than
  `establish`, which routes through real cryptographic verification against a
  trust anchor. A verified-evidence inconsistency (evidence naming a different
  agent/issuer than the mandate) yields `InvalidEvidence`, distinct from an
  ordinary policy `Denied`.
- **Testable as:** the `policy` tests
  `invalid_evidence_when_verified_agent_differs_from_mandate`,
  `invalid_evidence_when_verified_issuer_differs_from_mandate`, and
  `denies_when_intent_agent_claim_differs_from_verified_agent`.

### INV-11 — No invented cryptography; a concrete pinned-algorithm Ed25519 verifier exists. (enforced)
- **Stage(s):** B. **Rules:** Rule 10, Rule 13.
- `kya-core` implements no algorithm; it defines only the seam. The concrete
  engine in `kya-crypto` uses a standard, reviewed primitive (`ed25519-dalek`,
  RFC 8032) and **pins a single algorithm**: only `EdDSA`/Ed25519 is accepted.
  `alg: none`, HMAC, RSA, ECDSA, the empty string, and any other identifier are
  rejected with `UnsupportedAlgorithm` (algorithm-confusion and downgrade
  defense). No cryptographic algorithm is invented, and no JWT/JOSE or base64
  framework is pulled in; the EdDSA-only JWS parser and a strict base64url
  decoder are implemented in-crate.
- **Testable as (enforced):** `kya-crypto/tests/jws_security.rs` and
  `jws.rs::{rejects_alg_none, rejects_non_eddsa_algorithms}` (allowlist), and
  `verifier.rs` malformed-key/signature tests. The core can still not enforce
  this on a third-party verifier; that remains a documented contract on the
  trait.

### INV-12 — Secrets, keys, and signatures are never logged. (enforced as policy)
- **Stage(s):** cross-cutting. **Rules:** Rule 18.
- Error types describe failure classes, not sensitive bytes; the core emits no
  logging that carries secrets.
- **Testable as:** a check that error `Display` impls and any logging contain no
  key/signature material.

### INV-13 — Replay, revocation, and cumulative budget are online-only. (enforced by omission + design intent)
- **Stage(s):** D. **Rules:** section 1, Rule 9.
- The offline stages deliberately do not claim to establish these; they are
  reached only via a stage-D `OnlineAuthorizer`. A revoked/replayed/over-budget
  request can only be stopped online, where `Denied` maps to `Deny`.
- **Testable as:** absence of any offline code path that returns `Allow` for
  these; and, once a concrete authorizer exists, tests that `Denied` for
  revoked/over-budget/replayed requests maps to `Deny`.

### INV-14 — Execution only ever acts on an authorized decision. (design intent)
- **Stage(s):** E. **Rules:** Rule 9, Rule 12.
- `IntegrationClient::submit` must be called only with a `Decision` that is an
  `Allow`. The core ships no concrete execution path; integrators must enforce
  this at the call site.
- **Testable as:** integration tests that `submit` is never invoked for a `Deny`.

### INV-15 — Dependency direction points inward; the core takes on no I/O deps. (enforced)
- **Stage(s):** architectural. **Rules:** Rule 2, Rule 13.
- `kya-core` depends on nothing in-repo and on no HTTP/DB/cloud/payment-provider
  crate; `kya-protocol` depends on `kya-core`; `kya-client` depends on both. A
  future protocol adapter lives in the outer ring and must not add I/O deps to
  `kya-core`.
- **Testable as:** a manifest/graph check that `kya-core`'s dependencies stay
  empty of in-repo and I/O crates.

### INV-16 — Public API evolves under semantic versioning; error enums stay additive. (design intent)
- **Stage(s):** cross-cutting. **Rules:** Rule 21, Rule 7.
- Error enums are `#[non_exhaustive]` so new variants are additive; breaking
  changes require a major version bump.
- **Testable as:** a semver-check in CI as the API stabilizes.

### INV-17 — No security test is weakened to make CI pass. (process invariant)
- **Stage(s):** cross-cutting. **Rules:** Rule 22, Rule 17.
- A failing security test is a blocker; it is fixed in the code, not deleted,
  skipped, or loosened. Security-sensitive changes add or update regression tests.

### INV-18 — A `Verified` outcome can be minted only by the reviewed concrete verifier inside `kya-crypto`. (enforced)
- **Stage(s):** B. **Rules:** section 1, Rules 9, 10, 11, 12, 17.
- A `kya_crypto::VerificationOutcome` whose status is `Verified`, and the
  verified evidence built on it (`VerifiedDelegation`, `VerifiedMandate`), can be
  minted **only** by constructors that live **inside `kya-crypto`** and are bound
  to the one reviewed concrete verifier `Ed25519SignatureVerifier`. This is a
  Rust visibility wall, not a runtime check:
  - The only mint-points — `VerificationProof::new`, `VerificationOutcome::verified`,
    the crate-private `run_verifier`, and `VerifiedDelegation::establish` /
    `VerifiedMandate::establish` — are all `pub(crate)` or private to
    `kya-crypto`. No external crate can name or reach them. `VerificationProof`
    additionally has a private, unnameable zero-sized `Sealed` field, so it has
    no external constructor.
  - `run_verifier` (the only thing that mints a verified outcome) takes
    `&Ed25519SignatureVerifier` by **concrete type** — there is no generic
    parameter and no registration door. An arbitrary `SignatureVerifier` — for
    example a malicious always-`Verified` verifier defined in another crate —
    **cannot even be passed** to it. It can describe a `Verified` status, but
    `kya-core` holds no mint-point to promote that report (INV-8), and
    `kya-crypto` will not run it, so it can never cause verified evidence to be
    minted.
- This **supersedes** the earlier trust-anchor-only framing of the forgery
  defense. A trusted public key alone never proves a message was signed with its
  private key (AGENTS.md section 1); trust-anchoring (INV-19) remains a necessary
  *second*, independent gate, but it is the crate-private, concrete-typed
  mint-point that closes threat [T-13](threat-model.md). `kya-core` holds only
  the `SignatureVerifier` description seam and cannot name or reach the verified
  types.
- **Testable as (enforced):** the external-crate forgery suite
  `kya-crypto/tests/forgery_regression.rs` (`malicious_verifier_answer_is_inert`,
  `genuine_sanctioned_path_still_establishes_evidence`,
  `anchored_key_with_bad_signature_still_fails_closed`); the verified-evidence
  unit tests in `kya-crypto/src/evidence.rs`
  (`invalid_outcome_is_not_verified`,
  `run_verifier_mints_verified_only_on_genuine_match`,
  `delegation_establishes_when_all_conditions_hold`,
  `delegation_rejects_untrusted_key_even_when_signature_verifies`,
  `delegation_rejects_invalid_outcome`, `mandate_rejects_binding_mismatch`); and
  the `compile_fail` doc-tests on `VerificationProof`, `VerificationOutcome`,
  `VerifiedDelegation`, and `VerifiedMandate` in `kya-crypto/src/evidence.rs`
  (external code can construct none of them). `kya-core/src/verification.rs`
  (`signature_verifier_is_only_a_description_seam`) confirms the seam cannot mint
  verified evidence.

### INV-19 — Verified evidence requires trust-anchoring independent of authenticity. (enforced)
- **Stage(s):** A, B. **Rules:** Rule 11, Rule 12.
- `VerifiedDelegation::establish` re-checks, independently of the verifier, that
  the outcome's issuer matches the claim and that the `(issuer, key_ref)` pair is
  anchored in `TrustAnchors`. A malicious `SignatureVerifier` that always returns
  `Verified` therefore still cannot promote an untrusted key. The concrete engine
  additionally requires the pair to resolve in an explicit
  `kya_crypto::TrustedKeyStore` with no URL fetch and no wildcard.
- **Testable as (enforced):**
  `kya-crypto/src/evidence.rs::{delegation_rejects_untrusted_key_even_when_signature_verifies,
  delegation_establishes_when_all_conditions_hold}`,
  and `kya-crypto/tests/engine_security.rs` unknown-issuer / untrusted-key cases.

### INV-20 — Verified claims are bound to an audience, a validity window, and the exact transaction. (enforced in `kya-crypto`)
- **Stage(s):** B (static validity), C. **Rules:** Rules 8, 9.
- `kya_crypto::verify_delegation` enforces, fail-closed and each with a distinct
  error: an exact-match `audience` (`AudienceMismatch`); an injected-`now`
  not-before / expiration window (`NotYetValid` / `Expired`, expiry exclusive,
  with no subtraction so extreme `u64` values cannot overflow or panic); and a
  byte-for-byte transaction `binding` (`BindingMismatch`). The signature is
  checked over the **exact** caller-supplied bytes; the engine invents no
  canonicalization of wire fields.
- **Testable as (enforced):** `kya-crypto/tests/engine_security.rs` audience,
  not-yet-valid, expired, and binding-mismatch cases, and
  `engine.rs::does_not_panic_on_extreme_time_values`.

### INV-21 — The crypto engine never panics on untrusted input and bounds its size. (enforced)
- **Stage(s):** B. **Rules:** Rules 5, 6.
- `kya-crypto` returns a typed `CryptoVerificationError` on every malformed,
  oversized, or non-verifying input, never panicking, and rejects oversized
  signed bytes / signatures / bindings and oversized compact-JWS tokens with
  `OversizedInput` before heavy work. Each error maps to a stable
  `ErrorCode` and carries no secrets.
- **Testable as (enforced):** `kya-crypto/tests/property_fuzz.rs`,
  `jws.rs::{rejects_oversized_input, does_not_panic_on_arbitrary_bytes}`, and
  `engine.rs::oversized_input_is_rejected`.

### INV-22 — The five authorization-result meanings are distinct and only one is forwardable. (enforced)
- **Stage(s):** C, C→D boundary. **Rules:** section 1, Rules 3, 9, 12.
- Stage-C evaluation resolves to exactly one of five `PolicyOutcome` meanings,
  each carrying a machine-readable `ReasonCode`:
  - `InvalidEvidence` — the verified-evidence precondition was not met (a hard
    fail; the inputs do not cohere).
  - `Denied` — a static policy rule forbade the request.
  - `RequiresApproval` — human approval is required and must never be silently
    upgraded to an allow.
  - `Indeterminate` — a required fact could not be established offline; fails
    closed, never a pass.
  - `EligibleForOnlineAuthorization` — every static check passed. This is the
    **only** outcome the fail-closed bridge may forward to stage D, and it is
    explicitly **not** execution permission.
  `PolicyOutcome` is `#[non_exhaustive]`; `Decision` has only `Allow`/`Deny`
  (no `Unknown`); and there is still no `From<PolicyOutcome> for Decision`
  (INV-2). A missing-online-state / approval-required / indeterminate / invalid
  outcome can therefore never become `Decision::Allow` without the stage-D
  authority.
- **Testable as (enforced):** `decision.rs::{policy_eligible_is_not_authorization,
  non_eligible_outcomes_are_not_forwardable}`; the `kya-client` bridge tests;
  and the end-to-end integration tests
  `kya-client/tests/end_to_end.rs::{no_negative_stage_c_outcome_can_become_allow,
  missing_online_state_always_fails_closed_to_deny,
  only_an_eligible_outcome_with_authority_approval_yields_allow}`, which
  enumerate every non-eligible outcome and prove none yields `Allow`.

### INV-23 — An unsupported protocol version is rejected fail-closed, never processed. (enforced)
- **Stage(s):** protocol boundary (precedes A). **Rules:** Rules 9, 21.
- `kya_protocol::check_supported_version` parses a peer-announced `"major.minor"`
  version and accepts it only when the **major** matches this build exactly and
  the **minor** does not exceed the supported minor. A newer major, a newer
  minor, or a malformed version string all fail closed with a typed
  `VersionError` (`Unsupported`/`Malformed`) rather than being interpreted under
  semantics this build does not implement. A transport/adapter is expected to run
  this gate **before** decoding any wire body.
- **Testable as (enforced):** `kya-protocol` unit tests
  (`unsupported_major_is_rejected_fail_closed`, `newer_minor_is_rejected_fail_closed`,
  `malformed_version_strings_fail_closed_without_panic`,
  `older_minor_within_same_major_is_supported`,
  `current_version_string_is_supported`) and the integration suite
  `kya-protocol/tests/version_gate.rs`, which proves the version is checked
  before the body is decoded.

## How these map to the protocol adapter

The first protocol adapter now exists as the outer-ring `kya-adapter-ap2` crate
(see [first-adapter-decision.md](first-adapter-decision.md) and
[protocol-compatibility.md](protocol-compatibility.md)). It implements only the
independently-verifiable AP2 **constraint** surface and routes stage-B
verification through `kya-crypto` over caller-supplied exact bytes; byte-for-byte
AP2 envelope parsing and AP2 test-vector conformance remain `[UNVERIFIED]`/BLOCKED
and are deliberately not implemented or claimed. The adapter preserves every
**(enforced)** invariant and satisfies the **(design intent)** ones that touch it,
in particular: INV-1/2/3 (a verified AP2 mandate is not an authorization and
reaches a decision only through the bridge; the adapter never produces a
`Decision`), INV-6/11 (AP2 issuers map onto explicit `TrustAnchors` and
verification uses `kya-crypto`'s standard pinned Ed25519 / JWS-EdDSA engine),
INV-10 (AP2 mandate constraints translate into the bound stage-C checks and the
unchanged `evaluate` runs on them), INV-13 (AP2 issuer authorization / revocation
remain stage D), INV-18/19/20 (any AP2 mandate the adapter verifies goes through
the sanctioned mint-point, is trust-anchored independently of authenticity, and
is bound to audience, validity window, and transaction), and INV-22 (a verified
AP2 constraint set is at most `EligibleForOnlineAuthorization`). See
[protocol-compatibility.md](protocol-compatibility.md) for the honesty boundary
on what is claimed versus implemented.
