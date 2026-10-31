# Threat Model

This document records the trust boundaries, assets, adversaries, and threats for
FintechBear KYA, maps each threat to the stage (A through E) that mitigates it,
and is honest about which mitigations are **not** present in the open-source core
yet. It is kept current as the design evolves (AGENTS.md Rule 19).

## Central limitation (stated up front)

A valid cryptographic signature is **not** sufficient to authorize a financial
transaction. A signature proves the authenticity and integrity of some bytes
only. **Offline verification cannot establish current revocation state,
cumulative budget state, or global replay state**; those facts are global and
mutable and require trustworthy authoritative evidence obtained online (stage D).
Every mitigation that depends on current authoritative state is therefore outside
the reach of the offline stages.

## Trust boundaries

- **Untrusted input boundary.** Mandates, transaction requests, and wire bytes
  arriving from agents or the network are attacker-controlled. Code that parses
  or verifies them must not panic and must return typed errors (AGENTS.md Rules 5
  and 7).
- **Trust-anchor boundary.** Only explicitly allow-listed issuers are trusted
  (Rule 11). There is no implicit or wildcard trust. Everything an untrusted or
  unknown issuer asserts is outside the trust boundary.
- **Offline / online boundary.** The offline stages (A, B as a seam, C) sit
  inside the SDK and your process. Current authoritative state (revocation,
  cumulative budget, replay) sits on the far side of the stage-D boundary, with
  an online authority.
- **Core / edge boundary.** `kya-core` performs no I/O and carries no crypto
  dependency. All transport, crypto, and execution cross a trait-seam boundary
  (`SignatureVerifier`, `OnlineAuthorizer`, `IntegrationClient`). The concrete
  Ed25519 / JWS-EdDSA verifier lives in the outer-ring `kya-crypto` crate; see
  [cryptographic-architecture.md](cryptographic-architecture.md).

## Assets

- **Mandates.** The delegated authority an issuer grants an agent.
- **Keys and signatures.** The cryptographic material and signed bytes. These
  must never be logged (Rule 18).
- **Budgets.** Per-transaction limits (static, in the mandate) and cumulative
  budget state (authoritative, online).
- **Authorization decisions.** The `PolicyOutcome` and the final `Decision`, and
  the integrity of the path between them.

## Adversaries

- A malicious or compromised agent trying to exceed its delegated authority.
- A network attacker tampering with or replaying mandates and requests.
- A malicious issuer, or an attacker impersonating a trusted issuer.
- A dishonest or buggy `SignatureVerifier` implementation trying to vouch for an
  untrusted key, or an attacker trying to fabricate a `Verified` outcome.
- An attacker attempting algorithm confusion or an `alg: none` downgrade on a
  signed token.
- An insider or integration bug trying to take a permissive shortcut from
  "statically fine" to "authorized".

## Threats, mitigations, and honest gaps

Threats are identified (T-n) so other documents can cite them. Rows marked
"Mitigated in `kya-crypto`" apply to callers who verify through the concrete
engine over the exact signed bytes; see
[cryptographic-architecture.md](cryptographic-architecture.md).

| ID | Threat | Mitigating stage | Status in the open-source SDK |
|----|--------|------------------|-------------------------------|
| T-1 | Forged or tampered mandate | B (signature verification) | Mitigated in `kya-crypto`: `Ed25519SignatureVerifier` (RFC 8032) and `JwsEdDsa` verify authenticity over the exact caller-supplied bytes. `kya-core` itself still ships only the seam; a caller may supply another verifier. Conformance: `rfc8032_conformance.rs`; tampering: `engine_security.rs`. |
| T-2 | Algorithm confusion / `alg: none` downgrade on the signature | B | Mitigated in `kya-crypto`: a single-value `EdDSA` allowlist checked before any key/signature bytes are read; `alg: none`, HMAC, RSA, ECDSA, empty, and all other identifiers are rejected with `UnsupportedAlgorithm`. The compact-JWS parser is hardened against two further JOSE smuggling vectors (RFC 7515): a **duplicate top-level `alg` member** is rejected with `MalformedPayload` (the header scanner counts real `alg` keys and skips string values, so a second/earlier key cannot slip an accepted value past the allowlist), and a present **`crit` (critical) header** naming extensions the verifier does not understand fails closed with `UnsupportedAlgorithm` per RFC 7515 §4.1.11. Tests: `jws_security.rs` (`duplicate_alg_member_is_rejected_not_first_match`, `unsupported_crit_header_is_rejected`, `alg_substring_inside_a_value_is_not_treated_as_the_key`), `jws.rs::{rejects_alg_none,rejects_non_eddsa_algorithms,verify_rejects_token_with_duplicate_alg,verify_rejects_token_with_crit_header}`. |
| T-3 | Issuer / authority confusion (untrusted issuer treated as trusted) | A (identity and trust anchors) | Mitigated: trust is explicit and allow-listed, deny-by-default. `kya-crypto` additionally requires the `(issuer, key_ref)` pair to resolve in an explicit `TrustedKeyStore` (no URL fetch, no wildcard). |
| T-4 | Action outside delegated scope | C (static policy) | Mitigated in the core: `evaluate` rejects actions not permitted by scope (`ActionNotPermitted`). |
| T-5 | Amount exceeds per-transaction limit | C | Mitigated in the core: exceeding the mandate's per-transaction limit yields `AmountExceedsLimit`. |
| T-6 | Currency or amount manipulation | C (on exact money types) | Mitigated in the core: money is exact integer minor units with an explicit currency; cross-currency operations are rejected and arithmetic is checked and fails closed (no floats). |
| T-7 | Wrong agent uses a mandate | A and C | Mitigated in the core: an acting agent that does not match the mandate yields `AgentMismatch`. |
| T-8 | Replay of a previously processed request | D (online authoritative) | Not mitigated by the offline SDK. Replay state is global and mutable; it requires an online authority. The `kya-crypto` audience and nbf/exp checks (T-11) narrow a replay window but do not establish global non-replay. Documented gap. |
| T-9 | Double-spend / cumulative-budget evasion | D | Not mitigated offline. Cumulative budget is authoritative, mutable state; it requires an online authority with atomic reservations. Documented gap. |
| T-10 | Revocation evasion (using a revoked mandate) | D | Not mitigated offline. Revocation is current authoritative state; it requires an online authority. Documented gap. |
| T-11 | Audience confusion / stale validity window (claim replayed to a different audience or outside its lifetime) | B (static validity in `kya-crypto`) | Mitigated in `kya-crypto`: exact-match `audience`, and an injected-`now` nbf/exp window (`NotYetValid` / `Expired`, expiry exclusive). These reduce but do not replace the stage-D replay check (T-8). Tests: `engine_security.rs` audience/expiry/future-dating cases. |
| T-12 | Binding / transaction substitution (a signature captured for one action reused for another) | B (binding in `kya-crypto`) + C | Mitigated in `kya-crypto`: `verify_delegation` compares the signer's committed binding to the presented transaction binding byte for byte, failing closed with `BindingMismatch`. Stage C independently re-binds action/amount/currency/agent. Test: `engine_security.rs` binding-mismatch case. |
| T-13 | Verification bypass: an untrusted caller mints a `Verified` outcome without real cryptography (forgeable `VerificationOutcome`, or a malicious always-`Verified` verifier) | B (sanctioned-verifier capability seal) | **Mitigated (enforced at compile time).** A `Verified` `VerificationOutcome` can be minted **only** by the sealed `kya_core::verification::verify_signature` mint-point, which accepts **only a sanctioned verifier**: it is generic over a sealed `SanctionedVerifier` trait and additionally demands an unforgeable `VerifierSanction` capability token (private unnameable field; only constructor `grant::<V: SanctionedVerifier>()`). An external crate cannot satisfy the sealed supertrait, so a malicious always-`Verified` `SignatureVerifier` **cannot even be passed** to the mint-point — forgery is a compile error, not a runtime check. The single blessed implementor is `kya_crypto::Ed25519SignatureVerifier`. This capability seal **supersedes** the earlier framing in which trust-anchoring alone was the forgery defense: anchoring the genuinely-trusted key is the normal operating state, so a fake always-`Verified` verifier plus a legitimately-anchored key *would* have minted trusted evidence with no signature ever checked; the sanction seal closes exactly that. Trust-anchoring (`VerifiedDelegation::establish`, T-3) remains a necessary independent second gate. Tests: `verification.rs::{verify_signature_mints_verified_only_on_ok_verified,invalid_constructor_can_never_yield_verified,proof_gated_verified_requires_running_a_sanctioned_verifier}`, the collected compile-fail doc-tests on `VerificationProof`/`VerifierSanction`, the external-crate suite `forgery_regression.rs` (`malicious_verifier_answer_is_inert`), and `evidence.rs::malicious_always_verified_verifier_cannot_promote_untrusted_key`. |
| T-14 | Permissive fallback / silent authorization | the fail-closed bridge | Mitigated structurally: there is no `From<PolicyOutcome> for Decision`; the only path is the `authorize` bridge, which denies on error, timeout, unknown, or approval-required. |
| T-15 | Secrets or signatures leaking into logs | cross-cutting (Rule 18) | Policy: secrets, keys, and signatures must not be logged. The core and `kya-crypto` carry no logging that emits them, and error `Display` strings are fixed phrases. |
| T-16 | Panic on malformed untrusted input (denial of service) | cross-cutting (Rules 5, 6) | Mitigated: parsing, verification, and policy paths return typed errors and avoid `unwrap`/`expect`/panicking indexing in production code. `kya-crypto` additionally bounds untrusted input size and never panics on arbitrary bytes (`property_fuzz.rs`). |
| T-17 | Unsupported protocol version: a payload announced under a protocol version whose semantics this build does not implement is processed anyway | protocol boundary (precedes A) | Mitigated in `kya-protocol`: `check_supported_version` accepts only a matching major and a minor no greater than this build's, and rejects a newer major, a newer minor, or a malformed version string fail-closed with a typed `VersionError`. A transport/adapter runs this gate before decoding any wire body, so a payload under an unknown version is refused rather than partially interpreted. Tests: `kya-protocol` version unit tests and `version_gate.rs`. |

## Deny-by-default posture

The default answer is deny (Rule 9). The `Decision` type has no `Unknown` variant
that could be mistaken for a pass. In the `authorize` bridge, any static outcome
other than `EligibleForOnlineAuthorization` denies without contacting the
authority (this covers `InvalidEvidence`, `Denied`, `RequiresApproval`, and
`Indeterminate`), an authority `Denied` or `ApprovalRequired` denies, and any
authorizer error, timeout, or unknown state denies. `Allow` requires an explicit
authoritative approval. The five distinct stage-C result meanings and the proof
that only the eligible one is forwardable are recorded as INV-22 in
[security-invariants.md](security-invariants.md).

## Summary of honest gaps in v0.1.0

A concrete stage-B verifier now ships in `kya-crypto` (Ed25519 per RFC 8032 and
JWS-EdDSA per RFC 7515/7518/8037), so forged-signature, algorithm-confusion
(including the duplicate-`alg` and unsupported-`crit` JOSE hardening), audience,
validity-window, and binding threats (T-1, T-2, T-11, T-12) are mitigated for
callers who verify through it over the exact signed bytes. The former
verification-bypass defect (T-13) is now closed at compile time by the
sanctioned-verifier capability seal — not merely by trust-anchoring — so an
external always-`Verified` verifier can no longer mint trusted evidence. The
first protocol adapter (`kya-adapter-ap2`) maps AP2 constraint fields onto the
stage-C surface and reuses this engine; it adds no new trust surface. An
unsupported protocol version is rejected fail-closed at the protocol boundary
(T-17).

The SDK, on its own, still does **not** mitigate:

- replay, double-spend / cumulative-budget evasion, and revocation evasion
  (T-8, T-9, T-10 — all require stage-D online authoritative state), and
- unsafe execution (stage E ships as a seam, no concrete execution path).

It also does **not** claim AP2 wire compatibility: the real AP2 signature
envelope and algorithms are **[UNVERIFIED]**, so `kya-crypto` implements only
independently verifiable Ed25519 / JWS-EdDSA over caller-supplied exact bytes
(see [cryptographic-architecture.md](cryptographic-architecture.md) and
[protocol-compatibility.md](protocol-compatibility.md)). And an issuer-signed
delegation does not, by itself, prove the agent currently possesses its own
private key.

These remaining gaps are not oversights; they are the consequence of the central
limitation. They are addressed by supplying concrete stage-D and stage-E
implementations, as described in
[future-platform-architecture.md](future-platform-architecture.md). No
independent security audit or certification is claimed for the current code.
