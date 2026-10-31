# Cryptographic Architecture

This document describes the concrete cryptographic verification engine of the
FintechBear KYA SDK: the `kya-crypto` crate. It explains where the engine lives
and why, which algorithms it supports and which it rejects, the exact
verification semantics it enforces, and the honest boundaries on what it does
and does not establish. It is written to be consistent with, and to not
contradict, [architecture.md](architecture.md),
[trust-model.md](trust-model.md), [threat-model.md](threat-model.md),
[security-invariants.md](security-invariants.md), and
[protocol-compatibility.md](protocol-compatibility.md).

## Central limitation (restated, because it governs everything below)

A valid cryptographic signature is **not** an authorization. Verification in
`kya-crypto` establishes **authenticity, trust-anchoring, a validity window, an
audience, and a transaction binding**: the stage-A/B and static facts of the
model. It produces verified *evidence*
([`kya_core::evidence::VerifiedDelegation`]), never an `Allow`. Current
authoritative state (revocation, cumulative budget, global replay) is **stage
D** and lives in `kya-client`; `kya-crypto` never reaches it.

## Where the engine lives, and why

`kya-crypto` is an **outer-ring** crate. It depends **inward** on `kya-core`
and on nothing else in the repository, exactly as the dependency rule in
[architecture.md](architecture.md) requires (AGENTS.md Rule 2).

```
          +-------------------------------------------------+
          |   kya-crypto  (outer ring, concrete crypto)     |
          |  Ed25519SignatureVerifier (RFC 8032),           |
          |  JwsEdDsa (RFC 7515/7518/8037 compact JWS),     |
          |  TrustedKeyStore, verify_delegation             |
          |  #![forbid(unsafe_code)]                         |
          +------------------------+------------------------+
                                   | depends inward on
          +------------------------v------------------------+
          |                   kya-core                      |
          |  SignatureVerifier seam + sealed verify_signature|
          |  mint-point + VerifiedDelegation::establish     |
          |  (no I/O, no crypto dependency)                 |
          +-------------------------------------------------+
```

The concrete engine is deliberately kept **out of** `kya-core` for two reasons:

- **`kya-core` forbids `unsafe` and stays dependency-light.** Every in-repo
  crate begins with `#![forbid(unsafe_code)]`, and `kya-core` carries no
  cryptographic dependency at all. A reviewed cryptography crate may use
  `unsafe` transitively; that is acceptable for a dependency of an outer-ring
  crate, but it must not become a dependency of the auditable domain core
  (AGENTS.md Rules 2, 4, 13). Pushing concrete crypto outward keeps the core
  small, auditable, and free of third-party `unsafe`.
- **The core defines the seam; the ring implements it.** `kya-core` expresses
  signature verification only as the `SignatureVerifier` trait seam and provides
  no algorithm (AGENTS.md Rule 10). `kya-crypto` supplies the standard, reviewed
  algorithm behind that seam. `kya-crypto`'s own code still begins with
  `#![forbid(unsafe_code)]`; only its dependency may contain `unsafe`.

## The dependency choice: `ed25519-dalek`

The one external cryptographic dependency is `ed25519-dalek` 2.2.0, recorded
with its justification, license, and security rationale as AGENTS.md Rule 13
requires:

- **Justification.** Rule 10 forbids inventing cryptographic algorithms.
  `ed25519-dalek` is the de-facto standard, widely reviewed pure-Rust Ed25519
  implementation from the RustCrypto/dalek ecosystem. The engine uses **only**
  its verification path; it signs nothing in production code.
- **License.** Dual **MIT OR Apache-2.0**, compatible with this workspace's own
  MIT OR Apache-2.0 licensing.
- **Security rationale.** It implements **RFC 8032**. The engine verifies via
  the **strict** path (`VerifyingKey::verify_strict`), which rejects signature
  malleability (a non-canonical `S` component) and rejects small-order /
  non-canonical public keys, rather than the permissive `Verifier::verify`.
  This ensures a trust-anchored key cannot present a signature other than the
  canonical one the signer emitted. Verification is exposed so the SDK never
  touches raw curve arithmetic. The dependency may use `unsafe` transitively,
  which is acceptable for a reviewed dependency; `kya-crypto`'s own code forbids
  `unsafe` and the dependency is **not** added to `kya-core`.
- **Minimal surface.** Default features are disabled; only `std` is enabled. No
  `rand`, no `serde`, no `pkcs8`.

Two things are deliberately **not** pulled in, to keep the dependency set
minimal (Rule 13) and the untrusted-input decoders under the SDK's own
non-panicking control:

- **No base64 crate.** A strict, length-checked, unpadded base64url decoder
  (RFC 4648 §5) is implemented in-crate (the `b64url` module).
- **No JWT/JOSE framework.** The compact-JWS parse-and-verify is implemented
  directly against an explicit `EdDSA`-only allowlist, avoiding the
  algorithm-confusion-prone surface of general JWT libraries.

## The sealed path to verified evidence

The engine cannot mint evidence out of a boolean or an enum a caller passes in.
There is exactly one route to a [`kya_core::evidence::VerifiedDelegation`], and
it threads through the sealed mint-point in `kya-core`:

1. The concrete `Ed25519SignatureVerifier` is run **through**
   `kya_core::verification::verify_signature`, the **only** function that can
   produce a `VerificationOutcome` whose status is `Verified`. That mint-point
   accepts **only a sanctioned verifier**: it is generic over the sealed
   `SanctionedVerifier` trait and additionally requires an unforgeable
   `VerifierSanction` capability token (its single field is private and
   unnameable; its only constructor is `grant::<V: SanctionedVerifier>()`). An
   external crate cannot satisfy the sealed supertrait, so an arbitrary
   `SignatureVerifier` — including a malicious always-`Verified` one — **cannot
   even be passed** to the mint-point: the program will not compile. The one
   blessed implementor is `Ed25519SignatureVerifier`, sanctioned through the
   narrow `#[doc(hidden)]` `kya_core::sanction_verifier!` seam. The resulting
   verified outcome carries an unforgeable `VerificationProof` token whose
   constructor is `pub(crate)` inside `kya-core` and whose single field is a
   private, unnameable zero-sized marker, so the outcome also cannot be
   constructed directly.
2. Only with a genuine verified outcome does the engine call
   `kya_core::evidence::VerifiedDelegation::establish`, which independently
   re-checks that the outcome's issuer matches the claim and that the
   `(issuer, key_ref)` pair is present in the caller's `TrustAnchors`.

Because both steps are required and neither can be forged, the forgery vector is
closed from two independent directions. The sanctioned-verifier capability seal
means an always-`Verified` external verifier can never reach the mint-point in
the first place (a compile error); and even if a verified outcome is obtained
legitimately, `establish` still rejects an untrusted key with
`EvidenceError::UntrustedKey`. This supersedes the earlier framing in which
trust-anchoring alone was the defense: anchoring the genuinely-trusted key is the
normal operating state, so a fake always-`Verified` verifier plus an anchored key
*would* have minted trusted evidence with no signature ever checked — the sanction
seal is what closes exactly that. See [threat-model.md](threat-model.md) (T-13)
and [security-invariants.md](security-invariants.md) (INV-8, INV-18).

## Supported algorithms

The engine pins exactly one algorithm and rejects everything else:

- **Ed25519 (RFC 8032)** for raw detached signatures, via
  `Ed25519SignatureVerifier` (32-byte public key, 64-byte signature).
- **JWS compact serialization, EdDSA only (RFC 7515 / RFC 7518 / RFC 8037,
  `alg=EdDSA`)**, via `JwsEdDsa`, which verifies the Ed25519 signature over the
  exact RFC 7515 signing input.

The single accepted algorithm name is the constant
`kya_crypto::ACCEPTED_ALGORITHM` (`"EdDSA"`, the JOSE name for the Ed25519
instantiation per RFC 8037). Every other identifier is rejected with
`CryptoVerificationError::UnsupportedAlgorithm`:

- `alg: none` is rejected (no unsigned "verification" path exists);
- HMAC (`HS256`, …), RSA (`RS256`, …), and ECDSA (`ES256`, …) names are
  rejected;
- the empty string and any unknown identifier are rejected;
- case matters: `eddsa` is **not** accepted, only `EdDSA`.

This is the **algorithm-confusion and downgrade defense**: because the JWS
parser compares the header `alg` against a single allowlisted value before any
key or signature bytes are touched, an attacker cannot downgrade a token to an
unsigned or weaker algorithm, and cannot coerce a public key into being read as
an HMAC secret. The guarantees are locked in by
`crates/kya-crypto/tests/jws_security.rs` and the in-module tests in
`src/jws.rs` (`rejects_alg_none`, `rejects_non_eddsa_algorithms`).

### Two further JOSE hardening rules (duplicate `alg` and `crit`)

Beyond the allowlist, the compact-JWS protected-header handling closes two JOSE
smuggling vectors required by RFC 7515:

- **Duplicate top-level `alg` member.** The header scanner does not simply take
  the first `"alg"` it finds. It counts the real top-level `alg` **keys** (it
  skips over string *values*, so an `alg` substring inside another field's value
  is not mistaken for the key) and rejects a header carrying more than one `alg`
  member with `MalformedPayload`. This closes the attack in which a second or
  earlier duplicate `"alg"` pairing (for example `alg: none`) is smuggled past a
  naive first-match scan.
- **Unsupported `crit` (critical) header.** Per RFC 7515 §4.1.11 a `crit`
  member names header parameters the producer insists the consumer must
  understand. This verifier implements no JWS extensions, so a token that
  carries a `crit` member fails closed with `UnsupportedAlgorithm` rather than
  being verified while ignoring a parameter it was told it must honor.

Both are locked in by `jws.rs` unit tests
(`extract_alg_rejects_duplicate_alg_members`,
`extract_alg_ignores_alg_substring_inside_values`,
`reject_unsupported_crit_fails_closed_when_present`,
`verify_rejects_token_with_duplicate_alg`, `verify_rejects_token_with_crit_header`)
and by `tests/jws_security.rs`
(`duplicate_alg_member_is_rejected_not_first_match`,
`unsupported_crit_header_is_rejected`,
`alg_substring_inside_a_value_is_not_treated_as_the_key`).

## Verification semantics

### Exact-bytes signing input

The engine never guesses or canonicalizes what was signed. The caller supplies
the **exact** bytes:

- For **raw Ed25519**, `SignedClaim::signed_bytes` are the verbatim
  protocol-defined bytes the signer committed to.
- For **JWS-EdDSA**, `JwsEdDsa::verify` reconstructs the RFC 7515 signing input
  as `ASCII(BASE64URL(header) + "." + BASE64URL(payload))` and verifies the
  Ed25519 signature over precisely those bytes.

`kya-crypto` does **not** invent a canonicalization of `kya-protocol`'s wire
fields, which are not a standardized signed format. If a byte differs, the
signature does not verify; there is no tolerance or normalization step.

### Audience, validity window, and binding

`verify_delegation` validates, in strict fail-closed order and each with a
distinct structured error:

- **Audience.** `SignedClaim::audience` must exactly equal the expected
  audience, or `AudienceMismatch`. This stops a claim minted for one audience
  from being replayed against another.
- **Not-before / expiration.** The current time is **injected** as a `now: u64`
  (unix seconds); the engine never reads the system clock, so verification is
  deterministic and testable. `now < not_before` yields `NotYetValid`;
  `now >= expires_at` yields `Expired` (expiry is exclusive). Comparisons are
  checked integer comparisons with no subtraction, so extreme values cannot
  overflow or panic.
- **Binding.** `SignedClaim::binding` must match the presented
  `expected_binding` **byte for byte**, or `BindingMismatch`. This binds a
  verified signature to the specific transaction so a signature captured for one
  action cannot authorize a different action or amount.

Untrusted inputs are also size-bounded before heavy work: signed bytes,
signature, and binding each above 256 KiB, or a compact JWS above 64 KiB, are
rejected with `OversizedInput`.

### Structured failure taxonomy

Every failure path returns a `CryptoVerificationError`, a `#[non_exhaustive]`
enum implementing `Display` and `std::error::Error`. No variant carries secrets,
key bytes, signatures, or raw attacker payload (AGENTS.md Rule 18); each is a
flat description of the failure class, and each maps to a stable
`kya_core::error::ErrorCode` via `AsErrorCode`. The variants are:

| `CryptoVerificationError` | `ErrorCode` string | Meaning |
|---|---|---|
| `UnsupportedAlgorithm` | `verification-unsupported-algorithm` | `alg` not on the EdDSA allowlist (`none`/HMAC/RSA/ECDSA/empty/other) |
| `MalformedKey` | `verification-malformed-key` | public key not a valid 32-byte Ed25519 key |
| `MalformedSignature` | `verification-malformed-signature` | signature not a valid 64-byte Ed25519 signature |
| `SignatureInvalid` | `verification-signature-invalid` | well-formed but did not verify |
| `UnknownIssuer` | `verification-unknown-issuer` | issuer absent from the key store |
| `UntrustedKey` | `verification-untrusted-key` | `(issuer, key_ref)` not an anchored trust |
| `AudienceMismatch` | `verification-audience-mismatch` | audience did not exactly match |
| `Expired` | `verification-expired` | `now >= exp` |
| `NotYetValid` | `verification-not-yet-valid` | `now < nbf` |
| `BindingMismatch` | `verification-binding-mismatch` | transaction binding did not match |
| `MalformedPayload` | `verification-malformed-payload` | undecodable/unparsable untrusted payload |
| `OversizedInput` | `verification-oversized-input` | input exceeded the size bound |

A genuine non-match is `SignatureInvalid`, never silently rounded up to
verified; malformed key or signature bytes are their own distinct errors; and a
near-miss never surfaces as success.

### Seven distinct properties (verification yields evidence, never an Allow)

The engine is explicit that the following are **different properties**, proven
by different mechanisms. Confusing any one for the final answer is the defect
the whole architecture guards against:

1. **Valid signature** — the bytes are authentic under *some* key. Proven by
   `Ed25519SignatureVerifier` (stage B). Authenticity only.
2. **Trusted key** — the verifying key is allow-listed for the issuer. Proven by
   `TrustedKeyStore` resolution **and** `TrustAnchors::trusts_key`. A valid
   signature over an untrusted key is still untrusted.
3. **Authorized issuer** — the issuer is one the deployment accepts delegations
   from (stage A). Proven by the issuer being anchored; an unknown issuer fails
   closed.
4. **Valid delegation scope** — the requested action/amount/currency fall inside
   the mandate the issuer granted. This is **stage C** static policy
   (`kya_core::policy`), not something `kya-crypto` decides.
5. **Verified agent key possession** — proof that the *agent* currently controls
   its own private key. `kya-crypto` verifies the **issuer's** signature over the
   delegation; see "Known limitations" below. An issuer-signed delegation does
   **not**, by itself, prove present agent key possession.
6. **Static transaction eligibility** — the combined stage-C verdict that a
   specific request is statically within the mandate. A
   `PolicyOutcome::EligibleForOnlineAuthorization` is still **not** an
   authorization.
7. **Authoritative financial authorization** — the only property that can yield
   an `Allow`, and only via the fail-closed `kya_client::authorize` bridge after
   a stage-D `OnlineAuthorizer` ruling on revocation, budget, and replay.

`kya-crypto` establishes (1), (2), (3), the validity window, and the binding,
and returns evidence. Properties (4) and (6) are stage C; (7) is stage D.
Nothing in this crate can produce a `Decision::Allow`.

## Known limitations

These limits are structural, not oversights, and are stated plainly to satisfy
AGENTS.md Rule 20:

- **No AP2 wire compatibility is claimed.** Per
  [first-adapter-decision.md](first-adapter-decision.md), the real AP2 signature
  envelope and its accepted algorithms are **[UNVERIFIED]**. `kya-crypto`
  therefore implements only **independently verifiable** primitives — raw
  detached Ed25519 and JWS-EdDSA over **caller-supplied exact bytes** — and makes
  no claim of parsing or verifying real AP2 mandates. It does not invent a
  canonicalization of `kya-protocol`'s wire fields.
- **Revocation, cumulative budget, and replay are stage D only.** Offline
  verification cannot establish current global state. The nbf/exp window and the
  audience check narrow a replay window but do not establish global non-replay;
  that remains an `OnlineAuthorizer` concern.
- **Issuer-signed delegation is not proof of current agent key possession.**
  `verify_delegation` verifies the issuer's signature over the delegation claim.
  That the issuer signed a delegation naming an agent does **not** prove the
  agent currently holds its own private key. Request-level proof of possession
  requires the agent to sign request-specific bytes, verified through the same
  seam, and is a separate step.
- **No certification or audit is claimed.** No independent security audit or
  certification of this engine exists, and no vendor affiliation or endorsement
  is claimed.

## Regression tests

The security properties above are locked in by tests, so a regression is a CI
failure rather than a silent weakening (AGENTS.md Rules 14, 15, 17, 22):

- `crates/kya-crypto/tests/rfc8032_conformance.rs` — the official RFC 8032 §7.1
  Ed25519 vectors (empty-message and non-empty), transcribed verbatim and
  cross-checked by independent derivation from the RFC seed.
- `crates/kya-crypto/tests/engine_security.rs` — the full `verify_delegation`
  taxonomy: happy path plus tampering, wrong key, unknown issuer, untrusted key,
  audience mismatch, not-yet-valid, expired, binding mismatch, oversized input,
  and the structural guarantee that no path forges a `VerifiedDelegation`.
- `crates/kya-crypto/tests/jws_security.rs` — JWS allowlist enforcement:
  `alg: none` and non-EdDSA algorithms rejected, tampered payload rejected,
  wrong segment count and oversized input rejected.
- `crates/kya-crypto/tests/property_fuzz.rs` — randomized, dependency-free
  property/fuzz inputs asserting the engine never panics on arbitrary bytes.
- The sealed-path unit tests in `crates/kya-core/src/verification.rs`
  (`verify_signature_mints_verified_only_on_ok_verified`,
  `invalid_constructor_can_never_yield_verified`) and
  `crates/kya-core/src/evidence.rs`
  (`malicious_always_verified_verifier_cannot_promote_untrusted_key`).
