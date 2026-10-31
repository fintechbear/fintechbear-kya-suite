# Trust Model

This document defines the trust model for the FintechBear KYA SDK: the trust
boundaries, who is treated as an authority for what, how an agent proves it is
the legitimate holder of a mandate, how a transaction is bound to that mandate,
and the hard limits on what offline evaluation can and cannot establish. It is
written to be consistent with, and to not contradict,
[threat-model.md](threat-model.md) and [architecture.md](architecture.md).

It is scoped against the first selected protocol adapter (AP2, see
[first-adapter-decision.md](first-adapter-decision.md)) but states the general
model; AP2-specific mapping is in
[protocol-compatibility.md](protocol-compatibility.md).

## Central limitation (restated, because it governs everything below)

A valid cryptographic signature is **not** an authorization. A signature proves
the authenticity and integrity of some bytes. It says nothing about whether the
delegating mandate is still valid, whether a budget is exhausted, or whether a
request is a replay. **Offline verification cannot establish current revocation
state, cumulative budget state, or global replay state**; those facts are global
and mutable and require trustworthy authoritative evidence obtained online
(stage D). Any design decision below that seems to "trust a signature" is really
trusting authenticity only, never current authority.

## Trust boundaries

1. **Untrusted input boundary.** Mandates, transaction requests, protocol
   messages, signatures, and keys arriving from an agent or the network are
   attacker-controlled. Everything crossing into the SDK from this boundary must
   be parsed without panicking and must yield typed errors on malformed input
   (AGENTS.md Rules 5, 7). Nothing from this boundary is trusted until it has
   been verified against a configured trust anchor and checked by policy.

2. **Trust-anchor boundary.** Only issuers that have been explicitly added to a
   `TrustAnchors` set are trusted. This is enforced in code: `TrustAnchors::new`
   trusts nothing, and `is_trusted`/`trusts_key` return true only for an issuer
   or `(issuer, key_ref)` pair that was deliberately added. There is no implicit,
   inherited, or wildcard trust (AGENTS.md Rule 11). An assertion from an unknown
   or unlisted issuer is outside the trust boundary regardless of how well-formed
   or well-signed it is.

   The concrete engine adds an **explicit key-byte registry**,
   `kya_crypto::TrustedKeyStore`, that maps an `(issuer, key_ref)` pair to its
   32-byte Ed25519 public key. The store is populated by the caller up front;
   there is **no** URL fetching and **no** wildcard, prefix, or fallback match.
   Resolution and trust are two independent checks and **both** are required: a
   key must be resolvable in the `TrustedKeyStore` **and** anchored in
   `TrustAnchors` before any verified evidence is minted. Registering bytes in
   the store does not by itself make a key trusted. See
   [cryptographic-architecture.md](cryptographic-architecture.md).

   The `kya-sdk` facade bundles these two allow-listed inputs together in a
   single `TrustConfiguration` value (`trust_issuer_key(issuer, key_ref,
   &public_key_bytes)` registers the bytes and anchors the pair in one call,
   exposing `anchors()` and `key_store()` for the verifier). This makes the
   "anchor **and** register, both required" rule hard to get half-right, but it
   introduces **no** new trust: it is still explicit, allow-listed, wildcard-free,
   and performs no key discovery.

3. **Offline / online boundary.** The offline stages (A identity, B signature
   verification as a seam, C static policy) run inside your process and can be
   evaluated with no network. Current authoritative state (revocation, cumulative
   budget, replay) lives on the far side of the stage-D boundary, behind an
   `OnlineAuthorizer`. Crossing from "offline looks fine" to "authorized" is only
   possible through the fail-closed `kya_client::authorize` bridge.

4. **Core / edge boundary.** `kya-core` performs no I/O and carries no
   cryptographic dependency. All transport, concrete cryptography, and execution
   cross a trait-seam boundary (`SignatureVerifier`, `OnlineAuthorizer`,
   `IntegrationClient`). Code on the edge side of this boundary is where external
   dependencies and their risks live; the core stays auditable and
   dependency-light. The concrete Ed25519 / JWS-EdDSA verifier lives in the
   outer-ring `kya-crypto` crate, which depends inward on `kya-core` and whose
   own code still forbids `unsafe`. The first protocol adapter,
   `kya-adapter-ap2`, is likewise an outer-ring crate depending inward on
   `kya-core` and `kya-crypto`; it maps AP2 mandate *constraints* onto the
   stage-C surface and adds no new trust surface (the byte-for-byte AP2 wire
   envelope is `[UNVERIFIED]`/BLOCKED, so it never introduces a wildcard trust
   path or an attacker-controlled key source).

## Issuer authority

- An **issuer** is the party that delegates authority to an agent by creating a
  mandate. In the KYA domain the issuer is modelled as an explicit `IssuerId`.
- Issuer authority is **not inherent**. An issuer is authoritative for a mandate
  only if (a) the issuer is in the configured `TrustAnchors`, and (b) the
  mandate's signature verifies against that issuer's key material through the
  stage-B `SignatureVerifier` seam. Both conditions are necessary; neither alone
  is sufficient.
- Being a trusted issuer authorizes **delegation**, not **execution**. A mandate
  signed by a trusted issuer still only sets static constraints that stage C
  checks. Whether a specific transaction may proceed now remains a stage-D
  question (revocation/budget/replay), because the issuer's past signature cannot
  speak to present state.
- **A malicious verifier cannot promote an untrusted key.** Trust is established
  independently of authenticity, and the forgery vector is now closed from two
  directions. First, the sealed `verify_signature` mint-point accepts **only a
  sanctioned verifier** (a sealed `SanctionedVerifier` trait plus an unforgeable
  `VerifierSanction` capability token), so an arbitrary `SignatureVerifier` that
  always returns `Verified` cannot even be passed to it — that is a compile
  error, not a runtime check — and the single blessed implementor is
  `kya_crypto::Ed25519SignatureVerifier`. Second, even a legitimately-obtained
  authenticity outcome is not trust: `VerifiedDelegation::establish` re-checks,
  on its own, that the verifying `(issuer, key_ref)` pair is anchored in
  `TrustAnchors`, so a resolvable-but-unanchored key still fails closed with
  `EvidenceError::UntrustedKey`, and the concrete `kya-crypto` engine
  additionally requires the pair to resolve in the explicit `TrustedKeyStore`.
  Neither a dishonest verifier nor a resolvable-but-unanchored key can cross the
  trust boundary. This is locked in by
  `malicious_always_verified_verifier_cannot_promote_untrusted_key`
  (`kya-core/src/evidence.rs`), the external-crate
  `kya-crypto/tests/forgery_regression.rs`, and the untrusted-key cases in
  `kya-crypto/tests/engine_security.rs`.
- For the AP2 adapter, issuer/credential-authority mapping onto `TrustAnchors`
  and the exact key-distribution mechanics are an open implementation question
  and are **[UNVERIFIED]** until read from AP2's schemas; see
  [first-adapter-decision.md](first-adapter-decision.md).

## Agent proof of possession

- A mandate names the agent it was issued to (an `AgentId`). An incoming
  transaction request also carries the acting `AgentId`. Stage C already rejects
  a request whose acting agent does not match the mandate's agent
  (an agent-mismatch rejection).
- Name-matching alone is weak: anyone can *claim* to be a given agent. Genuine
  **proof of possession** requires the agent to demonstrate control of the
  private key bound to its identity, verified through the stage-B
  `SignatureVerifier` seam over request-specific bytes. A concrete verifier now
  exists (`kya-crypto`'s Ed25519 / JWS-EdDSA engine), but proof-of-possession
  strength still depends on *what bytes are signed by whom*.
- **Issuer-signed delegation is not, by itself, agent proof of possession.**
  `kya_crypto::verify_delegation` verifies the **issuer's** signature over a
  delegation claim naming an agent. That the issuer signed such a delegation does
  **not** prove the agent currently controls its own private key. Present agent
  proof of possession requires the agent to sign request-specific bytes,
  verified through the same seam, as a separate step.
- Proof of possession establishes **authenticity** of the request from that
  agent. It does **not** establish that the agent's authority is still valid
  (not revoked), within budget, or non-replayed. Those remain stage D.

## Transaction binding

- A verified signature must bind to the **specific transaction**, not merely to
  the agent's identity or to the mandate in the abstract. Binding is what stops a
  signature captured for one action from authorizing a different action or
  amount.
- In the KYA domain, the elements that must be bound together are: the acting
  agent, the requested action, and the exact amount and currency (`Money`,
  integer minor units plus an explicit ISO-4217 currency; no floats, checked
  arithmetic, cross-currency rejected per AGENTS.md Rule 8). Stage C checks that
  the requested action is within the mandate's scope and that the amount does not
  exceed the mandate's per-transaction limit, and it fails closed on a currency
  mismatch.
- For request-level binding over a transport, RFC 9421 (HTTP Message Signatures)
  is the adopted primitive: it binds a signature to selected HTTP message
  components so a request cannot be silently altered or re-pointed. The concrete
  binding of AP2 mandate fields is **[UNVERIFIED]** until the AP2 schemas are
  read.
- The concrete `kya-crypto` engine enforces binding directly: `verify_delegation`
  compares the signer's committed binding bytes against the presented
  transaction binding **byte for byte** (no tolerance, no float), failing closed
  with `BindingMismatch` on any difference. It also enforces an exact-match
  audience and an injected-`now` nbf/exp window. The engine verifies over the
  **exact caller-supplied bytes** (verbatim for raw Ed25519, or the RFC 7515
  signing input for JWS-EdDSA) and does **not** invent a canonicalization of
  `kya-protocol` wire fields; see
  [cryptographic-architecture.md](cryptographic-architecture.md).

## Replay limitations

- **Replay cannot be prevented by offline evaluation.** Whether a given request
  has already been processed is global, mutable state. Two independently valid-
  looking copies of the same signed request are indistinguishable offline.
- Replay is therefore a **stage-D** concern. An `OnlineAuthorizer` with
  authoritative, consistent state is required to detect and reject a replay. The
  open-source core does **not** mitigate replay; this is a documented gap in
  [threat-model.md](threat-model.md), not an oversight.
- Narrow, non-authoritative aids (for example a nonce or timestamp carried in a
  bound signature) can *reduce* a replay window but cannot *establish* global
  non-replay. They must never be treated as authorization.

## Revocation limitations

- **Revocation cannot be established offline.** A mandate that was valid when
  signed may have been revoked since. Offline logic has no way to know. A revoked
  mandate can still produce a perfectly valid signature and a passing stage-C
  outcome.
- Revocation is a **stage-D** concern: the `OnlineAuthorizer` consults current
  authoritative revocation state and returns `Denied` for a revoked mandate,
  which the bridge maps to `Deny`. The open-source core does **not** mitigate
  revocation evasion; documented gap.

## Offline vs online authorization

- **Offline (stages A, B, C)** can establish: issuer is trust-anchored (A),
  signature authenticity/integrity and agent proof of possession (B, via the
  seam), and static conformance to the mandate's scope, per-transaction limit,
  currency, and agent binding (C). The product of offline evaluation is a
  `PolicyOutcome`, which is explicitly **not** an authorization.
- **Online (stage D)** is the only stage that can establish current revocation,
  cumulative budget, and global replay state, and is the only stage that can
  yield an `Allow`. It is reached only through the fail-closed
  `kya_client::authorize` bridge and an `OnlineAuthorizer`.
- There is deliberately **no** `From<PolicyOutcome> for Decision` implementation
  anywhere in the SDK (AGENTS.md Rule 12). The type system itself prevents the
  shortcut from "statically fine" to "authorized".

## Error and verification semantics

The model is **deny-by-default and fail-closed** (AGENTS.md Rule 9). Concretely,
grounded in the current code:

- **Signature verification (stage B)** returns a binary
  `VerificationStatus` (`Verified` / `Invalid`); malformed keys/signatures or an
  unsupported algorithm return a typed `VerificationError`, never a silent pass
  and never a panic. A genuine non-match is `Ok(Invalid)`, not an error, so the
  two cases cannot be confused. The concrete `kya-crypto` engine refines this
  into a richer structured taxonomy (`CryptoVerificationError`: unsupported
  algorithm, malformed key, malformed signature, invalid signature, unknown
  issuer, untrusted key, audience mismatch, expired, not-yet-valid, binding
  mismatch, malformed payload, oversized input), each mapping to a stable
  `ErrorCode`, with no secrets in any message. A `Verified` outcome is minted
  **only** by the sealed `verify_signature` mint-point and cannot be fabricated
  by an untrusted caller.
- **Static policy (stage C)** returns a `PolicyOutcome` that is either `Passed`
  or `Rejected` with a `ReasonCode` (for example action-not-permitted,
  amount-exceeds-limit, agent-mismatch, currency-mismatch). `Passed` is not an
  allow.
- **The bridge (`authorize`)** maps outcomes to a final `Decision` fail-closed:
  a non-`Passed` outcome denies immediately and never contacts the authority;
  an authority `Approved` maps to `Allow`; `Denied` and `ApprovalRequired` map to
  `Deny`; and any authorizer error, timeout, or uninterpretable response maps to
  `Deny`. The `Decision` type has no `Unknown` variant that could be mistaken for
  a pass.
- **No secret leakage.** Secrets, keys, and signatures are never logged
  (AGENTS.md Rule 18); error types describe the failure class, not the sensitive
  bytes.

## Relationship to the threat model

This document defines the trust model; [threat-model.md](threat-model.md)
enumerates adversaries, threats, and the honest gaps in the open-source core.
They are intended to agree. A concrete stage-B verifier now exists in
`kya-crypto` (Ed25519 / JWS-EdDSA), so forged-signature and algorithm-confusion
threats are mitigated for callers who use it over the exact signed bytes. Where
the threat model still lists a mitigation as a "documented gap" (replay;
double-spend; revocation; unsafe execution), this trust model explains *why*
that gap is structural: those facts live on the far side of a trust boundary
that offline evaluation cannot cross.
