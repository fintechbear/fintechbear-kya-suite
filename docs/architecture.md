# Architecture

FintechBear KYA follows clean architecture: dependencies point inward toward the
domain core, and I/O-bound concerns live at the edges behind traits. This
document describes the layering realized by the crates and the five
non-interchangeable authorization stages.

## The dependency rule

Dependencies point inward toward `kya-core` (AGENTS.md Rule 2).

```
          +-------------------------------------------------+
          |                  kya-client                     |
          |  stage-D OnlineAuthorizer seam, stage-E         |
          |  IntegrationClient seam, fail-closed authorize  |
          |  bridge, runtime-agnostic block_on              |
          +------------------------+------------------------+
                                   | depends on
          +------------------------v------------------------+
          |                 kya-protocol                    |
          |  protocol version marker + wire shapes that     |
          |  reference core domain types                    |
          +------------------------+------------------------+
                                   | depends on
          +------------------------v------------------------+
          |                   kya-core                      |
          |  domain + money + identity/trust + scope +      |
          |  mandate + SignatureVerifier description seam + |
          |  evidence (raw claims + view traits) +          |
          |  stage-C policy + Decision/PolicyOutcome        |
          |  (no I/O; depends on nothing in-repo; no crypto)|
          +------------------------^------------------------+
                                   | depends inward on
          +------------------------+------------------------+
          |                  kya-crypto                     |
          |  concrete outer-ring crypto engine: Ed25519     |
          |  (RFC 8032) + JWS-EdDSA (RFC 7515/7518/8037)    |
          |  verification + TrustedKeyStore + the restricted|
          |  verify_delegation path to verified evidence    |
          |  (crate-private verified-evidence mint-points)  |
          +-------------------------------------------------+

          +-------------------------------------------------+
          |                kya-adapter-ap2                  |
          |  outer-ring AP2 *constraint* adapter: map AP2   |
          |  action/amount/currency/identities onto kya-core|
          |  Mandate/Scope/Money; verify via kya-crypto over|
          |  caller-supplied exact bytes (envelope BLOCKED) |
          |          depends inward on kya-core + kya-crypto |
          +-------------------------------------------------+
```

`kya-core` depends on nothing in the repository and performs no I/O: no HTTP, no
database, no cloud, no payment provider, and no cryptographic dependency.
`kya-protocol` and `kya-client` may depend on `kya-core`. `kya-client` also
depends on `kya-protocol`. The `kya-crypto` outer-ring crate depends **inward**
on `kya-core` only, and supplies the concrete cryptography the core refuses to
carry. The `kya-adapter-ap2` outer-ring crate depends **inward** on `kya-core`
and `kya-crypto` only, adds no HTTP/DB/cloud/endpoint dependency, and implements
the independently-verifiable AP2 constraint surface (the byte-for-byte AP2 wire
envelope is `[UNVERIFIED]`/BLOCKED; see the adapter section below). Concrete
crypto, HTTP, DB, and cloud code live outside the core, behind traits. Library
crates do not depend on examples. The cryptographic engine is described in detail
in [cryptographic-architecture.md](cryptographic-architecture.md).

## The `kya-sdk` public facade

The `kya-sdk` crate is the outermost ring: a thin, curated public **facade**
that re-exports a stable surface over `kya-core`, `kya-crypto`, and `kya-client`
so a consumer can run the whole verify + evaluate + authorize flow from one
import (`use kya_sdk::prelude::*;`). It depends **inward** on those three crates
and obeys the dependency rule.

The facade adds **no** new behaviour and **no** new trust: it never implements
cryptography, never performs I/O, and never exposes a constructor that mints
verified evidence without real verification. It bundles the two things
verification needs in `TrustConfiguration` (the `TrustAnchors` and the
`TrustedKeyStore`), and it exposes `requires_online_authorization` and
`online_state_is_unestablished` helpers that make "eligibility is not
authorization" explicit. It deliberately exposes no boolean-only authorization
API and no `From<PolicyOutcome> for Decision`. The experimental AP2 adapter is
deliberately **not** re-exported from the facade.

```
          +-------------------------------------------------+
          |         kya-sdk  (outermost-ring facade)        |
          |  curated re-exports of kya-core/kya-crypto/     |
          |  kya-client; TrustConfiguration bundling;       |
          |  eligibility-not-authorization helpers; no new  |
          |  behaviour, no new trust                        |
          +------------------------+------------------------+
                                   | depends inward on
          +------------------------v------------------------+
          |     kya-core / kya-crypto / kya-client          |
          |     (see the dependency rule above)             |
          +-------------------------------------------------+
```

## Separation of concerns

The user-facing concerns are separated as follows:

- **Protocol and domain types.** `kya-core` holds the value types (identity,
  scope, mandate, money, decision). `kya-protocol` holds the language-independent
  protocol version marker (and a fail-closed `check_supported_version` gate that
  rejects an unsupported peer version before any wire body is decoded) and the
  wire shapes that reference those domain types, so the wire and the domain
  cannot drift apart.
- **Cryptographic verification (trait seam + concrete engine).** The core
  expresses signature verification only as the
  `kya_core::verification::SignatureVerifier` trait and implements no
  cryptographic algorithm. The concrete, standard, reviewed engine lives in the
  **`kya-crypto` outer-ring crate** (AGENTS.md Rule 10), which supplies Ed25519
  (RFC 8032) and JWS-EdDSA verification behind that seam. `kya-crypto` also owns
  the crate-private verified-evidence mint-points (`run_verifier`, the verified
  `VerificationOutcome` constructor, and `VerifiedDelegation::establish` /
  `VerifiedMandate::establish`), bound to its one concrete verifier, so a
  verified outcome cannot be forged by an outside crate; `kya-core` holds only
  the description seam. See
  [cryptographic-architecture.md](cryptographic-architecture.md).
- **Identity and trust evaluation.** `kya_core::identity`, with explicit,
  allow-listed trust anchors. Trust is never implicit or wildcard (Rule 11).
- **Delegated authority verification.** `kya_core::mandate` and
  `kya_core::scope` express what an issuer delegated to an agent and the limits
  on it.
- **Static policy evaluation.** `kya_core::policy` is the deterministic, offline
  evaluator. Over verified delegation evidence it runs the twelve-check matrix
  (verified agent, trusted issuer, principal, validity window, audience, exact
  transaction binding, action, merchant, resource, currency, per-transaction
  limit, human approval) and produces one of five `PolicyOutcome` meanings
  (`InvalidEvidence`, `Denied`, `RequiresApproval`, `Indeterminate`,
  `EligibleForOnlineAuthorization`). It performs no I/O and reads no system
  clock.
- **External integration clients.** `kya_client` holds the online authoritative
  seam (`OnlineAuthorizer`, stage D) and the execution seam
  (`IntegrationClient`, stage E) as traits only. It is the only async crate, and
  it provides a runtime-agnostic pure-`std` `block_on` so no async runtime is
  imposed.

Per AGENTS.md Rule 1 (YAGNI), the SDK does not introduce abstractions for
hypothetical future features. The trait seams exist because the core genuinely
cannot perform those concerns offline, not as speculative extensibility.

## The five non-interchangeable stages

Authorization is decomposed into five stages that must never be conflated,
reordered into a shortcut, or collapsed into one another.

| Stage | Name                                | Where                                        | Can it yield Allow? |
|-------|-------------------------------------|----------------------------------------------|---------------------|
| A     | Identity                            | `kya_core::identity`                         | No                  |
| B     | Signature verification (seam + engine) | `kya_core::verification` + `kya-crypto`    | No                  |
| C     | Static policy evaluation (offline)  | `kya_core::policy`                           | No                  |
| D     | Online authoritative authorization  | `kya_client::OnlineAuthorizer` + `authorize` | Yes                 |
| E     | Execution enforcement               | integration layer (`IntegrationClient` seam) | No                  |

- **Stage A - Identity.** Resolve who the agent and issuer claim to be, against
  explicit trust anchors.
- **Stage B - Signature verification.** Verify the cryptographic authenticity of
  the signed mandate or request. `kya-core` defines the description seam only;
  the concrete Ed25519 / JWS-EdDSA engine, and the crate-private verified-evidence
  mint-points, are in the outer-ring `kya-crypto` crate (see
  [cryptographic-architecture.md](cryptographic-architecture.md)). A verified
  signature is **not** an authorization.
- **Stage C - Static policy evaluation.** Deterministic, offline scope and limit
  checks producing a `PolicyOutcome`. An `EligibleForOnlineAuthorization`
  outcome is **not** an authorization; it is only eligibility to proceed to
  stage D.
- **Stage D - Online authoritative authorization.** Revocation, cumulative
  budget, and global replay state, established via an authority. This is the only
  stage that can yield an `Allow`.
- **Stage E - Execution enforcement.** The integration layer enforces that only
  an authorized `Decision` is ever executed.

## The fail-closed bridge

The central security distinction: a valid cryptographic signature is **not**
sufficient to authorize a financial transaction, and **offline verification
cannot establish current revocation state, cumulative budget state, or global
replay state** without trustworthy authoritative evidence obtained online.

This is enforced structurally, not just by convention:

- There is deliberately **no** `From<PolicyOutcome> for Decision` implementation
  anywhere in the SDK.
- The only bridge from a stage-C `PolicyOutcome` to a final `Decision` is the
  fail-closed `kya_client::authorize` function. It never contacts the authority
  when the static outcome already rejected; it maps an authority `Approved` to
  `Allow`; and it maps `Denied`, `ApprovalRequired`, and any authorizer error,
  timeout, or unknown state to `Deny`.

Because the coercion from "statically fine" to "authorized" is absent at the
type level, a developer cannot accidentally take the shortcut the security model
forbids.

## Deny-by-default

The default answer is deny (AGENTS.md Rule 9). The `Decision` type has no
`Unknown` variant that could be mistaken for a pass, and every error path in the
`authorize` bridge resolves to `Deny`. `Allow` requires an explicit authoritative
approval.

## Protocol adapter design (AP2 constraint adapter implemented; wire envelope BLOCKED)

The first protocol adapter targets the Google Agent Payments Protocol (AP2). The
selection and its evidence are in
[first-adapter-decision.md](first-adapter-decision.md); the honesty boundary on
what is claimed versus implemented is in
[protocol-compatibility.md](protocol-compatibility.md). **The
independently-verifiable AP2 *constraint* adapter now ships as the outer-ring
`kya-adapter-ap2` crate**: it models the AP2 mandate constraint concepts
(permitted action, exact amount, currency, identities, validity, audience,
approval, binding) as explicit Rust types, maps them onto the `kya-core`
`Mandate`/`Scope`/`Money` domain so the unchanged stage-C evaluator runs on them,
and routes stage-B verification through `kya-crypto` over caller-supplied exact
bytes. What remains **`[UNVERIFIED]`/BLOCKED** is the byte-for-byte AP2 signature
**envelope** and AP2 test-vector conformance (see ADR-0001): the adapter parses
no real AP2 token and claims no AP2 wire compatibility. The outer-ring
`kya-crypto` crate is a protocol-independent cryptographic engine (see
[cryptographic-architecture.md](cryptographic-architecture.md)), **not** an AP2
adapter: it verifies Ed25519 / JWS-EdDSA signatures over caller-supplied exact
bytes and parses no AP2 object. This section describes the adapter's layering,
which the implemented crate follows.

### Where the adapter lives

The `kya-adapter-ap2` crate lives in the **outer ring** and depends **inward**
on `kya-core` (and on `kya-crypto` as the stage-B primitive). It obeys the
dependency rule exactly as the existing crates do:

```
          +-------------------------------------------------+
          |   kya-adapter-ap2  (outer ring, IMPLEMENTED)    |
          |  map AP2 mandate constraints onto kya-core      |
          |  domain types; verify via kya-crypto over       |
          |  caller-supplied exact bytes                    |
          +------------------------+------------------------+
                                   | depends inward on
          +------------------------v------------------------+
          |     kya-core / kya-protocol / kya-client        |
          |     (unchanged; see the dependency rule above)  |
          +-------------------------------------------------+
```

The adapter MUST NOT introduce HTTP, database, cloud, or payment-provider
dependencies into `kya-core` (AGENTS.md Rule 2). Any transport or concrete
cryptography it needs is its own concern, in the outer ring, behind the core's
existing trait seams.

### How AP2 concepts map onto the stage model

- **AP2 mandates (Checkout Mandate, Payment Mandate; Open and Closed states)**
  are parsed by the adapter into explicit Rust types, then translated into the
  `kya-core` domain: the mandate's issuer to an `IssuerId` checked against
  `TrustAnchors` (stage A), the permitted action/amount/currency to
  `Scope`/`Money` inside a `Mandate` (the inputs to stage C).
- **Mandate signatures** are verified through the existing
  `kya_core::verification::SignatureVerifier` seam, using a standard, reviewed
  crypto crate supplied by the adapter. The core gains no algorithm (stage B,
  Rule 10).
- **Static conformance** (action in scope, amount within the per-transaction
  limit, matching currency and agent) runs through the unchanged
  `kya_core::policy` evaluator, producing a `PolicyOutcome` (stage C).
- **Issuer authorization, revocation, cumulative budget, replay** remain
  **stage D**: an `OnlineAuthorizer` ruling reached only through the fail-closed
  `kya_client::authorize` bridge. A verified AP2 mandate is **not** an `Allow`.

### What the adapter deliberately is not

- It is not a second authorization path. It feeds the existing stages; it does
  not bypass the bridge and cannot synthesize an `Allow`.
- It is not a universal mandate standard. It maps **one** concrete protocol onto
  the existing domain types. The project does not invent, and does not claim, a
  universal mandate format.
- It is not a networked client in the core. AP2 mandate verification is
  offline-evaluable; any end-to-end AP2 transport belongs to the outer ring or to
  a stage-D/stage-E integration behind the seams.

### Supporting primitive: RFC 9421

RFC 9421 (HTTP Message Signatures) is adopted as a candidate implementation of a
request-signing `SignatureVerifier` where request-level binding over HTTP is
needed. It is an open IETF standard and the mechanism Visa TAP builds on, so it
keeps a future Visa TAP adapter incremental. It is a verification primitive, not
an authorization authority.
