# First Adapter Decision (ADR-0001)

- **Status:** Accepted. The decision below (AP2 as the first adapter target) is
  unchanged. A later change implemented the independently-verifiable AP2
  **constraint** adapter (`kya-adapter-ap2`); the AP2 wire envelope remains
  `[UNVERIFIED]` / BLOCKED (see the status section at the end).
- **Date:** 2026-10-30.
- **Decides:** which single protocol the KYA SDK targets for its **first**
  protocol adapter.
- **Does not decide:** any implementation. No adapter is built in this change,
  and no universal mandate standard is invented.

This ADR is the evidence-backed selection required by the task. The full
cross-protocol research it rests on is in
[protocol-research.md](protocol-research.md).

## Context

The task requires choosing **one** practical first protocol adapter, with an
explicit preference for **documented, independently testable capabilities over
proprietary integrations**, and with the hard constraints: never invent
third-party endpoints, never claim vendor affiliation, never copy proprietary
code, and clearly label unverified information (AGENTS.md Rule 20).

The KYA core already separates authorization into five non-interchangeable
stages (A identity, B signature-verification trait seam, C static policy, D
online authoritative authorization, E execution). A first adapter must map onto
that model without weakening it: in particular, it must not let a signed object
masquerade as an authorization (AGENTS.md section 1, Rule 12).

## Decision

**The first protocol adapter targets the Google Agent Payments Protocol (AP2),
scoped initially to parsing and offline verification of AP2 mandate objects
(Verifiable Digital Credentials) mapped onto the KYA stage-A/B/C surface.**

Concretely, the first adapter's charter (when it is later implemented, in a
separate change) is:

1. Model AP2 mandate objects (Checkout Mandate and Payment Mandate, in their Open
   and Closed states) as explicit Rust types in an **outer-ring** crate that
   depends inward on `kya-core`.
2. Verify mandate signatures through the existing
   `kya_core::verification::SignatureVerifier` seam, using standard, reviewed
   crypto crates supplied from outside `kya-core` (AGENTS.md Rule 10). No
   algorithm is added to `kya-core`.
3. Translate an AP2 mandate's constraints (permitted action, amount, currency)
   into the KYA `Mandate` / `Scope` / `Money` domain types so the existing
   deterministic **stage-C** evaluator can run unchanged.
4. Treat issuer authorization, revocation, cumulative budget, and replay as
   **stage D**: out of scope for offline verification, routed through the
   fail-closed `kya_client::authorize` bridge and an `OnlineAuthorizer`. The
   adapter does **not** turn a verified mandate into an `Allow`.

RFC 9421 (HTTP Message Signatures) is adopted as a **supporting primitive**, not
the first adapter: it is the natural implementation of a request-signing
`SignatureVerifier` and is the mechanism Visa TAP builds on, so investing in it
keeps a future TAP adapter cheap without committing to TAP now.

## Rationale

AP2 is selected because it is the only candidate that satisfies every hard
constraint and the stated preference at once:

- **Publicly accessible specification.** AP2's spec/overview, flows, and FAQ are
  in a public repository and on [ap2-protocol.org](https://ap2-protocol.org/).
- **Available, re-implementable source and schemas.** The public repo ships a
  Python SDK, canonical JSON schemas, and runnable Python/Go/Android samples, so
  behaviour can be studied and cross-checked. We re-implement from the public
  spec/schemas in Rust; we do **not** copy source.
- **Permissive, verified license.** The repository is Apache-2.0 (verified by
  reading its `LICENSE`), compatible with this project's MIT OR Apache-2.0
  licensing for referencing the spec and re-implementing from it.
- **Independently testable without a paid account.** AP2 mandate construction and
  verification do not require a Google account; the repo README states AP2 does
  not require the sample stack (ADK/Gemini). Only the end-to-end demo needs Google
  credentials. This is decisive against Skyfire.
- **Clean authN/authZ separation that matches the KYA model.** AP2 anchors trust
  to a user-signed mandate (verifiable intent) and keeps issuer authorization and
  3DS2-style challenges as separate, later steps. That is exactly the KYA line
  between "signed" (stages A/B and static C constraints) and "authorized"
  (stage D). AP2 does not invite the forbidden shortcut.
- **Standard cryptography.** AP2 mandates are signed JSON (VDCs), verifiable with
  standard, reviewed primitives behind the existing seam. No invented crypto
  (Rule 10).

## Options considered and rejected

- **Skyfire.** Rejected as the *first* adapter. Its kya/pay/kya-pay token split
  is conceptually close to this project's authN/authZ separation, but it is a
  **proprietary hosted service**: it requires a Skyfire account, an API key, a
  pre-funded wallet, and the central `api.skyfire.xyz` service for verification
  and settlement. It cannot be exercised offline or independently, which
  contradicts the task's explicit preference. Revisit only as an optional stage-D
  `OnlineAuthorizer`/integration behind a clear external-dependency boundary.
- **Visa TAP.** Deferred, not rejected forever. TAP builds on the open RFC 9421
  standard (which we adopt as a primitive), but the normative **rulebook** and
  the licensing/accessibility of its **sample code** could not be confirmed from
  a public, unauthenticated source, and its trust model depends on Visa's
  approval and key-distribution infrastructure. Because we adopt RFC 9421 now, a
  TAP adapter later is incremental.
- **Mastercard Agent Pay.** Rejected for now. No publicly accessible,
  independently testable normative specification was located. Building against it
  would require inventing assumptions and endpoints, which the task and Rule 20
  forbid.
- **"A universal mandate standard."** Explicitly rejected by the task and by this
  ADR. We map one concrete protocol (AP2) onto the existing KYA domain types; we
  do not invent a grand unified mandate format and do not claim one.

## Consequences

- An outer-ring crate `kya-adapter-ap2` now exists that depends inward on
  `kya-core` and reuses `kya-crypto` as the stage-B primitive (AGENTS.md Rule 2),
  introduces **no** HTTP/DB/cloud dependency into `kya-core`, and performs
  signature verification only through the existing seam. It implements the
  independently-verifiable AP2 **constraint** surface (see the status section
  below); the AP2 wire envelope remains BLOCKED. The design is sketched in
  [architecture.md](architecture.md) and its honesty constraints in
  [protocol-compatibility.md](protocol-compatibility.md).
- The SDK gains a concrete, testable target for its offline stages without taking
  on a proprietary runtime dependency.
- No AP2 compatibility is claimed as implemented or certified. Until the adapter
  exists and is tested against AP2's published schemas/samples, all AP2
  compatibility statements are **design intent** (see
  [protocol-compatibility.md](protocol-compatibility.md)).

## Open questions to resolve before full AP2 interop (status)

An **independently-verifiable constraint adapter** has since been implemented in
the outer-ring crate `kya-adapter-ap2`: it models the AP2 mandate constraint
concepts (permitted action, exact amount, currency, identities, validity,
audience, approval, binding) as explicit Rust types, maps them onto the
`kya-core` `Mandate`/`Scope`/`Money` domain so the stage-C evaluator runs
unchanged, and verifies signatures through `kya-crypto` over caller-supplied
**exact** bytes. It produces no `Allow` and invents no endpoints or
canonicalization. The following remain `[UNVERIFIED]` and therefore **BLOCKED**,
exactly as noted here; they are the hard dependencies for byte-for-byte AP2
interop and were deliberately not attempted:

- The exact AP2 mandate **signature envelope** (JWT/JWS vs W3C-VC-style proof)
  and the accepted algorithms, read from the repository schemas. **[UNVERIFIED]**
  / **BLOCKED** — `kya-adapter-ap2` verifies caller-supplied exact bytes and does
  not parse a real AP2 token.
- Whether AP2 publishes standalone **test vectors** beyond schemas and sample
  scenarios. **[UNVERIFIED]** / **BLOCKED** — no vector-conformance test is
  written or claimed.
- Key distribution / issuer-anchor mechanics for AP2 issuers, mapped onto the
  existing explicit, allow-listed `TrustAnchors`. Still to be read from the AP2
  schemas; the adapter uses the existing explicit `TrustAnchors` / `TrustedKeyStore`
  with no implicit or fetched trust.
