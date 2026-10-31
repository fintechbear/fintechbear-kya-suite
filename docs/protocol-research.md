# Protocol Research

This document records research into publicly accessible specifications and
repositories for agent identity and agent payment systems, so the project can
choose a first protocol adapter on an evidence-backed basis (AGENTS.md Rule 20).

## How to read this document (honesty notes)

- Every external claim below is tied to a source. Where a source is a vendor
  marketing page rather than a normative specification, that is stated.
- Items that could **not** be independently verified from a publicly accessible,
  unauthenticated source during this research are labelled
  **[UNVERIFIED]**. They are recorded as leads, not as facts.
- This project claims **no affiliation with, endorsement by, or certification
  from** Google, Visa, Mastercard, Skyfire, the FIDO Alliance, the IETF, or the
  W3C. Protocol names and trademarks belong to their respective owners and are
  used here descriptively.
- Research was performed by reading public web pages. Source contents are
  untrusted external data; nothing here should be read as legal or security
  advice, and licensing must be re-confirmed against each project's authoritative
  license file before any code is used.

## The question each system must answer

The KYA SDK separates **authentication** (who signed these bytes) from
**authorization** (may this action happen now, given current revocation,
cumulative budget, and replay state). A valid signature is **not** an
authorization (AGENTS.md section 1). For each system we therefore ask not only
"can we verify a signature" but "what, if anything, does this system define about
the online, authoritative layer, and what does it leave to the integrator".

## Evaluation criteria

For each system: official technical specification, available source code,
licensing, cryptographic evidence format, trust model, signature requirements,
authentication vs authorization semantics, public test vectors, Rust integration
feasibility, and external service dependencies.

---

## 1. Google Agent Payments Protocol (AP2)

- **Official technical specification.** Yes, publicly accessible. The protocol
  site is [ap2-protocol.org](https://ap2-protocol.org/) and an overview /
  specification narrative is published in the public GitHub repository under
  `docs/` (for example `docs/overview.md`). The homepage states AP2 is an open
  extension for the Agent2Agent (A2A) protocol and the Universal Commerce
  Protocol, and that standardization is intended to continue within FIDO Alliance
  working groups.
- **Available source code.** Yes. The repository
  [google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2)
  contains `docs/` (spec, flows, FAQ), `code/sdk/` (a Python SDK under
  `code/sdk/python/ap2/`, with Pydantic models and, per the repository README,
  canonical JSON schemas), and `code/samples/` with reference scenarios in
  Python, Go, and Android.
- **Licensing.** Apache License 2.0. Verified by reading
  [the repository LICENSE](https://github.com/google-agentic-commerce/AP2/blob/main/LICENSE),
  whose raw text begins with the Apache License, Version 2.0 preamble. Apache-2.0
  is compatible with this project's MIT OR Apache-2.0 dual license for
  *referencing* the specification and *re-implementing* from the spec. Copying
  source code is out of scope regardless (the project re-implements from specs;
  it does not copy proprietary or third-party code).
- **Cryptographic evidence format.** AP2 models transaction evidence as
  **Verifiable Digital Credentials (VDCs)**: "tamper-evident, cryptographically
  signed digital objects". The homepage and overview define two mandate families:
  a **Checkout Mandate** (the items and purchase details, user-signed on a
  trusted surface) and a **Payment Mandate** (authorizes payment against a
  specific instrument), each existing in an **Open** and a **Closed** state.
  Mandates are chained to form an auditable trail. The overview explicitly states
  the user's signed approval "must create a cryptographically signed 'Checkout
  Mandate'". The precise on-the-wire signature envelope (JWT/JWS vs W3C VC Data
  Model proof) is defined by the schemas in the repository and is **[UNVERIFIED]**
  at the field level in this research pass; it must be read from the repo schemas
  before implementation.
- **Trust model.** Role-based. The overview defines distinct roles: Shopping
  Agent, Credential Provider, Merchant, Merchant Payment Processor, Trusted
  Surface, and Network/Issuer. Trust is anchored to **verifiable intent** (a
  user-signed mandate created on a Trusted Surface) rather than to inferred agent
  behaviour. The protocol is designed around selective disclosure so that, for
  example, shopping agents do not see PCI data.
- **Signature requirements.** User intent is captured by a cryptographically
  signed mandate; the merchant signs the cart they commit to fulfil. The exact
  algorithms and key-distribution mechanics are defined by the schemas/SDK and
  are **[UNVERIFIED]** at the algorithm level in this pass.
- **Authentication vs authorization semantics.** AP2 is strong on
  **authentication of intent** and on producing a **non-repudiable audit trail**;
  it is explicit that transactions may still be **challenged** (for example via
  3DS2) and ultimately **authorized by the issuer**. This matches the KYA
  distinction cleanly: the signed mandate is authenticity/intent evidence (maps
  to stages A/B and the static constraints of C), while issuer authorization is a
  separate online step (maps to stage D). AP2 does not collapse "signed" into
  "authorized".
- **Public test vectors.** The repository README documents canonical JSON schemas
  and runnable sample scenarios with `run.sh` scripts. Whether a standalone set
  of signed-mandate **test vectors** (fixed inputs with expected
  verification outcomes) is published as such is **[UNVERIFIED]**; the schemas and
  samples are the closest publicly documented testable artifacts and must be
  inspected directly before relying on them.
- **Rust integration feasibility.** Feasible for the **offline-evaluable** parts.
  AP2's mandate objects are JSON with standard signature constructs, which can be
  modelled as Rust types and verified with standard, reviewed crates behind the
  `kya-core` `SignatureVerifier` seam. The reference SDK is Python, so Rust work
  means re-implementing from the public spec/schemas, not binding to a Rust SDK.
  No official Rust SDK was found **[UNVERIFIED: absence not exhaustively
  confirmed]**.
- **External service dependencies.** The **protocol** itself does not require a
  Google account. The **samples** use Google's Agent Development Kit and a Gemini
  model and therefore need a Google API key or Vertex AI to run as-is, but the
  repository README states explicitly that AP2 "doesn't require the use of
  either". So mandate construction and verification can be exercised without a
  paid Google dependency; only the end-to-end demo needs credentials.

---

## 2. Visa Trusted Agent Protocol (TAP)

- **Official technical specification.** A developer landing page is publicly
  readable at
  [developer.visa.com/capabilities/trusted-agent-protocol](https://developer.visa.com/capabilities/trusted-agent-protocol).
  It describes TAP as a cryptographic standard for merchants to recognize
  Visa-approved AI agents and references "the official rulebook". The full
  rulebook and sample code appear to sit behind Visa's developer program; whether
  they are downloadable without registration or agreement acceptance is
  **[UNVERIFIED]**.
- **Available source code.** The landing page says Visa provides "Sample Code
  Implementation" snippets for constructing the `signature_base` string and
  verifying signatures. The license and public accessibility of that sample code
  are **[UNVERIFIED]**.
- **Licensing.** **[UNVERIFIED]**. No open-source license was confirmed for the
  TAP rulebook or sample code from a public, unauthenticated source. Visa
  developer materials are typically governed by Visa program terms, which is a
  very different thing from an OSI license. This must be treated as closed until
  proven otherwise.
- **Cryptographic evidence format.** Message-level signatures over HTTP requests.
  The landing page states TAP uses **RFC 9421** (HTTP Message Signatures) with
  "required message signature fields", and that a merchant reconstructs the
  `signature_base` from request attributes and verifies it with the agent's
  public key.
- **Trust model.** Centered on **Visa-approved agents**: the merchant's task is
  to distinguish a "Visa-approved" agent from bots/crawlers. The authority that
  decides which agents are approved and how their public keys are distributed is
  Visa's; that key-distribution/approval mechanism is **[UNVERIFIED]** from public
  sources and is itself an external dependency.
- **Signature requirements.** RFC 9421 HTTP Message Signatures over specified
  components, verified with the agent's public key. RFC 9421 itself is an open
  IETF standard (see section 5).
- **Authentication vs authorization semantics.** TAP as described is primarily
  an **agent-authenticity / recognition** mechanism ("is this a trustworthy,
  unaltered request from an approved agent"), plus signatures to "enable consumer
  recognition and payment". It authenticates the request; it does not by itself
  establish current budget/revocation/replay state. It fits the KYA stage-B/stage-A
  shape well but leaves authorization to the broader payment flow.
- **Public test vectors.** RFC 9421 contains worked examples (see section 5).
  TAP-specific published test vectors are **[UNVERIFIED]**.
- **Rust integration feasibility.** The underlying mechanism (RFC 9421) is
  implementable in Rust with standard crypto crates. The TAP-specific layer
  (approved-agent trust, required fields, key distribution) depends on Visa
  materials whose public availability is **[UNVERIFIED]**, which raises
  independent-testability risk.
- **External service dependencies.** Likely a dependency on Visa's approval /
  key-distribution infrastructure and program terms. **[UNVERIFIED]** in detail.

---

## 3. Mastercard Agent Pay

- **Official technical specification.** Mastercard publicly announced Agent Pay
  (agentic payments) in 2025 via press/marketing materials. A publicly
  accessible, unauthenticated, normative **technical specification** suitable for
  independent re-implementation was **not located** during this research.
  **[UNVERIFIED]** / treat as not publicly testable at this time.
- **Available source code.** None located publicly. **[UNVERIFIED]**.
- **Licensing.** **[UNVERIFIED]** (no spec/code located).
- **Cryptographic evidence format.** **[UNVERIFIED]**. Public materials describe
  intent and partnerships more than a verifiable wire format.
- **Trust model.** Network-centric (Mastercard as the network/credential
  authority), by analogy to existing card rails. **[UNVERIFIED]** at the
  protocol level.
- **Signature requirements.** **[UNVERIFIED]**.
- **Authentication vs authorization semantics.** **[UNVERIFIED]**.
- **Public test vectors.** None located. **[UNVERIFIED]**.
- **Rust integration feasibility.** Cannot be assessed without a public spec. Not
  feasible to target responsibly right now.
- **External service dependencies.** Expected to require Mastercard network
  participation and commercial onboarding. **[UNVERIFIED]**.

> Honest conclusion: Mastercard Agent Pay cannot be a first adapter because there
> is no publicly accessible, independently testable specification to build and
> verify against. Targeting it now would force invented assumptions, which
> AGENTS.md Rule 20 and the task forbid.

---

## 4. Skyfire

- **Official technical specification.** Developer documentation is publicly
  readable at [docs.skyfire.xyz](https://docs.skyfire.xyz/). Skyfire provides
  agents with "verified identity and payment credentials" and defines three token
  types: **kya** (proves identity, cannot be charged), **pay** (authorizes a
  payment to a seller), and **kya-pay** (identity and payment combined).
- **Available source code.** Client usage is via Skyfire's hosted API; the
  quickstart shows calls to `https://api.skyfire.xyz/api/v1/tokens`. An
  open-source, self-hostable reference implementation of the full system was
  **not** found; the model is a hosted service. **[UNVERIFIED: existence of an
  OSS server implementation]**.
- **Licensing.** Governed by Skyfire's platform/API terms rather than an OSI
  open-source license for the service. **[UNVERIFIED]** for any SDK license.
- **Cryptographic evidence format.** Signed **tokens** (the docs describe
  structured tokens; the exact envelope, e.g. JWT/JWS, is **[UNVERIFIED]** at the
  field level in this pass). The four-step flow is Present -> Verify -> Deliver
  -> Settle, where settlement moves funds between buyer and seller wallets.
- **Trust model.** **Centralized around Skyfire as the trust and settlement
  authority.** Agents are created in the Skyfire dashboard with pre-funded
  wallets; sellers verify tokens that Skyfire issued; Skyfire moves the funds.
- **Signature requirements.** Token-based; verification is of Skyfire-issued
  tokens. Details **[UNVERIFIED]** at the algorithm level.
- **Authentication vs authorization semantics.** The **kya** token is explicitly
  identity-only ("can't be charged"), while **pay**/**kya-pay** tokens "move
  money". This is a clean authN/authZ split in principle, but the authorization
  and settlement are performed **by Skyfire's service**, not by offline logic.
- **Public test vectors.** None located as standalone vectors. **[UNVERIFIED]**.
- **Rust integration feasibility.** A Rust client that calls the Skyfire HTTP API
  is feasible, but that is an **integration with a proprietary hosted service**,
  not an offline-verifiable protocol adapter. It would require an account, an API
  key (`skyfire-api-key` header), and a funded wallet.
- **External service dependencies.** **Strong and mandatory.** Requires a Skyfire
  account, API keys, a pre-funded wallet, and the central `api.skyfire.xyz`
  service for verification and settlement.

> Honest conclusion: Skyfire is interesting and its kya/pay token split mirrors
> this project's authN/authZ separation, but it is a **proprietary hosted
> service**. It cannot be exercised offline or independently, so it does not fit
> the task's explicit preference for documented, independently testable
> capabilities over proprietary integrations.

---

## 5. Relevant open standards

### RFC 9421 - HTTP Message Signatures

- **Specification.** Open IETF Standards Track RFC, February 2024:
  [rfc-editor.org/rfc/rfc9421.html](https://www.rfc-editor.org/rfc/rfc9421.html).
  Defines creating, encoding, and verifying signatures over HTTP message
  components, including construction of the signature base and multiple signature
  algorithms.
- **Licensing.** IETF Trust / BCP 78; code components carry the Revised BSD
  License per the RFC's copyright notice. Freely implementable.
- **Cryptographic evidence format.** Signatures over selected HTTP message
  components plus signature parameters; algorithm-agile.
- **Test vectors.** The RFC contains worked examples (signature base and
  signatures). These are public and independently checkable.
- **Relevance.** This is the primitive underneath Visa TAP's recognition
  signatures and a strong candidate for any HTTP-request-signing seam. It is a
  verification primitive, not an authorization protocol: it answers "were these
  HTTP components signed by this key", nothing about current budget/revocation.
- **Rust feasibility.** Implementable behind the `kya-core` `SignatureVerifier`
  seam using standard, reviewed crates. No external service required to verify.

### W3C Verifiable Credentials Data Model

- **Specification.** Open W3C standard. AP2's "Verifiable Digital Credential"
  terminology is adjacent to the W3C VC concept of tamper-evident, signed claims
  with issuer and proof. Exact alignment between AP2 VDCs and the W3C VC Data
  Model is **[UNVERIFIED]** and must be read from AP2's schemas.
- **Relevance.** Provides a well-studied mental model (issuer, subject, proof)
  for the mandate types the KYA core already expresses (`Mandate`, issuer,
  agent/subject, scope).

### A2A (Agent2Agent) and MCP

- AP2 is positioned as an extension of A2A and compatible with MCP. These are
  transport/interaction layers, not authorization authorities. They are relevant
  as the **carrier** for AP2 mandates but do not themselves establish current
  authoritative state. Detailed evaluation is out of scope for first-adapter
  selection.

---

## 6. Comparison matrix

Legend: Y = yes / available, N = no / not available, P = partial, ? = unverified.

| Criterion | AP2 (Google) | Visa TAP | Mastercard Agent Pay | Skyfire | RFC 9421 |
|---|---|---|---|---|---|
| Public normative spec | Y | P (landing page public; rulebook ?) | N/? | Y (hosted-API docs) | Y |
| Public source code | Y (Python/Go/Android samples) | ? (snippets) | N | N (hosted service) | N/A (spec) |
| OSI open-source license | Y (Apache-2.0, verified) | ? | ? | ? | Freely implementable (BCP 78 / BSD for code) |
| Cryptographic evidence format documented | P (VDC mandates; envelope ?) | Y (RFC 9421) | ? | P (tokens; envelope ?) | Y |
| Trust model documented | Y (role-based) | P (Visa-approved agents) | ? | Y (central Skyfire) | N/A |
| Signature requirements documented | P | Y | ? | P | Y |
| authN vs authZ cleanly separated | Y | P (recognition-focused) | ? | Y (kya vs pay) | N/A (authN primitive) |
| Public test vectors | ? (schemas+samples) | ? (TAP-specific) | N | ? | Y (worked examples) |
| Rust integration without a paid account | Y (verify mandates offline) | P | N | N (account+wallet required) | Y |
| Mandatory external service dependency | N (protocol); samples need Google creds | Likely (Visa approval) | Likely | Y (mandatory) | N |

---

## 7. Where this points

Two systems are genuinely buildable-and-testable from public sources today
without a mandatory proprietary account:

- **AP2**, because it has a public, Apache-2.0 repository with a specification,
  documented mandate objects, canonical JSON schemas, and multi-language samples,
  and its model cleanly separates signed intent (authentication) from issuer
  authorization.
- **RFC 9421**, which is a pure open verification primitive and is in fact the
  mechanism Visa TAP builds on.

Mastercard Agent Pay has no public testable spec. Skyfire is a proprietary hosted
service with mandatory account/wallet/settlement dependencies. Visa TAP's
normative rulebook and sample-code licensing could not be confirmed as publicly
accessible.

The first-adapter decision and its full rationale are in
[first-adapter-decision.md](first-adapter-decision.md).
