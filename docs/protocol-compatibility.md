# Protocol Compatibility

This document states, honestly and with evidence, what protocol compatibility
the FintechBear KYA SDK claims today, what is merely design intent, and what is
out of scope. It exists to satisfy AGENTS.md Rule 20: compatibility and security
claims MUST be truthful and evidence-backed, and this project claims no
certification, no independent audit, no vendor affiliation, and no protocol
compatibility without evidence.

## The one-sentence honest status

**As of this change, the KYA SDK ships an independently-verifiable AP2
*constraint* adapter (`kya-adapter-ap2`): it models the AP2 mandate constraint
concepts (permitted action, exact amount, currency, and identities) as explicit
Rust types, maps them onto the `kya-core` `Mandate`/`Scope`/`Money` domain so the
existing stage-C evaluator runs unchanged, and verifies signatures through
`kya-crypto` over caller-supplied exact bytes. It does NOT parse the real AP2
signature envelope and does NOT assert AP2 wire compatibility: the exact AP2
envelope and any standalone AP2 test vectors are `[UNVERIFIED]` per
[first-adapter-decision.md](first-adapter-decision.md) and that byte-for-byte
interop remains BLOCKED. No AP2 compatibility, conformance, or certification is
claimed.** The SDK also ships the protocol-independent cryptographic engine
(`kya-crypto`) that verifies Ed25519 (RFC 8032) and JWS-EdDSA (RFC
7515/7518/8037) signatures over **caller-supplied exact bytes**; that engine is
**not** an AP2 adapter and makes no AP2 wire-format claim (see
[cryptographic-architecture.md](cryptographic-architecture.md)).

## Claims matrix

| Claim | Status | Basis |
|---|---|---|
| We selected AP2 as the first adapter target | True (decision made) | [first-adapter-decision.md](first-adapter-decision.md) |
| AP2 is an open protocol with a public, Apache-2.0 repository | True (verified) | Repository `LICENSE` reads Apache-2.0; see [protocol-research.md](protocol-research.md) |
| The KYA core separates signed intent (authN) from authorization (authZ) in a way that matches AP2's model | True (design); AP2 side evidence-backed | AP2 overview keeps issuer authorization and 3DS2 challenges separate from the signed mandate |
| The SDK verifies Ed25519 signatures per RFC 8032 | True (implemented) | `kya-crypto` `Ed25519SignatureVerifier`, anchored by `tests/rfc8032_conformance.rs` (official §7.1 vectors) |
| The SDK verifies JWS compact-form EdDSA signatures (RFC 7515/7518/8037, `alg=EdDSA`) over the exact signing input | True (implemented) | `kya-crypto` `JwsEdDsa`; `alg: none` and non-EdDSA rejected, see `tests/jws_security.rs` |
| The crypto engine implements an AP2 mandate / envelope parser | **False** | `kya-crypto` verifies only caller-supplied exact bytes; it invents no canonicalization of wire fields and parses no AP2 object |
| An AP2 *constraint* adapter is implemented (maps action/amount/currency/identities onto stage-C) | True (implemented) | `kya-adapter-ap2`: `Ap2MandateConstraints::to_mandate` + `verify_ap2_delegation`, anchored by `crates/kya-adapter-ap2/tests/ap2_stage_c.rs` and its unit tests |
| An AP2 *wire/envelope* adapter is implemented (byte-for-byte parsing of real AP2 tokens) | **False / BLOCKED** | The exact AP2 signature envelope is `[UNVERIFIED]` per ADR-0001; `kya-adapter-ap2` verifies caller-supplied exact bytes and parses no AP2 serialization |
| KYA is "AP2-compatible" / "AP2-compliant" | **Not claimed** | The constraint adapter maps AP2 *concepts* onto stage C; nothing has been tested against real AP2 tokens, schemas, or vectors |
| KYA is certified or audited against any protocol | **Not claimed** | No certification or independent audit exists |
| We have affiliation with or endorsement from Google/Visa/Mastercard/Skyfire/FIDO/IETF/W3C | **Not claimed; explicitly denied** | Names used descriptively only |
| The exact AP2 signature envelope and algorithms | **[UNVERIFIED]** | Must be read from AP2's published schemas before implementation; the `kya-crypto` algorithms are chosen for independent verifiability, not from AP2 |
| AP2 publishes standalone test vectors (beyond schemas/samples) | **[UNVERIFIED]** | Not confirmed during research |

## AP2-to-stage mapping (constraint adapter implemented; envelope BLOCKED)

The mapping below is the compatibility contract. The **constraint** rows
(action / amount / currency / identities onto stage C, and stage-B verification
over caller-supplied exact bytes) are now **implemented** in `kya-adapter-ap2`
and covered by tests. The **wire-envelope** row (byte-for-byte parsing of the
real AP2 signed object) remains **design intent and BLOCKED** because the AP2
envelope is `[UNVERIFIED]` per ADR-0001.

| AP2 concept | KYA stage | KYA surface it maps onto |
|---|---|---|
| Issuer / credential authority identity | A (identity) | `IssuerId` checked against explicit `TrustAnchors`. **Implemented** via `Ap2Identities` -> `Mandate`. |
| Mandate signature (VDC) over the exact signed bytes | B (signature, seam + engine) | `SignatureVerifier::verify`, realized by `kya-crypto`'s Ed25519 / JWS-EdDSA engine; invoked by `kya_adapter_ap2::verify_ap2_delegation` over **caller-supplied exact bytes**. **Implemented** for exact bytes. The mapping of the **real AP2 envelope** onto those bytes is `[UNVERIFIED]` / **BLOCKED** until AP2's schemas are read. |
| Mandate constraints (permitted action, amount, currency) | C (static policy) | `Scope` + `Money` inside a `Mandate`, evaluated by `kya_core::policy`. **Implemented** via `Ap2MandateConstraints::to_mandate`. |
| Acting agent identity | A + C | `AgentId` with the stage-C agent-match check. **Implemented**. |
| Issuer authorization / 3DS2-style challenge | D (online) | `OnlineAuthorizer` via the fail-closed `authorize` bridge. Out of adapter scope. |
| Revocation / cumulative budget / replay | D (online) | `OnlineAuthorizer`; never established offline. Out of adapter scope. |
| Execution / settlement | E (execution) | `IntegrationClient` seam; acts only on an `Allow`. Out of adapter scope. |

### What is BLOCKED (and why)

Two AP2 facts are `[UNVERIFIED]` per ADR-0001 and could not be established from a
public, unauthenticated source during research:

1. the **exact AP2 signature envelope** (JWT/JWS vs a W3C-VC-style proof) and its
   accepted algorithms; and
2. whether AP2 publishes **standalone test vectors** beyond schemas and samples.

Byte-for-byte AP2 token parsing and AP2 test-vector conformance both depend on
those facts, so they are **not implemented and not claimed**. `kya-adapter-ap2`
exposes the verification *seam* (`verify_ap2_delegation` over caller-supplied
exact bytes) but stops at that boundary: it never guesses the AP2 byte layout,
never invents a canonicalization, and never asserts a real AP2 token verifies.
When the envelope is later confirmed from AP2's published schemas, a byte-exact
parser can be layered in front of the existing seam without weakening it.

## What compatibility will mean once the adapter exists

When the adapter is implemented and tested (a separate change), a truthful
compatibility claim will be scoped precisely, for example: "parses and verifies
AP2 `<specific mandate type>` objects conforming to `<specific schema version>`,
mapping their constraints onto stage-C evaluation, verified against `<the AP2
schemas/samples used as fixtures>`." It will **not** be a blanket "AP2
compatible" claim, and it will name the exact versions and artifacts tested. Any
part of AP2 not implemented will be stated as not implemented.

## Non-goals and explicit non-claims

- **No universal mandate standard.** The project maps one concrete protocol onto
  its existing domain types. It does not invent, publish, or claim a universal
  mandate format. The task and this document forbid it.
- **No invented endpoints.** No third-party endpoints are fabricated anywhere in
  the SDK or its docs. The AP2 adapter's offline verification needs no endpoint;
  any online authority is an integrator-supplied `OnlineAuthorizer`.
- **No proprietary code copied.** The adapter will be re-implemented from AP2's
  public specification and schemas under its Apache-2.0 terms; it will not copy
  proprietary or third-party source.
- **Other protocols are not claimed.** Visa TAP, Mastercard Agent Pay, and
  Skyfire are researched in [protocol-research.md](protocol-research.md) but are
  not targeted now; no compatibility with any of them is claimed. RFC 9421 is
  adopted only as a candidate verification primitive, not as a compatibility
  claim about any vendor layer built on top of it.
- **The crypto engine is protocol-independent, not an AP2 adapter.**
  `kya-crypto` verifies Ed25519 and JWS-EdDSA signatures over caller-supplied
  **exact** bytes. It does not parse AP2 objects, does not invent a
  canonicalization of `kya-protocol` wire fields, and establishes no revocation,
  budget, or replay state (those are stage D). An issuer-signed delegation does
  not, by itself, prove the agent currently possesses its own private key. See
  [cryptographic-architecture.md](cryptographic-architecture.md) for the full
  limitations.

## If you find an inaccurate claim

Per the README and AGENTS.md Rule 20, an untruthful or unsupported compatibility
or security claim is a bug. See [SECURITY.md](../SECURITY.md) for disclosure.
