# Future Commercial Platform (not built)

This document describes how a future commercial FintechBear KYA authorization
platform (**Product 2**) can reuse the **same** open-source Rust core
(**Product 1**) without forking its verification logic. Everything here is
**future** and **not implemented**. No service described below ships in this
repository, and using the open-source SDK requires no FintechBear account.

This page is a consumer-facing overview and a map to the detailed design docs.
It does not restate them in full; it links to them:

- [product-strategy.md](product-strategy.md) - the two-product strategy.
- [open-source-commercial-boundary.md](open-source-commercial-boundary.md) -
  precisely what is open vs commercial, and how the boundary stays clean.
- [future-platform-architecture.md](future-platform-architecture.md) - each
  future capability mapped to the stage it serves and the seam it would
  implement.

## The two products

- **Product 1 - the open-source SDK.** Free, independent, public. Runs entirely
  on your own infrastructure. Provides stages A, B, and C plus the fail-closed
  `authorize` bridge and the stage-D / stage-E trait seams. This is what this
  repository ships.
- **Product 2 - the commercial platform.** A future managed FintechBear KYA
  authorization platform built directly on the same Rust core. **Not built.**

## Why reuse works without forking

The core expresses every I/O-bound or environment-specific concern as a **trait
seam** and never implements those seams itself. The commercial platform would be
just another outer ring that depends **inward** on `kya-core` (AGENTS.md
Rule 2). It would supply concrete implementations of the same traits the
open-source SDK already defines, so:

- the authorization model does not diverge across the two products,
- the platform does not reimplement stage C or the fail-closed bridge, and
- deny-by-default and the "eligibility is not authorization" rule hold across
  the boundary.

A fix in the core applies to both products. Removing the commercial services
leaves a coherent, usable SDK.

## Future managed capabilities (all not built)

Each capability below is a **managed service** that implements or surrounds the
core's seams. These are documented, not implemented. The stage mapping and the
exact seam each would implement are detailed in
[future-platform-architecture.md](future-platform-architecture.md).

- **Managed agent registry** (stage A): an authoritative source for which agents
  and issuers to allow-list, feeding the core's identity types and trust
  anchors.
- **Trusted key management** (stage A): managed custody and rotation of the
  public keys the core verifies against, feeding the `TrustedKeyStore` and trust
  anchors. The core gains no key-discovery or wildcard-trust path.
- **Delegation and mandate management** (stages A and C): issuance, storage, and
  lifecycle of the delegations and mandates the core evaluates offline.
- **Online revocation** (stage D): authoritative revocation state consulted by a
  concrete `OnlineAuthorizer`; a revoked mandate yields `Denied`, which the
  bridge maps to `Deny`.
- **Atomic budget reservations** (stage D): cumulative-budget tracking with
  atomic reserve-and-commit semantics inside the authorizer, preventing
  double-spend across concurrent requests, on top of the core's exact integer
  money types.
- **Human approval workflows** (stage D): surfacing the core's `ApprovalRequired`
  verdict to a human approver and resolving it out of band; the request stays
  denied until an explicit approval arrives.
- **Authoritative authorization API** (stage D): a concrete `OnlineAuthorizer`
  that answers with a real, current verdict, always routed through the
  fail-closed `authorize` bridge.
- **Tamper-evident audit systems** (cross-cutting): durable, tamper-evident
  records of the core's machine-readable `PolicyOutcome`, `Decision`, and
  `ReasonCode`, with no secrets, keys, or signatures in logs (Rule 18).
- **Execution-point payment enforcement** (stage E): a concrete
  `IntegrationClient` that submits an **already authorized** `Decision` to
  payment providers or ledgers and enforces that only an authorized decision is
  ever executed.
- **Enterprise dashboard** (cross-cutting): managed APIs and an operator
  dashboard over the services above, adding no new authorization semantics.

## What stays true across the future platform

- A valid signature is still not an authorization.
- Offline evaluation still cannot establish current revocation, cumulative
  budget, or global replay state; only the online authority can.
- Agent proof of possession is still not established by local verification.
- The only path from a static `PolicyOutcome` to a final `Decision` is the
  fail-closed `authorize` bridge. The platform plugs an authority into that
  bridge; it never bypasses it.
- Deny-by-default holds.

## Non-goals of this document

This document **describes** reuse. It does **not** implement any managed
service, and the SDK does **not** add generic traits or infrastructure merely to
anticipate these features (AGENTS.md Rule 1, YAGNI). The real core business logic
is kept reusable; the speculative platform is kept out of the codebase.
