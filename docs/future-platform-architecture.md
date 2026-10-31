# Future Platform Architecture (not built)

This document describes how the **same open-source core** can later support a
managed commercial platform (Product 2). Everything here is **future** and
**not implemented**. No service described below ships in this repository. The
purpose is to show that the core's design already accommodates these services as
seams, so the commercial platform can be built without rewriting or forking the
verification logic.

See [product-strategy.md](product-strategy.md) and
[open-source-commercial-boundary.md](open-source-commercial-boundary.md) for
context, and [architecture.md](architecture.md) for the stage model.

## Guiding constraint

The commercial platform is an outer ring that depends **inward** on `kya-core`
(AGENTS.md Rule 2). It supplies concrete implementations of the core's trait
seams and managed services around them. It does not invert the dependency
direction, it does not reimplement stage C or the fail-closed `authorize`
bridge, and it preserves the deny-by-default posture.

Each future capability below is mapped to the stage it serves and the existing
seam it would implement.

## Future capabilities (all not built)

### Managed agent registry

- **Stage:** A (identity).
- **Future seam:** a managed directory of agents and issuers that feeds the
  core's identity types and trust anchors. The core already models explicit,
  allow-listed trust; the registry would be an authoritative source for what to
  allow-list.
- **Status:** not built.

### Mandate management

- **Stage:** A and C (identity and the mandates that stage C evaluates).
- **Future seam:** issuance, storage, and lifecycle of mandates, producing the
  `Mandate` values the core evaluates offline. The core defines the mandate
  shape; the platform would manage its lifecycle.
- **Status:** not built.

### Real-time authorization

- **Stage:** D (online authoritative authorization).
- **Future seam:** a concrete `OnlineAuthorizer` that answers `authorize_request`
  with a real, current verdict. The core already defines this trait and routes
  every verdict through the fail-closed `authorize` bridge.
- **Status:** not built.

### Revocation

- **Stage:** D.
- **Future seam:** authoritative revocation state consulted by the
  `OnlineAuthorizer`. Offline evaluation cannot know whether a mandate has been
  revoked; only an online authority can. A revoked mandate yields `Denied`, which
  the bridge maps to `Deny`.
- **Status:** not built.

### Atomic budget reservations

- **Stage:** D.
- **Future seam:** cumulative-budget tracking with atomic reserve-and-commit
  semantics inside the `OnlineAuthorizer`, preventing double-spend across
  concurrent requests. The core's exact integer money types give the arithmetic
  foundation; the platform supplies the authoritative, mutable budget state.
- **Status:** not built.

### Human approval workflows

- **Stage:** D.
- **Future seam:** the platform surfaces the core's `ApprovalRequired` verdict to
  a human approver and resolves it out of band. Until an explicit approval
  arrives, the bridge keeps the request denied. The core already models
  `ApprovalRequired` as distinct from an allow, so it can never be silently
  coerced into one.
- **Status:** not built.

### Audit infrastructure

- **Stage:** cross-cutting (A through E).
- **Future seam:** durable, tamper-evident records of outcomes and decisions. The
  core's `PolicyOutcome`, `Decision`, and `ReasonCode` are machine-readable and
  auditable by design, so the platform can record them without parsing prose.
  Audit logging must follow AGENTS.md Rule 18: no secrets, keys, or signatures in
  logs.
- **Status:** not built.

### Payment execution enforcement

- **Stage:** E (execution enforcement).
- **Future seam:** a concrete `IntegrationClient` that submits an **already
  authorized** `Decision` to payment providers or ledgers, and enforces that
  only an authorized decision is ever executed.
- **Status:** not built.

### Enterprise APIs and dashboard

- **Stage:** cross-cutting integration surface.
- **Future seam:** managed APIs and an operator dashboard over the services
  above. These are transport and presentation layers; they depend inward on the
  core and the other services and add no new authorization semantics of their
  own.
- **Status:** not built.

## What stays true across the future platform

- A valid signature is still not an authorization.
- Offline evaluation still cannot establish current revocation, cumulative
  budget, or global replay state; only the online authority can.
- The only path from a static `PolicyOutcome` to a final `Decision` is the
  fail-closed `authorize` bridge. The platform plugs an authority into that
  bridge; it never bypasses it.
- Deny-by-default holds: any error, timeout, unknown state, or approval-required
  signal resolves to `Deny`.
