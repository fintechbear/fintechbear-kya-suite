# API Usage: the `kya-sdk` facade

This document describes the public surface of the `kya-sdk` facade crate and
maps it onto the ten developer tasks the facade promises. The facade is a thin,
outermost-ring crate that re-exports a curated, stable surface over the inner
crates (`kya-core`, `kya-crypto`, `kya-client`). It adds no new behaviour and no
new trust: every security-relevant operation it exposes is the same function
from the underlying crates, routed through the same sealed, fail-closed paths.

FintechBear is the maintainer. The project has no affiliation with and no
endorsement from Google, Visa, Mastercard, Skyfire, or any payment network or
standards body.

## Import surface

```rust,ignore
use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on;
```

The AP2 adapter is **not** in the prelude (it is experimental and incomplete);
import `kya-adapter-ap2` directly if you want to experiment with it.

## The ten developer tasks

### 1. Configure explicit trusted issuer keys

`TrustConfiguration` bundles `TrustAnchors` (which `(issuer, key_ref)` pairs are
trusted) and `TrustedKeyStore` (the concrete 32-byte Ed25519 public keys),
because verification needs both and configuring them separately is a common
first-day mistake.

```rust,ignore
let mut trust = TrustConfiguration::new();
trust.trust_issuer_key(issuer.clone(), key_ref.clone(), &public_key_bytes)?;
assert!(trust.trusts_issuer_key(&issuer, &key_ref));
let anchors = trust.anchors();
let key_store = trust.key_store();
```

Errors: `TrustConfigurationError` (for example `MalformedPublicKey { got }` when
the key is not 32 bytes). Trust is allow-listed with no wildcard and no key
discovery over the network.

### 2. Configure a verification context

`RequestConditions::new(now, audience, binding)` captures the injected current
time (Unix seconds), the expected audience, and the exact transaction-binding
bytes.

```rust,ignore
let conditions = RequestConditions::new(1_000u64, "aud:acme-payments", b"txn-binding:invoice-42");
```

### 3. Submit supported signed evidence

Assemble a `SignedMandate` (the `DelegationClaim`, the `Mandate`, the detached
Ed25519 signature, the audience / validity / binding), or a `SignedClaim` for
delegation-only verification.

```rust,ignore
let signed = SignedMandate {
    claim: &claim,
    mandate: &mandate,
    signature: &signature,
    audience,
    not_before: 0,
    expires_at: 2_000,
    binding,
};
```

### 4. Verify actual cryptographic signatures

`verify_mandate` and `verify_delegation` route through the real `kya-crypto`
engine and the sealed `kya-core` mint-point. There is no stand-in verifier.

```rust,ignore
let verified: VerifiedMandate = verify_mandate(
    &signed,
    trust.key_store(),
    trust.anchors(),
    conditions.now,
    conditions.expected_audience,
    conditions.expected_binding,
)?;
```

A `VerifiedMandate` cryptographically binds the complete mandate to the
signature via the mandate's canonical encoding (an internal, non-standardized,
versioned byte format). Errors are a `CryptoVerificationError` that maps to a
stable `ErrorCode` (see task 8).

### 5. Inspect authenticated claims

```rust,ignore
let issuer = verified.issuer();
let agent = verified.agent();
let key_ref = verified.key_ref();
// Honest proof-of-possession: only the ISSUER signed.
assert_eq!(verified.proof_of_possession(), ProofOfPossession::NotEstablished);
```

### 6. Supply a transaction intent

```rust,ignore
let intent = TransactionIntent::new(
    AgentId::new("agent:treasury")?,
    MerchantId::new("merchant:supplier")?,
    ResourceId::new("invoice:42")?,
    Action::new("transfer")?,
    Money::from_code(5_000, "USD")?,
);
```

`Money` is integer minor units plus an explicit ISO-4217 `CurrencyCode`; there
are no floats, arithmetic is checked, and cross-currency operations are
rejected.

### 7. Evaluate supported static constraints

`evaluate(&verified, &intent, now)` runs the deterministic, offline stage-C
evaluator over the verified mandate and the intent. It is synchronous and
performs no I/O.

```rust,ignore
let outcome: PolicyOutcome = evaluate(&verified, &intent, now);
```

### 8. Inspect structured outcomes and reason codes

`PolicyOutcome` has five meanings: `InvalidEvidence`, `Denied`,
`RequiresApproval`, `Indeterminate`, and `EligibleForOnlineAuthorization`. Each
carries a `ReasonCode`. Every public typed error maps to a stable kebab-case
`ErrorCode` via `AsErrorCode`, so you can branch on machine-readable codes
without parsing prose.

```rust,ignore
match outcome.reason() {
    ReasonCode::StaticChecksPassed => { /* eligible */ }
    other => { /* rejected statically; inspect `other` */ }
}
```

### 9. Identify missing authoritative online checks

```rust,ignore
// Eligibility is NOT authorization: you still owe an online check.
assert!(requires_online_authorization(&outcome));
// The offline flow never learns revocation / budget / replay state.
assert!(kya_sdk::online_state_is_unestablished(&outcome));
```

### 10. Integrate into a backend via the fail-closed bridge

Implement `OnlineAuthorizer` (and, for execution, `IntegrationClient`) against
your own backend, then call the one fail-closed `authorize` bridge.

```rust,ignore
let decision: Decision = block_on(authorize(&my_authority, &outcome));
if decision.is_allowed() {
    // proceed to stage E in your integration layer
}
```

Only an explicit `AuthorityVerdict::Approved` yields `Allow`. A rejecting
outcome never contacts the authority; any `AuthorizerError`, timeout, or
unknown state resolves to `Deny`. There is deliberately no
`From<PolicyOutcome> for Decision`.

## What the facade is not

- No new logic, no boolean-only authorization API, and no async wrapper around
  the synchronous local path.
- No concrete online authority, payment processor, budget ledger, approval
  server, or SaaS backend. Those are stage-D / stage-E seams you (or a future
  managed platform) implement.
- Not AP2 support; the experimental AP2 adapter is not re-exported here.

## See also

- [quickstart.md](quickstart.md) - a guided first run.
- [architecture.md](architecture.md) - the five-stage model and crate layering.
- [trust-model.md](trust-model.md) - explicit allow-listed trust.
- [security-limitations.md](security-limitations.md) - the structural limits.
