# Quick Start

This is a detailed quick start for the FintechBear KYA SDK. It mirrors the
[README](../README.md) Quick Start with more explanation. It walks the offline
stages (A identity, B signature verification, C static policy) through the
`kya-sdk` facade and shows explicitly that the result is **not** an
authorization until an online authority (stage D) rules on it.

FintechBear is the maintainer of this open-source project. It has no affiliation
with and no endorsement from Google, Visa, Mastercard, Skyfire, or any payment
network or standards body.

## Prerequisites

- Rust toolchain, minimum supported version **1.85** (edition 2021).
- A checkout of the repository (the crates are unpublished):

  ```sh
  git clone https://github.com/fintechbear/fintechbear-kya-suite.git
  cd fintechbear-kya-suite
  ```

- On **Windows**, source `vcvars64.bat` before building the crypto-linked
  crates, for example:

  ```bat
  "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  ```

## Run the example first

The quickest way to see a real verification is to run a compiling example:

```sh
cargo run -p kya-examples --example example_02_verify_signed_evidence
```

The source is
[`examples/example_02_verify_signed_evidence.rs`](../examples/example_02_verify_signed_evidence.rs).
The full end-to-end flow, including the stage-D bridge, is exercised by the
public-surface integration test at
[`crates/kya-sdk/tests/public_surface.rs`](../crates/kya-sdk/tests/public_surface.rs).

## One import

Everything a consumer needs comes from the facade prelude:

```rust,ignore
use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on; // only needed for the stage-D bridge
```

## Stage A: configure explicit trusted keys

Trust is explicit and allow-listed. `TrustConfiguration` bundles the trust
anchors (which `(issuer, key_ref)` pairs are trusted) and the key store (the
concrete 32-byte Ed25519 public-key bytes), because verification needs both.

```rust,ignore
let issuer = IssuerId::new("issuer:acme-bank")?;
let key_ref = TrustedKeyRef::new("kid:acme-2026")?;
let public_key_bytes: [u8; 32] = /* the issuer's real public key */;

let mut trust = TrustConfiguration::new();
trust.trust_issuer_key(issuer.clone(), key_ref.clone(), &public_key_bytes)?;
assert!(trust.trusts_issuer_key(&issuer, &key_ref));
```

A malformed key is rejected immediately with `TrustConfigurationError`.

## Build the mandate and a verification context

```rust,ignore
let principal = PrincipalId::new("principal:acme-treasury")?;
let agent = AgentId::new("agent:treasury-bot")?;

let limit = Money::from_code(10_000, "USD")?; // 100.00 USD, integer minor units
let scope = Scope::new()
    .allow(Action::new("transfer")?)
    .with_per_transaction_limit(limit);
let mandate = Mandate::new(
    issuer.clone(),
    principal,
    agent.clone(),
    scope,
    ValidityWindow::new(0, 2_000)?,
);

// Injected current time, expected audience, and the exact binding bytes.
let now: u64 = 1_000;
let audience = "aud:acme-payments";
let binding = b"txn-binding:invoice-2026-0042";
let conditions = RequestConditions::new(now, audience, binding);
```

## Stage B: verify the signature

`verify_mandate` routes through the real `kya-crypto` Ed25519 / JWS-EdDSA engine
and, on success, mints an authenticated `VerifiedMandate` that cryptographically
binds the complete mandate to the signature via the mandate's canonical
encoding.

```rust,ignore
let signed = SignedMandate {
    claim: &claim,
    mandate: &mandate,
    signature: &signature, // detached Ed25519 signature over mandate.canonical_encoding()
    audience,
    not_before: 0,
    expires_at: 2_000,
    binding,
};
let verified: VerifiedMandate = verify_mandate(
    &signed,
    trust.key_store(),
    trust.anchors(),
    conditions.now,
    conditions.expected_audience,
    conditions.expected_binding,
)?;

// Honest proof-of-possession reporting: only the ISSUER signed.
assert_eq!(verified.proof_of_possession(), ProofOfPossession::NotEstablished);
```

Passing stage B is **not** authorization.

## Stage C: evaluate static policy

```rust,ignore
let intent = TransactionIntent::new(
    AgentId::new("agent:treasury-bot")?,
    MerchantId::new("merchant:supplier-co")?,
    ResourceId::new("invoice:2026-0042")?,
    Action::new("transfer")?,
    Money::from_code(5_000, "USD")?,
);
let outcome = evaluate(&verified, &intent, now);
println!("reason: {:?}", outcome.reason());
```

## Verification vs authorization

Eligibility is not authorization. After local verification and evaluation the
online state is still unestablished:

```rust,ignore
assert!(requires_online_authorization(&outcome));
assert!(kya_sdk::online_state_is_unestablished(&outcome));
```

## Stage D: the fail-closed bridge

Only an explicit authority approval, routed through `authorize`, yields `Allow`.
You implement `OnlineAuthorizer` against your own backend.

```rust,ignore
let decision = block_on(authorize(&my_authority, &outcome));
if decision.is_allowed() {
    // proceed to stage E (execution enforcement) in your integration layer
}
```

There is deliberately no `From<PolicyOutcome> for Decision`. Any error, timeout,
unknown state, or approval-required signal resolves to `Deny`.

## Next steps

- [api-usage.md](api-usage.md) - the full facade surface, task by task.
- [architecture.md](architecture.md) - the five-stage model and crate layering.
- [security-limitations.md](security-limitations.md) - what the SDK cannot
  establish.
