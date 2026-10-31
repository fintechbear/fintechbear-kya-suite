# Primary demo walkthrough

This is the single recommended walkthrough of the FintechBear KYA SDK. It drives
the whole verify -> evaluate -> authorize flow end to end through the public
`kya-sdk` facade and narrates each of the five non-interchangeable stages.

The numbered examples (`example_01..10`) and `offline_evaluation` drill into
individual facets; [`examples/demo.rs`](../examples/demo.rs) is the one example
to read first. None of the existing examples are removed; they are referenced
across the docs and remain part of the release set.

## Run it

One command runs the demo:

```sh
cargo run -p kya-examples --example demo
```

On **Windows**, the MSVC linker is required (the crypto-linked crates need
`link.exe`). Source `vcvars64.bat` first, for example:

```bat
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cargo run -p kya-examples --example demo
```

## What the demo shows

The example exercises all of the following, in order, through the facade
(`use kya_sdk::prelude::*;` plus `kya_sdk::runtime::block_on`):

1. **Trusted-issuer configuration (stage A).** Trust is explicit and
   allow-listed: it anchors the `(issuer, key_ref)` pair and registers the
   issuer's 32-byte Ed25519 **public** key via
   `TrustConfiguration::trust_issuer_key`. There is no implicit trust and no key
   discovery over a network.
2. **Genuine signature verification (stage B).** It produces a real Ed25519
   signature over the mandate's canonical encoding and verifies it with
   `verify_mandate`, minting an authenticated `VerifiedMandate`. A verified
   signature is **not** authorization, and agent proof-of-possession is reported
   honestly as not established (only the issuer signed).
3. **Static policy evaluation (stage C).** `evaluate` runs the deterministic,
   offline evaluator over the verified mandate and a concrete
   `TransactionIntent`, producing a structured `PolicyOutcome`.
4. **An in-scope transaction shown eligible.** A 50.00 USD transfer against a
   100.00 USD per-transaction limit is eligible
   (`requires_online_authorization == true`). Eligibility is **not**
   authorization; an online check is still owed.
5. **Fail-closed rejections.**
   - **5a** A tampered signature (one byte flipped) is rejected with
     `CryptoVerificationError::SignatureInvalid`; no mandate is minted.
   - **5b** An over-limit intent (100.01 USD) is denied by stage C with
     `ReasonCode::AmountExceedsLimit`, terminally and offline.
6. **Required online authorization (stage D).** The eligible outcome is routed
   through the fail-closed `authorize` bridge against an in-example
   `OnlineAuthorizer` that cannot establish online state. The bridge never
   upgrades eligibility to an `Allow`: an `ApprovalRequired` verdict and an
   authorizer `Timeout` both yield a `Decision` that is **not** allowed. Only an
   explicit authority approval could let stage E (execution enforcement)
   proceed.

### Test-only signing key

The demo uses a **test-only**, deterministic signing key derived from a fixed
seed (`SigningKey::from_bytes(&[7u8; 32])`) purely so the walkthrough is
reproducible. It is **never a production secret**. A real issuer holds its
private key in a secure store; you would configure only the corresponding
**public** key. The repository contains no real secrets.

## Authorization-flow stages

```text
Stage A  Identity               who the agent and issuer claim to be
Stage B  Signature verification cryptographic authenticity (NOT authorization)
Stage C  Static policy          deterministic, offline scope/limit checks
Stage D  Online authority       revocation / budget / replay (only stage -> Allow)
Stage E  Execution enforcement  only an authorized Decision is ever executed
```

Eligibility (stages A + B + C passing) is never authorization. The only bridge
from a static `PolicyOutcome` to a final `Decision` is the fail-closed
`kya_client::authorize` function; there is deliberately no
`From<PolicyOutcome> for Decision` anywhere in the SDK.

## Captured output

The block below is the **real, verbatim** stdout of
`cargo run -p kya-examples --example demo` (captured on Windows with MSVC
sourced). It is not hand-written.

```text
=== FintechBear KYA primary demo ===
Flow: stage A identity -> B signature -> C policy -> D authority -> E execution.

[1] stage A - identity: issuer=issuer:acme-bank principal=principal:acme-treasury agent=agent:treasury-bot
    trusted issuer key configured: trusts_issuer_key=true
[2] stage B - signature verified: issuer=issuer:acme-bank agent=agent:treasury-bot key_ref=kid:acme-2026
    note: a verified signature is NOT authorization.
    agent proof-of-possession: agent proof-of-possession not established (only the ISSUER signed).
[3] stage C - static policy: reason=StaticChecksPassed (deterministic, offline).
[4] in-scope transaction is ELIGIBLE (requires_online_authorization=true).
    ELIGIBILITY IS NOT AUTHORIZATION - an online check is still owed.
[5a] tampered signature rejected fail-closed: signature did not verify (VerificationSignatureInvalid).
[5b] over-limit intent denied by stage C: reason=AmountExceedsLimit (terminal, fail-closed).
[6] stage D - online authority (only stage that can yield Allow):
    [authority requires out-of-band approval] -> allowed=false reason=ApprovalRequired
    [authority unreachable (timeout)] -> allowed=false reason=AuthorityUnavailable

Summary: a valid signature and an eligible static outcome are NOT
authorization. Without an authoritative stage-D approval the fail-closed
bridge returns Deny. Only an explicit authority Allow would let stage E
(execution enforcement) proceed.
```
