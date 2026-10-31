//! PRIMARY DEMO - the single recommended walkthrough of the FintechBear KYA SDK.
//!
//! This one example drives the whole verify -> evaluate -> authorize flow end to
//! end through the public [`kya_sdk`] facade, narrating each of the five
//! non-interchangeable stages (A identity, B signature verification, C static
//! policy, D online authority, E execution). The numbered `example_01..10`
//! files drill into individual facets; this file is the recommended starting
//! point.
//!
//! It demonstrates all six required points:
//!   1. explicit, allow-listed trusted-issuer configuration;
//!   2. a genuine Ed25519-signed mandate verified through `verify_mandate`;
//!   3. deterministic, offline static policy evaluation with `evaluate`;
//!   4. a valid in-scope transaction shown ELIGIBLE (online check still owed);
//!   5. a tampered signature rejected fail-closed (SignatureInvalid) and an
//!      over-limit intent denied by stage C (AmountExceedsLimit);
//!   6. the eligible outcome routed through the fail-closed `authorize` bridge
//!      against an authority that cannot establish online state -> Deny.
//!
//! The central lesson: a valid signature is NOT authorization, and an eligible
//! static outcome is NOT authorization. Only an explicit stage-D authority
//! approval, via the fail-closed bridge, can yield `Allow`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on;
use kya_sdk::CryptoVerificationError;

/// An in-example [`OnlineAuthorizer`] that returns a fixed verdict/error, using
/// the same ready-future pattern as the workspace's end-to-end tests. A real
/// consumer would implement this trait against their own authoritative backend
/// (revocation, cumulative budget, global replay). Here it stands in for an
/// authority that cannot establish that online state.
struct UnavailableAuthority {
    result: Result<AuthorityVerdict, AuthorizerError>,
}

struct Ready(Result<AuthorityVerdict, AuthorizerError>);

impl Future for Ready {
    type Output = Result<AuthorityVerdict, AuthorizerError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.0.clone())
    }
}

impl OnlineAuthorizer for UnavailableAuthority {
    type Fut = Ready;
    fn authorize_request(&self, _outcome: &PolicyOutcome) -> Self::Fut {
        Ready(self.result.clone())
    }
}

fn main() {
    println!("=== FintechBear KYA primary demo ===");
    println!("Flow: stage A identity -> B signature -> C policy -> D authority -> E execution.");
    println!();

    // TEST-ONLY deterministic issuer signing key, derived from a fixed seed so
    // the demo is reproducible. This is NEVER a production secret; a real issuer
    // would hold its private key in a secure store and you would configure only
    // the PUBLIC key below.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    // ---- Stage A: identity --------------------------------------------------
    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");
    println!("[1] stage A - identity: issuer={issuer} principal={principal} agent={agent}");

    // (1) Trusted-issuer configuration: trust is EXPLICIT and allow-listed.
    //     We anchor the (issuer, key_ref) pair and register its 32-byte public
    //     key. There is no implicit trust and no key discovery over a network.
    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");
    println!(
        "    trusted issuer key configured: trusts_issuer_key={}",
        trust.trusts_issuer_key(&issuer, &key_ref)
    );

    // The mandate the issuer delegates: the agent may `transfer` up to 100.00
    // USD per transaction, valid within the window [0, 2000).
    let per_txn_limit = Money::from_code(10_000, "USD").expect("valid limit");
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(per_txn_limit);
    let mandate = Mandate::new(
        issuer.clone(),
        principal.clone(),
        agent.clone(),
        scope,
        ValidityWindow::new(0, 2_000).expect("valid window"),
    );

    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-2026-0042";
    let now: u64 = 1_000;

    // (2) A GENUINE Ed25519 signature over the mandate's canonical encoding.
    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    let claim = DelegationClaim::new(issuer.clone(), agent.clone(), key_ref.clone());
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };

    // Stage B: verify the real signature through the facade. Success mints an
    // authenticated `VerifiedMandate`.
    let verified: VerifiedMandate = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine signature over the canonical encoding must verify");
    println!(
        "[2] stage B - signature verified: issuer={} agent={} key_ref={}",
        verified.issuer(),
        verified.agent(),
        verified.key_ref()
    );
    println!("    note: a verified signature is NOT authorization.");
    println!(
        "    agent proof-of-possession: {} (only the ISSUER signed).",
        verified.proof_of_possession()
    );

    // (3) + (4) Static, offline stage-C evaluation of an in-scope intent.
    //     Transfer 50.00 USD to a supplier - well under the 100.00 USD limit.
    let good_intent = TransactionIntent::new(
        agent.clone(),
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(5_000, "USD").expect("valid amount"),
    )
    .with_principal(principal.clone());

    let outcome = evaluate(&verified, &good_intent, now);
    println!(
        "[3] stage C - static policy: reason={:?} (deterministic, offline).",
        outcome.reason()
    );
    assert!(
        requires_online_authorization(&outcome),
        "an in-scope, in-limit intent should be eligible for online authorization"
    );
    println!(
        "[4] in-scope transaction is ELIGIBLE (requires_online_authorization={}).",
        requires_online_authorization(&outcome)
    );
    println!("    ELIGIBILITY IS NOT AUTHORIZATION - an online check is still owed.");

    // (5a) A tampered signature must fail closed. Flip one byte and re-verify.
    let mut tampered_signature = signature.clone();
    tampered_signature[0] ^= 0xFF;
    let tampered_signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &tampered_signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    match verify_mandate(
        &tampered_signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    ) {
        Ok(_) => panic!("SECURITY DEFECT: a tampered signature must never verify"),
        Err(e) => {
            assert_eq!(
                e,
                CryptoVerificationError::SignatureInvalid,
                "a flipped signature byte must fail closed with SignatureInvalid"
            );
            println!(
                "[5a] tampered signature rejected fail-closed: {e} ({:?}).",
                e.error_code()
            );
        }
    }

    // (5b) An over-limit intent is denied by stage C, terminally and offline.
    //      Transfer 100.01 USD against the 100.00 USD per-transaction limit.
    let over_limit_intent = TransactionIntent::new(
        agent.clone(),
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(10_001, "USD").expect("valid amount"),
    )
    .with_principal(principal);
    let denied = evaluate(&verified, &over_limit_intent, now);
    assert!(
        !requires_online_authorization(&denied),
        "an over-limit intent must not be eligible"
    );
    assert_eq!(denied.reason(), ReasonCode::AmountExceedsLimit);
    println!(
        "[5b] over-limit intent denied by stage C: reason={:?} (terminal, fail-closed).",
        denied.reason()
    );

    // (6) Route the ELIGIBLE outcome through the fail-closed `authorize` bridge
    //     against an authority that cannot establish online state. The bridge
    //     NEVER upgrades eligibility to an Allow.
    println!("[6] stage D - online authority (only stage that can yield Allow):");
    for (label, authority) in [
        (
            "authority requires out-of-band approval",
            UnavailableAuthority {
                result: Ok(AuthorityVerdict::ApprovalRequired),
            },
        ),
        (
            "authority unreachable (timeout)",
            UnavailableAuthority {
                result: Err(AuthorizerError::Timeout),
            },
        ),
    ] {
        let decision: Decision = block_on(authorize(&authority, &outcome));
        assert!(
            !decision.is_allowed(),
            "missing online state must never yield Allow"
        );
        println!(
            "    [{label}] -> allowed={} reason={:?}",
            decision.is_allowed(),
            decision.reason()
        );
    }

    println!();
    println!("Summary: a valid signature and an eligible static outcome are NOT");
    println!("authorization. Without an authoritative stage-D approval the fail-closed");
    println!("bridge returns Deny. Only an explicit authority Allow would let stage E");
    println!("(execution enforcement) proceed.");
}
