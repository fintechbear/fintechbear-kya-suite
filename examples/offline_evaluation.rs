//! Offline evaluation example.
//!
//! Demonstrates stages A, B, and C running entirely offline, and shows that the
//! result is explicitly **not** an online authorization. The transaction is not
//! authorized until an authority (stage D) rules on it via the fail-closed
//! `kya_client::authorize` bridge, which this example does not do.
//!
//! Stage B here runs the **real** `kya-crypto` engine over a genuine Ed25519
//! signature produced in-example with a deterministic signing key, and it signs
//! the **mandate's canonical encoding**. This is deliberate: the authenticated
//! `VerifiedMandate` can only be minted when the signature covers the exact
//! mandate being evaluated, so an attacker cannot pair a signature over one
//! payload with a substituted mandate (Security Check B). An arbitrary
//! always-`Verified` stand-in verifier also cannot mint trusted evidence: the
//! real `kya-crypto` engine is the only path to a `VerifiedMandate`, and its
//! proof-minting path is owned privately inside `kya-crypto` and bound to the
//! reviewed `kya_crypto::Ed25519SignatureVerifier`, so an external verifier
//! cannot reach it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_core::decision::PolicyOutcome;
use kya_core::identity::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
};
use kya_core::mandate::{Mandate, TransactionIntent, ValidityWindow};
use kya_core::money::Money;
use kya_core::scope::{Action, Scope};
use kya_crypto::{verify_mandate, SignedMandate, TrustedKeyStore, VerifiedMandate};

fn main() {
    // Stage A: identity claims. Trust is explicit and deny-by-default. An
    // issuer is trusted only together with the specific key reference it signs
    // with.
    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    // A deterministic issuer signing key for the demo (NEVER do this in
    // production; real issuer private keys live in an HSM/KMS and never appear
    // in code). We only need the PUBLIC key to be trust-anchored and resolvable.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = signing_key.verifying_key();

    // Build the mandate: the agent, acting for the principal, may 'transfer' up
    // to 100.00 USD per transaction, valid within [0, 2000). THIS is what the
    // issuer signs over, via its canonical encoding.
    let limit = Money::from_code(10_000, "USD").expect("valid limit");
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(limit);
    let validity = ValidityWindow::new(0, 2_000).expect("valid window");
    let mandate = Mandate::new(
        issuer.clone(),
        principal.clone(),
        agent.clone(),
        scope,
        validity,
    );

    // The issuer signs the mandate's CANONICAL ENCODING, plus the request-time
    // audience and transaction binding it commits to. Signing the canonical
    // encoding is what binds the signature to this exact mandate.
    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-2026-0042";
    let signature = signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    // Explicit, allow-listed trust: anchor the (issuer, key) pair AND register
    // its concrete public-key bytes in the key store. Both are required.
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer.clone(), key_ref.clone());
    let mut key_store = TrustedKeyStore::new();
    key_store.insert(issuer.clone(), key_ref.clone(), *public_key.as_bytes());
    println!(
        "Stage A  issuer+key trusted: {}",
        anchors.trusts_key(&issuer, &key_ref)
    );

    // The agent presents a RAW claim: "issuer X delegated to me, signing with
    // key K". A claim proves nothing on its own.
    let claim =
        kya_core::evidence::DelegationClaim::new(issuer.clone(), agent.clone(), key_ref.clone());

    // Stage B: run the real cryptographic engine. `verify_mandate` derives the
    // bytes-to-verify from the mandate's canonical encoding, runs the real
    // `kya-crypto` engine whose verified-evidence mint-point is owned privately
    // inside `kya-crypto` and bound to the reviewed `Ed25519SignatureVerifier`,
    // checks the trust
    // anchor, audience, validity window, and binding, and finally mints a
    // `VerifiedMandate` only if the signed bytes equal the mandate's canonical
    // encoding. An arbitrary always-true verifier cannot reach this path, and a
    // substituted mandate cannot be paired with the signature. A verified
    // signature is still NOT an authorization.
    let now: u64 = 1_000;
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    match verify_mandate(&signed, &key_store, &anchors, now, audience, binding) {
        Ok(verified) => {
            println!(
                "Stage B  verified mandate for agent {} from issuer {}",
                verified.agent(),
                verified.issuer()
            );
            run_stage_c(verified, principal, agent, now);
        }
        Err(e) => {
            println!("Stage B  mandate NOT verified ({e}); fail closed.");
        }
    }
}

/// Stage C: static, offline policy evaluation of a concrete intent against the
/// authenticated verified mandate and an injected current time.
fn run_stage_c(verified: VerifiedMandate, principal: PrincipalId, agent: AgentId, now: u64) {
    let amount = Money::from_code(5_000, "USD").expect("valid amount");
    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        amount,
    )
    .with_principal(principal);

    let outcome = kya_core::policy::evaluate(&verified, &intent, now);
    match &outcome {
        PolicyOutcome::EligibleForOnlineAuthorization { reason } => {
            println!("Stage C  static checks PASSED, eligible for stage D ({reason})");
        }
        PolicyOutcome::Denied { reason } => {
            println!("Stage C  static checks DENIED ({reason})");
        }
        PolicyOutcome::InvalidEvidence { reason } => {
            println!("Stage C  invalid evidence ({reason})");
        }
        PolicyOutcome::RequiresApproval { reason } => {
            println!("Stage C  human approval required ({reason})");
        }
        PolicyOutcome::Indeterminate { reason } => {
            println!("Stage C  indeterminate, fail closed ({reason})");
        }
        _ => {
            // PolicyOutcome is #[non_exhaustive]; future variants are handled
            // conservatively as "not eligible".
            println!("Stage C  static checks produced an unrecognized outcome");
        }
    }

    println!();
    println!("IMPORTANT: an ELIGIBLE static outcome is NOT an authorization.");
    println!("No online authority (stage D) was consulted, so revocation,");
    println!("cumulative budget, and replay state are all unknown. The");
    println!("transaction remains UNAUTHORIZED until kya_client::authorize");
    println!("obtains an explicit approval from an OnlineAuthorizer.");
}
