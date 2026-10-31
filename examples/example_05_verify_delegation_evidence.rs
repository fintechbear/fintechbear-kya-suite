//! EXAMPLE 5 - Verify genuine signed delegation evidence.
//!
//! Walks the mandate-bound verification path (the FEAT-002 fix): the issuer
//! signs the mandate's canonical encoding, and the real `kya-crypto` engine
//! (via the facade's [`verify_mandate`]) mints a [`VerifiedMandate`] only when
//! the signature provably covers that exact mandate. The example then inspects
//! the AUTHENTICATED claims that come back - issuer, agent, key reference, and
//! the mandate's bound scope - none of which can be substituted after signing.
//! It also reads the honest [`ProofOfPossession`] state.
//!
//! What this example does NOT verify: the verified mandate proves the ISSUER
//! signed the complete mandate. It does NOT prove the AGENT holds its own
//! private key - [`VerifiedMandate::proof_of_possession`] is
//! [`ProofOfPossession::NotEstablished`]. It also establishes NO online state
//! (revocation / cumulative budget / global replay). Verified evidence is not
//! authorization.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;

fn main() {
    // TEST-ONLY synthetic issuer key, deterministic from a fixed seed. NEVER a
    // production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");

    // A fully-featured mandate: the agent may 'transfer' up to 250.00 USD, for
    // one merchant and one resource, within [0, 3000), targeting a named
    // audience and pinned to a transaction binding.
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(Money::from_code(25_000, "USD").expect("valid limit"))
        .with_allowed_merchants(vec![
            MerchantId::new("merchant:supplier-co").expect("valid merchant")
        ])
        .with_allowed_resources(vec![
            ResourceId::new("invoice:2026-0042").expect("valid resource")
        ])
        .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid currency")]);
    let mandate = Mandate::new(
        issuer.clone(),
        principal,
        agent.clone(),
        scope,
        ValidityWindow::new(0, 3_000).expect("valid window"),
    )
    .with_required_audience(Audience::new("aud:acme-payments").expect("valid audience"))
    .bound_to(TransactionBinding::new("txn:invoice-2026-0042").expect("valid binding"));

    let audience = "aud:acme-payments";
    let binding = b"txn:invoice-2026-0042";
    let now: u64 = 1_500;

    // The issuer signs the mandate's canonical encoding.
    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref);
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 3_000,
        binding,
    };

    let verified: VerifiedMandate = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine delegation over the canonical encoding must verify");

    // Inspect the AUTHENTICATED claims bound to the signature.
    println!("verified delegation evidence (mandate-bound):");
    println!("  issuer    = {}", verified.issuer());
    println!("  agent     = {}", verified.agent());
    println!("  key_ref   = {}", verified.key_ref());
    let m = verified.mandate();
    println!("  principal = {}", m.principal());
    if let Some(limit) = m.scope().per_transaction_limit() {
        println!(
            "  limit     = {} {} (minor units)",
            limit.minor_units(),
            limit.currency().as_str()
        );
    }
    println!("  proof_of_possession = {}", verified.proof_of_possession());

    println!();
    println!("Does NOT verify: this proves the ISSUER signed the complete mandate.");
    println!("It does NOT prove the AGENT possesses its own private key (PoP not");
    println!("established), and establishes NO online state (revocation / budget /");
    println!("replay). Verified evidence is not authorization.");
}
