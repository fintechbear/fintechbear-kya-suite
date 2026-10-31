//! EXAMPLE 10 - Honestly-documented AP2 adapter functionality.
//!
//! ============================================================================
//! EXPERIMENTAL / INCOMPLETE - NOT FULL AP2 INTEROP.
//! ----------------------------------------------------------------------------
//! The `kya-adapter-ap2` crate models AP2-style mandate CONSTRAINTS (permitted
//! action, exact amount + currency, identities, validity, audience, binding)
//! as explicit Rust types and maps them onto the `kya-core` domain. It does
//! NOT parse a real AP2 signature envelope, invents NO wire canonicalization or
//! endpoints, ships NO AP2 conformance test vectors, and claims NO AP2 wire
//! compatibility or certification. Official AP2 affiliation: NONE. See the
//! crate docs and docs/protocol-compatibility.md for the precise supported /
//! unsupported / unverified boundary. The adapter is deliberately NOT part of
//! the `kya-sdk` facade or prelude; this example depends on it directly.
//! ============================================================================
//!
//! What this example shows: build [`Ap2MandateConstraints`], map them to a
//! `kya-core` [`Mandate`] with `to_mandate()`, sign that mandate's CANONICAL
//! ENCODING (the kya-core internal format, NOT an AP2 serialization), verify it
//! through the real engine with [`verify_ap2_mandate`], and run the unchanged
//! stage-C [`evaluate`].
//!
//! What this example does NOT verify: it does NOT verify any AP2 wire envelope
//! (that is explicitly BLOCKED/UNVERIFIED). A verified mandate here is still
//! NOT an authorization: no online state (revocation / cumulative budget /
//! global replay) is established, and agent proof-of-possession is NOT
//! established.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_adapter_ap2::verify_ap2_mandate;
use kya_adapter_ap2::{
    Ap2Identities, Ap2MandateConstraints, Ap2SignedMandateBinding, Ap2SpendingLimit,
};

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{AgentId, IssuerId, MerchantId, ResourceId, TrustAnchors, TrustedKeyRef};
use kya_core::mandate::{Audience, TransactionBinding, TransactionIntent};
use kya_core::money::Money;
use kya_core::scope::Action;
use kya_crypto::TrustedKeyStore;

fn main() {
    println!("=== EXPERIMENTAL AP2 adapter (constraint mapping only; NOT AP2 wire interop) ===");

    // TEST-ONLY synthetic issuer key, deterministic. NEVER a production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    // Build AP2-style constraints (the independently-verifiable half).
    let constraints = Ap2MandateConstraints {
        identities: Ap2Identities {
            issuer: "issuer:acme-bank".to_owned(),
            principal: "principal:acme-treasury".to_owned(),
            agent: "agent:treasury-bot".to_owned(),
            allowed_merchants: Some(vec!["merchant:supplier-co".to_owned()]),
            allowed_resources: Some(vec!["invoice:2026-0042".to_owned()]),
        },
        permitted_action: "transfer".to_owned(),
        spending_limit: Ap2SpendingLimit {
            max_minor_units: 10_000,
            currency: "USD".to_owned(),
        },
        not_before: 0,
        not_after: 3_000,
        required_audience: Some("aud:acme-payments".to_owned()),
        requires_human_approval: false,
        transaction_binding: Some("txn:invoice-2026-0042".to_owned()),
    };

    // Map the constraints onto a kya-core Mandate (pure, panic-free, total).
    let mandate = constraints
        .to_mandate()
        .expect("AP2 constraints should map onto a valid mandate");
    println!(
        "mapped AP2 constraints -> mandate: issuer={} agent={}",
        mandate.issuer(),
        mandate.agent()
    );

    // Explicit, allow-listed trust configured directly (the adapter is outside
    // the facade).
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer.clone(), key_ref.clone());
    let mut store = TrustedKeyStore::new();
    store.insert(issuer.clone(), key_ref.clone(), *public_key.as_bytes());

    let audience = "aud:acme-payments";
    let binding = b"txn:invoice-2026-0042";
    let now: u64 = 1_500;

    // Sign the mandate's CANONICAL ENCODING (kya-core internal format, not AP2).
    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    let claim = DelegationClaim::new(issuer, agent.clone(), key_ref);
    let bundle = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 3_000,
        binding,
    };

    // Verify through the real engine (routes through kya_crypto::verify_mandate).
    let verified = verify_ap2_mandate(&bundle, &store, &anchors, now, audience, binding)
        .expect("genuine mandate-bound signature must verify through the AP2 seam");
    println!(
        "verified (adapter): issuer={} agent={} pop={}",
        verified.issuer(),
        verified.agent(),
        verified.proof_of_possession()
    );

    // The unchanged stage-C evaluator runs against the verified mandate. The
    // intent carries the audience and binding the mandate requires, so it is
    // eligible for online authorization.
    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(5_000, "USD").expect("valid amount"),
    )
    .with_audience(Audience::new("aud:acme-payments").expect("valid audience"))
    .with_binding(TransactionBinding::new("txn:invoice-2026-0042").expect("valid binding"));
    let outcome = kya_core::policy::evaluate(&verified, &intent, now);
    println!("stage C (adapter): reason={:?}", outcome.reason());

    println!();
    println!("Does NOT verify: this is EXPERIMENTAL and does NOT implement AP2");
    println!("wire interop (no envelope parsing, no conformance vectors, no");
    println!("verified serialization; official AP2 affiliation: none). A verified");
    println!("mandate is NOT authorization: no online state (revocation / budget /");
    println!("replay) is established, and agent proof-of-possession is NOT established.");
}
