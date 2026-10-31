//! EXAMPLE 9 - Explicit non-allowing outcome when required online state is
//! missing.
//!
//! Takes an eligible stage-C outcome (a genuine mandate, an in-scope intent)
//! and routes it through the fail-closed [`authorize`] bridge with an
//! [`OnlineAuthorizer`] that cannot establish authoritative online state. The
//! bridge NEVER upgrades eligibility to an `Allow`: an `ApprovalRequired`
//! verdict yields [`ReasonCode::ApprovalRequired`], and an authorizer error
//! (timeout / transport / unknown) yields [`ReasonCode::AuthorityUnavailable`].
//! Both are a [`Decision`] that is NOT allowed.
//!
//! What this example does NOT verify: it demonstrates precisely that
//! ELIGIBILITY IS NOT AUTHORIZATION. Because the authority could not establish
//! revocation / cumulative budget / global replay state, the only safe result
//! is `Deny`. There is no code path that turns a missing online check into an
//! approval.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on;

/// An in-example authorizer that returns a fixed verdict/error, using the same
/// ready-future pattern as the workspace's end-to-end tests. A real consumer
/// would implement `OnlineAuthorizer` against their own backend; here it stands
/// in for an authority that cannot establish online state.
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
    // TEST-ONLY synthetic issuer key, deterministic. NEVER a production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");

    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid limit"));
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

    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    let claim = DelegationClaim::new(issuer, agent.clone(), key_ref);
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    let verified = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine mandate must verify");

    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(5_000, "USD").expect("valid amount"),
    )
    .with_principal(principal);

    let outcome = evaluate(&verified, &intent, now);
    assert!(
        requires_online_authorization(&outcome),
        "the static outcome should be eligible so we can route it to stage D"
    );
    println!(
        "stage C: eligible ({:?}) - online check still owed.",
        outcome.reason()
    );

    // Route the ELIGIBLE outcome through the fail-closed bridge against an
    // authority that cannot establish online state.
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
        println!(
            "stage D [{label}]: allowed={} reason={:?}",
            decision.is_allowed(),
            decision.reason()
        );
        assert!(
            !decision.is_allowed(),
            "missing online state must never yield Allow"
        );
    }

    println!();
    println!("Does NOT verify: ELIGIBILITY IS NOT AUTHORIZATION. The authority");
    println!("could not establish revocation / cumulative budget / global replay");
    println!("state, so the fail-closed bridge returned Deny. No path upgrades a");
    println!("missing online check into an approval.");
}
