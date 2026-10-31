//! Property-based tests for the stage-C policy engine (AGENTS.md Rule 15).
//!
//! These use the same dependency-free deterministic splitmix64 generator as the
//! other `kya-core` property suites (no proptest; Rule 13), exercising a wide,
//! reproducible spread of amounts, limits, and currencies. The two invariants
//! pinned here are:
//!
//! 1. `evaluate` never panics on any generated input (Rule 5); it always
//!    returns a typed [`PolicyOutcome`].
//! 2. The per-transaction spending-limit decision is *exactly* integer
//!    comparison of minor units in the same currency (Rule 8): an amount is
//!    eligible iff it is `<=` the limit, with no rounding, conversion, or
//!    floating point anywhere. A currency mismatch always fails closed and is
//!    never a pass.
//!
//! Evidence is modeled through a test-only [`AuthenticatedMandate`] view (the
//! only coupling the policy surface needs), so the tests focus purely on the
//! policy decision surface. The real authenticated mandate
//! (`kya_crypto::VerifiedMandate`) is constructed only by `kya-crypto` after a
//! genuine signature verification; implementing the view trait here mints no
//! evidence and yields no authorization (stage C only).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::decision::{PolicyOutcome, ReasonCode};
use kya_core::evidence::AuthenticatedMandate;
use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustedKeyRef};
use kya_core::mandate::{Mandate, TransactionIntent, ValidityWindow};
use kya_core::money::Money;
use kya_core::policy::evaluate;
use kya_core::scope::{Action, Scope};

/// A tiny deterministic PRNG (splitmix64). Not cryptographic — it only
/// enumerates a reproducible spread of inputs without a dependency.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A non-negative i128 spread across the whole non-negative range.
    fn next_nonneg_i128(&mut self) -> i128 {
        let hi = u128::from(self.next_u64());
        let lo = u128::from(self.next_u64());
        let combined = (hi << 64) | lo;
        (combined & (i128::MAX as u128)) as i128
    }
}

const SEEDS: [u64; 6] = [
    1,
    42,
    0xDEAD_BEEF,
    0x1234_5678_9ABC_DEF0,
    u64::MAX,
    0xCAFE_F00D,
];

const CASES_PER_SEED: usize = 2_000;
const NOW: u64 = 1_500;

/// A test-only [`AuthenticatedMandate`] view used to exercise the stage-C
/// policy engine. Implementing the view trait is not a trust claim and mints no
/// evidence; `evaluate` only ever returns a [`PolicyOutcome`] (never an
/// authorization). The real authenticated mandate (`kya_crypto::VerifiedMandate`)
/// is built only by `kya-crypto` after a genuine signature verification.
struct TestMandate {
    mandate: Mandate,
    issuer: IssuerId,
    agent: AgentId,
    key_ref: TrustedKeyRef,
}

impl AuthenticatedMandate for TestMandate {
    fn mandate(&self) -> &Mandate {
        &self.mandate
    }
    fn issuer(&self) -> &IssuerId {
        &self.issuer
    }
    fn agent(&self) -> &AgentId {
        &self.agent
    }
    fn key_ref(&self) -> &TrustedKeyRef {
        &self.key_ref
    }
}

fn issuer() -> IssuerId {
    IssuerId::new("issuer:acme").expect("valid")
}
fn agent() -> AgentId {
    AgentId::new("agent:1").expect("valid")
}
fn key() -> TrustedKeyRef {
    TrustedKeyRef::new("kid:1").expect("valid")
}

/// Wrap `mandate` as a [`TestMandate`], deriving agent/issuer from the mandate
/// itself so evaluation's by-construction consistency checks hold exactly as a
/// genuine verified mandate guarantees.
fn verified(mandate: Mandate) -> TestMandate {
    TestMandate {
        issuer: mandate.issuer().clone(),
        agent: mandate.agent().clone(),
        key_ref: key(),
        mandate,
    }
}

fn mandate(limit: Money) -> Mandate {
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid"))
        .with_per_transaction_limit(limit);
    Mandate::new(
        issuer(),
        PrincipalId::new("principal:alice").expect("valid"),
        agent(),
        scope,
        ValidityWindow::new(1_000, 2_000).expect("valid window"),
    )
}

fn intent(amount: Money) -> TransactionIntent {
    TransactionIntent::new(
        agent(),
        MerchantId::new("merchant:store").expect("valid"),
        ResourceId::new("order:42").expect("valid"),
        Action::new("transfer").expect("valid"),
        amount,
    )
}

#[test]
fn prop_spending_limit_matches_exact_integer_comparison() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let limit_minor = rng.next_nonneg_i128();
            let amount_minor = rng.next_nonneg_i128();
            let m = mandate(Money::from_code(limit_minor, "USD").expect("valid USD"));
            let vm = verified(m);
            let r = intent(Money::from_code(amount_minor, "USD").expect("valid USD"));

            // Invariant 1: never panics; always a typed outcome.
            let outcome = evaluate(&vm, &r, NOW);

            // Invariant 2: eligible iff amount <= limit, exactly, no rounding.
            if amount_minor <= limit_minor {
                assert_eq!(
                    outcome,
                    PolicyOutcome::EligibleForOnlineAuthorization {
                        reason: ReasonCode::StaticChecksPassed
                    },
                    "seed {seed:#x}: amount {amount_minor} <= limit {limit_minor} must be eligible"
                );
            } else {
                assert_eq!(
                    outcome,
                    PolicyOutcome::Denied {
                        reason: ReasonCode::AmountExceedsLimit
                    },
                    "seed {seed:#x}: amount {amount_minor} > limit {limit_minor} must deny"
                );
            }
        }
    }
}

#[test]
fn prop_cross_currency_amount_always_fails_closed_never_eligible() {
    // The limit is USD; a EUR amount can never be silently converted. Across a
    // wide spread of magnitudes the outcome must always be a fail-closed
    // CurrencyNotPermitted denial and NEVER eligible for online authorization.
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let limit_minor = rng.next_nonneg_i128();
            let amount_minor = rng.next_nonneg_i128();
            let m = mandate(Money::from_code(limit_minor, "USD").expect("valid USD"));
            let vm = verified(m);
            let r = intent(Money::from_code(amount_minor, "EUR").expect("valid EUR"));

            let outcome = evaluate(&vm, &r, NOW);
            assert!(
                !outcome.is_eligible_for_online_authorization(),
                "seed {seed:#x}: cross-currency must never be eligible"
            );
            assert_eq!(
                outcome.reason(),
                ReasonCode::CurrencyNotPermitted,
                "seed {seed:#x}: cross-currency must fail closed"
            );
        }
    }
}
