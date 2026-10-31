//! Stage C: deterministic, offline static policy evaluation.
//!
//! The [`evaluate`] function checks a [`TransactionIntent`] against the mandate
//! held in an authenticated mandate (an [`crate::evidence::AuthenticatedMandate`],
//! in practice the concrete `kya_crypto::VerifiedMandate`), which is the source
//! of truth for both the agent/issuer identity **and** every mandate
//! constraint. It is pure and deterministic, performs no I/O, reads no system
//! clock (the current time is injected), and returns a typed [`PolicyOutcome`].
//!
//! # Evidence versus claims (the identity and mandate trust rule)
//!
//! The single most important rule here is that the evaluator treats **only**
//! the facts in an authenticated mandate as established. The agent, issuer, and
//! *all* mandate constraints (scope, limit, currency, validity, audience,
//! approval, binding, principal) come from the verified mandate, which (per the
//! `kya-crypto` crate) can only be minted by passing through real cryptographic
//! verification of the mandate's exact canonical encoding against a trust
//! anchor. A free-standing, unverified `Mandate` can therefore never be
//! substituted into evaluation as trusted constraints: the only constructor for
//! a `kya_crypto::VerifiedMandate` requires the signed bytes to equal the
//! mandate's canonical encoding. Everything in the [`TransactionIntent`] still
//! arrives from the untrusted input boundary and is a **claim** to be checked,
//! never evidence.
//!
//! Concretely, the acting agent is taken from `verified.agent()`, and the
//! intent's own `agent()` field is treated as a claim that must match it. An
//! intent whose claimed agent disagrees with the verified agent is rejected.
//!
//! # The twelve static checks
//!
//! Evaluation runs these checks, each with a distinct machine-readable
//! [`ReasonCode`], and short-circuits on the first failure (deny-leaning):
//!
//! 1. **Verified agent identity** — the verified agent must equal the mandate's
//!    agent, and the intent's claimed agent must equal the verified agent.
//! 2. **Trusted delegation issuer** — the verified delegation's issuer must
//!    equal the mandate's issuer (the verification already established the key
//!    is trust-anchored for that issuer).
//! 3. **Principal identity** — if the intent names a principal, it must match
//!    the mandate's principal.
//! 4. **Validity period** — the injected `now` must fall within the mandate's
//!    [`crate::mandate::ValidityWindow`].
//! 5. **Audience** — if the mandate requires an audience, the intent must
//!    target that exact audience.
//! 6. **Transaction binding** — if the mandate is bound to one transaction, the
//!    intent must carry the same binding (prevents transaction substitution).
//! 7. **Authorized actions** — the action must be in the scope allow-list.
//! 8. **Merchant restrictions** — the merchant must be permitted by scope.
//! 9. **Resource restrictions** — the resource must be permitted by scope.
//! 10. **Currency restrictions** — the amount's currency must be permitted by
//!     scope.
//! 11. **Transaction spending limit** — the amount must not exceed the
//!     per-transaction limit, compared with exact [`crate::money::Money`]
//!     arithmetic (cross-currency is rejected fail-closed).
//! 12. **Human approval** — if the mandate requires human approval, the outcome
//!     is [`PolicyOutcome::RequiresApproval`], never a silent eligible pass.
//!
//! # What a passing outcome means
//!
//! A [`PolicyOutcome::EligibleForOnlineAuthorization`] is **not** an
//! authorization. It only means the static rules found nothing to forbid and
//! the request is eligible to proceed to the authoritative stage D check.
//! Revocation, cumulative budgets, and global replay state are out of scope
//! here and require the online authority in `kya-client`. The evaluator never
//! produces a [`crate::decision::Decision`]; the only bridge is the fail-closed
//! `kya_client::authorize`.

use crate::decision::{PolicyOutcome, ReasonCode};
use crate::evidence::AuthenticatedMandate;
use crate::mandate::TransactionIntent;

/// Evaluate a transaction intent against an **authenticated** mandate using
/// static rules only, anchored on verified evidence and an injected current
/// time.
///
/// `verified` is any [`AuthenticatedMandate`] — in practice the concrete
/// `kya_crypto::VerifiedMandate`, which can only be produced by
/// `kya_crypto::verify_mandate` running the reviewed verifier over a real
/// signature covering the mandate's exact canonical encoding against a trust
/// anchor. It supplies both the established agent/issuer identity **and** the
/// mandate's constraints, cryptographically bound together. The mandate's
/// constraints are therefore read from `verified`, never from a free-standing,
/// unverified value — so an attacker cannot substitute a mandate whose
/// constraints differ from the signed one. `now` is the current time in Unix
/// seconds, injected by the caller so that evaluation stays deterministic and
/// `kya-core` reads no system clock.
///
/// The trait seam keeps `kya-core` crypto-free (it does not name the concrete
/// verified type) while still reading only authenticated facts. Implementing
/// [`AuthenticatedMandate`] is not a trust claim: `evaluate` only ever returns a
/// [`PolicyOutcome`] (stage C), which can never become an `Allow` without the
/// stage-D authority. The security boundary is the construction of the verified
/// mandate, which lives in `kya-crypto`.
///
/// Evaluation is deny-leaning: the first failing check short-circuits. The
/// returned [`PolicyOutcome`] is never an authorization; at most it is
/// [`PolicyOutcome::EligibleForOnlineAuthorization`], the single state the
/// fail-closed bridge may forward to the authority.
pub fn evaluate(
    verified: &impl AuthenticatedMandate,
    intent: &TransactionIntent,
    now: u64,
) -> PolicyOutcome {
    // The mandate's constraints and identities come from the authenticated
    // verified mandate: the signature provably covered this exact mandate's
    // canonical encoding, so none of these fields is attacker-substitutable.
    let mandate = verified.mandate();

    // Check 1a: the VERIFIED agent must be the agent the mandate was granted
    // to. The VerifiedMandate construction already binds the signed mandate's
    // fields, so this holds by construction; it is kept as a defense-in-depth
    // evidence-level consistency check (InvalidEvidence, not a policy denial).
    if verified.agent() != mandate.agent() {
        return PolicyOutcome::InvalidEvidence {
            reason: ReasonCode::EvidenceInvalid,
        };
    }

    // Check 2: the VERIFIED delegation must be for the mandate's issuer.
    // Likewise guaranteed by construction and kept for defense in depth.
    if verified.issuer() != mandate.issuer() {
        return PolicyOutcome::InvalidEvidence {
            reason: ReasonCode::EvidenceInvalid,
        };
    }

    // Check 1b: the acting agent CLAIMED by the untrusted intent must match the
    // verified agent. The intent's agent field is a claim, not evidence; a
    // mismatch means the request is not the one the delegation authorizes.
    if intent.agent() != verified.agent() {
        return PolicyOutcome::Denied {
            reason: ReasonCode::AgentMismatch,
        };
    }

    // Check 3: if the intent names a principal, it must match the mandate's.
    // A missing principal is not fabricated into a match; it simply is not
    // checked here and remains a stage-D concern if required.
    if let Some(principal) = intent.principal() {
        if principal != mandate.principal() {
            return PolicyOutcome::Denied {
                reason: ReasonCode::PrincipalMismatch,
            };
        }
    }

    // Check 4: the mandate must be within its validity window at `now`.
    let validity = mandate.validity();
    if validity.is_not_yet_valid_at(now) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::MandateNotYetValid,
        };
    }
    if validity.is_expired_at(now) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::MandateExpired,
        };
    }

    // Check 5: if the mandate requires an audience, the intent must target it.
    if let Some(required) = mandate.required_audience() {
        match intent.audience() {
            Some(aud) if aud == required => {}
            _ => {
                return PolicyOutcome::Denied {
                    reason: ReasonCode::AudienceMismatch,
                };
            }
        }
    }

    // Check 6: if the mandate is bound to one transaction, the intent must
    // carry the same binding. This is the anti-substitution check: a mandate
    // for one transaction cannot be replayed against a different one.
    if let Some(bound) = mandate.binding() {
        match intent.binding() {
            Some(b) if b == bound => {}
            _ => {
                return PolicyOutcome::Denied {
                    reason: ReasonCode::BindingMismatch,
                };
            }
        }
    }

    // Check 7: the requested action must be explicitly permitted by scope.
    let scope = mandate.scope();
    if !scope.permits(intent.action()) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::ActionNotPermitted,
        };
    }

    // Check 8: the merchant counterparty must be permitted by scope.
    if !scope.permits_merchant(intent.merchant()) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::MerchantNotPermitted,
        };
    }

    // Check 9: the resource acted on must be permitted by scope.
    if !scope.permits_resource(intent.resource()) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::ResourceNotPermitted,
        };
    }

    // Check 10: the transaction currency must be permitted by scope.
    if !scope.permits_currency(&intent.amount().currency()) {
        return PolicyOutcome::Denied {
            reason: ReasonCode::CurrencyNotPermitted,
        };
    }

    // Check 11: if a per-transaction limit exists, the amount must not exceed
    // it. Comparison uses exact i128 minor units via Money::try_cmp. A currency
    // mismatch between the limit and the intent is treated as a rejection
    // (fail-closed), never silently converted or rounded.
    if let Some(limit) = scope.per_transaction_limit() {
        match intent.amount().try_cmp(limit) {
            Ok(core::cmp::Ordering::Greater) => {
                return PolicyOutcome::Denied {
                    reason: ReasonCode::AmountExceedsLimit,
                };
            }
            Ok(_) => {}
            Err(_) => {
                // Cross-currency comparison: fail closed. This should normally
                // be caught earlier by the currency restriction, but if the
                // limit's currency differs from an otherwise-permitted amount
                // we still refuse rather than convert.
                return PolicyOutcome::Denied {
                    reason: ReasonCode::CurrencyNotPermitted,
                };
            }
        }
    }

    // Check 12: a mandate that requires human approval can never statically
    // pass. Surface RequiresApproval so the caller routes it to out-of-band
    // approval instead of forwarding it to the authority as eligible.
    if mandate.requires_human_approval() {
        return PolicyOutcome::RequiresApproval {
            reason: ReasonCode::ApprovalRequired,
        };
    }

    // Every static check passed. This is explicitly NOT an authorization: it is
    // eligibility to proceed to the authoritative stage D check.
    PolicyOutcome::EligibleForOnlineAuthorization {
        reason: ReasonCode::StaticChecksPassed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{AuthenticatedMandate, ProofOfPossession};
    use crate::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustedKeyRef};
    use crate::mandate::{Audience, Mandate, TransactionBinding, ValidityWindow};
    use crate::money::{CurrencyCode, Money};
    use crate::scope::{Action, Scope};

    const NOW: u64 = 1_500;

    fn agent(id: &str) -> AgentId {
        AgentId::new(id).expect("valid agent id")
    }

    fn issuer() -> IssuerId {
        IssuerId::new("issuer:acme").expect("valid issuer")
    }

    fn key() -> TrustedKeyRef {
        TrustedKeyRef::new("kid:1").expect("valid key ref")
    }

    fn usd(minor: i128) -> Money {
        Money::from_code(minor, "USD").expect("valid USD")
    }

    /// A test-only authenticated-mandate stand-in used purely to exercise the
    /// stage-C evaluator. Implementing [`AuthenticatedMandate`] is NOT a trust
    /// claim and mints no evidence: `evaluate` only ever returns a
    /// [`PolicyOutcome`], never an authorization. The real authenticated mandate
    /// (`kya_crypto::VerifiedMandate`) can only be constructed by `kya-crypto`
    /// after a real signature verification; this fixture does not and cannot
    /// stand in for that construction anywhere outside stage-C evaluation.
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

    /// Wrap a mandate as a [`TestMandate`], deriving the agent/issuer from the
    /// mandate itself (so evaluation's by-construction consistency checks hold,
    /// matching what a genuine `VerifiedMandate` guarantees).
    fn verified_mandate(mandate: Mandate) -> TestMandate {
        TestMandate {
            issuer: mandate.issuer().clone(),
            agent: mandate.agent().clone(),
            key_ref: key(),
            mandate,
        }
    }

    fn mandate_with(scope: Scope) -> Mandate {
        Mandate::new(
            issuer(),
            PrincipalId::new("principal:alice").expect("valid"),
            agent("agent:1"),
            scope,
            ValidityWindow::new(1_000, 2_000).expect("valid window"),
        )
    }

    fn mandate_for(action: &str, limit: Money) -> Mandate {
        mandate_with(
            Scope::new()
                .allow(Action::new(action).expect("valid"))
                .with_per_transaction_limit(limit),
        )
    }

    fn intent(agent_id: &str, action: &str, amount: Money) -> TransactionIntent {
        TransactionIntent::new(
            agent(agent_id),
            MerchantId::new("merchant:store").expect("valid"),
            ResourceId::new("order:42").expect("valid"),
            Action::new(action).expect("valid"),
            amount,
        )
    }

    // ---- authenticated-mandate view ------------------------------------

    #[test]
    fn test_mandate_reports_pop_not_established() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        assert_eq!(vm.proof_of_possession(), ProofOfPossession::NotEstablished);
        assert_eq!(vm.issuer(), &issuer());
        assert_eq!(vm.key_ref(), &key());
    }

    // ---- happy path ----------------------------------------------------

    #[test]
    fn eligible_when_all_static_checks_pass() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, NOW),
            PolicyOutcome::EligibleForOnlineAuthorization {
                reason: ReasonCode::StaticChecksPassed
            }
        );
    }

    // ---- check 1: verified agent identity -------------------------------

    #[test]
    fn denies_when_intent_agent_claim_differs_from_verified_agent() {
        // Verified mandate is for agent:1, but the untrusted intent claims
        // agent:2. A claim can never override the authenticated mandate.
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:2", "transfer", usd(5_000));
        assert_eq!(evaluate(&vm, &r, NOW).reason(), ReasonCode::AgentMismatch);
    }

    // ---- check 3: principal ---------------------------------------------

    #[test]
    fn denies_principal_mismatch() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_principal(PrincipalId::new("principal:mallory").expect("valid"));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::PrincipalMismatch
        );
    }

    #[test]
    fn passes_when_principal_matches() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_principal(PrincipalId::new("principal:alice").expect("valid"));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    // ---- check 4: validity window ---------------------------------------

    #[test]
    fn denies_when_mandate_not_yet_valid() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, 999).reason(),
            ReasonCode::MandateNotYetValid
        );
    }

    #[test]
    fn denies_when_mandate_expired() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, 2_000).reason(),
            ReasonCode::MandateExpired
        );
    }

    #[test]
    fn valid_at_nbf_inclusive_boundary() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert!(evaluate(&vm, &r, 1_000).is_eligible_for_online_authorization());
    }

    // ---- check 5: audience ----------------------------------------------

    #[test]
    fn denies_when_audience_missing_but_required() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .with_required_audience(Audience::new("aud:processor").expect("valid")),
        );
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::AudienceMismatch
        );
    }

    #[test]
    fn denies_when_audience_wrong() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .with_required_audience(Audience::new("aud:processor").expect("valid")),
        );
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_audience(Audience::new("aud:other").expect("valid"));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::AudienceMismatch
        );
    }

    #[test]
    fn passes_when_audience_matches() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .with_required_audience(Audience::new("aud:processor").expect("valid")),
        );
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_audience(Audience::new("aud:processor").expect("valid"));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    // ---- check 6: transaction binding -----------------------------------

    #[test]
    fn denies_transaction_substitution() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .bound_to(TransactionBinding::new("txn:A").unwrap()),
        );
        // Intent carries a DIFFERENT binding: substitution attempt.
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_binding(TransactionBinding::new("txn:B").unwrap());
        assert_eq!(evaluate(&vm, &r, NOW).reason(), ReasonCode::BindingMismatch);
    }

    #[test]
    fn denies_when_binding_required_but_absent() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .bound_to(TransactionBinding::new("txn:A").unwrap()),
        );
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(evaluate(&vm, &r, NOW).reason(), ReasonCode::BindingMismatch);
    }

    #[test]
    fn passes_when_binding_matches() {
        let vm = verified_mandate(
            mandate_for("transfer", usd(10_000))
                .bound_to(TransactionBinding::new("txn:A").unwrap()),
        );
        let r = intent("agent:1", "transfer", usd(5_000))
            .with_binding(TransactionBinding::new("txn:A").unwrap());
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    // ---- check 7: action -------------------------------------------------

    #[test]
    fn denies_action_not_in_scope() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "refund", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::ActionNotPermitted
        );
    }

    // ---- check 8: merchant ----------------------------------------------

    #[test]
    fn denies_merchant_not_in_allow_list() {
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_merchants(vec![MerchantId::new("merchant:trusted").expect("valid")]);
        let vm = verified_mandate(mandate_with(scope));
        // Intent's merchant is "merchant:store", not in the allow-list.
        let r = intent("agent:1", "transfer", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::MerchantNotPermitted
        );
    }

    #[test]
    fn passes_when_merchant_in_allow_list() {
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")]);
        let vm = verified_mandate(mandate_with(scope));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    // ---- check 9: resource ----------------------------------------------

    #[test]
    fn denies_resource_not_in_allow_list() {
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_resources(vec![ResourceId::new("order:allowed").expect("valid")]);
        let vm = verified_mandate(mandate_with(scope));
        let r = intent("agent:1", "transfer", usd(5_000)); // resource order:42
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::ResourceNotPermitted
        );
    }

    // ---- check 10: currency ---------------------------------------------

    #[test]
    fn denies_currency_not_in_allow_list() {
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_allowed_currencies(vec![CurrencyCode::new("EUR").expect("valid")]);
        let vm = verified_mandate(mandate_with(scope));
        let r = intent("agent:1", "transfer", usd(5_000)); // USD, not EUR
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::CurrencyNotPermitted
        );
    }

    #[test]
    fn passes_when_currency_in_allow_list() {
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]);
        let vm = verified_mandate(mandate_with(scope));
        let r = intent("agent:1", "transfer", usd(5_000));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    // ---- check 11: spending limit & financial boundaries ----------------

    #[test]
    fn denies_amount_over_limit() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(10_001));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::AmountExceedsLimit
        );
    }

    #[test]
    fn passes_amount_exactly_at_limit() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(10_000));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    #[test]
    fn passes_zero_amount() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(0));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    #[test]
    fn passes_one_minor_unit() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(1));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    #[test]
    fn handles_i128_max_limit_and_amount_without_panic() {
        // Limit at i128::MAX, amount at i128::MAX: exactly at limit, no overflow.
        let vm = verified_mandate(mandate_for("transfer", usd(i128::MAX)));
        let r = intent("agent:1", "transfer", usd(i128::MAX));
        assert!(evaluate(&vm, &r, NOW).is_eligible_for_online_authorization());
    }

    #[test]
    fn denies_amount_i128_max_over_lower_limit() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let r = intent("agent:1", "transfer", usd(i128::MAX));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::AmountExceedsLimit
        );
    }

    #[test]
    fn denies_cross_currency_limit_comparison_fail_closed() {
        // Limit in USD, amount in EUR. Currency restriction is Any (unset), so
        // the cross-currency comparison in try_cmp fails closed rather than
        // converting. The result is CurrencyNotPermitted (never a pass).
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)));
        let eur = Money::from_code(100, "EUR").expect("valid EUR");
        let r = intent("agent:1", "transfer", eur);
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::CurrencyNotPermitted
        );
    }

    // ---- check 12: human approval ---------------------------------------

    #[test]
    fn requires_approval_when_mandate_demands_it() {
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)).requiring_human_approval());
        let r = intent("agent:1", "transfer", usd(5_000));
        let outcome = evaluate(&vm, &r, NOW);
        assert_eq!(
            outcome,
            PolicyOutcome::RequiresApproval {
                reason: ReasonCode::ApprovalRequired
            }
        );
        assert!(
            !outcome.is_eligible_for_online_authorization(),
            "approval-required must never be eligible"
        );
    }

    #[test]
    fn approval_requirement_does_not_mask_an_earlier_denial() {
        // A failing static rule still short-circuits before the approval check.
        let vm = verified_mandate(mandate_for("transfer", usd(10_000)).requiring_human_approval());
        let r = intent("agent:1", "refund", usd(5_000));
        assert_eq!(
            evaluate(&vm, &r, NOW).reason(),
            ReasonCode::ActionNotPermitted
        );
    }
}
