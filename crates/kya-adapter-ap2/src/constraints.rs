//! AP2 mandate **constraint** modeling and its mapping onto the KYA domain.
//!
//! This module implements the independently-verifiable half of the AP2 adapter:
//! explicit Rust types for the mandate constraint concepts that map cleanly onto
//! [`kya_core`], plus a pure function that turns them into a
//! [`kya_core::mandate::Mandate`].
//!
//! # Scope boundary (what is modeled here, and what is NOT)
//!
//! Per ADR-0001 the real AP2 signature **envelope** and its published **test
//! vectors** are `[UNVERIFIED]` and therefore **BLOCKED**. This module models
//! only the AP2 constraint fields whose meaning does **not** depend on that
//! envelope:
//!
//! - the permitted **action** (AP2 "what the agent may do");
//! - the exact **amount** and **currency** (AP2 spending constraint), as exact
//!   integer minor units with an explicit ISO-4217 currency (AGENTS.md Rule 8);
//! - the **identities** (issuer / agent / principal, and optional merchant and
//!   resource allow-lists);
//! - the **validity window**, optional required **audience**, optional
//!   **human-approval** requirement, and optional exact **transaction binding**.
//!
//! It does **not** model, parse, or canonicalize the signed envelope, the wire
//! field order, or any AP2-specific byte layout. Those bytes are supplied
//! verbatim by the caller to [`crate::verify::verify_ap2_delegation`]; this
//! module makes no claim about how an AP2 token is serialized or signed, and
//! makes no AP2 wire-compatibility claim (AGENTS.md Rule 20).
//!
//! # The mapping is deliberately total and panic-free
//!
//! [`Ap2MandateConstraints::to_mandate`] returns a `Result`: every field is
//! re-validated through the `kya-core` newtype constructors (so an illegal
//! identity, currency, or inverted validity window is rejected with a typed
//! [`crate::Ap2AdapterError`], never a panic). The resulting
//! [`kya_core::mandate::Mandate`] is an ordinary domain mandate: the existing
//! stage-C evaluator runs against it unchanged, and nothing here produces or
//! implies an authorization.

use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId};
use kya_core::mandate::{Audience, Mandate, TransactionBinding, ValidityWindow};
use kya_core::money::Money;
use kya_core::scope::{Action, Scope};

use crate::error::Ap2AdapterError;

/// The identity constraints an AP2 mandate carries.
///
/// These are the AP2 "who" fields mapped onto the KYA identity newtypes. The
/// issuer, principal, and agent are required (an AP2 mandate always delegates
/// from a named issuer, on behalf of a named principal, to a named agent). The
/// merchant and resource allow-lists are optional narrowings: `None` leaves the
/// corresponding scope dimension unrestricted ([`kya_core::scope::Restriction::Any`]),
/// while `Some(list)` restricts it to exactly the listed values (an empty list
/// therefore permits nothing — deny-by-default).
///
/// All values are owned `String`s here because they arrive from the untrusted
/// AP2 input boundary as raw text; they are validated into newtypes only when
/// [`Ap2MandateConstraints::to_mandate`] runs, so a malformed value fails
/// closed with a typed error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ap2Identities {
    /// The issuer (credential authority) that signed the mandate.
    pub issuer: String,
    /// The principal on whose behalf authority is delegated.
    pub principal: String,
    /// The agent the mandate was granted to.
    pub agent: String,
    /// Optional merchant allow-list. `None` means any merchant; `Some(list)`
    /// restricts to exactly those merchants (empty list permits none).
    pub allowed_merchants: Option<Vec<String>>,
    /// Optional resource allow-list, with the same `None`/`Some` semantics.
    pub allowed_resources: Option<Vec<String>>,
}

/// An AP2 spending constraint: an exact maximum amount in one currency.
///
/// Represented as integer **minor units** plus an explicit ISO-4217 currency
/// code string; there is no floating point anywhere (AGENTS.md Rule 8). The
/// currency also narrows the mandate's allowed-currency set to exactly this
/// currency, so a transaction in a different currency is denied by stage C
/// rather than silently converted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ap2SpendingLimit {
    /// The maximum per-transaction amount, in the currency's minor units.
    pub max_minor_units: i128,
    /// The ISO-4217 currency code (e.g. `"USD"`).
    pub currency: String,
}

/// The full set of AP2 mandate constraints this adapter can model without the
/// unverified signature envelope.
///
/// This is the adapter's typed input. [`Ap2MandateConstraints::to_mandate`]
/// maps it onto a [`kya_core::mandate::Mandate`] so the existing stage-C
/// evaluator can run unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ap2MandateConstraints {
    /// The identity constraints (issuer / principal / agent and optional
    /// merchant / resource allow-lists).
    pub identities: Ap2Identities,
    /// The single permitted action name (AP2 "what the agent may do").
    pub permitted_action: String,
    /// The per-transaction spending limit (exact amount + currency).
    pub spending_limit: Ap2SpendingLimit,
    /// Not-before time in Unix seconds (inclusive).
    pub not_before: u64,
    /// Not-after time in Unix seconds (exclusive).
    pub not_after: u64,
    /// Optional required audience the request must target.
    pub required_audience: Option<String>,
    /// Whether the mandate requires out-of-band human approval.
    pub requires_human_approval: bool,
    /// Optional exact transaction binding the mandate is pinned to.
    pub transaction_binding: Option<String>,
}

impl Ap2MandateConstraints {
    /// Map these AP2 constraints onto a [`kya_core::mandate::Mandate`].
    ///
    /// Every field is validated through the `kya-core` newtype constructors, so
    /// an illegal identity, an invalid currency, a negative amount, or an
    /// inverted validity window is rejected with a typed
    /// [`crate::Ap2AdapterError`]. The mapping is pure and panic-free.
    ///
    /// The resulting mandate's [`kya_core::scope::Scope`]:
    ///
    /// - allows exactly the one permitted action;
    /// - carries the spending limit as a per-transaction [`Money`] limit;
    /// - restricts the allowed currency to exactly the spending-limit currency;
    /// - applies the optional merchant and resource allow-lists.
    ///
    /// The mandate also carries the validity window and the optional audience,
    /// human-approval, and binding conditions.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Ap2AdapterError`] for any invalid constraint value.
    pub fn to_mandate(&self) -> Result<Mandate, Ap2AdapterError> {
        let issuer = IssuerId::new(&self.identities.issuer)?;
        let principal = PrincipalId::new(&self.identities.principal)?;
        let agent = AgentId::new(&self.identities.agent)?;

        let action = Action::new(&self.permitted_action)?;
        // Build the exact Money (currency + minor units) in one step; this
        // yields a MoneyError for a bad currency code or a negative amount,
        // both of which the adapter error type already wraps. Reuse the
        // validated currency for the allowed-currency restriction below.
        let limit = Money::from_code(
            self.spending_limit.max_minor_units,
            &self.spending_limit.currency,
        )?;
        let currency = limit.currency();

        let mut scope = Scope::new()
            .allow(action)
            .with_per_transaction_limit(limit)
            // Narrow the allowed currency to exactly the limit's currency so a
            // cross-currency transaction is denied by stage C, never converted.
            .with_allowed_currencies(vec![currency]);

        if let Some(merchants) = &self.identities.allowed_merchants {
            let mut ids = Vec::with_capacity(merchants.len());
            for m in merchants {
                ids.push(MerchantId::new(m)?);
            }
            scope = scope.with_allowed_merchants(ids);
        }
        if let Some(resources) = &self.identities.allowed_resources {
            let mut ids = Vec::with_capacity(resources.len());
            for r in resources {
                ids.push(ResourceId::new(r)?);
            }
            scope = scope.with_allowed_resources(ids);
        }

        let validity = ValidityWindow::new(self.not_before, self.not_after)?;

        let mut mandate = Mandate::new(issuer, principal, agent, scope, validity);

        if let Some(aud) = &self.required_audience {
            mandate = mandate.with_required_audience(Audience::new(aud)?);
        }
        if self.requires_human_approval {
            mandate = mandate.requiring_human_approval();
        }
        if let Some(binding) = &self.transaction_binding {
            mandate = mandate.bound_to(TransactionBinding::new(binding)?);
        }

        Ok(mandate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kya_core::money::CurrencyCode;
    use kya_core::scope::Restriction;

    fn base_constraints() -> Ap2MandateConstraints {
        Ap2MandateConstraints {
            identities: Ap2Identities {
                issuer: "issuer:acme".to_owned(),
                principal: "principal:alice".to_owned(),
                agent: "agent:1".to_owned(),
                allowed_merchants: None,
                allowed_resources: None,
            },
            permitted_action: "purchase".to_owned(),
            spending_limit: Ap2SpendingLimit {
                max_minor_units: 10_000,
                currency: "USD".to_owned(),
            },
            not_before: 1_000,
            not_after: 2_000,
            required_audience: None,
            requires_human_approval: false,
            transaction_binding: None,
        }
    }

    #[test]
    fn maps_core_constraints_onto_mandate() {
        let m = base_constraints().to_mandate().expect("valid mapping");
        assert_eq!(m.issuer().as_str(), "issuer:acme");
        assert_eq!(m.principal().as_str(), "principal:alice");
        assert_eq!(m.agent().as_str(), "agent:1");
        // Action is allow-listed.
        assert!(m.scope().permits(&Action::new("purchase").unwrap()));
        assert!(!m.scope().permits(&Action::new("refund").unwrap()));
        // Limit is exact minor units in the right currency.
        let limit = m.scope().per_transaction_limit().expect("limit set");
        assert_eq!(limit.minor_units(), 10_000);
        assert_eq!(limit.currency().as_str(), "USD");
        // Currency restriction is narrowed to exactly USD.
        assert!(m
            .scope()
            .permits_currency(&CurrencyCode::new("USD").unwrap()));
        assert!(!m
            .scope()
            .permits_currency(&CurrencyCode::new("EUR").unwrap()));
        // Validity window maps across.
        assert_eq!(m.validity().not_before(), 1_000);
        assert_eq!(m.validity().not_after(), 2_000);
        // No optional conditions by default.
        assert!(m.required_audience().is_none());
        assert!(!m.requires_human_approval());
        assert!(m.binding().is_none());
    }

    #[test]
    fn unspecified_merchant_and_resource_are_unrestricted() {
        let m = base_constraints().to_mandate().expect("valid");
        assert!(matches!(m.scope().allowed_merchants(), Restriction::Any));
        assert!(matches!(m.scope().allowed_resources(), Restriction::Any));
    }

    #[test]
    fn merchant_and_resource_allow_lists_map_across() {
        let mut c = base_constraints();
        c.identities.allowed_merchants = Some(vec!["merchant:store".to_owned()]);
        c.identities.allowed_resources = Some(vec!["order:42".to_owned()]);
        let m = c.to_mandate().expect("valid");
        assert!(m
            .scope()
            .permits_merchant(&MerchantId::new("merchant:store").unwrap()));
        assert!(!m
            .scope()
            .permits_merchant(&MerchantId::new("merchant:evil").unwrap()));
        assert!(m
            .scope()
            .permits_resource(&ResourceId::new("order:42").unwrap()));
        assert!(!m
            .scope()
            .permits_resource(&ResourceId::new("order:99").unwrap()));
    }

    #[test]
    fn empty_merchant_allow_list_permits_nothing() {
        let mut c = base_constraints();
        c.identities.allowed_merchants = Some(Vec::new());
        let m = c.to_mandate().expect("valid");
        assert!(!m
            .scope()
            .permits_merchant(&MerchantId::new("merchant:store").unwrap()));
    }

    #[test]
    fn optional_conditions_map_across() {
        let mut c = base_constraints();
        c.required_audience = Some("aud:processor".to_owned());
        c.requires_human_approval = true;
        c.transaction_binding = Some("txn:abc".to_owned());
        let m = c.to_mandate().expect("valid");
        assert_eq!(
            m.required_audience().map(|a| a.as_str()),
            Some("aud:processor")
        );
        assert!(m.requires_human_approval());
        assert_eq!(m.binding().map(|b| b.as_str()), Some("txn:abc"));
    }

    #[test]
    fn exact_minor_units_preserve_boundaries() {
        let mut c = base_constraints();
        c.spending_limit.max_minor_units = i128::MAX;
        let m = c.to_mandate().expect("valid");
        assert_eq!(
            m.scope().per_transaction_limit().unwrap().minor_units(),
            i128::MAX
        );
    }

    // ---- fail-closed construction (negative mapping) --------------------

    #[test]
    fn rejects_malformed_issuer_identity() {
        let mut c = base_constraints();
        c.identities.issuer = "issuer\nacme".to_owned(); // control char
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Identity(_))));
    }

    #[test]
    fn rejects_empty_action() {
        let mut c = base_constraints();
        c.permitted_action = "   ".to_owned();
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Scope(_))));
    }

    #[test]
    fn rejects_invalid_currency() {
        let mut c = base_constraints();
        c.spending_limit.currency = "usd".to_owned(); // lowercase, invalid
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Money(_))));
    }

    #[test]
    fn rejects_negative_amount() {
        let mut c = base_constraints();
        c.spending_limit.max_minor_units = -1;
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Money(_))));
    }

    #[test]
    fn rejects_inverted_validity_window() {
        let mut c = base_constraints();
        c.not_before = 2_000;
        c.not_after = 1_000;
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Validity(_))));
    }

    #[test]
    fn rejects_malformed_audience() {
        let mut c = base_constraints();
        c.required_audience = Some("aud\tbad".to_owned());
        assert!(matches!(c.to_mandate(), Err(Ap2AdapterError::Identity(_))));
    }
}
