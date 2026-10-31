//! Delegated-authority scope types.
//!
//! A [`Scope`] describes what an agent is permitted to do under a mandate: a set
//! of allowed actions and an optional per-transaction spending limit. Scope is
//! deny-by-default: an action is permitted only if it is explicitly listed.

use crate::identity::{MerchantId, ResourceId};
use crate::money::{CurrencyCode, Money};
use core::fmt;

/// A restriction over a set of allowed values for one dimension of a scope.
///
/// This makes the difference between "this dimension is not restricted" and
/// "this dimension is restricted to an explicit allow-list" a type-level fact,
/// so it can never be confused. An empty [`Restriction::AllowList`] permits
/// nothing (deny-by-default), whereas [`Restriction::Any`] is an explicit,
/// deliberate decision to leave the dimension unrestricted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restriction<T> {
    /// The dimension is deliberately not restricted: any value is permitted.
    Any,
    /// The dimension is restricted to exactly the listed values. An empty list
    /// permits nothing.
    AllowList(Vec<T>),
}

impl<T: PartialEq> Restriction<T> {
    /// Returns `true` if `value` is permitted under this restriction.
    ///
    /// [`Restriction::Any`] permits everything; [`Restriction::AllowList`]
    /// permits only listed values (so an empty list permits nothing).
    pub fn permits(&self, value: &T) -> bool {
        match self {
            Restriction::Any => true,
            Restriction::AllowList(items) => items.contains(value),
        }
    }
}

impl<T> Default for Restriction<T> {
    /// By default a dimension is unrestricted. Callers opt into an allow-list
    /// explicitly; the per-dimension default must not be an empty deny-all that
    /// a caller forgot to populate, which would silently reject every request.
    fn default() -> Self {
        Restriction::Any
    }
}

/// A single named action an agent may be delegated authority to perform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Action(String);

/// Error constructing an [`Action`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeError {
    /// The action name was empty.
    EmptyAction,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::EmptyAction => f.write_str("action name must not be empty"),
        }
    }
}

impl std::error::Error for ScopeError {}

impl Action {
    /// Construct and validate an action name.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError::EmptyAction`] if the name is empty after trimming.
    pub fn new(raw: &str) -> Result<Self, ScopeError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ScopeError::EmptyAction);
        }
        Ok(Action(trimmed.to_owned()))
    }

    /// The action name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The delegated authority granted to an agent.
///
/// Permission is allow-listed. An empty scope permits no actions. Merchant,
/// resource, and currency restrictions default to [`Restriction::Any`] (an
/// explicit "unrestricted" choice) and can be narrowed to an allow-list; the
/// per-transaction limit defaults to absent (no limit). The action set is the
/// exception: it is always deny-by-default, because an agent with no listed
/// action can do nothing at all.
#[derive(Debug, Clone)]
pub struct Scope {
    allowed_actions: Vec<Action>,
    per_transaction_limit: Option<Money>,
    allowed_merchants: Restriction<MerchantId>,
    allowed_resources: Restriction<ResourceId>,
    allowed_currencies: Restriction<CurrencyCode>,
}

impl Default for Scope {
    fn default() -> Self {
        Scope::new()
    }
}

impl Scope {
    /// Create an empty scope that permits no actions. Merchant, resource, and
    /// currency dimensions are unrestricted until narrowed; there is no
    /// per-transaction limit until one is set.
    pub fn new() -> Self {
        Scope {
            allowed_actions: Vec::new(),
            per_transaction_limit: None,
            allowed_merchants: Restriction::Any,
            allowed_resources: Restriction::Any,
            allowed_currencies: Restriction::Any,
        }
    }

    /// Allow a specific action.
    pub fn allow(mut self, action: Action) -> Self {
        if !self.allowed_actions.contains(&action) {
            self.allowed_actions.push(action);
        }
        self
    }

    /// Set a per-transaction spending limit.
    pub fn with_per_transaction_limit(mut self, limit: Money) -> Self {
        self.per_transaction_limit = Some(limit);
        self
    }

    /// Restrict the scope to a specific set of merchants (counterparties).
    ///
    /// Passing an empty list restricts the agent to transacting with no
    /// merchant at all (deny-by-default); use [`Restriction::Any`] via
    /// [`Scope::new`]'s default to leave merchants unrestricted.
    pub fn with_allowed_merchants(mut self, merchants: Vec<MerchantId>) -> Self {
        self.allowed_merchants = Restriction::AllowList(merchants);
        self
    }

    /// Restrict the scope to a specific set of resources.
    pub fn with_allowed_resources(mut self, resources: Vec<ResourceId>) -> Self {
        self.allowed_resources = Restriction::AllowList(resources);
        self
    }

    /// Restrict the scope to a specific set of transaction currencies.
    pub fn with_allowed_currencies(mut self, currencies: Vec<CurrencyCode>) -> Self {
        self.allowed_currencies = Restriction::AllowList(currencies);
        self
    }

    /// Returns `true` only if the action was explicitly allowed.
    pub fn permits(&self, action: &Action) -> bool {
        self.allowed_actions.contains(action)
    }

    /// The allowed actions, in the order they were declared.
    ///
    /// Exposed so the canonical mandate encoding can fold the action allow-list
    /// into the signed bytes deterministically; it is not part of the policy
    /// evaluation surface (use [`Scope::permits`] for that).
    pub fn allowed_actions(&self) -> &[Action] {
        &self.allowed_actions
    }

    /// The per-transaction spending limit, if any.
    pub fn per_transaction_limit(&self) -> Option<&Money> {
        self.per_transaction_limit.as_ref()
    }

    /// The merchant restriction.
    pub fn allowed_merchants(&self) -> &Restriction<MerchantId> {
        &self.allowed_merchants
    }

    /// The resource restriction.
    pub fn allowed_resources(&self) -> &Restriction<ResourceId> {
        &self.allowed_resources
    }

    /// The currency restriction.
    pub fn allowed_currencies(&self) -> &Restriction<CurrencyCode> {
        &self.allowed_currencies
    }

    /// Returns `true` if the merchant is permitted under this scope.
    pub fn permits_merchant(&self, merchant: &MerchantId) -> bool {
        self.allowed_merchants.permits(merchant)
    }

    /// Returns `true` if the resource is permitted under this scope.
    pub fn permits_resource(&self, resource: &ResourceId) -> bool {
        self.allowed_resources.permits(resource)
    }

    /// Returns `true` if the currency is permitted under this scope.
    pub fn permits_currency(&self, currency: &CurrencyCode) -> bool {
        self.allowed_currencies.permits(currency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{MerchantId, ResourceId};
    use crate::money::CurrencyCode;

    #[test]
    fn empty_scope_permits_nothing() {
        let scope = Scope::new();
        let action = Action::new("transfer").expect("valid");
        assert!(!scope.permits(&action));
    }

    #[test]
    fn allow_is_explicit() {
        let transfer = Action::new("transfer").expect("valid");
        let refund = Action::new("refund").expect("valid");
        let scope = Scope::new().allow(transfer.clone());
        assert!(scope.permits(&transfer));
        assert!(!scope.permits(&refund));
    }

    #[test]
    fn rejects_empty_action() {
        assert_eq!(Action::new("  "), Err(ScopeError::EmptyAction));
    }

    #[test]
    fn restriction_any_permits_everything() {
        let r: Restriction<MerchantId> = Restriction::Any;
        let m = MerchantId::new("merchant:store").expect("valid");
        assert!(r.permits(&m));
    }

    #[test]
    fn restriction_allow_list_is_deny_by_default_when_empty() {
        let r: Restriction<MerchantId> = Restriction::AllowList(Vec::new());
        let m = MerchantId::new("merchant:store").expect("valid");
        assert!(!r.permits(&m), "empty allow-list permits nothing");
    }

    #[test]
    fn restriction_allow_list_permits_only_listed() {
        let allowed = MerchantId::new("merchant:store").expect("valid");
        let other = MerchantId::new("merchant:evil").expect("valid");
        let r = Restriction::AllowList(vec![allowed.clone()]);
        assert!(r.permits(&allowed));
        assert!(!r.permits(&other));
    }

    #[test]
    fn scope_merchant_restriction_defaults_to_any() {
        let scope = Scope::new();
        let m = MerchantId::new("merchant:store").expect("valid");
        assert!(scope.permits_merchant(&m));
    }

    #[test]
    fn scope_narrows_merchants() {
        let allowed = MerchantId::new("merchant:store").expect("valid");
        let other = MerchantId::new("merchant:evil").expect("valid");
        let scope = Scope::new().with_allowed_merchants(vec![allowed.clone()]);
        assert!(scope.permits_merchant(&allowed));
        assert!(!scope.permits_merchant(&other));
    }

    #[test]
    fn scope_narrows_resources() {
        let allowed = ResourceId::new("order:42").expect("valid");
        let other = ResourceId::new("order:99").expect("valid");
        let scope = Scope::new().with_allowed_resources(vec![allowed.clone()]);
        assert!(scope.permits_resource(&allowed));
        assert!(!scope.permits_resource(&other));
    }

    #[test]
    fn scope_narrows_currencies() {
        let usd = CurrencyCode::new("USD").expect("valid");
        let eur = CurrencyCode::new("EUR").expect("valid");
        let scope = Scope::new().with_allowed_currencies(vec![usd]);
        assert!(scope.permits_currency(&usd));
        assert!(!scope.permits_currency(&eur));
    }
}
