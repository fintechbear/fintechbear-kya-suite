//! Mandate and transaction-intent domain types.
//!
//! A [`Mandate`] is a delegation of authority from an issuer to an agent (on
//! behalf of a principal), bounded by a [`Scope`]. A [`TransactionIntent`] is a
//! concrete action an agent wants to perform and is checked against a mandate
//! by the static policy evaluator (stage C). Neither type authorizes anything
//! on its own.
//!
//! Beyond the scope allow-lists, a mandate carries the time-bounded and
//! request-bounded conditions the static evaluator enforces:
//!
//! - a [`ValidityWindow`] (not-before / not-after, in Unix seconds) checked
//!   against an **injected** `now` — `kya-core` never reads the system clock;
//! - an optional required [`Audience`] the request must target;
//! - a human-approval requirement flag; and
//! - an optional [`TransactionBinding`] that pins the mandate to one exact
//!   transaction so a verified mandate cannot be replayed against a different
//!   request (transaction substitution).

use crate::identity::{AgentId, IdentityError, IssuerId, MerchantId, PrincipalId, ResourceId};
use crate::money::Money;
use crate::scope::{Action, Scope};
use core::fmt;

/// An intended audience a mandate may be restricted to (e.g. a specific payment
/// processor, API, or relying party).
///
/// This is a validated, opaque newtype so an audience value cannot be confused
/// with any other identifier and cannot smuggle control characters into a log
/// (it reuses the same validation as the identity newtypes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Audience(String);

impl Audience {
    /// Construct and validate an audience value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if the value is empty, too long, or contains
    /// control characters.
    pub fn new(raw: &str) -> Result<Self, IdentityError> {
        Ok(Audience(crate::identity::validate_identifier(raw)?))
    }

    /// The audience as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A binding that pins a mandate to one exact transaction.
///
/// A mandate that carries a binding may be used only for a request that carries
/// the **same** binding. This is what prevents transaction substitution: a
/// verified mandate for "pay invoice X" cannot be replayed to authorize "pay
/// invoice Y". It is a validated, opaque newtype.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionBinding(String);

impl TransactionBinding {
    /// Construct and validate a transaction binding.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if the value is empty, too long, or contains
    /// control characters.
    pub fn new(raw: &str) -> Result<Self, IdentityError> {
        Ok(TransactionBinding(crate::identity::validate_identifier(
            raw,
        )?))
    }

    /// The binding as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransactionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors constructing a [`ValidityWindow`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidityError {
    /// The not-before time was after the not-after time, so the window would
    /// never be valid. An inverted window is rejected at construction rather
    /// than silently treated as "always invalid".
    Inverted {
        /// The not-before time supplied.
        not_before: u64,
        /// The not-after time supplied.
        not_after: u64,
    },
}

impl fmt::Display for ValidityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidityError::Inverted {
                not_before,
                not_after,
            } => write!(
                f,
                "validity window is inverted: nbf {not_before} > exp {not_after}"
            ),
        }
    }
}

impl std::error::Error for ValidityError {}

/// A half-open validity window `[not_before, not_after)` in Unix seconds.
///
/// A mandate is valid when the injected `now` satisfies
/// `not_before <= now < not_after`. The window is checked against an injected
/// time; `kya-core` never reads the system clock (it performs no I/O), mirroring
/// `kya-crypto`'s injected-time pattern. The result is therefore deterministic
/// and testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityWindow {
    not_before: u64,
    not_after: u64,
}

impl ValidityWindow {
    /// Construct a validity window.
    ///
    /// # Errors
    ///
    /// Returns [`ValidityError::Inverted`] if `not_before > not_after`.
    pub fn new(not_before: u64, not_after: u64) -> Result<Self, ValidityError> {
        if not_before > not_after {
            return Err(ValidityError::Inverted {
                not_before,
                not_after,
            });
        }
        Ok(ValidityWindow {
            not_before,
            not_after,
        })
    }

    /// The not-before time (inclusive), in Unix seconds.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// The not-after time (exclusive), in Unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Returns `true` only if `now` is before the window opens.
    pub fn is_not_yet_valid_at(&self, now: u64) -> bool {
        now < self.not_before
    }

    /// Returns `true` only if `now` is at or after the window closes.
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.not_after
    }

    /// Returns `true` only if `now` falls within `[not_before, not_after)`.
    pub fn is_valid_at(&self, now: u64) -> bool {
        !self.is_not_yet_valid_at(now) && !self.is_expired_at(now)
    }
}

/// A delegation of authority from an issuer to an agent, bounded by a scope.
///
/// A mandate is a **claim**. It must be cryptographically verified (stage B,
/// via the [`crate::verification`] trait seam, and promoted to a verified
/// delegation `kya_crypto::VerifiedDelegation`) and authoritatively checked for
/// revocation and budget (stage D, in `kya-client`) before it can authorize a
/// transaction.
///
/// The mandate records the **principal** on whose behalf authority is
/// exercised, the **issuer** that granted it, and the **agent** it was granted
/// to. These are three distinct roles and are typed distinctly so they cannot
/// be transposed. It also carries the conditions the static evaluator enforces:
/// a [`ValidityWindow`], an optional required [`Audience`], a human-approval
/// flag, and an optional [`TransactionBinding`].
#[derive(Debug, Clone)]
pub struct Mandate {
    issuer: IssuerId,
    principal: PrincipalId,
    agent: AgentId,
    scope: Scope,
    validity: ValidityWindow,
    required_audience: Option<Audience>,
    requires_human_approval: bool,
    binding: Option<TransactionBinding>,
}

impl Mandate {
    /// Construct a mandate with the given validity window and default
    /// conditions: no required audience, no human-approval requirement, and no
    /// transaction binding. Use the `with_*`/`requiring_*` builders to add
    /// them.
    pub fn new(
        issuer: IssuerId,
        principal: PrincipalId,
        agent: AgentId,
        scope: Scope,
        validity: ValidityWindow,
    ) -> Self {
        Mandate {
            issuer,
            principal,
            agent,
            scope,
            validity,
            required_audience: None,
            requires_human_approval: false,
            binding: None,
        }
    }

    /// Require the request to target a specific audience.
    pub fn with_required_audience(mut self, audience: Audience) -> Self {
        self.required_audience = Some(audience);
        self
    }

    /// Mark the mandate as requiring out-of-band human approval. A request
    /// against such a mandate surfaces
    /// [`crate::decision::PolicyOutcome::RequiresApproval`] and can never be
    /// statically passed through to the authority as eligible.
    pub fn requiring_human_approval(mut self) -> Self {
        self.requires_human_approval = true;
        self
    }

    /// Pin the mandate to one exact transaction binding.
    pub fn bound_to(mut self, binding: TransactionBinding) -> Self {
        self.binding = Some(binding);
        self
    }

    /// The issuer that granted this mandate.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The principal on whose behalf the mandate's authority is exercised.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The agent the mandate was granted to.
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The scope that bounds this mandate.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The validity window that time-bounds this mandate.
    pub fn validity(&self) -> &ValidityWindow {
        &self.validity
    }

    /// The audience the request must target, if the mandate restricts it.
    pub fn required_audience(&self) -> Option<&Audience> {
        self.required_audience.as_ref()
    }

    /// Whether the mandate requires out-of-band human approval.
    pub fn requires_human_approval(&self) -> bool {
        self.requires_human_approval
    }

    /// The exact transaction binding the mandate is pinned to, if any.
    pub fn binding(&self) -> Option<&TransactionBinding> {
        self.binding.as_ref()
    }

    /// Serialize the **complete** security-relevant content of this mandate
    /// into a deterministic, versioned byte string — the exact bytes a signer
    /// commits to when they sign this mandate.
    ///
    /// # Why this exists (the signed-mandate binding)
    ///
    /// A cryptographic signature authenticates *bytes*, not a Rust value. If
    /// the bytes a signature covers do not encode the whole mandate, an
    /// attacker can pair a genuine signature over one payload with a different
    /// mandate (substituting the agent, principal, issuer, audience, merchant,
    /// resource, action, limit, currency, validity window, or approval
    /// requirement). This encoding closes that gap: it folds **every**
    /// security-relevant field into one unambiguous byte string so that a
    /// signature over these bytes commits to this mandate and no other. The
    /// authenticated verified mandate (`kya_crypto::VerifiedMandate`) is minted
    /// only when the bytes actually verified equal this encoding (see
    /// `kya_crypto::VerifiedMandate::establish`).
    ///
    /// # Format (internal, non-standardized, versioned)
    ///
    /// This is an **internal** serialization of `kya-core`, not a standardized
    /// wire format and not interoperable with any external protocol (mirroring
    /// `kya-protocol`'s honesty about not being a standardized signed format,
    /// AGENTS.md Rule 20). It uses **no** external dependency, no `serde`, and
    /// no JSON: it is a hand-rolled, length-prefixed, unambiguous `std`-only
    /// framing. The layout is, in order:
    ///
    /// 1. a fixed magic tag and a one-byte format `VERSION`, so a future format
    ///    change is explicit and can never be confused with an old one;
    /// 2. the issuer, principal, and agent identifiers;
    /// 3. the scope: the allowed actions (in their declared order), the
    ///    per-transaction limit as `(minor_units: i128, currency)` or an
    ///    explicit "no limit" marker, and the merchant / resource / currency
    ///    restrictions, each tagged `Any` vs an explicit allow-list;
    /// 4. the validity window `(not_before, not_after)`;
    /// 5. the optional required audience (present/absent tagged);
    /// 6. the human-approval flag; and
    /// 7. the optional transaction binding (present/absent tagged).
    ///
    /// Every variable-length field is length-prefixed so that two distinct
    /// mandates can never produce the same bytes by concatenation ambiguity
    /// (for example issuer `"ab"` + agent `"c"` must not collide with issuer
    /// `"a"` + agent `"bc"`). Integers are fixed-width big-endian. Money is
    /// encoded as exact `i128` minor units plus the ISO-4217 code; **no**
    /// floating point is used (AGENTS.md Rule 8).
    pub fn canonical_encoding(&self) -> Vec<u8> {
        canonical::encode_mandate(self)
    }
}

/// Deterministic, versioned, `std`-only canonical byte encoding of a
/// [`Mandate`].
///
/// See [`Mandate::canonical_encoding`] for the rationale and the on-wire
/// layout. This module is deliberately dependency-free: it builds the byte
/// string with primitive length-prefixing so the encoding is unambiguous and
/// reproducible without `serde`, JSON, or any external crate.
mod canonical {
    use super::Mandate;
    use crate::scope::Restriction;

    /// Magic tag identifying a KYA canonical mandate encoding. Guards against a
    /// different byte string being mistaken for a mandate encoding.
    const MAGIC: &[u8] = b"KYA-MANDATE";

    /// Format version. Bump on any layout change so an old and a new encoding
    /// can never collide or be silently cross-interpreted.
    const VERSION: u8 = 1;

    /// Append a length-prefixed byte field: an 8-byte big-endian length then
    /// the bytes. Length-prefixing makes the concatenation unambiguous.
    fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// Append a length-prefixed string field.
    fn put_str(out: &mut Vec<u8>, s: &str) {
        put_bytes(out, s.as_bytes());
    }

    /// Append an optional string as a present/absent tag byte followed by the
    /// length-prefixed value when present.
    fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
        match s {
            Some(v) => {
                out.push(1);
                put_str(out, v);
            }
            None => out.push(0),
        }
    }

    /// Append a string restriction: a tag byte (`0` = `Any`, `1` = allow-list)
    /// then, for an allow-list, a count and each length-prefixed value in list
    /// order.
    fn put_restriction<T, F>(out: &mut Vec<u8>, restriction: &Restriction<T>, as_str: F)
    where
        F: Fn(&T) -> &str,
    {
        match restriction {
            Restriction::Any => out.push(0),
            Restriction::AllowList(items) => {
                out.push(1);
                out.extend_from_slice(&(items.len() as u64).to_be_bytes());
                for item in items {
                    put_str(out, as_str(item));
                }
            }
        }
    }

    /// Encode the complete security-relevant content of `mandate`.
    pub(super) fn encode_mandate(mandate: &Mandate) -> Vec<u8> {
        let mut out = Vec::new();

        // (1) Magic + version.
        out.extend_from_slice(MAGIC);
        out.push(VERSION);

        // (2) Identities.
        put_str(&mut out, mandate.issuer().as_str());
        put_str(&mut out, mandate.principal().as_str());
        put_str(&mut out, mandate.agent().as_str());

        // (3) Scope.
        let scope = mandate.scope();

        // Allowed actions, in declared order, count-prefixed.
        let actions = scope.allowed_actions();
        out.extend_from_slice(&(actions.len() as u64).to_be_bytes());
        for action in actions {
            put_str(&mut out, action.as_str());
        }

        // Per-transaction limit: present/absent tag, then (minor_units i128,
        // currency). Money as exact integer minor units; no floats (Rule 8).
        match scope.per_transaction_limit() {
            Some(limit) => {
                out.push(1);
                out.extend_from_slice(&limit.minor_units().to_be_bytes());
                put_str(&mut out, limit.currency().as_str());
            }
            None => out.push(0),
        }

        // Merchant / resource / currency restrictions.
        put_restriction(&mut out, scope.allowed_merchants(), |m| m.as_str());
        put_restriction(&mut out, scope.allowed_resources(), |r| r.as_str());
        put_restriction(&mut out, scope.allowed_currencies(), |c| c.as_str());

        // (4) Validity window.
        out.extend_from_slice(&mandate.validity().not_before().to_be_bytes());
        out.extend_from_slice(&mandate.validity().not_after().to_be_bytes());

        // (5) Required audience (optional).
        put_opt_str(&mut out, mandate.required_audience().map(|a| a.as_str()));

        // (6) Human-approval flag.
        out.push(u8::from(mandate.requires_human_approval()));

        // (7) Transaction binding (optional).
        put_opt_str(&mut out, mandate.binding().map(|b| b.as_str()));

        out
    }
}

/// A concrete transaction an agent intends to perform.
///
/// This is the stage-C input: the acting agent, the action, the exact amount
/// and currency ([`Money`]), the counterparty [`MerchantId`], and the
/// [`ResourceId`] being acted on. The principal is optional because not every
/// transport carries it explicitly; when present it is checked against the
/// mandate's principal. The intent may also carry the [`Audience`] it targets
/// and the [`TransactionBinding`] it belongs to, which are checked against the
/// mandate's requirements.
#[derive(Debug, Clone)]
pub struct TransactionIntent {
    agent: AgentId,
    principal: Option<PrincipalId>,
    merchant: MerchantId,
    resource: ResourceId,
    action: Action,
    amount: Money,
    audience: Option<Audience>,
    binding: Option<TransactionBinding>,
}

impl TransactionIntent {
    /// Construct a transaction intent.
    pub fn new(
        agent: AgentId,
        merchant: MerchantId,
        resource: ResourceId,
        action: Action,
        amount: Money,
    ) -> Self {
        TransactionIntent {
            agent,
            principal: None,
            merchant,
            resource,
            action,
            amount,
            audience: None,
            binding: None,
        }
    }

    /// Attach the principal the intent is exercised on behalf of.
    pub fn with_principal(mut self, principal: PrincipalId) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Attach the audience this intent targets.
    pub fn with_audience(mut self, audience: Audience) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Attach the transaction binding this intent belongs to.
    pub fn with_binding(mut self, binding: TransactionBinding) -> Self {
        self.binding = Some(binding);
        self
    }

    /// The agent making the request.
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The principal the intent is exercised on behalf of, if provided.
    pub fn principal(&self) -> Option<&PrincipalId> {
        self.principal.as_ref()
    }

    /// The merchant counterparty the transaction is directed to.
    pub fn merchant(&self) -> &MerchantId {
        &self.merchant
    }

    /// The resource the transaction acts on.
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    /// The action being requested.
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// The amount involved in the transaction.
    pub fn amount(&self) -> &Money {
        &self.amount
    }

    /// The audience this intent targets, if provided.
    pub fn audience(&self) -> Option<&Audience> {
        self.audience.as_ref()
    }

    /// The transaction binding this intent belongs to, if provided.
    pub fn binding(&self) -> Option<&TransactionBinding> {
        self.binding.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn money() -> Money {
        Money::from_code(1_000, "USD").expect("valid USD")
    }

    fn window() -> ValidityWindow {
        ValidityWindow::new(1_000, 2_000).expect("valid window")
    }

    #[test]
    fn mandate_keeps_roles_distinct() {
        let m = Mandate::new(
            IssuerId::new("issuer:acme").expect("valid"),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new(),
            window(),
        );
        assert_eq!(m.issuer().as_str(), "issuer:acme");
        assert_eq!(m.principal().as_str(), "principal:alice");
        assert_eq!(m.agent().as_str(), "agent:1");
    }

    #[test]
    fn mandate_defaults_have_no_extra_conditions() {
        let m = Mandate::new(
            IssuerId::new("issuer:acme").expect("valid"),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new(),
            window(),
        );
        assert!(m.required_audience().is_none());
        assert!(!m.requires_human_approval());
        assert!(m.binding().is_none());
    }

    #[test]
    fn mandate_builders_set_conditions() {
        let m = Mandate::new(
            IssuerId::new("issuer:acme").expect("valid"),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new(),
            window(),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .requiring_human_approval()
        .bound_to(TransactionBinding::new("txn:abc").expect("valid"));
        assert_eq!(
            m.required_audience().map(|a| a.as_str()),
            Some("aud:processor")
        );
        assert!(m.requires_human_approval());
        assert_eq!(m.binding().map(|b| b.as_str()), Some("txn:abc"));
    }

    #[test]
    fn validity_window_rejects_inverted() {
        assert_eq!(
            ValidityWindow::new(2_000, 1_000),
            Err(ValidityError::Inverted {
                not_before: 2_000,
                not_after: 1_000
            })
        );
    }

    #[test]
    fn validity_window_boundaries_are_half_open() {
        let w = ValidityWindow::new(1_000, 2_000).expect("valid");
        assert!(w.is_not_yet_valid_at(999));
        assert!(w.is_valid_at(1_000), "nbf is inclusive");
        assert!(w.is_valid_at(1_999));
        assert!(w.is_expired_at(2_000), "exp is exclusive");
        assert!(!w.is_valid_at(2_000));
    }

    #[test]
    fn intent_defaults_to_no_principal() {
        let intent = TransactionIntent::new(
            AgentId::new("agent:1").expect("valid"),
            MerchantId::new("merchant:store").expect("valid"),
            ResourceId::new("order:42").expect("valid"),
            Action::new("purchase").expect("valid"),
            money(),
        );
        assert!(intent.principal().is_none());
        assert!(intent.audience().is_none());
        assert!(intent.binding().is_none());
        assert_eq!(intent.merchant().as_str(), "merchant:store");
        assert_eq!(intent.resource().as_str(), "order:42");
        assert_eq!(intent.amount().minor_units(), 1_000);
    }

    #[test]
    fn intent_can_carry_principal() {
        let intent = TransactionIntent::new(
            AgentId::new("agent:1").expect("valid"),
            MerchantId::new("merchant:store").expect("valid"),
            ResourceId::new("order:42").expect("valid"),
            Action::new("purchase").expect("valid"),
            money(),
        )
        .with_principal(PrincipalId::new("principal:alice").expect("valid"));
        assert_eq!(
            intent.principal().map(|p| p.as_str()),
            Some("principal:alice")
        );
    }

    #[test]
    fn intent_can_carry_audience_and_binding() {
        let intent = TransactionIntent::new(
            AgentId::new("agent:1").expect("valid"),
            MerchantId::new("merchant:store").expect("valid"),
            ResourceId::new("order:42").expect("valid"),
            Action::new("purchase").expect("valid"),
            money(),
        )
        .with_audience(Audience::new("aud:processor").expect("valid"))
        .with_binding(TransactionBinding::new("txn:abc").expect("valid"));
        assert_eq!(intent.audience().map(|a| a.as_str()), Some("aud:processor"));
        assert_eq!(intent.binding().map(|b| b.as_str()), Some("txn:abc"));
    }

    #[test]
    fn audience_and_binding_reject_control_chars() {
        assert!(Audience::new("aud\nx").is_err());
        assert!(TransactionBinding::new("txn\tx").is_err());
    }

    // ---- canonical encoding --------------------------------------------

    fn canonical_mandate() -> Mandate {
        use crate::identity::{MerchantId, ResourceId};
        use crate::money::CurrencyCode;
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(money())
            .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
            .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
            .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]);
        Mandate::new(
            IssuerId::new("issuer:acme").expect("valid"),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            scope,
            window(),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid"))
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let m = canonical_mandate();
        assert_eq!(m.canonical_encoding(), m.canonical_encoding());
        // Rebuilding an equivalent mandate yields identical bytes.
        assert_eq!(
            canonical_mandate().canonical_encoding(),
            canonical_mandate().canonical_encoding()
        );
    }

    #[test]
    fn canonical_encoding_is_versioned_and_tagged() {
        let bytes = canonical_mandate().canonical_encoding();
        assert!(
            bytes.starts_with(b"KYA-MANDATE"),
            "encoding must carry the magic tag"
        );
        // The byte immediately after the magic tag is the format version.
        assert_eq!(bytes[b"KYA-MANDATE".len()], 1, "format version 1");
    }

    #[test]
    fn canonical_encoding_changes_when_any_field_changes() {
        let base = canonical_mandate().canonical_encoding();

        // Agent.
        let mut m = canonical_mandate_with_agent("agent:other");
        assert_ne!(m.canonical_encoding(), base);

        // Human-approval flag.
        m = canonical_mandate().requiring_human_approval();
        assert_ne!(m.canonical_encoding(), base);
    }

    fn canonical_mandate_with_agent(agent: &str) -> Mandate {
        use crate::identity::{MerchantId, ResourceId};
        use crate::money::CurrencyCode;
        let scope = Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(money())
            .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
            .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
            .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]);
        Mandate::new(
            IssuerId::new("issuer:acme").expect("valid"),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new(agent).expect("valid"),
            scope,
            window(),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid"))
    }

    #[test]
    fn canonical_encoding_is_unambiguous_across_field_boundaries() {
        // Issuer "ab" + principal "c" must not collide with issuer "a" +
        // principal "bc": length-prefixing prevents the concatenation
        // ambiguity.
        let m1 = Mandate::new(
            IssuerId::new("ab").expect("valid"),
            PrincipalId::new("c").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new().allow(Action::new("transfer").expect("valid")),
            window(),
        );
        let m2 = Mandate::new(
            IssuerId::new("a").expect("valid"),
            PrincipalId::new("bc").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new().allow(Action::new("transfer").expect("valid")),
            window(),
        );
        assert_ne!(m1.canonical_encoding(), m2.canonical_encoding());
    }
}
