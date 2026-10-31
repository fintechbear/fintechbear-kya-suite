//! Stage A domain types: the identities and trust anchors of the KYA model.
//!
//! Identity here is a **claim** that must be cryptographically verified
//! (stage B) and authoritatively checked (stage D) before it can authorize
//! anything. Nothing in this module grants authority on its own.
//!
//! The module distinguishes four kinds of actor:
//!
//! - [`PrincipalId`] — the human or organization on whose behalf authority is
//!   ultimately exercised. The principal *delegates* to an agent.
//! - [`AgentId`] — the (typically non-human) agent that acts under a delegated
//!   mandate on the principal's behalf.
//! - [`IssuerId`] — the party that issues and attests to a mandate (often the
//!   principal or a credential authority acting for it).
//! - [`MerchantId`] — the counterparty a transaction is directed *to*.
//!
//! A [`ResourceId`] names the concrete resource or endpoint a transaction acts
//! on, and a [`TrustedKeyRef`] is a non-secret reference to the key material an
//! issuer signs with.
//!
//! None of these identifiers is a secret, so all of them may appear in logs and
//! audit records (AGENTS.md Rule 18). Key *material* never lives here; only a
//! [`TrustedKeyRef`] (a reference/fingerprint) does.

use core::fmt;

/// Errors produced while constructing identity newtypes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// The identifier was empty or only whitespace.
    Empty,
    /// The identifier exceeded the maximum permitted length.
    TooLong {
        /// The length that was supplied.
        got: usize,
        /// The maximum permitted length.
        max: usize,
    },
    /// The identifier contained a disallowed character (e.g. a control
    /// character). Only printable, non-whitespace-interior identifiers are
    /// accepted so that an identifier can never smuggle control bytes into a
    /// log or audit record.
    Malformed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Empty => f.write_str("identifier must not be empty"),
            IdentityError::TooLong { got, max } => {
                write!(f, "identifier too long: {got} > {max}")
            }
            IdentityError::Malformed => f.write_str("identifier contains disallowed characters"),
        }
    }
}

impl std::error::Error for IdentityError {}

const MAX_ID_LEN: usize = 512;

/// Validate and normalize a raw identifier string.
///
/// The input is trimmed, then checked for emptiness, length, and the presence
/// of any ASCII control character (including embedded ones). Control characters
/// are rejected because an identifier is logged and audited verbatim and must
/// not be able to inject terminal control sequences or line breaks.
fn validate_id(raw: &str) -> Result<String, IdentityError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(IdentityError::Empty);
    }
    if trimmed.len() > MAX_ID_LEN {
        return Err(IdentityError::TooLong {
            got: trimmed.len(),
            max: MAX_ID_LEN,
        });
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(IdentityError::Malformed);
    }
    Ok(trimmed.to_owned())
}

/// Validate and normalize a raw identifier-like string with the shared identity
/// rules (trimmed, non-empty, length-bounded, no control characters).
///
/// Crate-internal so other domain newtypes (for example an audience or a
/// transaction binding) can be validated identically without duplicating the
/// rule (DRY, AGENTS.md Rule 1).
pub(crate) fn validate_identifier(raw: &str) -> Result<String, IdentityError> {
    validate_id(raw)
}

/// Declare an opaque, validated identifier newtype with a shared constructor,
/// accessor, and `Display`. Keeping the shape in one macro enforces that every
/// identity type is validated identically (DRY, AGENTS.md Rule 1) and that one
/// identity can never be confused with another at the type level (Rule 3).
macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Construct and validate ", $what, ".")]
            ///
            /// # Errors
            ///
            /// Returns [`IdentityError`] if the identifier is empty, too long,
            /// or contains control characters.
            pub fn new(raw: &str) -> Result<Self, IdentityError> {
                Ok($name(validate_id(raw)?))
            }

            /// The identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier! {
    /// A stable identifier for an AI **agent** principal.
    ///
    /// This is an opaque, validated string identifier (for example a DID or a
    /// URN). It is a newtype so an agent id can never be confused with any other
    /// identifier in the domain.
    AgentId, "an agent identifier"
}

identifier! {
    /// A stable identifier for the **principal** — the human or organization on
    /// whose behalf an agent acts. The principal is the source of delegated
    /// authority; the agent exercises it.
    PrincipalId, "a principal identifier"
}

identifier! {
    /// An identifier for the **issuer** that attests to an agent's mandate.
    IssuerId, "an issuer identifier"
}

identifier! {
    /// An identifier for a **merchant** — the counterparty a transaction is
    /// directed to.
    MerchantId, "a merchant identifier"
}

identifier! {
    /// An identifier for a concrete **resource** or endpoint a transaction acts
    /// on (for example an account, order, or API resource).
    ResourceId, "a resource identifier"
}

/// A non-secret reference to the key material a trusted issuer signs with.
///
/// This is deliberately **not** the key itself: `kya-core` holds no key bytes
/// and performs no cryptography. A [`TrustedKeyRef`] is an opaque, validated
/// handle — for example a key id (`kid`), a JWK thumbprint, or a certificate
/// fingerprint — that a concrete [`crate::verification::SignatureVerifier`]
/// (supplied from outside the core) resolves to real key material. Because it
/// carries no secret, it is safe to log (AGENTS.md Rule 18).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustedKeyRef(String);

impl TrustedKeyRef {
    /// Construct and validate a trusted key reference.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if the reference is empty, too long, or
    /// contains control characters.
    pub fn new(raw: &str) -> Result<Self, IdentityError> {
        Ok(TrustedKeyRef(validate_id(raw)?))
    }

    /// The reference as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustedKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An explicit allow-list binding trusted issuers to their trusted key
/// references.
///
/// Trust is explicit and allow-listed: an issuer is trusted only if it has been
/// deliberately added, and then only for the specific key references it was
/// added with. There is no implicit or wildcard trust (AGENTS.md Rule 11). This
/// models the "explicit trust anchors" requirement.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    anchors: Vec<(IssuerId, Vec<TrustedKeyRef>)>,
}

impl TrustAnchors {
    /// Create an empty trust anchor set. By default, nothing is trusted.
    pub fn new() -> Self {
        TrustAnchors {
            anchors: Vec::new(),
        }
    }

    fn entry_mut(&mut self, issuer: &IssuerId) -> &mut Vec<TrustedKeyRef> {
        if let Some(pos) = self.anchors.iter().position(|(i, _)| i == issuer) {
            &mut self.anchors[pos].1
        } else {
            self.anchors.push((issuer.clone(), Vec::new()));
            // The entry was just pushed, so it is the last one.
            let last = self.anchors.len() - 1;
            &mut self.anchors[last].1
        }
    }

    /// Trust an issuer without binding any specific key reference.
    ///
    /// This records the issuer as known but is **not** on its own enough to
    /// verify a signature: a [`TrustedKeyRef`] must still be bound via
    /// [`TrustAnchors::trust_key`] before [`TrustAnchors::trusts_key`] can
    /// return `true` for a given key.
    pub fn trust(&mut self, issuer: IssuerId) {
        self.entry_mut(&issuer);
    }

    /// Trust an issuer together with one of its key references.
    ///
    /// Idempotent: adding the same issuer/key pair twice has no additional
    /// effect.
    pub fn trust_key(&mut self, issuer: IssuerId, key: TrustedKeyRef) {
        let keys = self.entry_mut(&issuer);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    /// Returns `true` only if the issuer has been explicitly trusted.
    pub fn is_trusted(&self, issuer: &IssuerId) -> bool {
        self.anchors.iter().any(|(i, _)| i == issuer)
    }

    /// Returns `true` only if the issuer is trusted **and** the specific key
    /// reference has been bound to it. This is the check a verifier should make
    /// before honoring a signature attributed to an issuer.
    pub fn trusts_key(&self, issuer: &IssuerId, key: &TrustedKeyRef) -> bool {
        self.anchors
            .iter()
            .any(|(i, keys)| i == issuer && keys.contains(key))
    }

    /// The key references bound to an issuer, or an empty slice if the issuer
    /// is untrusted or has no bound keys.
    pub fn keys_for(&self, issuer: &IssuerId) -> &[TrustedKeyRef] {
        self.anchors
            .iter()
            .find(|(i, _)| i == issuer)
            .map(|(_, keys)| keys.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_identifiers() {
        assert_eq!(AgentId::new("   "), Err(IdentityError::Empty));
        assert_eq!(IssuerId::new(""), Err(IdentityError::Empty));
        assert_eq!(PrincipalId::new("\t"), Err(IdentityError::Empty));
        assert_eq!(MerchantId::new(""), Err(IdentityError::Empty));
        assert_eq!(ResourceId::new("  "), Err(IdentityError::Empty));
        assert_eq!(TrustedKeyRef::new(""), Err(IdentityError::Empty));
    }

    #[test]
    fn rejects_too_long() {
        let big = "a".repeat(MAX_ID_LEN + 1);
        assert_eq!(
            AgentId::new(&big),
            Err(IdentityError::TooLong {
                got: MAX_ID_LEN + 1,
                max: MAX_ID_LEN
            })
        );
    }

    #[test]
    fn accepts_max_length_boundary() {
        let exact = "a".repeat(MAX_ID_LEN);
        assert!(AgentId::new(&exact).is_ok());
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(AgentId::new("agent\x00id"), Err(IdentityError::Malformed));
        assert_eq!(IssuerId::new("line\nbreak"), Err(IdentityError::Malformed));
        assert_eq!(
            MerchantId::new("tab\tinside"),
            Err(IdentityError::Malformed)
        );
    }

    #[test]
    fn trims_and_stores() {
        let id = AgentId::new("  agent:123  ").expect("valid");
        assert_eq!(id.as_str(), "agent:123");
        assert_eq!(id.to_string(), "agent:123");
    }

    #[test]
    fn distinct_identifier_types_do_not_unify() {
        // This is a compile-time property: AgentId and MerchantId are different
        // types even though both wrap a String. The test documents the intent;
        // the real guarantee is that `let _: AgentId = merchant;` would not
        // compile.
        let agent = AgentId::new("x").expect("valid");
        let merchant = MerchantId::new("x").expect("valid");
        assert_eq!(agent.as_str(), merchant.as_str());
    }

    #[test]
    fn trust_is_explicit_and_deny_by_default() {
        let issuer = IssuerId::new("issuer:acme").expect("valid");
        let mut anchors = TrustAnchors::new();
        assert!(!anchors.is_trusted(&issuer), "nothing trusted by default");
        anchors.trust(issuer.clone());
        assert!(anchors.is_trusted(&issuer));

        let other = IssuerId::new("issuer:evil").expect("valid");
        assert!(!anchors.is_trusted(&other), "unlisted issuer not trusted");
    }

    #[test]
    fn key_trust_requires_explicit_binding() {
        let issuer = IssuerId::new("issuer:acme").expect("valid");
        let key = TrustedKeyRef::new("kid:1").expect("valid");
        let other_key = TrustedKeyRef::new("kid:2").expect("valid");

        let mut anchors = TrustAnchors::new();
        anchors.trust(issuer.clone());
        // Issuer is trusted, but no key is bound yet.
        assert!(anchors.is_trusted(&issuer));
        assert!(!anchors.trusts_key(&issuer, &key));

        anchors.trust_key(issuer.clone(), key.clone());
        assert!(anchors.trusts_key(&issuer, &key));
        assert!(
            !anchors.trusts_key(&issuer, &other_key),
            "unbound key not trusted"
        );
        assert_eq!(anchors.keys_for(&issuer), &[key]);
    }

    #[test]
    fn trust_key_is_idempotent() {
        let issuer = IssuerId::new("issuer:acme").expect("valid");
        let key = TrustedKeyRef::new("kid:1").expect("valid");
        let mut anchors = TrustAnchors::new();
        anchors.trust_key(issuer.clone(), key.clone());
        anchors.trust_key(issuer.clone(), key.clone());
        assert_eq!(anchors.keys_for(&issuer).len(), 1);
    }

    #[test]
    fn unknown_issuer_has_no_keys() {
        let issuer = IssuerId::new("issuer:ghost").expect("valid");
        let anchors = TrustAnchors::new();
        assert!(anchors.keys_for(&issuer).is_empty());
    }
}
