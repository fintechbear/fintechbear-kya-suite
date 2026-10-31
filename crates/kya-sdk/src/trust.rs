//! Explicit trust configuration and request conditions for the facade.
//!
//! Verifying a signed mandate requires two pieces of configuration that the
//! underlying crates keep deliberately separate:
//!
//! - [`TrustAnchors`] decide *which* `(issuer, key_ref)` pairs are trusted at
//!   all; and
//! - [`TrustedKeyStore`] supplies the concrete Ed25519 public-key *bytes* for a
//!   pair.
//!
//! The engine requires **both** — a key must be anchored *and* resolvable — and
//! a very common first-day mistake is to populate one and forget the other.
//! [`TrustConfiguration`] bundles them so they are configured together, with a
//! single [`TrustConfiguration::trust_issuer_key`] call that updates both at
//! once and validates up front that the two never drift apart.
//!
//! Trust stays **explicit and allow-listed** (AGENTS.md Rule 11): there is no
//! implicit trust, no wildcard, and no key discovery. Nothing is trusted until
//! the consumer adds it here.

use kya_core::identity::{IssuerId, TrustAnchors, TrustedKeyRef};
use kya_crypto::{Ed25519PublicKeyBytes, TrustedKeyStore};

/// A single bundle of the trust configuration the verification engine requires.
///
/// It wraps the [`TrustAnchors`] and the [`TrustedKeyStore`] together so a
/// consumer configures *which* keys are trusted and *what bytes* they have in
/// one place and cannot accidentally configure only one. Construct an empty
/// configuration with [`TrustConfiguration::new`] (nothing is trusted by
/// default — deny-by-default, AGENTS.md Rule 9) and add each trusted key with
/// [`TrustConfiguration::trust_issuer_key`].
///
/// This type performs **no** cryptography and **no** I/O; it is a validated
/// configuration holder. Ownership is straightforward: it owns its two inner
/// collections and lends them to the verification functions by reference via
/// [`TrustConfiguration::anchors`] and [`TrustConfiguration::key_store`].
#[derive(Debug, Clone, Default)]
pub struct TrustConfiguration {
    anchors: TrustAnchors,
    key_store: TrustedKeyStore,
}

/// Why adding a trusted issuer key to a [`TrustConfiguration`] failed.
///
/// `#[non_exhaustive]` so new, additive variants do not break the public API
/// (AGENTS.md Rule 21). No variant carries key bytes or other sensitive data
/// (Rule 18): it reports only *what class* of configuration error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustConfigurationError {
    /// The supplied public key did not have the required length for an Ed25519
    /// public key (32 bytes, RFC 8032). The configuration is unchanged.
    MalformedPublicKey {
        /// The number of bytes supplied (never the bytes themselves).
        got: usize,
    },
}

impl core::fmt::Display for TrustConfigurationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrustConfigurationError::MalformedPublicKey { got } => write!(
                f,
                "trusted public key must be 32 bytes for Ed25519, got {got}"
            ),
        }
    }
}

impl std::error::Error for TrustConfigurationError {}

impl TrustConfiguration {
    /// Create an empty trust configuration. By default **nothing** is trusted
    /// (deny-by-default): a verification will fail closed until the consumer
    /// adds at least the issuer key it expects to sign the mandate.
    pub fn new() -> Self {
        TrustConfiguration {
            anchors: TrustAnchors::new(),
            key_store: TrustedKeyStore::new(),
        }
    }

    /// Trust a specific issuer key by adding it to **both** the trust anchors
    /// and the key store in one call.
    ///
    /// This is the single, explicit act of trust. After it returns `Ok`, the
    /// `(issuer, key_ref)` pair is anchored *and* its public-key bytes resolve,
    /// which are exactly the two conditions [`crate::verify_mandate`] and
    /// [`crate::verify_delegation`] require. Calling it again for the same pair
    /// updates the stored bytes and is idempotent on the anchor set.
    ///
    /// The key is validated for length **up front** (predictable
    /// initialization): a wrong-length key is rejected with
    /// [`TrustConfigurationError::MalformedPublicKey`] and the configuration is
    /// left unchanged, so a bad key can never be half-registered.
    ///
    /// # Parameters
    ///
    /// - `issuer`: the issuer the key belongs to.
    /// - `key_ref`: the reference (key id) the issuer signs with.
    /// - `public_key`: the Ed25519 public-key bytes; must be exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustConfigurationError::MalformedPublicKey`] if `public_key`
    /// is not exactly 32 bytes long. It never panics on a wrong-length slice.
    pub fn trust_issuer_key(
        &mut self,
        issuer: IssuerId,
        key_ref: TrustedKeyRef,
        public_key: &[u8],
    ) -> Result<(), TrustConfigurationError> {
        // Validate the length BEFORE mutating anything, so a malformed key never
        // half-registers (predictable initialization).
        let bytes: Ed25519PublicKeyBytes =
            public_key
                .try_into()
                .map_err(|_| TrustConfigurationError::MalformedPublicKey {
                    got: public_key.len(),
                })?;

        // Update both sides together: anchor the pair AND store its bytes.
        self.anchors.trust_key(issuer.clone(), key_ref.clone());
        self.key_store.insert(issuer, key_ref, bytes);
        Ok(())
    }

    /// Borrow the trust anchors, for passing to the verification functions.
    pub fn anchors(&self) -> &TrustAnchors {
        &self.anchors
    }

    /// Borrow the trusted-key store, for passing to the verification functions.
    pub fn key_store(&self) -> &TrustedKeyStore {
        &self.key_store
    }

    /// Returns `true` if the `(issuer, key_ref)` pair is both anchored and
    /// resolvable — i.e. a verification could use it. Useful for a consumer to
    /// assert its configuration before attempting verification.
    pub fn trusts_issuer_key(&self, issuer: &IssuerId, key_ref: &TrustedKeyRef) -> bool {
        self.anchors.trusts_key(issuer, key_ref)
            && self.key_store.resolve(issuer, key_ref).is_some()
    }
}

/// The request-time conditions a verification checks, bundled for convenience.
///
/// Verification requires the current time (injected — the SDK never reads the
/// system clock), the audience the request targets, and the exact
/// transaction-binding bytes it presents. Grouping them keeps a call site
/// readable and documents that each is a *request-time expectation* the signer
/// must have committed to.
///
/// The lifetime ties the borrowed audience and binding to the caller's buffers;
/// no copy is made.
#[derive(Debug, Clone, Copy)]
pub struct RequestConditions<'a> {
    /// The current time in Unix seconds, injected by the caller.
    pub now: u64,
    /// The audience the request requires the signed claim to name (exact match).
    pub expected_audience: &'a str,
    /// The exact transaction-binding bytes the request presents (compared
    /// byte-for-byte).
    pub expected_binding: &'a [u8],
}

impl<'a> RequestConditions<'a> {
    /// Build the request conditions for a verification call.
    pub fn new(now: u64, expected_audience: &'a str, expected_binding: &'a [u8]) -> Self {
        RequestConditions {
            now,
            expected_audience,
            expected_binding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> IssuerId {
        IssuerId::new("issuer:acme").expect("valid")
    }
    fn key_ref() -> TrustedKeyRef {
        TrustedKeyRef::new("kid:1").expect("valid")
    }

    #[test]
    fn empty_configuration_trusts_nothing() {
        let cfg = TrustConfiguration::new();
        assert!(!cfg.trusts_issuer_key(&issuer(), &key_ref()));
    }

    #[test]
    fn trusting_a_key_updates_both_anchors_and_store() {
        let mut cfg = TrustConfiguration::new();
        cfg.trust_issuer_key(issuer(), key_ref(), &[7u8; 32])
            .expect("32-byte key is accepted");
        // Both sides are populated together.
        assert!(cfg.anchors().trusts_key(&issuer(), &key_ref()));
        assert_eq!(
            cfg.key_store().resolve(&issuer(), &key_ref()),
            Some(&[7u8; 32])
        );
        assert!(cfg.trusts_issuer_key(&issuer(), &key_ref()));
    }

    #[test]
    fn malformed_key_is_rejected_and_leaves_configuration_unchanged() {
        let mut cfg = TrustConfiguration::new();
        let err = cfg
            .trust_issuer_key(issuer(), key_ref(), &[0u8; 31])
            .expect_err("31-byte key must be rejected");
        assert_eq!(err, TrustConfigurationError::MalformedPublicKey { got: 31 });
        // Nothing was registered: the configuration is unchanged.
        assert!(!cfg.trusts_issuer_key(&issuer(), &key_ref()));
    }

    #[test]
    fn malformed_key_error_message_leaks_no_bytes() {
        let err = TrustConfigurationError::MalformedPublicKey { got: 10 };
        let msg = err.to_string();
        assert!(msg.contains("32 bytes"));
        assert!(msg.contains("got 10"));
    }

    #[test]
    fn re_trusting_a_pair_overwrites_the_bytes() {
        let mut cfg = TrustConfiguration::new();
        cfg.trust_issuer_key(issuer(), key_ref(), &[1u8; 32])
            .unwrap();
        cfg.trust_issuer_key(issuer(), key_ref(), &[2u8; 32])
            .unwrap();
        assert_eq!(
            cfg.key_store().resolve(&issuer(), &key_ref()),
            Some(&[2u8; 32])
        );
    }

    #[test]
    fn request_conditions_group_the_three_expectations() {
        let rc = RequestConditions::new(1_000, "aud:payments", b"binding");
        assert_eq!(rc.now, 1_000);
        assert_eq!(rc.expected_audience, "aud:payments");
        assert_eq!(rc.expected_binding, b"binding");
    }
}
