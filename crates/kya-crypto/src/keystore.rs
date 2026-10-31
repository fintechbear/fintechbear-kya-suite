//! Explicit, caller-supplied trusted-key configuration and resolution.
//!
//! Resolving an `(issuer, key_ref)` to concrete Ed25519 public-key bytes is an
//! explicit, allow-listed operation. There is **no** fetching from a URL, and
//! there is **no** implicit or wildcard trust (AGENTS.md Rule 11): keys are
//! configured by the caller up front.
//!
//! This store supplies the *bytes* for a reference. It is complementary to
//! [`kya_core::identity::TrustAnchors`], which gates *which* `(issuer, key_ref)`
//! pairs are trusted at all. The engine requires both: a key must be resolvable
//! here **and** anchored there before any evidence is minted.

use kya_core::identity::{IssuerId, TrustedKeyRef};

/// Raw bytes of an Ed25519 public key (32 bytes, RFC 8032).
///
/// Stored as a fixed-size array so a malformed-length key can never be
/// registered in the first place; the engine still revalidates the bytes
/// through the verifier before trusting them.
pub type Ed25519PublicKeyBytes = [u8; 32];

/// An explicit registry mapping `(issuer, key_ref)` to Ed25519 public-key bytes.
///
/// Trust bytes are populated by the caller. Lookups are exact and fail closed:
/// an unknown issuer or an unbound key reference resolves to `None`, never to a
/// fallback or wildcard key. The registry holds only **public** key material,
/// which is not a secret, but the engine still refuses to log it (Rule 18).
#[derive(Debug, Clone, Default)]
pub struct TrustedKeyStore {
    entries: Vec<(IssuerId, TrustedKeyRef, Ed25519PublicKeyBytes)>,
}

impl TrustedKeyStore {
    /// Create an empty key store. By default nothing resolves.
    pub fn new() -> Self {
        TrustedKeyStore {
            entries: Vec::new(),
        }
    }

    /// Register the public-key bytes for an `(issuer, key_ref)` pair.
    ///
    /// Idempotent per pair: inserting the same pair again overwrites the stored
    /// bytes rather than accumulating duplicates. Registering bytes here does
    /// **not** by itself make the key trusted; the pair must also be present in
    /// the caller's [`kya_core::identity::TrustAnchors`].
    pub fn insert(
        &mut self,
        issuer: IssuerId,
        key_ref: TrustedKeyRef,
        public_key: Ed25519PublicKeyBytes,
    ) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|(i, k, _)| i == &issuer && k == &key_ref)
        {
            slot.2 = public_key;
        } else {
            self.entries.push((issuer, key_ref, public_key));
        }
    }

    /// Resolve the public-key bytes for an `(issuer, key_ref)` pair, if present.
    ///
    /// Returns `None` for an unknown issuer or an unbound key reference. This is
    /// an exact lookup; there is no wildcard, prefix, or fallback match.
    pub fn resolve(
        &self,
        issuer: &IssuerId,
        key_ref: &TrustedKeyRef,
    ) -> Option<&Ed25519PublicKeyBytes> {
        self.entries
            .iter()
            .find(|(i, k, _)| i == issuer && k == key_ref)
            .map(|(_, _, bytes)| bytes)
    }

    /// Returns `true` if the issuer has at least one key registered. Useful for
    /// distinguishing an unknown issuer from an unbound key reference.
    pub fn knows_issuer(&self, issuer: &IssuerId) -> bool {
        self.entries.iter().any(|(i, _, _)| i == issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> IssuerId {
        IssuerId::new("issuer:acme").expect("valid")
    }
    fn key() -> TrustedKeyRef {
        TrustedKeyRef::new("kid:1").expect("valid")
    }

    #[test]
    fn resolves_registered_key() {
        let mut store = TrustedKeyStore::new();
        store.insert(issuer(), key(), [7u8; 32]);
        assert_eq!(store.resolve(&issuer(), &key()), Some(&[7u8; 32]));
    }

    #[test]
    fn unknown_issuer_and_unbound_key_resolve_to_none() {
        let mut store = TrustedKeyStore::new();
        store.insert(issuer(), key(), [1u8; 32]);
        let other_issuer = IssuerId::new("issuer:evil").expect("valid");
        let other_key = TrustedKeyRef::new("kid:2").expect("valid");
        assert_eq!(store.resolve(&other_issuer, &key()), None);
        assert_eq!(store.resolve(&issuer(), &other_key), None);
        assert!(!store.knows_issuer(&other_issuer));
        assert!(store.knows_issuer(&issuer()));
    }

    #[test]
    fn insert_overwrites_same_pair() {
        let mut store = TrustedKeyStore::new();
        store.insert(issuer(), key(), [1u8; 32]);
        store.insert(issuer(), key(), [2u8; 32]);
        assert_eq!(store.resolve(&issuer(), &key()), Some(&[2u8; 32]));
        assert_eq!(store.entries.len(), 1);
    }
}
