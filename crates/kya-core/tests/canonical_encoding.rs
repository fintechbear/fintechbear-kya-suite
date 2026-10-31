//! Adversarial matrix for the mandate canonical encoding (AGENTS.md Rules 15,
//! 17), the byte string the signed-mandate binding commits to.
//!
//! The in-crate unit tests in `mandate.rs` already prove determinism, the magic
//! tag + version prefix, that changing a field changes the bytes, and
//! cross-field-boundary unambiguity for the identity fields. The crypto-level
//! `mandate_binding.rs` suite proves each field substitution fails closed over
//! real signatures. This file closes the remaining *encoding-level* gaps the
//! audit (Section 3) calls out, which do not need a signature to demonstrate:
//!
//! - **field reordering** of the action allow-list and the merchant/resource/
//!   currency allow-lists must change the bytes (order is signed, so a reorder
//!   is a different signed object and cannot be a silent equivalent);
//! - **field omission** of each optional field (limit, audience, binding) must
//!   change the bytes versus its presence (present/absent is tagged, so an
//!   attacker cannot drop a constraint and keep the same bytes);
//! - **length-prefix unambiguity** across every variable-length boundary, not
//!   just the identity fields, so no two logically-different mandates can
//!   collide by concatenation;
//! - **two logically-different mandates never share an encoding** (the whole
//!   point of a canonical, injective encoding);
//! - **magic tag + version domain separation**: the encoding always begins with
//!   the exact magic bytes and the version `1`, so bytes framed for a different
//!   format (or a future version) can never be mistaken for a current mandate
//!   (this is what the `establish` byte-equality check leans on to reject
//!   cross-format reuse).
//!
//! Every negative assertion here would also be caught at verify time by
//! `VerifiedMandate::establish`'s byte-equality check; pinning them at the
//! encoding layer documents *why* that check is sufficient and guards the
//! encoding's injectivity against a future refactor that broke it silently.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId};
use kya_core::mandate::{Audience, Mandate, TransactionBinding, ValidityWindow};
use kya_core::money::{CurrencyCode, Money};
use kya_core::scope::{Action, Scope};

fn issuer() -> IssuerId {
    IssuerId::new("issuer:acme").expect("valid")
}
fn principal() -> PrincipalId {
    PrincipalId::new("principal:alice").expect("valid")
}
fn agent() -> AgentId {
    AgentId::new("agent:1").expect("valid")
}
fn window() -> ValidityWindow {
    ValidityWindow::new(1_000, 2_000).expect("valid")
}
fn usd(minor: i128) -> Money {
    Money::from_code(minor, "USD").expect("valid USD")
}

/// Build a mandate from an explicit scope and the standard identities/window.
fn mandate_with(scope: Scope) -> Mandate {
    Mandate::new(issuer(), principal(), agent(), scope, window())
}

const MAGIC: &[u8] = b"KYA-MANDATE";
const VERSION: u8 = 1;

// ---- magic tag + version domain separation --------------------------------

#[test]
fn encoding_always_starts_with_magic_and_version() {
    // A minimal mandate and a fully-featured one must BOTH carry the exact
    // magic + version prefix: it is unconditional domain separation.
    let minimal = mandate_with(Scope::new());
    let featured = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")]),
    )
    .with_required_audience(Audience::new("aud:processor").expect("valid"))
    .bound_to(TransactionBinding::new("txn:abc").expect("valid"));

    for m in [minimal, featured] {
        let bytes = m.canonical_encoding();
        assert!(
            bytes.starts_with(MAGIC),
            "every encoding must begin with the magic tag"
        );
        assert_eq!(
            bytes[MAGIC.len()],
            VERSION,
            "the byte after the magic tag must be the format version"
        );
    }
}

#[test]
fn bytes_framed_for_a_different_format_do_not_match_a_mandate_encoding() {
    // A payload that is NOT a KYA mandate encoding (e.g. a raw delegation blob
    // or an AP2-style envelope) must never equal a mandate's canonical bytes,
    // because the mandate encoding is magic-tagged. This is the encoding-level
    // reason cross-format signature reuse fails: the verified-mandate
    // byte-equality check can never match foreign-framed bytes.
    let m = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    let enc = m.canonical_encoding();

    for foreign in [
        b"not-a-kya-mandate".to_vec(),
        b"AP2-ENVELOPE\x01some-other-payload".to_vec(),
        {
            // Same payload but a DIFFERENT (future) version byte: must differ.
            let mut v = enc.clone();
            v[MAGIC.len()] = VERSION.wrapping_add(1);
            v
        },
        {
            // Correct version but corrupted magic: must differ.
            let mut v = enc.clone();
            v[0] ^= 0xFF;
            v
        },
    ] {
        assert_ne!(
            enc, foreign,
            "foreign-framed / wrong-version bytes must never equal a mandate encoding"
        );
    }
}

// ---- action allow-list ordering is signed ---------------------------------

#[test]
fn action_order_changes_the_encoding() {
    let ab = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .allow(Action::new("refund").expect("valid")),
    );
    let ba = mandate_with(
        Scope::new()
            .allow(Action::new("refund").expect("valid"))
            .allow(Action::new("transfer").expect("valid")),
    );
    assert_ne!(
        ab.canonical_encoding(),
        ba.canonical_encoding(),
        "the action allow-list order is part of the signed bytes"
    );
}

#[test]
fn merchant_resource_currency_order_changes_the_encoding() {
    let base_actions = || Scope::new().allow(Action::new("transfer").expect("valid"));

    // Merchant allow-list order.
    let m_ab = mandate_with(base_actions().with_allowed_merchants(vec![
        MerchantId::new("merchant:a").expect("valid"),
        MerchantId::new("merchant:b").expect("valid"),
    ]));
    let m_ba = mandate_with(base_actions().with_allowed_merchants(vec![
        MerchantId::new("merchant:b").expect("valid"),
        MerchantId::new("merchant:a").expect("valid"),
    ]));
    assert_ne!(m_ab.canonical_encoding(), m_ba.canonical_encoding());

    // Resource allow-list order.
    let r_ab = mandate_with(base_actions().with_allowed_resources(vec![
        ResourceId::new("order:a").expect("valid"),
        ResourceId::new("order:b").expect("valid"),
    ]));
    let r_ba = mandate_with(base_actions().with_allowed_resources(vec![
        ResourceId::new("order:b").expect("valid"),
        ResourceId::new("order:a").expect("valid"),
    ]));
    assert_ne!(r_ab.canonical_encoding(), r_ba.canonical_encoding());

    // Currency allow-list order.
    let c_ab = mandate_with(base_actions().with_allowed_currencies(vec![
        CurrencyCode::new("USD").expect("valid"),
        CurrencyCode::new("EUR").expect("valid"),
    ]));
    let c_ba = mandate_with(base_actions().with_allowed_currencies(vec![
        CurrencyCode::new("EUR").expect("valid"),
        CurrencyCode::new("USD").expect("valid"),
    ]));
    assert_ne!(c_ab.canonical_encoding(), c_ba.canonical_encoding());
}

// ---- optional-field omission is tagged ------------------------------------

#[test]
fn omitting_the_spending_limit_changes_the_encoding() {
    let with_limit = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000)),
    );
    let without_limit = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    assert_ne!(
        with_limit.canonical_encoding(),
        without_limit.canonical_encoding(),
        "present vs absent per-transaction limit must change the bytes"
    );
}

#[test]
fn omitting_the_audience_changes_the_encoding() {
    let base = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    let with_audience = base
        .clone()
        .with_required_audience(Audience::new("aud:processor").expect("valid"));
    assert_ne!(
        base.canonical_encoding(),
        with_audience.canonical_encoding(),
        "present vs absent required audience must change the bytes"
    );
}

#[test]
fn omitting_the_binding_changes_the_encoding() {
    let base = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    let with_binding = base
        .clone()
        .bound_to(TransactionBinding::new("txn:abc").expect("valid"));
    assert_ne!(
        base.canonical_encoding(),
        with_binding.canonical_encoding(),
        "present vs absent transaction binding must change the bytes"
    );
}

#[test]
fn omitting_the_approval_flag_changes_the_encoding() {
    let base = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    let requiring = base.clone().requiring_human_approval();
    assert_ne!(
        base.canonical_encoding(),
        requiring.canonical_encoding(),
        "the human-approval flag must change the bytes"
    );
}

// ---- length-prefix unambiguity across more boundaries ---------------------

#[test]
fn audience_binding_boundary_is_unambiguous() {
    // audience "ab" + binding "c" must not collide with audience "a" +
    // binding "bc": the present/absent tag plus length prefix prevents it.
    let m1 = mandate_with(Scope::new())
        .with_required_audience(Audience::new("ab").expect("valid"))
        .bound_to(TransactionBinding::new("c").expect("valid"));
    let m2 = mandate_with(Scope::new())
        .with_required_audience(Audience::new("a").expect("valid"))
        .bound_to(TransactionBinding::new("bc").expect("valid"));
    assert_ne!(m1.canonical_encoding(), m2.canonical_encoding());
}

#[test]
fn action_list_boundary_is_unambiguous() {
    // Two actions ["ab","c"] vs ["a","bc"] must not collide: each action is
    // length-prefixed so the split point is unambiguous.
    let m1 = mandate_with(
        Scope::new()
            .allow(Action::new("ab").expect("valid"))
            .allow(Action::new("c").expect("valid")),
    );
    let m2 = mandate_with(
        Scope::new()
            .allow(Action::new("a").expect("valid"))
            .allow(Action::new("bc").expect("valid")),
    );
    assert_ne!(m1.canonical_encoding(), m2.canonical_encoding());
}

#[test]
fn single_action_cannot_be_confused_with_two_actions() {
    // One action "ab" (count 1) must not encode the same as two actions "a"
    // and "b" (count 2): the count prefix disambiguates.
    let one = mandate_with(Scope::new().allow(Action::new("ab").expect("valid")));
    let two = mandate_with(
        Scope::new()
            .allow(Action::new("a").expect("valid"))
            .allow(Action::new("b").expect("valid")),
    );
    assert_ne!(one.canonical_encoding(), two.canonical_encoding());
}

// ---- injectivity: different logical mandates never share bytes ------------

#[test]
fn two_different_logical_mandates_never_share_an_encoding() {
    // A representative spread of single-field differences, each of which must
    // yield distinct bytes. (Per-field coverage is also in mandate_binding.rs
    // over real signatures; this asserts the encoding injectivity directly.)
    let base = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000))
            .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
            .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
            .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]),
    )
    .with_required_audience(Audience::new("aud:processor").expect("valid"))
    .bound_to(TransactionBinding::new("txn:abc").expect("valid"));
    let base_bytes = base.canonical_encoding();

    let variants = [
        // Different issuer.
        Mandate::new(
            IssuerId::new("issuer:other").expect("valid"),
            principal(),
            agent(),
            Scope::new()
                .allow(Action::new("transfer").expect("valid"))
                .with_per_transaction_limit(usd(10_000))
                .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
                .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
                .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]),
            window(),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid")),
        // Different limit amount (one minor unit).
        mandate_with(
            Scope::new()
                .allow(Action::new("transfer").expect("valid"))
                .with_per_transaction_limit(usd(10_001))
                .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
                .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
                .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid")),
        // Different limit currency.
        mandate_with(
            Scope::new()
                .allow(Action::new("transfer").expect("valid"))
                .with_per_transaction_limit(Money::from_code(10_000, "EUR").expect("valid"))
                .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
                .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
                .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid")),
        // Different validity window.
        Mandate::new(
            issuer(),
            principal(),
            agent(),
            Scope::new()
                .allow(Action::new("transfer").expect("valid"))
                .with_per_transaction_limit(usd(10_000))
                .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")])
                .with_allowed_resources(vec![ResourceId::new("order:42").expect("valid")])
                .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid")]),
            ValidityWindow::new(1_000, 9_999).expect("valid"),
        )
        .with_required_audience(Audience::new("aud:processor").expect("valid"))
        .bound_to(TransactionBinding::new("txn:abc").expect("valid")),
    ];

    for v in variants {
        assert_ne!(
            base_bytes,
            v.canonical_encoding(),
            "a single-field-different mandate must encode to different bytes"
        );
    }
}

// ---- alternative "equivalent" encodings collapse to the same bytes --------

#[test]
fn logically_identical_mandates_built_differently_encode_identically() {
    // Two mandates built via different builder call orders but representing the
    // SAME logical mandate must encode identically (determinism / canonicality).
    // The builder order for distinct fields must not leak into the bytes.
    let a = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .with_per_transaction_limit(usd(10_000)),
    )
    .with_required_audience(Audience::new("aud:processor").expect("valid"))
    .requiring_human_approval()
    .bound_to(TransactionBinding::new("txn:abc").expect("valid"));

    let b = mandate_with(
        Scope::new()
            .with_per_transaction_limit(usd(10_000))
            .allow(Action::new("transfer").expect("valid")),
    )
    .bound_to(TransactionBinding::new("txn:abc").expect("valid"))
    .with_required_audience(Audience::new("aud:processor").expect("valid"))
    .requiring_human_approval();

    assert_eq!(
        a.canonical_encoding(),
        b.canonical_encoding(),
        "builder call order for distinct fields must not change the canonical bytes"
    );
}

#[test]
fn idempotent_duplicate_action_does_not_change_encoding() {
    // `Scope::allow` is documented idempotent (it dedups), so allowing the same
    // action twice yields the same logical scope and the same bytes.
    let once = mandate_with(Scope::new().allow(Action::new("transfer").expect("valid")));
    let twice = mandate_with(
        Scope::new()
            .allow(Action::new("transfer").expect("valid"))
            .allow(Action::new("transfer").expect("valid")),
    );
    assert_eq!(
        once.canonical_encoding(),
        twice.canonical_encoding(),
        "a de-duplicated duplicate action must not change the canonical bytes"
    );
}
