//! Property-based tests for the kya-protocol decode/encode boundary.
//!
//! These reuse the dependency-free, deterministic splitmix64 PRNG pattern from
//! `kya-core`'s property tests (AGENTS.md Rule 13: no `proptest`, no new
//! dependency) to exercise a wide, reproducible input space against the
//! fail-closed wire decoder (Rule 15). Every case is deterministic: a failure
//! reprints the seed so it can be replayed exactly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::error::{AsErrorCode, ErrorCode};
use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustedKeyRef};
use kya_core::money::Money;
use kya_protocol::{WireDelegationClaim, WireFields, WireMandate, WireTransactionIntent};

/// A tiny deterministic PRNG (splitmix64). Not cryptographic — it exists only
/// to enumerate a reproducible spread of test inputs without a dependency.
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

const SEEDS: [u64; 8] = [
    1,
    42,
    0xDEAD_BEEF,
    0x1234_5678_9ABC_DEF0,
    u64::MAX,
    0xA5A5_A5A5_A5A5_A5A5,
    7,
    0xCAFE_F00D,
];

const CASES_PER_SEED: usize = 1_500;

/// A small pool of valid, control-char-free identifier strings.
const VALID_IDS: [&str; 6] = [
    "agent:1",
    "issuer:acme",
    "principal:alice",
    "merchant:store",
    "order:42",
    "kid:1",
];

/// A small pool of valid three-uppercase-ASCII currency codes.
const VALID_CURRENCIES: [&str; 5] = ["USD", "EUR", "GBP", "JPY", "CHF"];

fn pick<'a>(rng: &mut SplitMix64, pool: &[&'a str]) -> &'a str {
    let idx = (rng.next_u64() as usize) % pool.len();
    pool[idx]
}

/// Build a valid mandate field-map.
fn valid_mandate_fields(rng: &mut SplitMix64) -> (WireFields, WireMandate) {
    let m = WireMandate {
        issuer: IssuerId::new(pick(rng, &VALID_IDS)).unwrap(),
        principal: PrincipalId::new(pick(rng, &VALID_IDS)).unwrap(),
        agent: AgentId::new(pick(rng, &VALID_IDS)).unwrap(),
    };
    (m.encode(), m)
}

/// Build a valid claim field-map.
fn valid_claim_fields(rng: &mut SplitMix64) -> (WireFields, WireDelegationClaim) {
    let c = WireDelegationClaim {
        issuer: IssuerId::new(pick(rng, &VALID_IDS)).unwrap(),
        agent: AgentId::new(pick(rng, &VALID_IDS)).unwrap(),
        claimed_key_ref: TrustedKeyRef::new(pick(rng, &VALID_IDS)).unwrap(),
    };
    (c.encode(), c)
}

/// Build a valid intent field-map with a random non-negative amount.
fn valid_intent_fields(rng: &mut SplitMix64) -> (WireFields, WireTransactionIntent) {
    let minor = rng.next_nonneg_i128();
    let currency = pick(rng, &VALID_CURRENCIES);
    let i = WireTransactionIntent {
        agent: AgentId::new(pick(rng, &VALID_IDS)).unwrap(),
        merchant: MerchantId::new(pick(rng, &VALID_IDS)).unwrap(),
        resource: ResourceId::new(pick(rng, &VALID_IDS)).unwrap(),
        amount: Money::from_code(minor, currency).unwrap(),
    };
    (i.encode(), i)
}

fn drop_field(fields: &WireFields, key: &str) -> WireFields {
    let mut out = WireFields::new();
    for (k, v) in fields.as_pairs() {
        if k != key {
            out.push(k.clone(), v.clone());
        }
    }
    out
}

fn set_field(fields: &WireFields, key: &str, value: &str) -> WireFields {
    let mut out = WireFields::new();
    for (k, v) in fields.as_pairs() {
        if k == key {
            out.push(k.clone(), value.to_string());
        } else {
            out.push(k.clone(), v.clone());
        }
    }
    out
}

#[test]
fn prop_valid_field_maps_round_trip_and_never_panic() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let (mf, m) = valid_mandate_fields(&mut rng);
            assert_eq!(WireMandate::decode(&mf), Ok(m), "mandate seed={seed}");

            let (cf, c) = valid_claim_fields(&mut rng);
            assert_eq!(WireDelegationClaim::decode(&cf), Ok(c), "claim seed={seed}");

            let (inf, i) = valid_intent_fields(&mut rng);
            assert_eq!(
                WireTransactionIntent::decode(&inf),
                Ok(i),
                "intent seed={seed}"
            );
        }
    }
}

#[test]
fn prop_dropped_required_field_yields_missing_field() {
    let mandate_keys = [
        WireMandate::FIELD_ISSUER,
        WireMandate::FIELD_PRINCIPAL,
        WireMandate::FIELD_AGENT,
    ];
    let claim_keys = [
        WireDelegationClaim::FIELD_ISSUER,
        WireDelegationClaim::FIELD_AGENT,
        WireDelegationClaim::FIELD_CLAIMED_KEY_REF,
    ];
    let intent_keys = [
        WireTransactionIntent::FIELD_AGENT,
        WireTransactionIntent::FIELD_MERCHANT,
        WireTransactionIntent::FIELD_RESOURCE,
        WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
        WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
    ];

    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let (mf, _) = valid_mandate_fields(&mut rng);
            let dropped = mandate_keys[(rng.next_u64() as usize) % mandate_keys.len()];
            let err = WireMandate::decode(&drop_field(&mf, dropped)).expect_err("missing");
            assert_eq!(err.error_code(), ErrorCode::MissingField, "seed={seed}");

            let (cf, _) = valid_claim_fields(&mut rng);
            let dropped = claim_keys[(rng.next_u64() as usize) % claim_keys.len()];
            let err = WireDelegationClaim::decode(&drop_field(&cf, dropped)).expect_err("missing");
            assert_eq!(err.error_code(), ErrorCode::MissingField, "seed={seed}");

            let (inf, _) = valid_intent_fields(&mut rng);
            let dropped = intent_keys[(rng.next_u64() as usize) % intent_keys.len()];
            let err =
                WireTransactionIntent::decode(&drop_field(&inf, dropped)).expect_err("missing");
            assert_eq!(err.error_code(), ErrorCode::MissingField, "seed={seed}");
        }
    }
}

#[test]
fn prop_corrupted_values_always_error_never_panic() {
    // Corruptions that are guaranteed-invalid for any field: a control char
    // breaks every identifier and every currency; a non-integer breaks the
    // amount.
    let corruptions = ["bad\x00value", "\n", "\t", "   ", ""];

    let mandate_keys = [
        WireMandate::FIELD_ISSUER,
        WireMandate::FIELD_PRINCIPAL,
        WireMandate::FIELD_AGENT,
    ];
    let intent_id_keys = [
        WireTransactionIntent::FIELD_AGENT,
        WireTransactionIntent::FIELD_MERCHANT,
        WireTransactionIntent::FIELD_RESOURCE,
    ];

    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let corruption = corruptions[(rng.next_u64() as usize) % corruptions.len()];

            // Corrupt one identifier field of a mandate.
            let (mf, _) = valid_mandate_fields(&mut rng);
            let key = mandate_keys[(rng.next_u64() as usize) % mandate_keys.len()];
            let res = WireMandate::decode(&set_field(&mf, key, corruption));
            assert!(res.is_err(), "mandate corruption must fail; seed={seed}");

            // Corrupt one identifier field of an intent.
            let (inf, _) = valid_intent_fields(&mut rng);
            let key = intent_id_keys[(rng.next_u64() as usize) % intent_id_keys.len()];
            let res = WireTransactionIntent::decode(&set_field(&inf, key, corruption));
            assert!(res.is_err(), "intent id corruption must fail; seed={seed}");

            // Corrupt the amount with a non-integer string.
            let bad_amounts = ["12.5", "abc", "1e3", "", "-", "+"];
            let bad = bad_amounts[(rng.next_u64() as usize) % bad_amounts.len()];
            let (inf2, _) = valid_intent_fields(&mut rng);
            let res = WireTransactionIntent::decode(&set_field(
                &inf2,
                WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
                bad,
            ));
            assert!(res.is_err(), "amount corruption must fail; seed={seed}");
        }
    }
}
