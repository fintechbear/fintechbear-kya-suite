//! Property-based tests for exact monetary arithmetic and identifier parsing.
//!
//! These tests use a small, dependency-free deterministic generator (a
//! `std`-only splitmix64 PRNG seeded from a fixed list of seeds) rather than an
//! external property-testing crate, to keep `kya-core`'s dependency set empty
//! (AGENTS.md Rule 13) while still exercising a wide, reproducible input space
//! (Rule 15). Every case is deterministic: a failure reprints the seed path and
//! can be replayed exactly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::money::{CurrencyError, Money, MoneyError};

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
        // Keep it within the non-negative i128 range.
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

const CASES_PER_SEED: usize = 2_000;

fn usd(minor: i128) -> Money {
    Money::from_code(minor, "USD").expect("valid USD amount")
}

#[test]
fn prop_construction_rejects_exactly_the_negative_values() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let n = rng.next_nonneg_i128();
            // Non-negative always constructs.
            assert!(Money::from_code(n, "USD").is_ok(), "n={n} seed={seed}");
            // Its negation (when representable and non-zero) never constructs.
            if n != 0 {
                if let Some(neg) = n.checked_neg() {
                    assert_eq!(
                        Money::from_code(neg, "USD"),
                        Err(MoneyError::Negative),
                        "neg={neg} seed={seed}"
                    );
                }
            }
        }
    }
}

#[test]
fn prop_add_is_commutative_and_never_wraps() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let a = rng.next_nonneg_i128();
            let b = rng.next_nonneg_i128();
            let (ma, mb) = (usd(a), usd(b));

            let ab = ma.checked_add(&mb);
            let ba = mb.checked_add(&ma);
            assert_eq!(ab, ba, "addition must be commutative; a={a} b={b}");

            match a.checked_add(b) {
                Some(sum) => {
                    assert_eq!(
                        ab.map(|m| m.minor_units()),
                        Ok(sum),
                        "non-overflowing sum must match i128 add"
                    );
                }
                None => {
                    assert_eq!(ab, Err(MoneyError::Overflow), "overflow must fail closed");
                }
            }
        }
    }
}

#[test]
fn prop_sub_matches_checked_semantics() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let a = rng.next_nonneg_i128();
            let b = rng.next_nonneg_i128();
            let result = usd(a).checked_sub(&usd(b));
            if a >= b {
                assert_eq!(result.map(|m| m.minor_units()), Ok(a - b), "a={a} b={b}");
            } else {
                // A result below zero must be rejected, never silently clamped.
                assert_eq!(result, Err(MoneyError::Negative), "a={a} b={b}");
            }
        }
    }
}

#[test]
fn prop_cmp_total_order_consistent_with_minor_units() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let a = rng.next_nonneg_i128();
            let b = rng.next_nonneg_i128();
            let got = usd(a).try_cmp(&usd(b)).expect("same currency");
            assert_eq!(got, a.cmp(&b), "a={a} b={b}");
        }
    }
}

#[test]
fn prop_cross_currency_always_rejected() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let a = rng.next_nonneg_i128();
            let b = rng.next_nonneg_i128();
            let usd_a = Money::from_code(a, "USD").expect("valid");
            let eur_b = Money::from_code(b, "EUR").expect("valid");

            assert!(matches!(
                usd_a.checked_add(&eur_b),
                Err(MoneyError::CurrencyMismatch { .. })
            ));
            assert!(matches!(
                usd_a.checked_sub(&eur_b),
                Err(MoneyError::CurrencyMismatch { .. })
            ));
            assert!(matches!(
                usd_a.try_cmp(&eur_b),
                Err(MoneyError::CurrencyMismatch { .. })
            ));
        }
    }
}

#[test]
fn prop_overflow_boundary_is_exact() {
    // i128::MAX + 1 overflows; i128::MAX + 0 does not.
    let max = usd(i128::MAX);
    assert_eq!(
        max.checked_add(&usd(0)).map(|m| m.minor_units()),
        Ok(i128::MAX)
    );
    assert_eq!(max.checked_add(&usd(1)), Err(MoneyError::Overflow));
}

#[test]
fn prop_currency_parser_accepts_only_three_uppercase_ascii() {
    // Deterministically enumerate short ASCII strings and assert the parser's
    // acceptance set is exactly {len==3 and all A..=Z}.
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let len = (rng.next_u64() % 6) as usize; // 0..=5
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                // Bias toward the ASCII range so both valid and invalid bytes appear.
                let b = (rng.next_u64() % 128) as u8;
                s.push(b as char);
            }
            let parsed = kya_core::money::CurrencyCode::new(&s);
            let expected_ok = s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase());
            match (parsed, expected_ok) {
                (Ok(c), true) => assert_eq!(c.as_str(), s),
                (Err(_), false) => {}
                (Ok(_), false) => panic!("parser wrongly accepted {s:?}"),
                (Err(e), true) => panic!("parser wrongly rejected {s:?}: {e}"),
            }
        }
    }
}

#[test]
fn currency_wrong_length_reports_got() {
    assert_eq!(
        kya_core::money::CurrencyCode::new("US"),
        Err(CurrencyError::WrongLength { got: 2 })
    );
}
