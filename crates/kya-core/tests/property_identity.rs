//! Property-based tests for identifier validation.
//!
//! Dependency-free deterministic generation (see `property_money.rs` for the
//! rationale). These assert the acceptance set of the identifier parsers and
//! that no input — however adversarial — causes a panic (AGENTS.md Rules 5, 7).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::identity::{AgentId, IdentityError, IssuerId, MerchantId, PrincipalId, ResourceId};

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
}

const SEEDS: [u64; 6] = [1, 99, 0xBADC_0FFE, 0x0102_0304, u64::MAX, 0x5555_5555];
const CASES_PER_SEED: usize = 3_000;
const MAX_ID_LEN: usize = 512;

/// Build the canonical acceptance predicate directly from the documented rule:
/// after trimming, non-empty, length <= MAX, no control characters.
fn should_accept(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty() && trimmed.len() <= MAX_ID_LEN && !trimmed.chars().any(|c| c.is_control())
}

#[test]
fn prop_agent_id_acceptance_matches_rule_and_never_panics() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let len = (rng.next_u64() % 12) as usize;
            let mut s = String::new();
            for _ in 0..len {
                // Mix in control chars, spaces, and printable chars.
                let choice = rng.next_u64() % 100;
                let ch = if choice < 15 {
                    (rng.next_u64() % 0x20) as u8 as char // control
                } else if choice < 25 {
                    ' '
                } else {
                    (b'!' + (rng.next_u64() % 93) as u8) as char // printable ASCII
                };
                s.push(ch);
            }
            // No panic on any of these; result matches the rule.
            let got = AgentId::new(&s);
            assert_eq!(got.is_ok(), should_accept(&s), "input={s:?} seed={seed}");
        }
    }
}

#[test]
fn prop_all_identifier_types_agree_on_the_same_rule() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let len = (rng.next_u64() % 8) as usize;
            let mut s = String::new();
            for _ in 0..len {
                let b = (rng.next_u64() % 128) as u8;
                s.push(b as char);
            }
            let expected = should_accept(&s);
            assert_eq!(AgentId::new(&s).is_ok(), expected, "AgentId {s:?}");
            assert_eq!(PrincipalId::new(&s).is_ok(), expected, "PrincipalId {s:?}");
            assert_eq!(IssuerId::new(&s).is_ok(), expected, "IssuerId {s:?}");
            assert_eq!(MerchantId::new(&s).is_ok(), expected, "MerchantId {s:?}");
            assert_eq!(ResourceId::new(&s).is_ok(), expected, "ResourceId {s:?}");
        }
    }
}

#[test]
fn prop_accepted_identifiers_round_trip_trimmed() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let len = (rng.next_u64() % 10) as usize;
            let mut s = String::new();
            for _ in 0..len {
                let b = (b'!' + (rng.next_u64() % 93) as u8) as char;
                s.push(b);
            }
            // Pad with surrounding whitespace to exercise trimming.
            let padded = format!("  {s}  ");
            if let Ok(id) = AgentId::new(&padded) {
                assert_eq!(id.as_str(), padded.trim());
            }
        }
    }
}

#[test]
fn oversized_input_reports_too_long_not_panic() {
    let big = "x".repeat(MAX_ID_LEN + 100);
    assert_eq!(
        AgentId::new(&big),
        Err(IdentityError::TooLong {
            got: MAX_ID_LEN + 100,
            max: MAX_ID_LEN
        })
    );
}
