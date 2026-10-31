//! Exact monetary representation for KYA.
//!
//! Money is represented as an [`i128`] count of **minor units** (the currency's
//! smallest unit) paired with an explicit [`CurrencyCode`]. No floating point is
//! used anywhere in monetary logic.
//!
//! Invariants enforced by this module:
//!
//! - Amounts are **non-negative**; a spend is never negative.
//! - Arithmetic is **checked**; overflow fails closed with a typed error and
//!   never wraps.
//! - Operations across **different currencies are rejected**; there is no
//!   implicit conversion.
//! - Comparisons are **exact**: no tolerance, epsilon, or rounding slack.

pub mod iso4217;

pub use iso4217::{CurrencyCode, CurrencyError};

use core::cmp::Ordering;
use core::fmt;

/// Errors produced by monetary construction and arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MoneyError {
    /// An amount was negative; domain amounts must be `>= 0`.
    Negative,
    /// An arithmetic operation overflowed the `i128` minor-unit range.
    Overflow,
    /// Two amounts in different currencies were combined or compared.
    CurrencyMismatch {
        /// The left-hand currency.
        left: CurrencyCode,
        /// The right-hand currency.
        right: CurrencyCode,
    },
    /// The currency code itself was invalid (see [`CurrencyError`]).
    Currency(CurrencyError),
}

impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MoneyError::Negative => f.write_str("monetary amount must be non-negative"),
            MoneyError::Overflow => f.write_str("monetary arithmetic overflowed"),
            MoneyError::CurrencyMismatch { left, right } => {
                write!(f, "currency mismatch: {left} vs {right}")
            }
            MoneyError::Currency(e) => write!(f, "invalid currency: {e}"),
        }
    }
}

impl std::error::Error for MoneyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MoneyError::Currency(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CurrencyError> for MoneyError {
    fn from(e: CurrencyError) -> Self {
        MoneyError::Currency(e)
    }
}

/// An exact, non-negative monetary amount in a specific currency.
///
/// Stored as an [`i128`] count of minor units. The signed type is used so that
/// intermediate arithmetic stays safe, but the public constructors reject
/// negative values, so a `Money` is always `>= 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Money {
    minor_units: i128,
    currency: CurrencyCode,
}

impl Money {
    /// Construct a `Money` from a minor-unit amount and a currency.
    ///
    /// # Errors
    ///
    /// Returns [`MoneyError::Negative`] if `minor_units < 0`.
    pub fn new(minor_units: i128, currency: CurrencyCode) -> Result<Self, MoneyError> {
        if minor_units < 0 {
            return Err(MoneyError::Negative);
        }
        Ok(Money {
            minor_units,
            currency,
        })
    }

    /// Construct a `Money` from a minor-unit amount and a currency code string.
    ///
    /// # Errors
    ///
    /// Returns [`MoneyError::Currency`] if the code is invalid, or
    /// [`MoneyError::Negative`] if the amount is negative.
    pub fn from_code(minor_units: i128, code: &str) -> Result<Self, MoneyError> {
        let currency = CurrencyCode::new(code)?;
        Money::new(minor_units, currency)
    }

    /// The amount in minor units (always `>= 0`).
    pub fn minor_units(&self) -> i128 {
        self.minor_units
    }

    /// The currency of this amount.
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }

    fn ensure_same_currency(&self, other: &Money) -> Result<(), MoneyError> {
        if self.currency != other.currency {
            return Err(MoneyError::CurrencyMismatch {
                left: self.currency,
                right: other.currency,
            });
        }
        Ok(())
    }

    /// Checked addition. Both operands must share the same currency.
    ///
    /// # Errors
    ///
    /// - [`MoneyError::CurrencyMismatch`] if currencies differ.
    /// - [`MoneyError::Overflow`] if the sum overflows `i128`.
    pub fn checked_add(&self, other: &Money) -> Result<Money, MoneyError> {
        self.ensure_same_currency(other)?;
        let sum = self
            .minor_units
            .checked_add(other.minor_units)
            .ok_or(MoneyError::Overflow)?;
        Money::new(sum, self.currency)
    }

    /// Checked subtraction. Both operands must share the same currency.
    ///
    /// # Errors
    ///
    /// - [`MoneyError::CurrencyMismatch`] if currencies differ.
    /// - [`MoneyError::Negative`] if the result would be negative.
    /// - [`MoneyError::Overflow`] if the subtraction overflows `i128`.
    pub fn checked_sub(&self, other: &Money) -> Result<Money, MoneyError> {
        self.ensure_same_currency(other)?;
        let diff = self
            .minor_units
            .checked_sub(other.minor_units)
            .ok_or(MoneyError::Overflow)?;
        Money::new(diff, self.currency)
    }

    /// Compare two amounts of the same currency.
    ///
    /// # Errors
    ///
    /// Returns [`MoneyError::CurrencyMismatch`] if the currencies differ. There
    /// is deliberately no cross-currency ordering.
    pub fn try_cmp(&self, other: &Money) -> Result<Ordering, MoneyError> {
        self.ensure_same_currency(other)?;
        Ok(self.minor_units.cmp(&other.minor_units))
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.minor_units, self.currency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd(minor: i128) -> Money {
        Money::from_code(minor, "USD").expect("valid USD amount")
    }

    fn eur(minor: i128) -> Money {
        Money::from_code(minor, "EUR").expect("valid EUR amount")
    }

    #[test]
    fn rejects_negative_construction() {
        assert_eq!(Money::from_code(-1, "USD"), Err(MoneyError::Negative));
    }

    #[test]
    fn checked_add_same_currency() {
        let total = usd(100).checked_add(&usd(250)).expect("no overflow");
        assert_eq!(total.minor_units(), 350);
        assert_eq!(total.currency().as_str(), "USD");
    }

    #[test]
    fn checked_add_rejects_currency_mismatch() {
        let err = usd(100).checked_add(&eur(100)).expect_err("mismatch");
        match err {
            MoneyError::CurrencyMismatch { left, right } => {
                assert_eq!(left.as_str(), "USD");
                assert_eq!(right.as_str(), "EUR");
            }
            other => panic!("expected CurrencyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn checked_add_detects_overflow() {
        let big = usd(i128::MAX);
        assert_eq!(big.checked_add(&usd(1)), Err(MoneyError::Overflow));
    }

    #[test]
    fn checked_sub_rejects_negative_result() {
        assert_eq!(usd(100).checked_sub(&usd(250)), Err(MoneyError::Negative));
    }

    #[test]
    fn checked_sub_rejects_currency_mismatch() {
        assert!(matches!(
            usd(100).checked_sub(&eur(50)),
            Err(MoneyError::CurrencyMismatch { .. })
        ));
    }

    #[test]
    fn try_cmp_rejects_currency_mismatch() {
        assert!(matches!(
            usd(100).try_cmp(&eur(100)),
            Err(MoneyError::CurrencyMismatch { .. })
        ));
    }

    #[test]
    fn try_cmp_orders_same_currency() {
        assert_eq!(usd(100).try_cmp(&usd(250)), Ok(Ordering::Less));
        assert_eq!(usd(250).try_cmp(&usd(100)), Ok(Ordering::Greater));
        assert_eq!(usd(100).try_cmp(&usd(100)), Ok(Ordering::Equal));
    }
}
