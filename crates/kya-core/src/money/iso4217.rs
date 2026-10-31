//! ISO 4217 currency code newtype.
//!
//! A [`CurrencyCode`] is a validated three-letter uppercase ASCII code. Making
//! it a newtype means a currency can never be confused with an arbitrary string
//! elsewhere in the domain, and illegal codes are unrepresentable once
//! constructed.

use core::fmt;

/// Errors produced while constructing a [`CurrencyCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CurrencyError {
    /// The code was not exactly three bytes long.
    ///
    /// An ISO 4217 code is exactly three uppercase ASCII letters, so a valid
    /// code is always exactly three bytes. `got` is the **byte** length of the
    /// input, which for multibyte (non-ASCII) input may differ from the number
    /// of characters.
    WrongLength {
        /// The number of bytes that were supplied.
        got: usize,
    },
    /// The code contained a byte that is not an ASCII uppercase letter
    /// (`A..=Z`). This includes lowercase letters, digits, punctuation, and any
    /// byte of a multibyte (non-ASCII) character.
    NotUppercaseAscii,
}

impl fmt::Display for CurrencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurrencyError::WrongLength { got } => {
                write!(f, "currency code must be 3 bytes, got {got}")
            }
            CurrencyError::NotUppercaseAscii => {
                f.write_str("currency code must be ASCII uppercase letters")
            }
        }
    }
}

impl std::error::Error for CurrencyError {}

/// A validated ISO 4217 currency code (three uppercase ASCII letters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
    /// Construct a currency code from a string.
    ///
    /// The input is validated but not checked against the live ISO 4217 table;
    /// the SDK intentionally avoids embedding a mutable registry in the core.
    ///
    /// Valid ISO 4217 syntax is **exactly three uppercase ASCII letters**
    /// (`A..=Z`), which is always exactly three bytes. Anything else — a wrong
    /// byte length, a lowercase letter, a digit, punctuation, or any multibyte
    /// (non-ASCII) character — is rejected with a typed error. In particular, a
    /// three-*byte* multibyte string (such as a single 3-byte UTF-8 character)
    /// is rejected: it passes the byte-length gate but fails the
    /// uppercase-ASCII check, yielding [`CurrencyError::NotUppercaseAscii`].
    ///
    /// # Errors
    ///
    /// - [`CurrencyError::WrongLength`] if the input is not exactly 3 bytes.
    /// - [`CurrencyError::NotUppercaseAscii`] if any byte is not `A..=Z`.
    pub fn new(code: &str) -> Result<Self, CurrencyError> {
        let bytes = code.as_bytes();
        if bytes.len() != 3 {
            return Err(CurrencyError::WrongLength { got: bytes.len() });
        }
        let mut out = [0u8; 3];
        for (slot, &b) in out.iter_mut().zip(bytes.iter()) {
            if !b.is_ascii_uppercase() {
                return Err(CurrencyError::NotUppercaseAscii);
            }
            *slot = b;
        }
        Ok(CurrencyCode(out))
    }

    /// The code as a string slice.
    pub fn as_str(&self) -> &str {
        // Safe conversion: constructor guarantees ASCII uppercase bytes.
        core::str::from_utf8(&self.0).unwrap_or("???")
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_code() {
        let usd = CurrencyCode::new("USD").expect("USD is valid");
        assert_eq!(usd.as_str(), "USD");
        assert_eq!(usd.to_string(), "USD");
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            CurrencyCode::new("US"),
            Err(CurrencyError::WrongLength { got: 2 })
        );
        assert_eq!(
            CurrencyCode::new("USDD"),
            Err(CurrencyError::WrongLength { got: 4 })
        );
    }

    #[test]
    fn rejects_lowercase_and_digits() {
        assert_eq!(
            CurrencyCode::new("usd"),
            Err(CurrencyError::NotUppercaseAscii)
        );
        assert_eq!(
            CurrencyCode::new("US1"),
            Err(CurrencyError::NotUppercaseAscii)
        );
    }

    #[test]
    fn rejects_three_byte_multibyte_char() {
        // '€' is a single character encoded as three UTF-8 bytes. It passes the
        // byte-length gate but must be rejected at the uppercase-ASCII check
        // rather than slipping through.
        let euro = "\u{20AC}";
        assert_eq!(euro.len(), 3, "precondition: 3-byte input");
        assert_eq!(euro.chars().count(), 1);
        assert_eq!(
            CurrencyCode::new(euro),
            Err(CurrencyError::NotUppercaseAscii)
        );
    }

    #[test]
    fn rejects_two_char_three_byte_string() {
        // "Aé": 'A' is one byte, 'é' is two bytes, totalling three bytes but
        // only two characters. It must be rejected, not length-accepted.
        let s = "A\u{00E9}";
        assert_eq!(s.len(), 3, "precondition: 3-byte input");
        assert_eq!(s.chars().count(), 2);
        assert_eq!(CurrencyCode::new(s), Err(CurrencyError::NotUppercaseAscii));
    }

    #[test]
    fn wrong_length_reports_byte_length_and_accurate_display() {
        // A four-byte, single-character input: the reported length is the BYTE
        // length (4), and the Display text says "bytes", not "characters".
        let four_byte_char = "\u{1F600}"; // 😀, 4 bytes, 1 char
        assert_eq!(four_byte_char.len(), 4);
        let err = CurrencyCode::new(four_byte_char).expect_err("too long in bytes");
        assert_eq!(err, CurrencyError::WrongLength { got: 4 });
        let msg = err.to_string();
        assert!(msg.contains("bytes"), "display should say bytes: {msg}");
        assert!(
            !msg.contains("characters"),
            "display must not conflate bytes with characters: {msg}"
        );
        assert!(
            msg.contains('4'),
            "display should report byte length: {msg}"
        );
    }
}
