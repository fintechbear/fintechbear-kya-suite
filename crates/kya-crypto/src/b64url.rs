//! Strict base64url (RFC 4648 §5, no padding) decoding, implemented in-crate.
//!
//! JWS compact serialization encodes its segments with base64url and **no**
//! padding (RFC 7515 §2). This module decodes exactly that alphabet and nothing
//! else. It is intentionally tiny and dependency-free (AGENTS.md Rule 13), and
//! it never panics on untrusted input: every byte is bounds-checked against the
//! alphabet, and malformed input yields `None` rather than a partial result.
//!
//! Deliberately rejected, to avoid parser ambiguity on attacker-controlled
//! input:
//! - the standard base64 alphabet characters `+` and `/`;
//! - `=` padding (RFC 7515 forbids padding in the compact form);
//! - any whitespace or other non-alphabet byte;
//! - a trailing group of a single base64 character (an impossible encoding).

/// Decode a base64url string with no padding into raw bytes.
///
/// Returns `None` for any input that is not strict, unpadded base64url. The
/// function allocates at most `input.len()` bytes and performs no unchecked
/// indexing or arithmetic.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    // Each base64 character carries 6 bits. Groups of 4 chars -> 3 bytes.
    // Valid remainders when dividing len by 4 are 0, 2, or 3; a remainder of 1
    // is impossible in canonical base64 and is rejected.
    let rem = input.len() % 4;
    if rem == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input {
        let value = decode_char(byte)?;
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Shift down to the top 8 bits we have completed.
            let b = (acc >> bits) & 0xFF;
            out.push(b as u8);
        }
    }

    // Any leftover bits in a valid encoding must be zero padding bits; a
    // non-zero remainder means the input encoded extra set bits, which is not a
    // canonical encoding.
    if bits > 0 {
        let mask = (1u32 << bits) - 1;
        if acc & mask != 0 {
            return None;
        }
    }

    Some(out)
}

/// Map a single base64url character to its 6-bit value, or `None` if it is not
/// in the base64url alphabet.
fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_vectors() {
        // "Hello" -> SGVsbG8 (no padding).
        assert_eq!(decode(b"SGVsbG8").unwrap(), b"Hello");
        // Empty decodes to empty.
        assert_eq!(decode(b"").unwrap(), b"");
        // "f" -> Zg
        assert_eq!(decode(b"Zg").unwrap(), b"f");
        // "fo" -> Zm8
        assert_eq!(decode(b"Zm8").unwrap(), b"fo");
    }

    #[test]
    fn uses_url_safe_alphabet() {
        // Bytes 0xFB 0xFF 0xFE -> standard "+/+" but url-safe "-_-".
        assert_eq!(decode(b"-_8").unwrap(), [0xFB, 0xFF]);
    }

    #[test]
    fn rejects_standard_alphabet_and_padding() {
        assert!(decode(b"SGVsbG8=").is_none(), "padding rejected");
        assert!(decode(b"a+b/").is_none(), "standard alphabet rejected");
    }

    #[test]
    fn rejects_whitespace_and_junk() {
        assert!(decode(b"SG Vs").is_none());
        assert!(decode(b"\n").is_none());
        assert!(decode(b"h\xE9llo".as_slice()).is_none());
    }

    #[test]
    fn rejects_impossible_length_remainder() {
        // A single trailing char cannot encode any whole byte.
        assert!(decode(b"A").is_none());
        assert!(decode(b"ABCDE").is_none());
    }

    #[test]
    fn does_not_panic_on_arbitrary_bytes() {
        for b in 0u8..=255 {
            // Single arbitrary byte (len 1) always returns None without panic.
            let _ = decode(&[b]);
            let _ = decode(&[b, b, b, b]);
        }
    }
}
