// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal hex helpers (lowercase, optional `0x` prefix on decode) so the
//! crate stays dependency-light. Used by the deploy harness and tests.

/// Encode bytes as a lowercase hex string WITHOUT a `0x` prefix.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16"));
    }
    s
}

/// Encode bytes as a lowercase hex string WITH a `0x` prefix.
pub fn encode_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", encode(bytes))
}

/// Decode a hex string (case-insensitive, optional `0x` prefix).
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength(s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or(HexError::BadDigit(bytes[i] as char))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or(HexError::BadDigit(bytes[i + 1] as char))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Decode into a fixed-size array; errors if the byte length differs.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let v = decode(s)?;
    let len = v.len();
    v.try_into().map_err(|_| HexError::BadLength {
        expected: N,
        actual: len,
    })
}

/// Typed hex-decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// Hex strings must have an even number of digits.
    OddLength(usize),
    /// A character was not a hex digit.
    BadDigit(char),
    /// Decoded length differed from the expected fixed size.
    BadLength { expected: usize, actual: usize },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HexError::OddLength(n) => write!(f, "odd hex length {n}"),
            HexError::BadDigit(c) => write!(f, "invalid hex digit {c:?}"),
            HexError::BadLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0x00u8, 0x01, 0xab, 0xff];
        let s = encode(&bytes);
        assert_eq!(s, "0001abff");
        assert_eq!(decode(&s).unwrap(), bytes.to_vec());
        assert_eq!(decode("0x0001ABFF").unwrap(), bytes.to_vec());
        assert_eq!(encode_prefixed(&bytes), "0x0001abff");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode("abc"), Err(HexError::OddLength(3)));
        assert_eq!(decode("zz"), Err(HexError::BadDigit('z')));
        assert_eq!(
            decode_array::<2>("0xabcdef"),
            Err(HexError::BadLength {
                expected: 2,
                actual: 3
            })
        );
    }
}
