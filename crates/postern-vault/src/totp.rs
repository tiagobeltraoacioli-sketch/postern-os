//! TOTP (RFC 6238) on top of HOTP (RFC 4226) for the vault's 2FA entries.
//!
//! - HMAC via RustCrypto `hmac` with `sha1`/`sha2` (MIT OR Apache-2.0).
//!   **SHA-1 is the RFC 6238 default** and what nearly every `otpauth://`
//!   issuer uses; it lives inside HMAC here, where SHA-1 collision attacks do
//!   not apply. SHA-256 and SHA-512 variants are provided for issuers that
//!   request them.
//! - Configurable digits (6–9) and period; defaults are the ecosystem
//!   standard 6 digits / 30 s.
//! - Secrets arrive base32-encoded (RFC 4648) from QR/otpauth URIs;
//!   [`decode_base32_secret`] normalizes case/whitespace/padding first.
//! - The seed is held in a [`Zeroizing`] buffer and wiped from RAM on drop,
//!   as is every intermediate HMAC output derived from it.
//!
//! **Honesty note:** a TOTP seed stored in the vault gets exactly the same
//! at-rest protection as any other entry — Argon2id + XChaCha20-Poly1305 via
//! [`Vault::seal`](crate::Vault::seal) — and nothing more. The crate-level
//! caveats apply unchanged: no TEE wrapping exists here, and an OS keychain
//! is NOT a TEE.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// RFC 6238 default time step (seconds).
pub const DEFAULT_PERIOD: u64 = 30;
/// The ecosystem-standard code length (RFC 4226 minimum).
pub const DEFAULT_DIGITS: u8 = 6;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("invalid base32 secret")]
    InvalidBase32,
    #[error("empty TOTP secret")]
    EmptySecret,
    #[error("digits must be between 6 and 9")]
    InvalidDigits,
    #[error("period must be at least 1 second")]
    InvalidPeriod,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

/// The HMAC hash for HOTP/TOTP. [`Algorithm::Sha1`] is the RFC 6238 default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// HMAC over `msg` under `key`; the tag buffer is wiped on drop because it is
/// key-derived material (the OTP is truncated out of it).
fn hmac_bytes(alg: Algorithm, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    match alg {
        Algorithm::Sha1 => {
            let mut m =
                <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(msg);
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        }
        Algorithm::Sha256 => {
            let mut m =
                <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(msg);
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        }
        Algorithm::Sha512 => {
            let mut m =
                <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(msg);
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        }
    }
}

/// RFC 4226 §5.3 dynamic truncation: the low nibble of the last MAC byte
/// picks a 4-byte window; mask the sign bit. Every supported MAC is ≥ 20
/// bytes, so `offset + 4 ≤ len` always holds (offset ≤ 15).
fn dynamic_truncate(mac: &[u8]) -> u32 {
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let window: [u8; 4] = mac[offset..offset + 4].try_into().expect("4-byte window");
    u32::from_be_bytes(window) & 0x7fff_ffff
}

fn check_params(secret: &[u8], digits: u8, period: u64) -> Result<(), TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if !(6..=9).contains(&digits) {
        // 10^9 still fits the 31-bit truncated value's u32; ≥10 digits would
        // just left-pad zeros and RFC 4226 mandates ≥6.
        return Err(TotpError::InvalidDigits);
    }
    if period == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    Ok(())
}

/// RFC 4226 HOTP as a zero-padded decimal string.
pub fn hotp(
    alg: Algorithm,
    secret: &[u8],
    counter: u64,
    digits: u8,
) -> Result<String, TotpError> {
    check_params(secret, digits, 1)?;
    let mac = hmac_bytes(alg, secret, &counter.to_be_bytes());
    let code = dynamic_truncate(&mac) % 10u32.pow(u32::from(digits));
    Ok(format!("{:0width$}", code, width = usize::from(digits)))
}

/// Decode a base32 (RFC 4648) TOTP secret as issuers hand them out:
/// case-insensitive, ASCII whitespace ignored (QR payloads are often grouped
/// `"gezd gnbv ..."`), trailing `=` padding optional. The decoded seed — and
/// the normalized intermediate copy — are wiped on drop.
pub fn decode_base32_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    // Normalization never exceeds the pre-reserved capacity (we only drop or
    // 1:1-map bytes), so the secret is never left behind in a reallocated
    // heap block.
    let mut norm = Zeroizing::new(String::with_capacity(encoded.len()));
    for c in encoded.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        norm.push(c.to_ascii_uppercase());
    }
    while norm.ends_with('=') {
        norm.pop(); // '=' padding is not secret; leaving it past len is fine
    }
    let decoded = data_encoding::BASE32_NOPAD
        .decode(norm.as_bytes())
        .map_err(|_| TotpError::InvalidBase32)?;
    Ok(Zeroizing::new(decoded))
}

/// A validated TOTP generator. The seed lives in a [`Zeroizing`] buffer and
/// is wiped from RAM when the value is dropped. Parameters are checked once
/// at construction, so code generation itself cannot fail.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u8,
    period: u64,
}

/// Manual impl so the seed can never leak through `{:?}` — only its length
/// and the public parameters are shown.
impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &format_args!("<{} bytes redacted>", self.secret.len()))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl Totp {
    /// Build from a raw seed. `digits` must be 6–9, `period` ≥ 1 second.
    /// On a validation error the seed is still wiped (it was moved in).
    pub fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        digits: u8,
        period: u64,
    ) -> Result<Self, TotpError> {
        check_params(&secret, digits, period)?;
        Ok(Self { secret, algorithm, digits, period })
    }

    /// Build from a base32-encoded seed (see [`decode_base32_secret`]).
    pub fn from_base32(
        encoded: &str,
        algorithm: Algorithm,
        digits: u8,
        period: u64,
    ) -> Result<Self, TotpError> {
        Self::new(decode_base32_secret(encoded)?, algorithm, digits, period)
    }

    /// The ecosystem default: SHA-1, 6 digits, 30 s — what a bare
    /// `otpauth://totp/...?secret=...` URI means.
    pub fn from_base32_default(encoded: &str) -> Result<Self, TotpError> {
        Self::from_base32(encoded, Algorithm::Sha1, DEFAULT_DIGITS, DEFAULT_PERIOD)
    }

    /// The code for a given Unix time (T0 = 0, per RFC 6238's default epoch).
    pub fn code_at(&self, unix_seconds: u64) -> String {
        let counter = unix_seconds / self.period; // period ≥ 1: no div-by-zero
        hotp(self.algorithm, &self.secret, counter, self.digits)
            .expect("parameters validated at construction")
    }

    /// The code for the current system time.
    pub fn code_now(&self) -> Result<String, TotpError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TotpError::Clock)?;
        Ok(self.code_at(now.as_secs()))
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn digits(&self) -> u8 {
        self.digits
    }
    pub fn period(&self) -> u64 {
        self.period
    }
    /// The raw seed, for serialization inside the crate only.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D secret ("12345678901234567890").
    const RFC4226_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_appendix_d_hotp_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(Algorithm::Sha1, RFC4226_SECRET, counter as u64, 6).unwrap();
            assert_eq!(&got, want, "HOTP counter {counter}");
        }
    }

    // RFC 6238 Appendix B seeds: the ASCII digits repeated to the hash's
    // block-appropriate length (20 / 32 / 64 bytes).
    const SHA1_SEED: &[u8] = b"12345678901234567890";
    const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SEED: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    fn totp_for(alg: Algorithm, seed: &[u8]) -> Totp {
        Totp::new(Zeroizing::new(seed.to_vec()), alg, 8, 30).unwrap()
    }

    #[test]
    fn rfc6238_appendix_b_sha1() {
        let t = totp_for(Algorithm::Sha1, SHA1_SEED);
        assert_eq!(t.code_at(59), "94287082");
        assert_eq!(t.code_at(1111111109), "07081804");
        assert_eq!(t.code_at(1111111111), "14050471");
        assert_eq!(t.code_at(1234567890), "89005924");
        assert_eq!(t.code_at(2000000000), "69279037");
        assert_eq!(t.code_at(20000000000), "65353130");
    }

    #[test]
    fn rfc6238_appendix_b_sha256() {
        let t = totp_for(Algorithm::Sha256, SHA256_SEED);
        assert_eq!(t.code_at(59), "46119246");
        assert_eq!(t.code_at(1111111109), "68084774");
        assert_eq!(t.code_at(1111111111), "67062674");
        assert_eq!(t.code_at(1234567890), "91819424");
        assert_eq!(t.code_at(2000000000), "90698825");
        assert_eq!(t.code_at(20000000000), "77737706");
    }

    #[test]
    fn rfc6238_appendix_b_sha512() {
        let t = totp_for(Algorithm::Sha512, SHA512_SEED);
        assert_eq!(t.code_at(59), "90693936");
        assert_eq!(t.code_at(1111111109), "25091201");
        assert_eq!(t.code_at(1111111111), "99943326");
        assert_eq!(t.code_at(1234567890), "93441116");
        assert_eq!(t.code_at(2000000000), "38618901");
        assert_eq!(t.code_at(20000000000), "47863826");
    }

    #[test]
    fn base32_decodes_rfc4226_seed() {
        // base32("12345678901234567890")
        let s = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(&*s, RFC4226_SECRET);
    }

    #[test]
    fn base32_normalization_edge_cases() {
        let canonical = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        // Lowercase, grouped with spaces (how issuers display secrets), and
        // trailing '=' padding must all decode identically.
        for variant in [
            "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
            "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
        ] {
            assert_eq!(&*decode_base32_secret(variant).unwrap(), &*canonical);
        }
        // A padded, non-block-aligned secret ("Hello!" + 0xDEADBEEF).
        let padded = decode_base32_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(&*padded, b"Hello!\xde\xad\xbe\xef");
        // Invalid characters: '1', '8', '0' are not RFC 4648 base32.
        assert_eq!(decode_base32_secret("GEZ1").unwrap_err(), TotpError::InvalidBase32);
        assert_eq!(decode_base32_secret("A8").unwrap_err(), TotpError::InvalidBase32);
        assert_eq!(decode_base32_secret("A0AA").unwrap_err(), TotpError::InvalidBase32);
        // Interior '=' is invalid (only trailing padding is stripped).
        assert_eq!(decode_base32_secret("GE=ZD").unwrap_err(), TotpError::InvalidBase32);
        // Wrong length remainder (1 leftover char can never be valid base32).
        assert_eq!(decode_base32_secret("A").unwrap_err(), TotpError::InvalidBase32);
        // Empty decodes to an empty seed, which construction then refuses.
        assert!(decode_base32_secret("").unwrap().is_empty());
        assert_eq!(
            Totp::from_base32_default("").unwrap_err(),
            TotpError::EmptySecret
        );
    }

    #[test]
    fn parameter_validation() {
        let seed = || Zeroizing::new(b"12345678901234567890".to_vec());
        assert_eq!(
            Totp::new(Zeroizing::new(Vec::new()), Algorithm::Sha1, 6, 30).unwrap_err(),
            TotpError::EmptySecret
        );
        assert_eq!(
            Totp::new(seed(), Algorithm::Sha1, 5, 30).unwrap_err(),
            TotpError::InvalidDigits
        );
        assert_eq!(
            Totp::new(seed(), Algorithm::Sha1, 10, 30).unwrap_err(),
            TotpError::InvalidDigits
        );
        assert_eq!(
            Totp::new(seed(), Algorithm::Sha1, 6, 0).unwrap_err(),
            TotpError::InvalidPeriod
        );
        assert!(Totp::new(seed(), Algorithm::Sha1, 9, 1).is_ok());
        assert_eq!(hotp(Algorithm::Sha1, b"", 0, 6).unwrap_err(), TotpError::EmptySecret);
        assert_eq!(
            hotp(Algorithm::Sha1, b"k", 0, 5).unwrap_err(),
            TotpError::InvalidDigits
        );
    }

    #[test]
    fn code_now_runs() {
        let t = Totp::from_base32_default("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let code = t.code_now().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn custom_period_changes_counter() {
        let t30 = totp_for(Algorithm::Sha1, SHA1_SEED);
        let t60 = Totp::new(Zeroizing::new(SHA1_SEED.to_vec()), Algorithm::Sha1, 8, 60).unwrap();
        // At T=59 the 30s counter is 1, the 60s counter is 0 (= HOTP(0)).
        assert_eq!(t30.code_at(59), "94287082");
        assert_eq!(t60.code_at(59), t60.code_at(0));
        assert_ne!(t60.code_at(59), t30.code_at(59));
    }
}
