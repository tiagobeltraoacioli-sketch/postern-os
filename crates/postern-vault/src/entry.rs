//! Typed vault entries: Password / Note / TOTP.
//!
//! A typed entry is a **tagged, length-prefixed record** (no serde, same
//! checked-bounds style as the vault's own serialization) stored as the
//! *value* of a normal [`Vault`] entry. The existing seal/open/serialize
//! paths are untouched: a typed record rides through them as opaque bytes,
//! so it gets exactly the same at-rest protection as every other entry —
//! Argon2id + XChaCha20-Poly1305 — and nothing more (the crate-level "no TEE
//! wrapping exists here" caveat applies unchanged).
//!
//! Record layout (all lengths little-endian `u32`):
//!
//! ```text
//! [version:u8 = 1][tag:u8][payload...]
//! tag 1 Password: [ulen:u32][username][plen:u32][password]
//! tag 2 Note:     [blen:u32][body]
//! tag 3 Totp:     [alg:u8][digits:u8][period:u64 LE][slen:u32][seed]
//! ```
//!
//! Malformed records are rejected as [`VaultError::Corrupt`]; every secret
//! field is parsed straight into a [`Zeroizing`] container, so partial
//! secrets are wiped from RAM on parse-failure paths.

use crate::totp::{Algorithm, Totp};
use crate::{Vault, VaultError};
use zeroize::{Zeroize, Zeroizing};

const RECORD_VERSION: u8 = 1;
const TAG_PASSWORD: u8 = 1;
const TAG_NOTE: u8 = 2;
const TAG_TOTP: u8 = 3;
const ALG_SHA1: u8 = 1;
const ALG_SHA256: u8 = 2;
const ALG_SHA512: u8 = 3;

/// A typed vault entry. All payload fields — including the username and the
/// note body — are treated as secret and wiped from RAM on drop (only entry
/// *names* are non-secret, matching [`Vault`]'s policy).
pub enum Entry {
    /// A credential pair.
    Password {
        username: Zeroizing<String>,
        password: Zeroizing<Vec<u8>>,
    },
    /// A free-form encrypted note (UTF-8).
    Note(Zeroizing<String>),
    /// A TOTP (RFC 6238) seed with its parameters, always in a validated
    /// state — decoding a record with out-of-range digits/period/seed fails
    /// as `Corrupt` instead of producing an unusable generator.
    Totp(Totp),
}

impl Entry {
    /// Serialize into ONE exactly-sized zeroizing buffer (same hygiene as the
    /// vault serializer: no reallocation, so no un-wiped fragments in freed
    /// heap blocks).
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let len_u32 = |n: usize| u32::try_from(n).map_err(|_| VaultError::TooLarge);
        let size = match self {
            Entry::Password { username, password } => {
                len_u32(username.len())?;
                len_u32(password.len())?;
                2usize
                    .checked_add(4)
                    .and_then(|s| s.checked_add(username.len()))
                    .and_then(|s| s.checked_add(4))
                    .and_then(|s| s.checked_add(password.len()))
                    .ok_or(VaultError::TooLarge)?
            }
            Entry::Note(body) => {
                len_u32(body.len())?;
                2usize
                    .checked_add(4)
                    .and_then(|s| s.checked_add(body.len()))
                    .ok_or(VaultError::TooLarge)?
            }
            Entry::Totp(t) => {
                len_u32(t.secret().len())?;
                2usize
                    .checked_add(1 + 1 + 8 + 4)
                    .and_then(|s| s.checked_add(t.secret().len()))
                    .ok_or(VaultError::TooLarge)?
            }
        };
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.push(RECORD_VERSION);
        match self {
            Entry::Password { username, password } => {
                out.push(TAG_PASSWORD);
                out.extend_from_slice(&(username.len() as u32).to_le_bytes());
                out.extend_from_slice(username.as_bytes());
                out.extend_from_slice(&(password.len() as u32).to_le_bytes());
                out.extend_from_slice(password);
            }
            Entry::Note(body) => {
                out.push(TAG_NOTE);
                out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                out.extend_from_slice(body.as_bytes());
            }
            Entry::Totp(t) => {
                out.push(TAG_TOTP);
                out.push(match t.algorithm() {
                    Algorithm::Sha1 => ALG_SHA1,
                    Algorithm::Sha256 => ALG_SHA256,
                    Algorithm::Sha512 => ALG_SHA512,
                });
                out.push(t.digits());
                out.extend_from_slice(&t.period().to_le_bytes());
                out.extend_from_slice(&(t.secret().len() as u32).to_le_bytes());
                out.extend_from_slice(t.secret());
            }
        }
        debug_assert_eq!(out.len(), size, "size precomputation must be exact (no realloc)");
        Ok(out)
    }

    /// Parse a typed record. Any malformation — bad version/tag, truncated
    /// length, trailing bytes, invalid UTF-8, out-of-range TOTP parameters —
    /// is [`VaultError::Corrupt`]. Secrets parsed before the failure point
    /// sit in `Zeroizing` containers and are wiped as they drop.
    pub fn decode(data: &[u8]) -> Result<Entry, VaultError> {
        let mut r = Reader { data, i: 0 };
        if r.u8()? != RECORD_VERSION {
            return Err(VaultError::Corrupt);
        }
        let entry = match r.u8()? {
            TAG_PASSWORD => {
                let mut raw = r.len_prefixed()?.to_vec();
                let username = utf8_secret_in_place(&mut raw)?;
                let password = Zeroizing::new(r.len_prefixed()?.to_vec());
                Entry::Password { username, password }
            }
            TAG_NOTE => {
                let mut raw = r.len_prefixed()?.to_vec();
                Entry::Note(utf8_secret_in_place(&mut raw)?)
            }
            TAG_TOTP => {
                let algorithm = match r.u8()? {
                    ALG_SHA1 => Algorithm::Sha1,
                    ALG_SHA256 => Algorithm::Sha256,
                    ALG_SHA512 => Algorithm::Sha512,
                    _ => return Err(VaultError::Corrupt),
                };
                let digits = r.u8()?;
                let period = r.u64()?;
                let secret = Zeroizing::new(r.len_prefixed()?.to_vec());
                // Totp::new re-validates digits/period/seed; on failure it
                // owns (and therefore wipes) the just-parsed seed.
                Entry::Totp(
                    Totp::new(secret, algorithm, digits, period)
                        .map_err(|_| VaultError::Corrupt)?,
                )
            }
            _ => return Err(VaultError::Corrupt),
        };
        if r.i != data.len() {
            // Trailing garbage: reject; `entry` drops here and its Zeroizing
            // fields wipe the already-parsed secrets.
            return Err(VaultError::Corrupt);
        }
        Ok(entry)
    }
}

/// Convert a just-parsed secret byte buffer into a self-wiping UTF-8 string.
///
/// Zeroize gap this closes: `String::from_utf8(vec)` on invalid input hands
/// the buffer back inside `FromUtf8Error`, and `.map_err(|_| ...)` used to
/// drop that copy of the secret **un-zeroized**. Validating first (and wiping
/// `bytes` in place before returning `Err`) means the invalid-UTF-8 error
/// path leaves no un-wiped copy behind. On success the buffer is taken
/// (left empty) and returned wrapped in [`Zeroizing`].
fn utf8_secret_in_place(bytes: &mut Vec<u8>) -> Result<Zeroizing<String>, VaultError> {
    if std::str::from_utf8(bytes).is_err() {
        bytes.zeroize();
        return Err(VaultError::Corrupt);
    }
    Ok(Zeroizing::new(
        String::from_utf8(std::mem::take(bytes)).expect("validated as UTF-8 just above"),
    ))
}

impl Vault {
    /// Store a typed entry under `name` (replacing any previous value, which
    /// the untyped `put` wipes).
    pub fn put_entry(&mut self, name: &str, entry: &Entry) -> Result<(), VaultError> {
        let record = entry.encode()?;
        self.put(name, &record);
        Ok(())
    }

    /// Fetch and parse a typed entry. `Ok(None)` if the name is absent;
    /// [`VaultError::Corrupt`] if the value is not a well-formed typed record
    /// (e.g. it was stored with the untyped `put`).
    pub fn get_entry(&self, name: &str) -> Result<Option<Entry>, VaultError> {
        match self.get(name) {
            None => Ok(None),
            Some(raw) => Entry::decode(raw).map(Some),
        }
    }
}

// ── checked-bounds reader (defense-in-depth on AEAD-authenticated bytes) ────

struct Reader<'a> {
    data: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        // Checked add: `n` can be attacker-shaped (a u32 length from the
        // record) and `i + n` could wrap usize on 32-bit targets.
        let end = self
            .i
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or(VaultError::Corrupt)?;
        let s = &self.data[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, VaultError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, VaultError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn len_prefixed(&mut self) -> Result<&'a [u8], VaultError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn password_roundtrip() {
        let e = Entry::Password {
            username: z("alice@example.com"),
            password: Zeroizing::new(b"correct horse battery staple".to_vec()),
        };
        let rec = e.encode().unwrap();
        match Entry::decode(&rec).unwrap() {
            Entry::Password { username, password } => {
                assert_eq!(&**username, "alice@example.com");
                assert_eq!(&**password, b"correct horse battery staple");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn note_roundtrip() {
        let e = Entry::Note(z("seed phrase location: safe #2 — UTF-8 ✓"));
        let rec = e.encode().unwrap();
        match Entry::decode(&rec).unwrap() {
            Entry::Note(body) => assert_eq!(&**body, "seed phrase location: safe #2 — UTF-8 ✓"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn totp_roundtrip_preserves_codes() {
        let t = Totp::new(
            Zeroizing::new(b"12345678901234567890".to_vec()),
            Algorithm::Sha256,
            8,
            60,
        )
        .unwrap();
        let want = t.code_at(1234567890);
        let rec = Entry::Totp(t).encode().unwrap();
        match Entry::decode(&rec).unwrap() {
            Entry::Totp(t2) => {
                assert_eq!(t2.algorithm(), Algorithm::Sha256);
                assert_eq!(t2.digits(), 8);
                assert_eq!(t2.period(), 60);
                assert_eq!(t2.code_at(1234567890), want);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn typed_entries_roundtrip_through_seal_open() {
        let key = [11u8; 32];
        let mut v = Vault::new();
        v.put_entry(
            "email",
            &Entry::Password {
                username: z("alice"),
                password: Zeroizing::new(b"hunter2".to_vec()),
            },
        )
        .unwrap();
        v.put_entry("memo", &Entry::Note(z("renew domain in July"))).unwrap();
        let totp = Totp::from_base32_default("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let want_code = totp.code_at(59);
        v.put_entry("github-2fa", &Entry::Totp(totp)).unwrap();
        // Untyped and typed entries coexist in the same vault.
        v.put("raw", b"opaque bytes");

        let sealed = v.seal(&key).unwrap();
        let opened = Vault::open(&sealed, &key).unwrap();

        match opened.get_entry("email").unwrap().unwrap() {
            Entry::Password { username, password } => {
                assert_eq!(&**username, "alice");
                assert_eq!(&**password, b"hunter2");
            }
            _ => panic!("wrong variant"),
        }
        match opened.get_entry("memo").unwrap().unwrap() {
            Entry::Note(body) => assert_eq!(&**body, "renew domain in July"),
            _ => panic!("wrong variant"),
        }
        match opened.get_entry("github-2fa").unwrap().unwrap() {
            Entry::Totp(t) => assert_eq!(t.code_at(59), want_code),
            _ => panic!("wrong variant"),
        }
        assert!(opened.get_entry("absent").unwrap().is_none());
        // An untyped value is not a typed record.
        assert!(matches!(opened.get_entry("raw"), Err(VaultError::Corrupt)));
    }

    #[test]
    fn malformed_records_are_corrupt() {
        // Empty / truncated header.
        assert!(matches!(Entry::decode(&[]), Err(VaultError::Corrupt)));
        assert!(matches!(Entry::decode(&[RECORD_VERSION]), Err(VaultError::Corrupt)));
        // Unknown version and unknown tag.
        assert!(matches!(Entry::decode(&[9, TAG_NOTE, 0, 0, 0, 0]), Err(VaultError::Corrupt)));
        assert!(matches!(
            Entry::decode(&[RECORD_VERSION, 42, 0, 0, 0, 0]),
            Err(VaultError::Corrupt)
        ));

        // A valid note, then variously damaged.
        let good = Entry::Note(z("hello")).encode().unwrap();
        assert!(Entry::decode(&good).is_ok());
        // Truncated payload.
        assert!(matches!(
            Entry::decode(&good[..good.len() - 1]),
            Err(VaultError::Corrupt)
        ));
        // Trailing garbage after a well-formed record.
        let mut trailing = good.to_vec();
        trailing.push(0);
        assert!(matches!(Entry::decode(&trailing), Err(VaultError::Corrupt)));
        // Length prefix claiming u32::MAX bytes (checked-add path).
        let mut huge = vec![RECORD_VERSION, TAG_NOTE];
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        huge.extend_from_slice(b"x");
        assert!(matches!(Entry::decode(&huge), Err(VaultError::Corrupt)));
        // Invalid UTF-8 note body.
        let mut bad_utf8 = vec![RECORD_VERSION, TAG_NOTE];
        bad_utf8.extend_from_slice(&2u32.to_le_bytes());
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert!(matches!(Entry::decode(&bad_utf8), Err(VaultError::Corrupt)));

        // Password whose second field is truncated: the parsed username is
        // dropped (and wiped) on the error path.
        let full = Entry::Password {
            username: z("alice"),
            password: Zeroizing::new(b"pw".to_vec()),
        }
        .encode()
        .unwrap();
        let cut = 2 + 4 + "alice".len() + 2; // mid-way through the password length prefix
        assert!(matches!(Entry::decode(&full[..cut]), Err(VaultError::Corrupt)));
    }

    /// Regression (zeroize gap): on the invalid-UTF-8 error path the parsed
    /// secret buffer must be wiped IN PLACE before `Err` is returned. Before
    /// the fix, `String::from_utf8(vec).map_err(|_| Corrupt)` dropped the
    /// secret copy un-zeroized inside the discarded `FromUtf8Error`.
    #[test]
    fn invalid_utf8_secret_buffer_is_wiped_before_err() {
        // Secret-looking bytes made invalid UTF-8 by a trailing 0xFF.
        let mut buf = b"hunter2\xff".to_vec();
        assert!(matches!(
            super::utf8_secret_in_place(&mut buf),
            Err(VaultError::Corrupt)
        ));
        assert!(
            buf.iter().all(|b| *b == 0),
            "the invalid-UTF-8 secret copy must be zeroized before the error returns, got {buf:?}"
        );

        // And the success path still round-trips (buffer is taken, not leaked).
        let mut ok = b"alice".to_vec();
        let s = super::utf8_secret_in_place(&mut ok).unwrap();
        assert_eq!(&*s, "alice");
        assert!(ok.is_empty(), "success path takes the buffer");
    }

    #[test]
    fn totp_records_with_bad_parameters_are_corrupt() {
        let t = Totp::new(Zeroizing::new(b"12345678901234567890".to_vec()), Algorithm::Sha1, 6, 30)
            .unwrap();
        let good = Entry::Totp(t).encode().unwrap();
        // Layout: [ver][tag][alg][digits][period u64][slen u32][seed].
        let mut bad_alg = good.to_vec();
        bad_alg[2] = 0;
        assert!(matches!(Entry::decode(&bad_alg), Err(VaultError::Corrupt)));
        let mut bad_digits = good.to_vec();
        bad_digits[3] = 0;
        assert!(matches!(Entry::decode(&bad_digits), Err(VaultError::Corrupt)));
        let mut bad_period = good.to_vec();
        bad_period[4..12].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(Entry::decode(&bad_period), Err(VaultError::Corrupt)));
        let mut empty_seed = good[..16].to_vec(); // keep header, drop seed
        empty_seed[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(Entry::decode(&empty_seed), Err(VaultError::Corrupt)));
    }
}
