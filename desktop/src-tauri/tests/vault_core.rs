// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the desktop vault backend (src/vault.rs), driven
//! through the `bloch_desktop` library facade (src/lib.rs) — the same
//! disclosed dual-compile pattern as tests/hygiene_scrub.rs and
//! tests/terem_lifecycle.rs. No Tauri app/window is spun up: these exercise
//! the pure core — the on-disk file format, the status JSON (with its
//! mandatory "not a TEE until real hardware" honesty field), and the
//! RFC 6238 TOTP path behind `vault_totp_code` (fail-closed branches
//! included). Everything under test is UNAUDITED, pre-mainnet.

use bloch_desktop::vault::{
    decode_vault_file, encode_vault_file, status_json, totp_code_impl, Unlocked, HONESTY,
    KEYCHAIN_HONESTY,
};
use postern_vault::Vault;
use zeroize::Zeroizing;

// ── on-disk file format: u32-le salt_len ‖ salt ‖ sealed ───────────────────

#[test]
fn file_format_round_trips() {
    let salt = b"sixteen-byte-slt".to_vec();
    let sealed = vec![0xAB; 137];
    let buf = encode_vault_file(&salt, &sealed);
    assert_eq!(&buf[0..4], &(salt.len() as u32).to_le_bytes());
    let (got_salt, got_sealed) = decode_vault_file(&buf).expect("round-trip");
    assert_eq!(got_salt, salt);
    assert_eq!(got_sealed, sealed);
}

#[test]
fn file_format_round_trips_empty_edges() {
    // Degenerate but well-formed: empty salt and/or empty sealed blob must
    // survive the trip byte-exactly (the seal itself rejects garbage later).
    for (salt, sealed) in [
        (Vec::new(), Vec::new()),
        (Vec::new(), vec![1, 2, 3]),
        (vec![9; 32], Vec::new()),
    ] {
        let (s, b) = decode_vault_file(&encode_vault_file(&salt, &sealed)).unwrap();
        assert_eq!(s, salt);
        assert_eq!(b, sealed);
    }
}

#[test]
fn corrupt_file_fails_closed() {
    // Too short to even hold the length header.
    for short in [&[][..], &[1][..], &[1, 2, 3][..]] {
        assert!(decode_vault_file(short).is_err(), "short input must be corrupt");
    }
    // salt_len points past the end of the buffer.
    let mut lying = (100u32).to_le_bytes().to_vec();
    lying.extend_from_slice(b"only-a-few-bytes");
    assert!(decode_vault_file(&lying).is_err(), "over-long salt_len must be corrupt");
    // salt_len = u32::MAX must not overflow the bounds arithmetic.
    let mut overflow = u32::MAX.to_le_bytes().to_vec();
    overflow.extend_from_slice(&[0; 8]);
    assert!(decode_vault_file(&overflow).is_err(), "u32::MAX salt_len must be corrupt");
}

#[test]
fn truncated_file_fails_closed() {
    let buf = encode_vault_file(&[7u8; 16], &[0xCD; 64]);
    // Cutting into the salt region must fail (header promises 16 salt bytes).
    let cut = &buf[..4 + 8];
    assert!(decode_vault_file(cut).is_err(), "truncated inside the salt must be corrupt");
}

#[test]
fn truncated_sealed_blob_fails_to_open() {
    // The file format itself can't know how long the sealed blob should be —
    // a cut INSIDE it still decodes structurally (salt is intact) but the
    // AEAD seal must then refuse to open. Fail closed end-to-end.
    let key = [7u8; 32];
    let mut vault = Vault::new();
    vault.put("hello", b"world");
    let sealed = vault.seal(&key).expect("seal");
    let buf = encode_vault_file(&[3u8; 16], &sealed);
    let cut = &buf[..buf.len() - 10];
    let (salt, sealed_cut) = decode_vault_file(cut).expect("structurally decodable");
    assert_eq!(salt, [3u8; 16]);
    assert!(Vault::open(&sealed_cut, &key).is_err(), "truncated ciphertext must not open");
}

#[test]
fn seal_survives_file_format_round_trip() {
    // Real postern-vault seal ‖ file encode ‖ decode ‖ open: the entry comes
    // back byte-exact under the right key and NOT under a wrong key.
    let key = [42u8; 32];
    let mut vault = Vault::new();
    vault.put("totp/example", b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    let sealed = vault.seal(&key).expect("seal");
    let (_, sealed_back) = decode_vault_file(&encode_vault_file(&[1u8; 16], &sealed)).unwrap();
    let reopened = Vault::open(&sealed_back, &key).expect("open under the right key");
    assert_eq!(reopened.get("totp/example"), Some(&b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"[..]));
    let wrong = [43u8; 32];
    assert!(Vault::open(&sealed_back, &wrong).is_err(), "wrong key must not open");
}

// ── status JSON: shape + the MANDATORY honesty disclosure ───────────────────

#[test]
fn status_json_carries_the_exact_honesty_text() {
    // The load-bearing phrase, verbatim. If this test fails, the UI has lost
    // its "this is a software seal" disclosure — that is a release blocker,
    // not a wording nit.
    assert!(HONESTY.contains("not a TEE until real hardware"));
    for status in [
        status_json(false, None, false, false),
        status_json(true, None, false, false),
        status_json(true, Some(3), true, true),
    ] {
        let honesty = status["honesty"].as_str().expect("honesty field is a string");
        assert!(
            honesty.contains("not a TEE until real hardware"),
            "every status answer must carry the honesty text, got: {honesty}"
        );
        assert_eq!(honesty, HONESTY);
    }
}

#[test]
fn status_json_carries_the_keychain_honesty_verbatim() {
    // The keychain disclosure, verbatim, in EVERY status answer — including
    // builds without the `vault-keychain` feature and states where nothing is
    // enrolled. Losing it is a release blocker, not a wording nit: keychain
    // unlock must never read as hardware protection.
    assert!(KEYCHAIN_HONESTY.contains("SOFTWARE convenience, not hardware"));
    assert!(KEYCHAIN_HONESTY.contains("Not a TEE until real hardware"));
    assert!(KEYCHAIN_HONESTY.contains("UNAUDITED"));
    for status in [
        status_json(false, None, false, false),
        status_json(true, None, true, false),
        status_json(true, Some(2), true, true),
    ] {
        let honesty = status["keychain"]["honesty"].as_str().expect("keychain.honesty is a string");
        assert_eq!(honesty, KEYCHAIN_HONESTY, "keychain honesty must ride verbatim");
    }
}

#[test]
fn status_json_keychain_flags_shape() {
    let off = status_json(true, None, false, false);
    assert_eq!(off["keychain"]["available"], false);
    assert_eq!(off["keychain"]["enrolled"], false);

    let available_not_enrolled = status_json(true, None, true, false);
    assert_eq!(available_not_enrolled["keychain"]["available"], true);
    assert_eq!(available_not_enrolled["keychain"]["enrolled"], false);

    let enrolled = status_json(true, Some(1), true, true);
    assert_eq!(enrolled["keychain"]["available"], true);
    assert_eq!(enrolled["keychain"]["enrolled"], true);
}

#[test]
fn status_json_shape() {
    let locked_absent = status_json(false, None, false, false);
    assert_eq!(locked_absent["exists"], false);
    assert_eq!(locked_absent["unlocked"], false);
    assert_eq!(locked_absent["count"], 0);

    let locked_present = status_json(true, None, false, false);
    assert_eq!(locked_present["exists"], true);
    assert_eq!(locked_present["unlocked"], false);
    assert_eq!(locked_present["count"], 0);

    let unlocked = status_json(true, Some(5), false, false);
    assert_eq!(unlocked["exists"], true);
    assert_eq!(unlocked["unlocked"], true);
    assert_eq!(unlocked["count"], 5);
}

// ── vault_totp_code core: RFC 6238 vectors + fail-closed branches ───────────

/// RFC 6238 Appendix B SHA-1 seed ("12345678901234567890") in base32 — the
/// exact string an `otpauth://` issuer would hand out.
const RFC6238_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn unlocked_with(entries: &[(&str, &[u8])]) -> Option<Unlocked> {
    let mut vault = Vault::new();
    for (name, value) in entries {
        vault.put(name, value);
    }
    Some(Unlocked { vault, key: Zeroizing::new([7u8; 32]), salt: vec![1u8; 16] })
}

#[test]
fn totp_matches_rfc6238_appendix_b_at_fixed_timestamps() {
    // Appendix B publishes 8-digit codes; the command uses the ecosystem
    // default of 6 digits (`Totp::from_base32_default`), which is the same
    // 31-bit truncated value mod 10^6 — i.e. the last 6 digits of the
    // published vectors. T=59 → 94287082 → "287082"; T=1111111109 →
    // 07081804 → "081804"; T=1234567890 → 89005924 → "005924".
    let guard = unlocked_with(&[("totp/github", RFC6238_B32.as_bytes())]);

    let v = totp_code_impl(&guard, "totp/github", 59).expect("code at T=59");
    assert_eq!(v["code"], "287082");
    assert_eq!(v["period"], 30);
    assert_eq!(v["remaining_secs"], 1, "59 % 30 = 29 → 1 s left in the step");

    let v = totp_code_impl(&guard, "totp/github", 1111111109).expect("code at T=1111111109");
    assert_eq!(v["code"], "081804");
    assert_eq!(v["remaining_secs"], 1);

    let v = totp_code_impl(&guard, "totp/github", 1234567890).expect("code at T=1234567890");
    assert_eq!(v["code"], "005924");

    // Exactly on a step boundary the full period remains.
    let v = totp_code_impl(&guard, "totp/github", 60).expect("code at T=60");
    assert_eq!(v["remaining_secs"], 30);
}

#[test]
fn totp_accepts_issuer_style_base32_formatting() {
    // Lowercase + space-grouped (how issuers display secrets) must produce
    // the same code as the canonical form.
    let guard = unlocked_with(&[("grouped", b"gezd gnbv gy3t qojq gezd gnbv gy3t qojq")]);
    let v = totp_code_impl(&guard, "grouped", 59).expect("normalized base32");
    assert_eq!(v["code"], "287082");
}

#[test]
fn totp_locked_vault_errors_never_a_code() {
    let guard: Option<Unlocked> = None;
    let err = totp_code_impl(&guard, "totp/github", 59).unwrap_err();
    assert!(err.contains("locked"), "unexpected error: {err}");
}

#[test]
fn totp_missing_entry_errors_never_a_code() {
    let guard = unlocked_with(&[("totp/github", RFC6238_B32.as_bytes())]);
    let err = totp_code_impl(&guard, "totp/gitlab", 59).unwrap_err();
    assert!(err.contains("no secret"), "unexpected error: {err}");
}

// ── keychain cores (opt-in `vault-keychain` feature) ────────────────────────
//
// Driven entirely through postern-vault's RAM-only InMemoryKeyStore via the
// `&mut dyn KeyStore` seam — no OS keychain (macOS Keychain / Secret Service)
// is touched, so these run headless in CI. The live MacKeyStore round-trip
// stays #[ignore]d inside postern-vault itself. HONESTY: what these prove is
// the WIRING, not hardware protection — keychain unlock is a SOFTWARE
// convenience (see KEYCHAIN_HONESTY, asserted verbatim above).

#[cfg(feature = "vault-keychain")]
mod keychain_cores {
    use super::*;
    use bloch_desktop::vault::{
        keychain_enable_impl, keychain_forget_impl, unlock_keychain_impl,
        unlock_prefer_keychain_impl, KEYCHAIN_ACCOUNT,
    };
    use postern_vault::keychain::{InMemoryKeyStore, KeyStore};

    /// A sealed one-entry vault plus its unlocked guard, under a fixed key —
    /// the state `vault_keychain_enable` sees in the live app.
    fn unlocked_sealed(key: [u8; 32]) -> (Vec<u8>, Vec<u8>, Option<Unlocked>) {
        let salt = vec![5u8; 16];
        let mut vault = Vault::new();
        vault.put("email", b"alice@example.com");
        let sealed = vault.seal(&key).expect("seal");
        let guard = Some(Unlocked { vault, key: Zeroizing::new(key), salt: salt.clone() });
        (salt, sealed, guard)
    }

    #[test]
    fn enable_lock_unlock_via_keychain_round_trip() {
        let key = [7u8; 32];
        let (salt, sealed, guard) = unlocked_sealed(key);
        let mut store = InMemoryKeyStore::new();

        // Enable while unlocked: the live key lands in the store.
        keychain_enable_impl(&guard, &mut store, KEYCHAIN_ACCOUNT).expect("enable");
        assert_eq!(store.retrieve(KEYCHAIN_ACCOUNT).unwrap().map(|k| *k), Some(key));

        // Lock (evict the unlocked state), then unlock with NO passphrase.
        drop(guard);
        let reopened =
            unlock_keychain_impl(&mut store, KEYCHAIN_ACCOUNT, &salt, &sealed).expect("keychain unlock");
        assert_eq!(reopened.vault.get("email"), Some(&b"alice@example.com"[..]));
        assert_eq!(*reopened.key, key, "the enrolled key, not a derived one");
        assert_eq!(reopened.salt, salt);
    }

    #[test]
    fn enable_on_a_locked_vault_fails_closed() {
        // No key in RAM → nothing to enroll; must never derive or invent one.
        let guard: Option<Unlocked> = None;
        let mut store = InMemoryKeyStore::new();
        let err = keychain_enable_impl(&guard, &mut store, KEYCHAIN_ACCOUNT).unwrap_err();
        assert!(err.contains("locked"), "unexpected error: {err}");
        assert!(store.retrieve(KEYCHAIN_ACCOUNT).unwrap().is_none(), "nothing may be stored");
    }

    #[test]
    fn forget_makes_keychain_unlock_fail_closed() {
        let key = [9u8; 32];
        let (salt, sealed, guard) = unlocked_sealed(key);
        let mut store = InMemoryKeyStore::new();
        keychain_enable_impl(&guard, &mut store, KEYCHAIN_ACCOUNT).expect("enable");

        assert!(keychain_forget_impl(&mut store, KEYCHAIN_ACCOUNT).expect("forget"), "was enrolled");
        // NOTE: `.unwrap_err()` would require `Debug` on `Unlocked`, which
        // deliberately has no Debug impl (it holds the live vault key) —
        // match the Err out instead.
        let err = match unlock_keychain_impl(&mut store, KEYCHAIN_ACCOUNT, &salt, &sealed) {
            Ok(_) => panic!("unlock after forget must fail closed"),
            Err(e) => e,
        };
        assert!(err.contains("no vault key is enrolled"), "unexpected error: {err}");
        // Forget is idempotent: a second forget is a clean `false`, not an error.
        assert!(!keychain_forget_impl(&mut store, KEYCHAIN_ACCOUNT).expect("forget again"));
    }

    #[test]
    fn passphrase_unlock_prefers_the_enrolled_key_over_re_deriving() {
        // The wired `vault_unlock` path (unlock_prefer_keychain_impl →
        // unwrap_or_derive → the OS KeyStore): when a key is enrolled, the
        // master key is OS-keychain-WRAPPED and used directly — Argon2id is
        // NOT re-run. Proven by handing a passphrase/salt that could never
        // derive the enrolled key: if the store were ignored and the KDF
        // fired, the wrong key would fail to open the vault.
        let key = [7u8; 32];
        let (salt, sealed, _guard) = unlocked_sealed(key);
        let mut store = InMemoryKeyStore::new();
        store.store(KEYCHAIN_ACCOUNT, &key).unwrap();

        let unlocked = unlock_prefer_keychain_impl(
            &store,
            KEYCHAIN_ACCOUNT,
            b"a passphrase that would derive a DIFFERENT key",
            &salt,
            &sealed,
        )
        .expect("stored key must be preferred and open the vault");
        assert_eq!(*unlocked.key, key, "the enrolled (wrapped) key, not a derived one");
        assert_eq!(unlocked.vault.get("email"), Some(&b"alice@example.com"[..]));
    }

    #[test]
    fn passphrase_unlock_falls_back_to_derive_when_store_is_empty() {
        // No enrolled key: unwrap_or_derive must fall back to the Argon2id
        // passphrase KDF. The vault here is sealed under a key DERIVED from a
        // known passphrase/salt, so the fallback derive reproduces it and
        // opens the file — the non-keychain path still works end to end.
        let passphrase = b"correct horse battery staple";
        let salt = b"postern-salt-16b".to_vec();
        let key = *postern_vault::derive_key(passphrase, &salt).expect("derive");
        let mut vault = Vault::new();
        vault.put("email", b"alice@example.com");
        let sealed = vault.seal(&key).expect("seal");

        let store = InMemoryKeyStore::new(); // empty — nothing enrolled
        let unlocked = unlock_prefer_keychain_impl(&store, KEYCHAIN_ACCOUNT, passphrase, &salt, &sealed)
            .expect("empty store must fall back to the passphrase KDF");
        assert_eq!(*unlocked.key, key);
        assert_eq!(unlocked.vault.get("email"), Some(&b"alice@example.com"[..]));

        // ...and a wrong passphrase with an empty store fails closed (no code,
        // no silently-empty vault).
        assert!(
            unlock_prefer_keychain_impl(&store, KEYCHAIN_ACCOUNT, b"wrong pw", &salt, &sealed).is_err(),
            "wrong passphrase with nothing enrolled must fail closed"
        );
    }

    #[test]
    fn stale_enrolled_key_fails_closed() {
        // The vault was re-created (new key) after enrollment: the stale
        // enrolled key must NOT open it — error, never a silently-empty vault.
        let (salt, sealed, _guard) = unlocked_sealed([1u8; 32]);
        let mut store = InMemoryKeyStore::new();
        store.store(KEYCHAIN_ACCOUNT, &[2u8; 32]).unwrap();
        assert!(unlock_keychain_impl(&mut store, KEYCHAIN_ACCOUNT, &salt, &sealed).is_err());
    }

    /// LIVE end-to-end: the same enable → lock → unlock → forget flow the four
    /// `vault_keychain_*` commands run, but driven against the **real macOS
    /// login Keychain** (`MacKeyStore`, the exact backend `os_keystore()` hands
    /// the live commands) instead of the RAM-only `InMemoryKeyStore`. This is
    /// the honest proof that the software Keychain path works on this host — it
    /// hits `SecItemAdd`/`SecItemCopyMatching`/`SecItemDelete` for real, so it
    /// is `#[ignore]`d (needs an unlocked, interactive login session — not
    /// headless CI). Run manually:
    /// `cargo test -p bloch-desktop --features vault-keychain -- --ignored`
    ///
    /// HONESTY: this proves the WIRING, not hardware protection. The status the
    /// UI would see still carries the mandatory "not a TEE until real hardware"
    /// disclosure ([`HONESTY`]) and the "SOFTWARE convenience, not hardware
    /// protection" keychain disclosure ([`KEYCHAIN_HONESTY`]) — both asserted
    /// below on the very status a keychain unlock produces.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a real, unlocked, interactive macOS login keychain — not available in headless CI"]
    fn live_macos_keychain_command_core_round_trip() {
        use bloch_desktop::vault::{status_json, HONESTY, KEYCHAIN_HONESTY};
        use postern_vault::keychain_macos::MacKeyStore;

        // A distinct account so this live test never collides with the app's
        // real enrolled key on the developer's machine.
        const TEST_ACCOUNT: &str = "bloch-desktop-vault-live-test";

        let key = [0x42u8; 32];
        let (salt, sealed, guard) = unlocked_sealed(key);
        let mut store = MacKeyStore::new();

        // Clean slate in case a crashed prior run left an entry behind.
        let _ = store.delete(TEST_ACCOUNT);

        // ── vault_keychain_enable: the live key lands in the real Keychain. ──
        keychain_enable_impl(&guard, &mut store, TEST_ACCOUNT).expect("enable");
        assert!(
            matches!(store.retrieve(TEST_ACCOUNT), Ok(Some(_))),
            "the key must now be enrolled in the real login Keychain"
        );

        // The status the live `vault_keychain_enable` returns — enrolled and
        // available — must STILL carry both honesty disclosures verbatim.
        let enrolled_status =
            status_json(true, guard.as_ref().map(|u| u.vault.names().len()), true, true);
        assert_eq!(enrolled_status["keychain"]["available"], true);
        assert_eq!(enrolled_status["keychain"]["enrolled"], true);
        let honesty = enrolled_status["honesty"].as_str().expect("honesty field");
        assert!(
            honesty.contains("not a TEE until real hardware"),
            "the vault_status honesty field must assert 'not a TEE until real hardware', got: {honesty}"
        );
        assert_eq!(honesty, HONESTY);
        assert_eq!(enrolled_status["keychain"]["honesty"], KEYCHAIN_HONESTY);

        // ── lock: evict the unlocked state; only ciphertext + the
        //    Keychain-held key remain. ──
        drop(guard);

        // ── vault_unlock_keychain: no passphrase, key fetched from the real
        //    Keychain and used directly to re-open the sealed vault. ──
        let reopened = unlock_keychain_impl(&mut store, TEST_ACCOUNT, &salt, &sealed)
            .expect("keychain unlock via the real login Keychain");
        assert_eq!(
            reopened.vault.get("email"),
            Some(&b"alice@example.com"[..]),
            "the secret must survive enable → real Keychain → unlock byte-for-byte"
        );
        assert_eq!(*reopened.key, key, "the enrolled key, not a derived one");
        assert_eq!(reopened.salt, salt);

        // ── vault_keychain_forget: delete the enrolled key; the passphrase-less
        //    path is now fail-closed, and forget is idempotent. ──
        assert!(keychain_forget_impl(&mut store, TEST_ACCOUNT).expect("forget"), "was enrolled");
        match unlock_keychain_impl(&mut store, TEST_ACCOUNT, &salt, &sealed) {
            Ok(_) => panic!("unlock after forget must fail closed"),
            Err(e) => assert!(e.contains("no vault key is enrolled"), "unexpected error: {e}"),
        }
        assert!(
            !keychain_forget_impl(&mut store, TEST_ACCOUNT).expect("forget again"),
            "forget is idempotent"
        );
    }
}

#[test]
fn totp_malformed_secret_errors_never_a_fake_code() {
    let guard = unlocked_with(&[
        ("bad/base32", b"not!valid@base32#1808".as_slice()), // invalid alphabet
        ("bad/empty", b"".as_slice()),                       // empty seed
        ("bad/utf8", &[0xFF, 0xFE, 0x00, 0x80][..]),         // not even UTF-8
    ]);
    for name in ["bad/base32", "bad/empty", "bad/utf8"] {
        let res = totp_code_impl(&guard, name, 59);
        assert!(res.is_err(), "'{name}' must fail closed, got: {res:?}");
    }
}
