//! Offline generator for the `postern-seal-verify-mobile` acceptance vectors.
//!
//! SYNTHETIC, offline, `vector-tested ≠ attested`: this builds a real
//! ECDSA-P256 `leaf(+Key-Attestation ext) ← intermediate ← self-signed root`
//! chain with `rcgen` (the crate's existing test-cert pattern, a dev-dependency)
//! and writes each cert DER to `testdata/mobile/`. NO real StrongBox produced
//! these certs — they exist only so the CLI's chain-parse + signature-verify +
//! pinned-root-anchor path can be exercised end to end without Android hardware,
//! matching the crate's offline-verify discipline (`tdx`/`snp` synth vectors).
//!
//! The embedded KeyDescription is the module's checked-in golden fixture
//! (`mobile.rs`'s `GOLDEN_KD_DER`): StrongBox, verified-boot + device-locked,
//! OS patch 202401, package `labs.postern.wallet`, signing digest `[0x11; 32]`,
//! attestation challenge (nonce) `A1B2C3D4`.
//!
//! Run:  cargo run -p postern-seal-companion --features mobile-attest \
//!           --example gen_mobile_attest_vectors
//!
//! Emits, under `crates/postern-seal-companion/testdata/mobile/`:
//!   leaf.der, intermediate.der, root.der   — the genuine leaf-first chain
//!   wrong_root.der                         — an UNRELATED self-signed root
//!   leaf_tampered.der                      — leaf.der with one signature byte flipped

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::path::PathBuf;

/// DER OID arcs of `1.3.6.1.4.1.11129.2.1.17` (Android Key Attestation).
const ATT_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

/// The module's golden KeyDescription (see `mobile.rs`
/// `golden_der_wire_fixture_locks_the_a_to_c_contract`): nonce A1B2C3D4,
/// StrongBox(2), verified(0)+locked, patch 202401, package labs.postern.wallet,
/// signing digest [0x11; 32].
#[rustfmt::skip]
const GOLDEN_KD_DER: &[u8] = &[
    0x30, 0x81, 0xBA, 0x02, 0x02, 0x00, 0xC8, 0x0A, 0x01, 0x02, 0x02, 0x01, 0x04, 0x0A, 0x01, 0x02,
    0x04, 0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0x04, 0x00, 0x30, 0x48, 0xBF, 0x85, 0x45, 0x44, 0x04, 0x42,
    0x30, 0x40, 0x31, 0x1A, 0x30, 0x18, 0x04, 0x13, 0x6C, 0x61, 0x62, 0x73, 0x2E, 0x70, 0x6F, 0x73,
    0x74, 0x65, 0x72, 0x6E, 0x2E, 0x77, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x02, 0x01, 0x01, 0x31, 0x22,
    0x04, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x30, 0x59, 0xBF, 0x85, 0x40, 0x4C, 0x30, 0x4A, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xFF, 0x0A,
    0x01, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xBF, 0x85, 0x42, 0x05, 0x02, 0x03, 0x03, 0x16, 0xA1,
];

fn ca_root(name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(vec![name.into()]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = p.self_signed(&key).unwrap();
    (cert, key)
}

fn main() {
    // testdata/mobile/ relative to this crate.
    let out_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "testdata", "mobile"].iter().collect();
    std::fs::create_dir_all(&out_dir).expect("create testdata/mobile");

    // Genuine chain: root ← intermediate ← leaf(+Key-Attestation ext).
    let (root, root_key) = ca_root("Postern Test Attestation Root");

    let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ip = CertificateParams::new(vec!["Postern Test Attestation Intermediate".into()]).unwrap();
    ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ip.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let inter = ip.signed_by(&inter_key, &root, &root_key).unwrap();

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut lp = CertificateParams::new(vec!["Android Keystore Attested Key".into()]).unwrap();
    lp.custom_extensions
        .push(CustomExtension::from_oid_content(ATT_OID_ARCS, GOLDEN_KD_DER.to_vec()));
    let leaf = lp.signed_by(&leaf_key, &inter, &inter_key).unwrap();

    let leaf_der = leaf.der().as_ref().to_vec();
    let inter_der = inter.der().as_ref().to_vec();
    let root_der = root.der().as_ref().to_vec();

    // An UNRELATED self-signed root — pinning against it must REJECT the genuine
    // chain (trust-anchor mismatch): the wire can never supply its own anchor.
    let (wrong_root, _wrong_key) = ca_root("Unrelated Attestation Root (wrong pin)");
    let wrong_root_der = wrong_root.der().as_ref().to_vec();

    // A tampered leaf: flip the final signature byte so the chain-link check
    // fails. (The signature sits at the tail of the cert DER.)
    let mut leaf_tampered = leaf_der.clone();
    let last = leaf_tampered.len() - 1;
    leaf_tampered[last] ^= 0x01;

    // A genuinely EXPIRED leaf (validity 2020-09-13 .. 2021-09-13), otherwise a
    // real, correctly-anchored chain member. Run the CLI with `--now` after its
    // not_after to see the named certificate-validity rejection.
    let leaf_exp_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ep = CertificateParams::new(vec!["Android Keystore Attested Key (expired)".into()]).unwrap();
    ep.not_before = rcgen::date_time_ymd(2020, 9, 13);
    ep.not_after = rcgen::date_time_ymd(2021, 9, 13);
    ep.custom_extensions
        .push(CustomExtension::from_oid_content(ATT_OID_ARCS, GOLDEN_KD_DER.to_vec()));
    let leaf_expired = ep.signed_by(&leaf_exp_key, &inter, &inter_key).unwrap();
    let leaf_expired_der = leaf_expired.der().as_ref().to_vec();

    let write = |name: &str, bytes: &[u8]| {
        let path = out_dir.join(name);
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    };

    write("leaf.der", &leaf_der);
    write("intermediate.der", &inter_der);
    write("root.der", &root_der);
    write("wrong_root.der", &wrong_root_der);
    write("leaf_tampered.der", &leaf_tampered);
    write("leaf_expired.der", &leaf_expired_der);

    println!(
        "\nSYNTHETIC offline vectors written (vector-tested != attested). Nonce A1B2C3D4; \
         StrongBox; verified-boot + device-locked; OS patch 202401; app labs.postern.wallet; \
         signing digest 1111...11 (32 bytes)."
    );
}
