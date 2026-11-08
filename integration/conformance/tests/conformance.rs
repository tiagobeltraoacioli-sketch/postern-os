// SPDX-License-Identifier: MIT OR Apache-2.0
//! The drift guard. `cargo test` recomputes every wire-format vector from the
//! crates and asserts it equals the pinned golden value. If a crate ever changes
//! an encoding, a digest layout, the SAS mapping, or a JSON shape, this test
//! FAILS the build — which is the point: an independent implementation pinned to
//! these vectors must never silently diverge from the reference crates.
//!
//! SCAFFOLD/UNAUDITED — pins a reference protocol; no key material is pinned.

use postern_signer_conformance::{computed, pinned, PINNED};

/// Every recomputed vector must match its pinned value exactly.
#[test]
fn computed_vectors_match_pinned() {
    let vectors = computed();
    assert!(!vectors.is_empty(), "there must be conformance vectors");

    let mut drift = Vec::new();
    let mut missing = Vec::new();
    for v in &vectors {
        match pinned(v.name) {
            Some(p) if p == v.value => {}
            Some(p) => drift.push(format!(
                "  DRIFT {}\n    pinned:   {}\n    computed: {}",
                v.name, p, v.value
            )),
            None => missing.push(format!("  MISSING pin for {} = {:?}", v.name, v.value)),
        }
    }

    if !drift.is_empty() || !missing.is_empty() {
        panic!(
            "conformance drift detected — a wire format changed or a vector is unpinned.\n\
             If intentional, bump the relevant protocol version and regenerate with\n\
             `cargo run --bin dump-vectors -- --emit`.\n\n{}\n{}",
            drift.join("\n"),
            missing.join("\n"),
        );
    }
}

/// The pinned table must have a golden entry for every computed vector and no
/// stale entries for vectors that no longer exist.
#[test]
fn pinned_table_is_in_sync_with_computed() {
    let names: Vec<&str> = computed().iter().map(|v| v.name).collect();

    for v in computed() {
        assert!(
            pinned(v.name).is_some(),
            "computed vector {:?} has no pinned entry — run dump-vectors --emit",
            v.name
        );
    }
    for (name, _) in PINNED {
        assert!(
            names.contains(name),
            "pinned entry {:?} no longer corresponds to any computed vector — remove it",
            name
        );
    }
}

/// A hard rail: no pinned vector may contain the reference scaffold SECRET, and
/// none may contain the raw seed. The scaffold secret is
/// `SHA3-256("scaffold-secret" ‖ seed)` (mirrors `ScaffoldSigner::from_seed`);
/// recompute it and assert it never appears in any vector value — belt-and-
/// suspenders on top of the crate's own structural key-material denylist.
#[test]
fn no_vector_contains_secret_or_seed() {
    use postern_signer_conformance::FIXTURE_SCAFFOLD_SEED;
    use sha3::{Digest, Sha3_256};

    let secret = {
        let mut h = Sha3_256::new();
        h.update(b"scaffold-secret");
        h.update(FIXTURE_SCAFFOLD_SEED);
        h.finalize().to_vec()
    };
    let secret_hex = hex::encode(&secret);
    let seed_hex = hex::encode(FIXTURE_SCAFFOLD_SEED);

    for v in computed() {
        assert!(
            !v.value.contains(&secret_hex),
            "vector {:?} leaks the scaffold secret",
            v.name
        );
        assert!(
            !v.value.contains(&seed_hex),
            "vector {:?} leaks the raw seed",
            v.name
        );
        // The seed is ASCII here, so also reject its literal text form.
        assert!(
            !v.value
                .contains(std::str::from_utf8(FIXTURE_SCAFFOLD_SEED).unwrap()),
            "vector {:?} leaks the seed text",
            v.name
        );
    }
}
