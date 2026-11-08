// SPDX-License-Identifier: MIT OR Apache-2.0
//! Print the conformance vector table, or (`--emit`) regenerate the pinned
//! tuples for pasting into `PINNED` in `src/lib.rs`.
//!
//! ```text
//! cargo run --bin dump-vectors            # human table + PASS/FAIL vs PINNED
//! cargo run --bin dump-vectors -- --emit  # Rust tuples to paste into PINNED
//! ```
//!
//! SCAFFOLD/UNAUDITED — these vectors pin a REFERENCE protocol. No key material
//! appears in any vector.

use postern_signer_conformance::{computed, pinned};

fn main() {
    let emit = std::env::args().any(|a| a == "--emit");
    let vectors = computed();

    if emit {
        // Emit the pinned tuples between the sentinel comments in lib.rs.
        println!("    // @@PINNED_START@@ (regenerate with `cargo run --bin dump-vectors -- --emit`)");
        for v in &vectors {
            println!("    ({:?}, {:?}),", v.name, v.value);
        }
        println!("    // @@PINNED_END@@");
        return;
    }

    println!("Postern phone-as-signer — CONFORMANCE VECTORS (scaffold, unaudited)");
    println!("Each value is recomputed from the crates' public APIs.\n");

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut unpinned = 0usize;
    for v in &vectors {
        let status = match pinned(v.name) {
            Some(p) if p == v.value => {
                pass += 1;
                "  OK "
            }
            Some(_) => {
                fail += 1;
                "DRIFT"
            }
            None => {
                unpinned += 1;
                " NEW "
            }
        };
        println!("[{status}] {}", v.name);
        println!("        note:  {}", v.note);
        println!("        value: {}", v.value);
    }

    println!(
        "\n{} vectors — {pass} pinned-OK, {fail} DRIFT, {unpinned} not-yet-pinned.",
        vectors.len()
    );
    if fail > 0 {
        eprintln!(
            "\nDRIFT: a pinned wire format changed. If intentional, bump the relevant\n\
             version and re-run with --emit; otherwise fix the crate regression."
        );
        std::process::exit(1);
    }
}
