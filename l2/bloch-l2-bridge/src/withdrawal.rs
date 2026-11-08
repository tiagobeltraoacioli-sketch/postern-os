// SPDX-License-Identifier: MIT OR Apache-2.0
//! Withdrawal messages — the leaves of the depth-32 withdrawal tree.
//!
//! Per BLOCH-L2-EVM-DESIGN §5, the L2BlochBridge predeploy (0x42..0010)
//! emits `WithdrawalInitiated(uint64 nonce, address l2Sender,
//! bytes20 l1Recipient, uint64 amountAtoms)` and appends
//!
//! ```text
//! leaf = keccak256(abi.encode(nonce, l2Sender, l1Recipient,
//!                             amountAtoms, epochNumber))
//! ```
//!
//! to the incremental Merkle tree (see [`crate::merkle`]).
//!
//! ## Canonical ABI-style encoding (normative for this scaffold)
//!
//! `abi.encode` of `(uint64, address, bytes20, uint64, uint64)` — five
//! static types, so the encoding is exactly 5 × 32-byte words, no heads/
//! tails, in argument order:
//!
//! | word | content | padding |
//! |---|---|---|
//! | 0 | `nonce`        (uint64)  | left-padded, big-endian value in bytes 24..32 |
//! | 1 | `l2_sender`    (address) | left-padded, 20 address bytes in bytes 12..32 |
//! | 2 | `l1_recipient` (bytes20) | RIGHT-padded, 20 bytes in bytes 0..20 (Solidity `bytesN` rule) |
//! | 3 | `amount_atoms` (uint64)  | left-padded, big-endian value in bytes 24..32 |
//! | 4 | `epoch_number` (uint64)  | left-padded, big-endian value in bytes 24..32 |
//!
//! Note the mixed padding: `address` and `uintN` are left-padded, `bytesN`
//! is right-padded — this matches Solidity `abi.encode` exactly, and the
//! golden-vector test pins the byte layout so a Solidity implementation
//! and this Rust one can never drift silently.
//!
//! `amount_atoms` is in L1 atoms (the predeploy divides `msg.value` by
//! `ATOM_SCALE` after the `% ATOM_SCALE == 0` check — see [`crate::atoms`]).
//!
//! SCAFFOLD, UNAUDITED: encoding + hashing only; nothing here moves value.

use crate::merkle::{keccak256, TREE_DEPTH};

/// Length of the canonical ABI-style encoding: five 32-byte words.
pub const ENCODED_LEN: usize = 5 * 32;

/// The all-zero hash — the sentinel for an UNANCHORED / uninitialised
/// withdrawal root. No real withdrawal tree can ever fold to it: the empty
/// tree's root is the depth-32 zero *cascade* `Z[32]` (a keccak output),
/// not `0x00…00`. The release path MUST refuse it outright — a zero root
/// means "no epoch anchored yet", so checking a proof against it could only
/// be a bug or an attack. This is the withdrawal-side twin of the harness
/// all-zero placeholder guard, and it stays as the honesty invariant.
pub const UNANCHORED_ROOT: [u8; 32] = [0u8; 32];

/// Three-way outcome of checking a withdrawal message for membership under
/// an anchored withdrawal root. Distinct from a bare `bool` so the
/// unanchored-root guard is a NON-SILENT, separately-observable result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalInclusion {
    /// The message's leaf verifies under `root` at `index`.
    Included,
    /// The proof does not reconstruct `root` (tampered leaf, sibling,
    /// index, or root — or simply not a member).
    NotIncluded,
    /// `root` is the all-zero unanchored sentinel: refused outright, never
    /// checked (see [`UNANCHORED_ROOT`]).
    UnanchoredRoot,
}

impl WithdrawalInclusion {
    /// True only for [`WithdrawalInclusion::Included`].
    pub fn is_included(&self) -> bool {
        matches!(self, WithdrawalInclusion::Included)
    }
}

/// One L2 → L1 withdrawal message (a tree leaf, pre-hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalMessage {
    /// Strictly-increasing per-bridge nonce (uint64 in the event).
    pub nonce: u64,
    /// The L2 EVM address that called `withdraw()`.
    pub l2_sender: [u8; 20],
    /// The Bloch L1 recipient: the raw 20-byte key hash
    /// (`SHA3-256(pubkey)[..20]`, the node's own address form) — carried
    /// as `bytes20`, NOT an EVM address.
    pub l1_recipient: [u8; 20],
    /// Withdrawal amount in L1 atoms (post `ATOM_SCALE` division).
    pub amount_atoms: u64,
    /// The L2 epoch in which the withdrawal was initiated.
    pub epoch_number: u64,
}

impl WithdrawalMessage {
    /// Canonical ABI-style encoding (see module docs). 160 bytes.
    pub fn abi_encode(&self) -> [u8; ENCODED_LEN] {
        let mut out = [0u8; ENCODED_LEN];
        // word 0: uint64 nonce, left-padded big-endian
        out[24..32].copy_from_slice(&self.nonce.to_be_bytes());
        // word 1: address l2_sender, left-padded
        out[44..64].copy_from_slice(&self.l2_sender);
        // word 2: bytes20 l1_recipient, RIGHT-padded
        out[64..84].copy_from_slice(&self.l1_recipient);
        // word 3: uint64 amount_atoms, left-padded big-endian
        out[120..128].copy_from_slice(&self.amount_atoms.to_be_bytes());
        // word 4: uint64 epoch_number, left-padded big-endian
        out[152..160].copy_from_slice(&self.epoch_number.to_be_bytes());
        out
    }

    /// The tree leaf: `keccak256(abi_encode(self))`.
    pub fn leaf(&self) -> [u8; 32] {
        keccak256(&self.abi_encode())
    }

    /// Verify this message's membership in the withdrawal tree whose root is
    /// `root`, using sibling `branch` for `index`. The unanchored-root guard
    /// runs FIRST — an all-zero `root` is refused and the inclusion check is
    /// never even run — then the depth-32 walk over `self.leaf()` decides
    /// membership. This is the message-level check a release-agent performs
    /// (item [3] of the §5 release checklist); it never moves value.
    pub fn verify_inclusion(
        &self,
        index: u64,
        branch: &[[u8; 32]; TREE_DEPTH],
        root: &[u8; 32],
    ) -> WithdrawalInclusion {
        if *root == UNANCHORED_ROOT {
            return WithdrawalInclusion::UnanchoredRoot;
        }
        if crate::merkle::verify_inclusion(&self.leaf(), index, branch, root) {
            WithdrawalInclusion::Included
        } else {
            WithdrawalInclusion::NotIncluded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WithdrawalMessage {
        WithdrawalMessage {
            nonce: 7,
            l2_sender: [0xaa; 20],
            l1_recipient: [0xbb; 20],
            amount_atoms: 100_000_000, // 1 BLCH
            epoch_number: 42,
        }
    }

    #[test]
    fn golden_encoding_vector() {
        // Pins the exact 160-byte layout (word boundaries + padding sides)
        // so Solidity abi.encode and this encoder cannot drift silently.
        let expected = concat!(
            // word 0: uint64 nonce = 7, left-padded
            "0000000000000000000000000000000000000000000000000000000000000007",
            // word 1: address 0xaa…aa, left-padded
            "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // word 2: bytes20 0xbb…bb, RIGHT-padded
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000000000000",
            // word 3: uint64 amount_atoms = 100_000_000 = 0x05f5e100
            "0000000000000000000000000000000000000000000000000000000005f5e100",
            // word 4: uint64 epoch_number = 42 = 0x2a
            "000000000000000000000000000000000000000000000000000000000000002a",
        );
        assert_eq!(crate::hex::encode(&sample().abi_encode()), expected);
    }

    #[test]
    fn leaf_is_keccak_of_encoding() {
        let m = sample();
        assert_eq!(m.leaf(), keccak256(&m.abi_encode()));
        // deterministic
        assert_eq!(m.leaf(), sample().leaf());
    }

    #[test]
    fn every_field_affects_the_leaf() {
        let base = sample();
        let variants = [
            WithdrawalMessage { nonce: 8, ..base },
            WithdrawalMessage {
                l2_sender: [0xac; 20],
                ..base
            },
            WithdrawalMessage {
                l1_recipient: [0xbc; 20],
                ..base
            },
            WithdrawalMessage {
                amount_atoms: 100_000_001,
                ..base
            },
            WithdrawalMessage {
                epoch_number: 43,
                ..base
            },
        ];
        for v in variants {
            assert_ne!(v.leaf(), base.leaf(), "changed field must change leaf: {v:?}");
        }
    }

    #[test]
    fn address_and_bytes20_words_are_not_interchangeable() {
        // The padding sides differ, so swapping the two 20-byte fields
        // must NOT produce the same encoding (guards against a naive
        // both-left-padded implementation).
        let m = WithdrawalMessage {
            nonce: 0,
            l2_sender: [0x11; 20],
            l1_recipient: [0x11; 20],
            amount_atoms: 0,
            epoch_number: 0,
        };
        let enc = m.abi_encode();
        // word 1 (address): zeros then 0x11s; word 2 (bytes20): 0x11s then zeros
        assert_eq!(&enc[32..44], &[0u8; 12]);
        assert_eq!(&enc[44..64], &[0x11u8; 20]);
        assert_eq!(&enc[64..84], &[0x11u8; 20]);
        assert_eq!(&enc[84..96], &[0u8; 12]);
        assert_ne!(&enc[32..64], &enc[64..96]);
    }

    #[test]
    fn withdrawal_leaves_insert_and_prove_in_the_tree() {
        // End-to-end shape: messages -> leaves -> tree -> proof -> verify.
        use crate::merkle::{verify_inclusion, IncrementalMerkleTree, ReferenceTree};
        let msgs: Vec<WithdrawalMessage> = (0..4u64)
            .map(|i| WithdrawalMessage {
                nonce: i,
                epoch_number: 42,
                ..sample()
            })
            .collect();
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        for m in &msgs {
            inc.insert(m.leaf()).unwrap();
            reference.push(m.leaf());
        }
        let root = inc.root();
        for (i, m) in msgs.iter().enumerate() {
            let branch = reference.proof(i as u64).unwrap();
            assert!(verify_inclusion(&m.leaf(), i as u64, &branch, &root));
        }
        // a message that was never withdrawn does not verify
        let ghost = WithdrawalMessage {
            nonce: 99,
            ..sample()
        };
        let branch = reference.proof(0).unwrap();
        assert!(!verify_inclusion(&ghost.leaf(), 0, &branch, &root));
    }

    // ---- message-level verify_inclusion + unanchored-root guard ----

    use crate::merkle::{zero_hashes, IncrementalMerkleTree, ReferenceTree, TREE_DEPTH};

    /// Build a small withdrawal tree of `n` messages and return
    /// `(messages, root)` plus a proof generator over the reference tree.
    fn tree_of(n: u64) -> (Vec<WithdrawalMessage>, [u8; 32], ReferenceTree) {
        let msgs: Vec<WithdrawalMessage> = (0..n)
            .map(|i| WithdrawalMessage {
                nonce: i,
                ..sample()
            })
            .collect();
        let mut inc = IncrementalMerkleTree::new();
        let mut reference = ReferenceTree::new();
        for m in &msgs {
            inc.insert(m.leaf()).unwrap();
            reference.push(m.leaf());
        }
        (msgs, inc.root(), reference)
    }

    #[test]
    fn verify_inclusion_accepts_valid_proof() {
        let (msgs, root, reference) = tree_of(5);
        for (i, m) in msgs.iter().enumerate() {
            let branch = reference.proof(i as u64).unwrap();
            assert_eq!(
                m.verify_inclusion(i as u64, &branch, &root),
                WithdrawalInclusion::Included
            );
            assert!(m
                .verify_inclusion(i as u64, &branch, &root)
                .is_included());
        }
    }

    #[test]
    fn verify_inclusion_rejects_tampering() {
        let (msgs, root, reference) = tree_of(5);
        let m = &msgs[2];
        let branch = reference.proof(2).unwrap();
        // baseline
        assert_eq!(
            m.verify_inclusion(2, &branch, &root),
            WithdrawalInclusion::Included
        );

        // tampered leaf (a different message's leaf under the same proof)
        let forged = WithdrawalMessage {
            amount_atoms: m.amount_atoms + 1,
            ..*m
        };
        assert_eq!(
            forged.verify_inclusion(2, &branch, &root),
            WithdrawalInclusion::NotIncluded
        );

        // tampered sibling
        let mut bad_branch = branch;
        bad_branch[0][0] ^= 0x01;
        assert_eq!(
            m.verify_inclusion(2, &bad_branch, &root),
            WithdrawalInclusion::NotIncluded
        );

        // wrong index
        assert_eq!(
            m.verify_inclusion(3, &branch, &root),
            WithdrawalInclusion::NotIncluded
        );

        // tampered root (a real, non-zero but wrong root)
        let mut bad_root = root;
        bad_root[7] ^= 0xff;
        assert_eq!(
            m.verify_inclusion(2, &branch, &bad_root),
            WithdrawalInclusion::NotIncluded
        );
    }

    #[test]
    fn all_zero_root_is_refused_not_checked() {
        // The all-zero root is the unanchored sentinel: refused outright,
        // for ANY leaf/index/branch — even ones that would "verify" if the
        // check were run. It is a DISTINCT outcome from NotIncluded.
        let (msgs, _root, reference) = tree_of(3);
        let m = &msgs[0];
        let branch = reference.proof(0).unwrap();
        assert_eq!(
            m.verify_inclusion(0, &branch, &UNANCHORED_ROOT),
            WithdrawalInclusion::UnanchoredRoot
        );
        // even a zeroed leaf + zeroed branch (the closest thing to matching
        // a zero root) is still refused, never accepted.
        let zero_msg = WithdrawalMessage {
            nonce: 0,
            l2_sender: [0; 20],
            l1_recipient: [0; 20],
            amount_atoms: 0,
            epoch_number: 0,
        };
        let zero_branch = [[0u8; 32]; TREE_DEPTH];
        assert_eq!(
            zero_msg.verify_inclusion(0, &zero_branch, &UNANCHORED_ROOT),
            WithdrawalInclusion::UnanchoredRoot
        );
    }

    #[test]
    fn empty_tree_root_is_distinct_from_unanchored_root() {
        // Per spec: the empty tree's root is the depth-32 zero cascade Z[32],
        // NOT the all-zero sentinel. A message checked against the empty root
        // is genuinely NotIncluded (the check runs), never UnanchoredRoot.
        let empty_root = IncrementalMerkleTree::new().root();
        assert_ne!(empty_root, UNANCHORED_ROOT);
        assert_eq!(empty_root, zero_hashes()[TREE_DEPTH]);

        let m = sample();
        let branch = [[0u8; 32]; TREE_DEPTH];
        assert_eq!(
            m.verify_inclusion(0, &branch, &empty_root),
            WithdrawalInclusion::NotIncluded
        );
    }
}
