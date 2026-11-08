//! `MockProver` / `MockProof` — pipeline plumbing with **ZERO soundness**.
//!
//! # This is not a zk proof. It proves nothing cryptographically.
//!
//! `MockProver::prove` simply re-runs the placeholder STF natively and binds
//! the resulting public values by a plain SHAKE-256 hash. Anyone who knows
//! the public values can forge a `MockProof` in one hash call — there is no
//! witness hiding, no succinctness, no soundness, no security property of any
//! kind. It exists ONLY so the sequencer/verifier plumbing (produce publics →
//! attach "proof" → check binding) can be built and tested end-to-end before
//! the real SP1 integration (`// SCAFFOLD:`, see [`crate::sp1_stub`]) exists.
//!
//! Never describe a `MockProof` as a "validity proof" or "proof of validity"
//! without this disclaimer: **the mock proves nothing; a real FRI proof from
//! the SP1 guest is the only thing that ever could.**

use crate::hash::{shake256_32, Hash32};
use crate::public_values::BatchPublicValues;
use crate::stf::{stf, StfError};
use crate::witness::ExecutionWitness;

/// Domain for the mock binding hash.
pub const MOCK_BINDING_DOMAIN: &str = "bloch-l2/mock-proof-binding/v0";

/// A mock "proof": nothing but a hash binding to a `BatchPublicValues`
/// encoding. **Forgeable by anyone; zero soundness** (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockProof {
    /// SHAKE-256(domain ‖ canonical public-values encoding).
    pub binding: Hash32,
}

/// Why a [`MockProof`] failed to verify against expected public values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockVerifyError {
    /// The binding hash does not match the expected public values.
    BindingMismatch,
}

impl core::fmt::Display for MockVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BindingMismatch => write!(f, "mock proof does not bind these public values"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MockVerifyError {}

/// The mock prover. In the real pipeline this slot is filled by the SP1 host
/// (`ProverClient::prove(elf, stdin).core()` — raw FRI per the repo's
/// post-quantum rule; SCAFFOLD, see [`crate::sp1_stub`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct MockProver;

impl MockProver {
    /// "Prove" a batch: re-run the placeholder STF natively and bind the
    /// resulting public values by hash. Fails exactly when the STF fails —
    /// mirroring the real property that an invalid batch cannot be proven —
    /// but WITHOUT any cryptographic force behind it.
    pub fn prove(
        &self,
        witness: ExecutionWitness,
    ) -> Result<(MockProof, BatchPublicValues), StfError> {
        let publics = stf(witness)?;
        Ok((Self::bind(&publics), publics))
    }

    /// Compute the binding for some public values. Public on purpose: it
    /// makes the forgeability explicit — this is all a `MockProof` is.
    pub fn bind(publics: &BatchPublicValues) -> MockProof {
        MockProof {
            binding: shake256_32(MOCK_BINDING_DOMAIN, &publics.encode()),
        }
    }

    /// Verify that a mock proof binds the expected public values. This is a
    /// hash equality check — **not** proof verification; it detects transport
    /// corruption or disagreement about bytes, never fraud.
    pub fn verify(
        &self,
        proof: &MockProof,
        expected: &BatchPublicValues,
    ) -> Result<(), MockVerifyError> {
        if proof.binding == Self::bind(expected).binding {
            Ok(())
        } else {
            Err(MockVerifyError::BindingMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stf::{state_commitment, Account, SimpleTx, StateMap};
    use crate::witness::{BatchContext, ExecutionWitness};
    use alloc::vec;
    use alloc::vec::Vec;

    fn setup() -> ExecutionWitness {
        let alice = [1u8; 20];
        let mut state = StateMap::new();
        state.insert(alice, Account { balance: 100, nonce: 0 });
        let tx = SimpleTx { from: alice, to: [2u8; 20], value: 40, nonce: 0 };
        let leaves: Vec<Vec<u8>> = state
            .iter()
            .map(|(a, ac)| crate::stf::encode_account_leaf(a, ac).to_vec())
            .collect();
        ExecutionWitness {
            context: BatchContext {
                l2_chain_id: 700_771,
                batch_index: 3,
                prev_batch_hash: [9; 32],
                l1_origin_hash: [8; 32],
                l1_origin_height: 77,
                timestamp: 42,
            },
            pre_state_root: state_commitment(&state),
            txs: vec![tx.encode().to_vec()],
            state_witness: leaves,
            bytecodes: vec![],
            ancestor_headers: vec![],
            deposits: vec![],
        }
    }

    #[test]
    fn accepts_on_match() {
        let prover = MockProver;
        let (proof, publics) = prover.prove(setup()).unwrap();
        assert_eq!(prover.verify(&proof, &publics), Ok(()));
    }

    #[test]
    fn rejects_on_tampered_publics() {
        let prover = MockProver;
        let (proof, publics) = prover.prove(setup()).unwrap();
        // Tamper with every field class: integer, hash, root.
        let mut t1 = publics;
        t1.batch_index += 1;
        assert_eq!(prover.verify(&proof, &t1), Err(MockVerifyError::BindingMismatch));
        let mut t2 = publics;
        t2.new_state_root[31] ^= 0x01;
        assert_eq!(prover.verify(&proof, &t2), Err(MockVerifyError::BindingMismatch));
        let mut t3 = publics;
        t3.withdrawal_root[0] ^= 0x80;
        assert_eq!(prover.verify(&proof, &t3), Err(MockVerifyError::BindingMismatch));
    }

    #[test]
    fn rejects_on_tampered_proof() {
        let prover = MockProver;
        let (mut proof, publics) = prover.prove(setup()).unwrap();
        proof.binding[0] ^= 1;
        assert_eq!(
            prover.verify(&proof, &publics),
            Err(MockVerifyError::BindingMismatch)
        );
    }

    #[test]
    fn prove_fails_exactly_when_stf_fails() {
        let prover = MockProver;
        let mut w = setup();
        w.pre_state_root[0] ^= 1;
        assert!(matches!(
            prover.prove(w),
            Err(crate::stf::StfError::WitnessRootMismatch { .. })
        ));
    }

    #[test]
    fn mock_is_explicitly_forgeable() {
        // Documented anti-property: anyone can forge a binding for arbitrary
        // public values WITHOUT running the STF. This test exists so nobody
        // ever mistakes the mock for a proof system.
        let forged_publics = crate::public_values::BatchPublicValues {
            l2_chain_id: 1,
            batch_index: 999,
            prev_batch_hash: [0; 32],
            prev_state_root: [1; 32],
            new_state_root: [2; 32], // a state nobody ever computed
            batch_tx_commitment: [3; 32],
            deposit_root: [4; 32],
            l1_origin_hash: [5; 32],
            l1_origin_height: 1,
            withdrawal_root: [6; 32],
            timestamp: 0,
        };
        let forged = MockProver::bind(&forged_publics);
        assert_eq!(MockProver.verify(&forged, &forged_publics), Ok(()));
    }
}
