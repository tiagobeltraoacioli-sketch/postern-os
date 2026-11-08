// SPDX-License-Identifier: MIT OR Apache-2.0
//! Honest stubs for the large integrations this scaffold does NOT contain.
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** Every function here panics with
//! `todo!()`/`unimplemented!()`. They exist to pin the intended surface from
//! BLOCH-L2-EVM-DESIGN §1 and to make it impossible to mistake this crate for
//! a node, an RPC server, a mempool, or a prover.

/// `eth_*` JSON-RPC — **STUBBED**.
///
/// The design mandates Reth's jsonrpsee RPC stack (eth_chainId, eth_call,
/// eth_sendRawTransaction, eth_getProof, eth_subscribe, ... — the full list
/// in §1 "Interfaces") so the surface is Reth's, not hand-rolled. None of it
/// exists here.
pub mod rpc {
    /// Start the JSON-RPC server.
    ///
    /// SCAFFOLD: the real implementation embeds reth-rpc; hand-rolling eth_*
    /// is exactly the compatibility bug-farm the design rejects.
    pub fn serve_eth_rpc() -> ! {
        // SCAFFOLD: Reth-SDK jsonrpsee eth_* stack, not hand-rolled RPC.
        unimplemented!("SCAFFOLD: eth_* JSON-RPC is provided by the Reth-SDK node embedding, not this scaffold")
    }

    /// The `bloch_anchorStatus` extension namespace (never `eth_*`).
    ///
    /// SCAFFOLD: reports honest finality state (anchored?, Bloch txid/height,
    /// confirmations, proofVerified) once the anchor reader exists.
    pub fn bloch_anchor_status() -> ! {
        // SCAFFOLD: needs the L2V0 anchor reader (sibling crate in the design).
        unimplemented!("SCAFFOLD: bloch_anchorStatus requires the L2V0 anchor layer")
    }
}

/// Transaction pool — **STUBBED**.
///
/// The design uses Reth's mainnet-grade txpool. This scaffold executes
/// pre-ordered `TxEnv`s only; there is no mempool, no gossip, no replacement
/// rules, no signature recovery.
pub mod txpool {
    /// Submit a raw RLP transaction to the pool.
    pub fn submit_raw_transaction(_rlp_bytes: &[u8]) -> ! {
        // SCAFFOLD: Reth txpool (validation, ordering, replacement, gossip).
        todo!("SCAFFOLD: txpool is Reth's, embedded via the node builder; not implemented here")
    }
}

/// Reth-SDK node embedding — **STUBBED**.
///
/// The design's NATIVE target is a Reth-SDK node (reth-node-builder with a
/// single-sequencer consensus stub, custom ChainSpec, reth-rpc, revm as the
/// executor — the op-reth pattern). That is a multi-month integration and a
/// heavy dependency; it is deliberately absent from this scaffold.
pub mod node {
    /// Build and launch the L2 full node / sequencer.
    pub fn launch_reth_node() -> ! {
        // SCAFFOLD: reth-node-builder embedding (consensus stub, txpool, RPC,
        // engine); this crate is only the STF core that node would call.
        todo!("SCAFFOLD: Reth-SDK node embedding is not part of this scaffold")
    }
}

/// SP1 guest (riscv32im) build target — **STUBBED**.
///
/// The design's GUEST target compiles this same execution logic for
/// riscv32im/no_std inside an SP1 program (the RSP pattern): verify an
/// ExecutionWitness against the pre-state root, re-execute with the SAME
/// pinned revm, commit public values, prove with FRI core proofs only (no
/// Groth16/Plonk wrap — the repo's post-quantum rule). No `#![no_std]`
/// support, no witness types, and no guest crate exist here.
pub mod sp1_guest {
    /// Re-execute a batch inside the zkVM guest.
    pub fn guest_main() -> ! {
        // SCAFFOLD: sp1_zkvm entrypoint + ExecutionWitness verification +
        // byte-identical revm re-execution (riscv32im build target).
        todo!("SCAFFOLD: the SP1 guest (riscv32im) target is not implemented in this scaffold")
    }

    /// Generate the host-side ExecutionWitness (touched MPT nodes, bytecodes,
    /// ancestor headers) for stateless guest re-execution.
    pub fn generate_execution_witness() -> ! {
        // SCAFFOLD: RSP-style witness recording requires the MPT layer
        // (crate::stateroot), itself stubbed.
        todo!("SCAFFOLD: ExecutionWitness generation requires the keccak-MPT state layer")
    }
}
