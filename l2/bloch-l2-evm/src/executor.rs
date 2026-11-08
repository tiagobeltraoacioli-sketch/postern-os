// SPDX-License-Identifier: MIT OR Apache-2.0
//! Block executor: UNMODIFIED revm at `SpecId::CANCUN` over [`L2State`].
//!
//! **SCAFFOLD, UNAUDITED, not a working L2.** This is the state-transition
//! core only: no consensus, no txpool, no RPC, no MPT root (all stubbed).
//! Per BLOCH-L2-EVM-DESIGN §1:
//!
//! * deposit mints (bridged BLCH only) are applied at block start;
//! * the EVM itself is unmodified revm at the pinned CANCUN hardfork;
//! * COINBASE / block beneficiary is the sequencer fee vault, so priority
//!   fees are paid there by revm's own (unmodified) beneficiary payment;
//! * the EIP-1559 basefee is NOT destroyed: it is routed to the
//!   `BaseFeeVault` as protocol-level accounting between transactions
//!   (outside EVM opcode semantics — the OP-Stack precedent). Bridged BLCH
//!   is never burned, so the L1 escrow always balances;
//! * type-3 (EIP-4844 blob) transactions are rejected at this boundary,
//!   exactly as on OP-Stack L2s.

use alloy_primitives::{Address, B256, U256};
use revm::context::result::{ExecutionResult, HaltReason};
use revm::context::TxEnv;
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};

use crate::chainspec::ChainSpec;
use crate::state::{credit_balance, DepositError, DepositMint, L2State};
use crate::stateroot::compute_keccak_mpt_state_root;

/// Per-block environment chosen by the sequencer (this scaffold has no
/// sequencer; tests supply it directly).
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// L2 block number.
    pub number: u64,
    /// Sequencer timestamp (monotonic, drift-bounded against the Bloch
    /// anchor in the full design; unchecked here).
    pub timestamp: u64,
    /// This block's EIP-1559 base fee per gas, in wei
    /// (see [`ChainSpec::next_base_fee`] for the update rule).
    pub base_fee_per_gas: u64,
    /// PREVRANDAO. In the full design this is
    /// `keccak256(parent_l2_block_hash ‖ bloch_anchor_block_hash)` and is
    /// documented as WEAK randomness, exactly as on every L2.
    pub prevrandao: B256,
}

/// Everything the executor consumes for one block.
#[derive(Debug, Clone, Default)]
pub struct BlockInput {
    /// Block environment.
    pub context: BlockContext,
    /// Deposit system-transactions, applied (minted) at block start, before
    /// any user transaction — they cannot be dropped once anchored.
    pub deposits: Vec<DepositMint>,
    /// User transactions in sequencer order. `TxEnv` is revm's transaction
    /// environment; signature recovery / RLP decoding belong to the (stubbed)
    /// node layer, not this scaffold.
    pub txs: Vec<TxEnv>,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            number: 1,
            timestamp: 0,
            base_fee_per_gas: ChainSpec::testnet().initial_base_fee,
            prevrandao: B256::ZERO,
        }
    }
}

/// Outcome of one applied transaction.
#[derive(Debug, Clone)]
pub struct TxOutcome {
    /// Whether execution succeeded (revert/halt still consume gas and pay
    /// fees; they are valid, included transactions).
    pub success: bool,
    /// Gas actually used (post-refund), as revm reports it.
    pub gas_used: u64,
    /// For CREATE transactions, the deployed contract address.
    pub created_address: Option<Address>,
    /// Raw revm execution result (logs, output, halt reason...).
    pub result: ExecutionResult<HaltReason>,
}

/// Outcome of executing one block against [`L2State`].
#[derive(Debug)]
pub struct ExecutionOutcome {
    /// The block number executed.
    pub block_number: u64,
    /// Total gas used by all transactions in the block.
    pub gas_used: u64,
    /// The base fee this block executed under.
    pub base_fee_per_gas: u64,
    /// Wei minted by deposits at block start.
    pub minted_wei: U256,
    /// Wei routed to the `BaseFeeVault` (basefee × gas, per tx). Never burned.
    pub base_fee_routed_wei: U256,
    /// Wei routed to the `SequencerFeeVault` (priority fee × gas, per tx,
    /// paid by unmodified revm to the block beneficiary).
    pub priority_fee_routed_wei: U256,
    /// Per-transaction outcomes, in block order.
    pub tx_outcomes: Vec<TxOutcome>,
    /// The keccak-256 hexary Merkle-Patricia state root over the post-execution
    /// account + storage tries (Ethereum-compatible; see [`crate::stateroot`]).
    pub state_root: alloy_primitives::B256,
}

/// Errors that abort block execution (state may be partially advanced; this
/// scaffold does not implement rollback — a real node executes into a
/// buffered `State` and discards on failure).
#[derive(Debug)]
pub enum BlockExecutionError {
    /// A deposit mint violated the exact-scaling / provenance rule.
    Deposit(DepositError),
    /// A type-3 (EIP-4844 blob) transaction was submitted; the sequencer
    /// rejects blob transactions exactly as on OP-Stack L2s.
    BlobTxRejected {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// Including this transaction would exceed the block gas limit.
    BlockGasLimitExceeded {
        /// Index of the offending transaction within the block.
        tx_index: usize,
    },
    /// revm rejected or failed the transaction pre-execution (invalid nonce,
    /// insufficient max-fee balance, chain-id mismatch, ...). Debug-printed
    /// revm error, since the concrete error type is generic over the DB.
    Evm {
        /// Index of the offending transaction within the block.
        tx_index: usize,
        /// Debug rendering of the revm error.
        detail: String,
    },
}

impl core::fmt::Display for BlockExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockExecutionError::Deposit(e) => write!(f, "deposit failed: {e}"),
            BlockExecutionError::BlobTxRejected { tx_index } => {
                write!(f, "tx {tx_index}: blob (type-3) transactions are rejected at the sequencer")
            }
            BlockExecutionError::BlockGasLimitExceeded { tx_index } => {
                write!(f, "tx {tx_index}: block gas limit exceeded")
            }
            BlockExecutionError::Evm { tx_index, detail } => {
                write!(f, "tx {tx_index}: evm error: {detail}")
            }
        }
    }
}

impl std::error::Error for BlockExecutionError {}

impl From<DepositError> for BlockExecutionError {
    fn from(e: DepositError) -> Self {
        BlockExecutionError::Deposit(e)
    }
}

/// EIP-4844 blob transaction type byte.
const BLOB_TX_TYPE: u8 = 3;

/// Execute one block: apply deposit mints, then run every transaction through
/// unmodified revm at the spec's pinned hardfork, routing fees to the vaults.
///
/// Returns the [`ExecutionOutcome`]; `state` is advanced in place.
pub fn execute_block(
    spec: &ChainSpec,
    state: &mut L2State,
    input: BlockInput,
) -> Result<ExecutionOutcome, BlockExecutionError> {
    // 1. Deposit mints at block start (before any user tx). This is the ONLY
    //    place native balance is created; provenance is bridged BLCH only.
    let mut minted_wei = U256::ZERO;
    for deposit in &input.deposits {
        state.deposit_mint(deposit)?;
        minted_wei += deposit.mint_wei;
    }

    // 2. Sequencer-boundary checks that never reach the EVM.
    for (i, tx) in input.txs.iter().enumerate() {
        if tx.tx_type == BLOB_TX_TYPE || !tx.blob_hashes.is_empty() || tx.max_fee_per_blob_gas != 0
        {
            return Err(BlockExecutionError::BlobTxRejected { tx_index: i });
        }
    }

    // 3. Build the EVM: UNMODIFIED revm, mainnet handler, pinned hardfork.
    //    The database is moved into the EVM context and recovered afterwards.
    let db = core::mem::take(&mut state.db);
    let base_fee = input.context.base_fee_per_gas;
    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = spec.chain_id;
            // Sets both the spec and its mainnet gas params (CANCUN here).
            cfg.set_spec_and_mainnet_gas_params(spec.spec_id);
        })
        .modify_block_chained(|b| {
            b.number = U256::from(input.context.number);
            b.timestamp = U256::from(input.context.timestamp);
            b.gas_limit = spec.gas_limit;
            b.basefee = base_fee;
            // COINBASE = fee-vault address (design §1): priority fees are
            // paid to the beneficiary by revm's unmodified handler.
            b.beneficiary = spec.coinbase();
            b.prevrandao = Some(input.context.prevrandao);
            b.difficulty = U256::ZERO;
            // Blobless blocks: BLOBHASH / blob-basefee opcodes still return
            // spec-correct values (zero excess gas) for Cancun.
            b.blob_excess_gas_and_price =
                Some(BlobExcessGasAndPrice::new_with_spec(0, spec.spec_id));
        })
        .build_mainnet();

    // 4. Execute transactions in order, routing fees per tx.
    let mut tx_outcomes = Vec::with_capacity(input.txs.len());
    let mut block_gas_used: u64 = 0;
    let mut base_fee_routed = U256::ZERO;
    let mut priority_fee_routed = U256::ZERO;

    for (i, tx) in input.txs.into_iter().enumerate() {
        if block_gas_used.saturating_add(tx.gas_limit) > spec.gas_limit {
            return Err(BlockExecutionError::BlockGasLimitExceeded { tx_index: i });
        }
        // Effective gas price per EIP-1559 (mirrors revm's own computation,
        // recomputed here only for fee-routing accounting).
        let max_fee = tx.gas_price;
        let effective_gas_price = match tx.gas_priority_fee {
            Some(priority) => core::cmp::min(max_fee, (base_fee as u128).saturating_add(priority)),
            None => max_fee, // legacy/2930 tx: pays its full gas price
        };
        let priority_per_gas = effective_gas_price.saturating_sub(base_fee as u128);

        let result = evm
            .transact_commit(tx)
            .map_err(|e| BlockExecutionError::Evm {
                tx_index: i,
                detail: format!("{e:?}"),
            })?;

        // Receipt-level gas used (post-refund; unambiguous name after revm's
        // EIP-8037 state-gas split).
        let gas_used = result.tx_gas_used();
        block_gas_used += gas_used;

        // Route the basefee portion to the BaseFeeVault (never burn).
        // Protocol-level accounting between transactions, outside EVM opcode
        // semantics — the journal is empty here (transact_commit finalized),
        // so direct DB credit is safe.
        let base_fee_wei = U256::from(base_fee) * U256::from(gas_used);
        credit_balance(
            &mut evm.ctx.journaled_state.database,
            spec.base_fee_vault,
            base_fee_wei,
        );
        base_fee_routed += base_fee_wei;
        // The priority portion was already paid to the beneficiary
        // (= SequencerFeeVault) by revm itself; track it for the outcome.
        priority_fee_routed += U256::from(priority_per_gas) * U256::from(gas_used);

        tx_outcomes.push(TxOutcome {
            success: result.is_success(),
            gas_used,
            created_address: result.created_address(),
            result,
        });
    }

    // 5. Recover the database (block reward is ZERO by design — nothing to
    //    pay the "miner"; issuance is deposits only).
    debug_assert_eq!(spec.block_reward, U256::ZERO);
    state.db = evm.ctx.journaled_state.database;

    Ok(ExecutionOutcome {
        block_number: input.context.number,
        gas_used: block_gas_used,
        base_fee_per_gas: base_fee,
        minted_wei,
        base_fee_routed_wei: base_fee_routed,
        priority_fee_routed_wei: priority_fee_routed,
        tx_outcomes,
        // Real keccak-256 MPT state root over the post-execution state.
        state_root: compute_keccak_mpt_state_root(state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::sats_to_wei;
    use crate::state::DepositProvenance;
    use alloy_primitives::{address, bytes, Bytes, TxKind};

    const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0000000000000000000000000000000000000b0b");

    const GWEI: u128 = 1_000_000_000;

    fn deposit(recipient: Address, l1_sats: u64) -> DepositMint {
        DepositMint {
            recipient,
            mint_wei: sats_to_wei(l1_sats),
            provenance: DepositProvenance::BridgedBlch {
                l1_txid: [7; 32],
                l1_vout: 1,
                l1_sats,
            },
        }
    }

    /// Init code that deploys a 10-byte runtime returning uint256(42) on any
    /// call:
    ///   runtime: 602a60005260206000f3
    ///     PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    ///   initcode: PUSH10 <runtime> PUSH1 0 MSTORE PUSH1 10 PUSH1 22 RETURN
    fn return42_initcode() -> Bytes {
        bytes!("69602a60005260206000f3600052600a6016f3")
    }

    #[test]
    fn value_transfer_state_transition() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let tip: u128 = GWEI; // 1 gwei priority fee

        // Fund alice with 10 BLCH via a bridged deposit.
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;
        let transfer_wei = sats_to_wei(crate::scale::SATS_PER_BLCH); // 1 BLCH

        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .value(transfer_wei)
            .gas_limit(21_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx env");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![tx],
            },
        )
        .expect("block executes");

        // Tx-level assertions.
        assert_eq!(outcome.tx_outcomes.len(), 1);
        assert!(outcome.tx_outcomes[0].success);
        assert_eq!(outcome.tx_outcomes[0].gas_used, 21_000);
        assert_eq!(outcome.gas_used, 21_000);

        // Post balances / nonces.
        let effective_price = base_fee as u128 + tip; // max fee covers both
        let gas_cost = U256::from(effective_price) * U256::from(21_000u64);
        assert_eq!(
            state.balance_of(&ALICE),
            sats_to_wei(funding_sats) - transfer_wei - gas_cost
        );
        assert_eq!(state.balance_of(&BOB), transfer_wei);
        assert_eq!(state.nonce_of(&ALICE), 1);
        assert_eq!(state.nonce_of(&BOB), 0);

        // Fee routing: basefee → BaseFeeVault, priority → SequencerFeeVault.
        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);

        // Zero issuance, never burn: supply is exactly the deposits.
        assert_eq!(outcome.minted_wei, sats_to_wei(funding_sats));
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
        assert_eq!(state.total_minted_wei(), sats_to_wei(funding_sats));
    }

    #[test]
    fn contract_deploy_and_call() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee;
        let tip: u128 = GWEI;
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        let deploy = TxEnv::builder()
            .caller(ALICE)
            .create()
            .data(return42_initcode())
            .gas_limit(300_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid deploy tx");

        // CREATE address is deterministic: keccak(rlp([sender, nonce])).
        let expected_contract = ALICE.create(0);

        let call = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(expected_contract))
            .gas_limit(100_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(1)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid call tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![deploy, call],
            },
        )
        .expect("block executes");

        assert_eq!(outcome.tx_outcomes.len(), 2);

        // Deploy landed at the CREATE address; deployment costs more than a
        // bare transfer (21k intrinsic + initcode + code deposit).
        let deploy_out = &outcome.tx_outcomes[0];
        assert!(deploy_out.success);
        assert_eq!(deploy_out.created_address, Some(expected_contract));
        assert!(deploy_out.gas_used > 21_000);
        let contract = state.account(&expected_contract).expect("contract exists");
        assert_ne!(contract.code_hash, revm::primitives::KECCAK_EMPTY);

        // The call returned uint256(42).
        let call_out = &outcome.tx_outcomes[1];
        assert!(call_out.success);
        let output = call_out.result.output().expect("call has output");
        assert_eq!(output.len(), 32);
        assert_eq!(U256::from_be_slice(output), U256::from(42));
        assert!(call_out.gas_used >= 21_000);

        // Nonce accounting: two txs from alice (CREATE bumps to 1, call to 2).
        assert_eq!(state.nonce_of(&ALICE), 2);
        // Contract accounts are created with nonce 1 (EIP-161).
        assert_eq!(contract.nonce, 1);

        // Gas accounting: block gas = sum of tx gas; payer balance reflects
        // exactly value(0) + gas at the effective price; fees all in vaults.
        let total_gas = deploy_out.gas_used + call_out.gas_used;
        assert_eq!(outcome.gas_used, total_gas);
        let effective_price = base_fee as u128 + tip;
        assert_eq!(
            state.balance_of(&ALICE),
            sats_to_wei(funding_sats) - U256::from(effective_price) * U256::from(total_gas)
        );
        assert_eq!(
            state.balance_of(&spec.base_fee_vault),
            U256::from(base_fee) * U256::from(total_gas)
        );
        assert_eq!(
            state.balance_of(&spec.sequencer_fee_vault),
            U256::from(tip) * U256::from(total_gas)
        );

        // Conservation: zero issuance, never burn.
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn deposit_mint_total_supply_is_sum_of_mints() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // Two deposit-only blocks, no user txs: pure mint accounting.
        for (block, sats) in [(1u64, 5_000u64), (2u64, 123_456_789u64)] {
            let outcome = execute_block(
                &spec,
                &mut state,
                BlockInput {
                    context: BlockContext {
                        number: block,
                        ..BlockContext::default()
                    },
                    deposits: vec![deposit(ALICE, sats), deposit(BOB, sats / 2 + 1)],
                    txs: vec![],
                },
            )
            .expect("deposit-only block executes");
            assert_eq!(outcome.gas_used, 0);
            assert_eq!(
                outcome.minted_wei,
                sats_to_wei(sats) + sats_to_wei(sats / 2 + 1)
            );
        }

        let expected = sats_to_wei(5_000) + sats_to_wei(2_501) + sats_to_wei(123_456_789)
            + sats_to_wei(61_728_395);
        // total supply == sum of mints (zero issuance).
        assert_eq!(state.total_minted_wei(), expected);
        assert_eq!(state.total_native_wei(), expected);
    }

    #[test]
    fn blob_transactions_are_rejected_at_the_sequencer() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        let blob_tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .blob_hashes(vec![B256::repeat_byte(1)])
            .max_fee_per_blob_gas(1)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build_fill();

        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, 1_000_000)],
                txs: vec![blob_tx],
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::BlobTxRejected { tx_index: 0 }
        ));
    }

    #[test]
    fn reverting_tx_still_consumes_gas_and_routes_fees() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee;
        let tip: u128 = GWEI;
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        // A CREATE whose initcode reverts immediately: PUSH1 0 PUSH1 0 REVERT.
        // The transaction is valid and included; it just fails.
        let revert_deploy = TxEnv::builder()
            .caller(ALICE)
            .create()
            .data(bytes!("60006000fd"))
            .gas_limit(100_000)
            .max_fee_per_gas(base_fee as u128 + tip)
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid deploy tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![revert_deploy],
            },
        )
        .expect("block executes even though the tx reverts");

        let out = &outcome.tx_outcomes[0];
        assert!(!out.success, "the deploy reverted");
        assert_eq!(out.created_address, None, "no contract is created on revert");
        assert!(
            out.gas_used > 21_000,
            "a revert still consumes intrinsic + execution gas"
        );

        // Fees are routed even for a failed-but-included transaction: a revert
        // is never free, and bridged BLCH is never burned.
        let base_part = U256::from(base_fee) * U256::from(out.gas_used);
        let tip_part = U256::from(tip) * U256::from(out.gas_used);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);

        // The nonce still advanced, and supply is conserved.
        assert_eq!(state.nonce_of(&ALICE), 1);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn priority_fee_is_capped_by_max_fee_per_gas() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei (BlockContext::default)
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        // The caller asks for a 2 gwei tip but caps total at 2 gwei per gas.
        // Effective price = min(max_fee, base_fee + priority) = 2 gwei, so only
        // 1 gwei of tip can actually be realized above the 1 gwei base fee.
        let requested_tip: u128 = 2 * GWEI;
        let max_fee: u128 = 2 * GWEI;
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(max_fee)
            .gas_priority_fee(Some(requested_tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![tx],
            },
        )
        .expect("block executes");

        let realized_tip: u128 = GWEI; // capped down from the requested 2 gwei
        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(realized_tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        // The realized tip is strictly less than the requested tip — the cap
        // (the `min` in the executor's effective-price calc) actually bit.
        assert!(U256::from(requested_tip) * U256::from(21_000u64) > tip_part);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn legacy_tx_routes_gas_price_minus_basefee_as_tip() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let base_fee = spec.initial_base_fee; // 1 gwei
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        // A legacy (type-0) transaction carries no priority-fee field; it pays
        // its full gas price and the executor routes (gas_price - base_fee) to
        // the sequencer vault (the `None => max_fee` branch).
        let gas_price: u128 = 3 * GWEI;
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .gas_price(gas_price)
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid legacy tx");
        assert_eq!(tx.tx_type, 0, "derived as a legacy transaction");
        assert!(tx.gas_priority_fee.is_none());

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![tx],
            },
        )
        .expect("block executes");

        let base_part = U256::from(base_fee) * U256::from(21_000u64);
        let tip_part = U256::from(gas_price - base_fee as u128) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.base_fee_vault), base_part);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.base_fee_routed_wei, base_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn zero_basefee_routes_nothing_to_the_base_fee_vault() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();
        let tip: u128 = GWEI;
        let funding_sats = 10 * crate::scale::SATS_PER_BLCH;

        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(21_000)
            .max_fee_per_gas(tip) // base fee 0 + up to 1 gwei tip
            .gas_priority_fee(Some(tip))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");

        let outcome = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext {
                    base_fee_per_gas: 0,
                    ..BlockContext::default()
                },
                deposits: vec![deposit(ALICE, funding_sats)],
                txs: vec![tx],
            },
        )
        .expect("block executes at zero base fee");

        // Zero base fee routes nothing to the BaseFeeVault; the whole effective
        // price is priority and lands in the SequencerFeeVault.
        assert_eq!(state.balance_of(&spec.base_fee_vault), U256::ZERO);
        assert_eq!(outcome.base_fee_routed_wei, U256::ZERO);
        let tip_part = U256::from(tip) * U256::from(21_000u64);
        assert_eq!(state.balance_of(&spec.sequencer_fee_vault), tip_part);
        assert_eq!(outcome.priority_fee_routed_wei, tip_part);
        assert_eq!(state.total_native_wei(), state.total_minted_wei());
    }

    #[test]
    fn block_gas_limit_exceeded_is_rejected() {
        let spec = ChainSpec::testnet();
        let mut state = L2State::new();

        // A single transaction whose gas limit alone exceeds the 30M block
        // limit is rejected at the executor boundary, before the EVM runs.
        let tx = TxEnv::builder()
            .caller(ALICE)
            .kind(TxKind::Call(BOB))
            .gas_limit(spec.gas_limit + 1)
            .max_fee_per_gas(2 * GWEI)
            .gas_priority_fee(Some(GWEI))
            .nonce(0)
            .chain_id(Some(spec.chain_id))
            .build()
            .expect("valid tx");

        let err = execute_block(
            &spec,
            &mut state,
            BlockInput {
                context: BlockContext::default(),
                deposits: vec![deposit(ALICE, 1_000_000)],
                txs: vec![tx],
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BlockExecutionError::BlockGasLimitExceeded { tx_index: 0 }
        ));
    }
}
