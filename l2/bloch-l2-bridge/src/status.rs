// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deposit / withdrawal lifecycle types + the K(amount) depth schedule.
//!
//! Types match BLOCH-L2-EVM-DESIGN §2 (AnchorManager API's
//! `withdrawal_status`) and §5 (deposit flow). The confirmation-depth
//! schedule is §5's TESTNET PLACEHOLDER, re-derived at each gate stage:
//!
//! ```text
//! K(amount):  <= 10 BLCH   -> 24 blocks
//!             <= 100 BLCH  -> 96
//!             <= 1000 BLCH -> 288
//!             above        -> 288 + operator review
//! ```
//!
//! NORMATIVE HONESTY CLAUSE (§2, verbatim): on a 51%-attackable chain NO
//! finite K is safe against a majority attacker; K only prices out casual
//! reorgs; no K may ever be represented as finality.
//!
//! SCAFFOLD, UNAUDITED: pure types and a pure function; nothing here
//! watches a chain or moves value.

/// L1 atoms per BLCH (8 decimals).
pub const ATOMS_PER_BLCH: u64 = 100_000_000;

/// A detected L1 → L2 deposit (vault payment + valid L2D0 envelope),
/// as the (stubbed) L1 watcher would emit it after replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositEvent {
    /// Bloch txid of the depositing transaction.
    pub txid: [u8; 32],
    /// First vault-paying output index (deposit_id = (txid, vout), §5).
    pub vout: u32,
    /// Sum of tx output values paying disclosed vault addresses, in atoms.
    pub amount_atoms: u64,
    /// Target L2 chain id from the envelope.
    pub l2_chain_id: u64,
    /// L2 recipient from the envelope.
    pub l2_recipient: [u8; 20],
    /// The L1 view: block hash the deposit was observed under.
    pub l1_block_hash: [u8; 32],
    /// The L1 view: height of that block.
    pub l1_block_height: u64,
}

/// Withdrawal lifecycle per §2's AnchorManager API:
/// `Queued | Provable | ReleaseEligible | Frozen | Halted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalStatus {
    /// Initiated on L2; its epoch's output root not yet anchored.
    Queued,
    /// The anchoring COMMIT is on Bloch: an inclusion proof against the
    /// proven withdrawal root exists, but the anchor is not yet deep
    /// enough for release.
    Provable {
        /// Bloch txid of the anchoring COMMIT envelope.
        commit_txid: [u8; 32],
        /// Current confirmation depth of that anchor.
        depth: u64,
    },
    /// Anchor depth >= K_w and all release-checklist preconditions are
    /// believed met. NOT finality — release is still an operator action
    /// against a custodial vault (§5, disclosed).
    ReleaseEligible,
    /// The authorizing commit's inclusion height is above an observed
    /// Bloch fork point: frozen until re-anchored and re-aged (§2 R3).
    Frozen {
        /// Height of the observed fork point.
        fork_point: u64,
    },
    /// Reorg deeper than K observed (majority-attack territory): bridge
    /// HALT, no releases, manual reconciliation required (§2 R4).
    Halted,
}

/// What the K(amount) schedule requires before a deposit is credited
/// (or, value-scaled, before a withdrawal releases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationRequirement {
    /// Wait `depth` confirmations, then proceed automatically.
    Automatic { depth: u32 },
    /// Wait at least `min_depth` confirmations AND require operator
    /// review (the "above 1000 BLCH" tier). Review is a disclosed manual
    /// step, not a protocol rule — stated per §5.
    OperatorReview { min_depth: u32 },
}

impl ConfirmationRequirement {
    /// The minimum depth component, whichever variant.
    pub fn min_depth(&self) -> u32 {
        match self {
            ConfirmationRequirement::Automatic { depth } => *depth,
            ConfirmationRequirement::OperatorReview { min_depth } => *min_depth,
        }
    }
}

/// The §5 K(amount) schedule (TESTNET PLACEHOLDER values) as a pure
/// function of the amount in atoms. Floor K=24 (6x the DAG k, matching
/// TKV0 §D.3). NO finite K is finality — see module docs.
pub fn confirmation_depth(amount_atoms: u64) -> ConfirmationRequirement {
    if amount_atoms <= 10 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 24 }
    } else if amount_atoms <= 100 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 96 }
    } else if amount_atoms <= 1000 * ATOMS_PER_BLCH {
        ConfirmationRequirement::Automatic { depth: 288 }
    } else {
        ConfirmationRequirement::OperatorReview { min_depth: 288 }
    }
}

/// Observations that drive a withdrawal through its lifecycle. These are
/// the L1 (Bloch) facts a release-agent folds in via
/// [`WithdrawalStatus::step`]; none of them moves value (§2, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalEvent {
    /// The epoch's withdrawal-root COMMIT was observed on Bloch under tx
    /// `commit_txid` at `depth` confirmations.
    AnchorObserved {
        /// Bloch txid of the anchoring COMMIT envelope.
        commit_txid: [u8; 32],
        /// Observed confirmation depth of that anchor.
        depth: u64,
    },
    /// The existing anchor gained confirmations; `depth` is the new observed
    /// depth. A value *smaller* than the current one is stale and is ignored
    /// — depth never counts down.
    AnchorDeepened {
        /// New observed confirmation depth.
        depth: u64,
    },
    /// The anchor reached `K_w` AND the §5 release-checklist preconditions
    /// are believed met (a disclosed operator judgement, NOT a protocol
    /// rule — release remains a custodial action, and no K is finality).
    ReleaseAuthorized,
    /// A Bloch fork was observed at/below the anchor's inclusion height:
    /// freeze until re-anchored and re-aged (§2 R3).
    ForkObserved {
        /// Height of the observed fork point.
        fork_point: u64,
    },
    /// A reorg deeper than `K` was observed — majority-attack territory:
    /// HALT the bridge (terminal, §2 R4).
    DeepReorg,
}

impl WithdrawalStatus {
    /// Happy-path progress rank: how far toward release a state is
    /// (`Queued`=0, `Provable`=1, `ReleaseEligible`=2). The two safety
    /// states are OFF this ladder (rank 0) — use [`Self::is_safety`] to tell
    /// them from `Queued`. Pins the monotonicity invariant: happy-path
    /// events never lower it.
    pub fn progress_rank(&self) -> u8 {
        match self {
            WithdrawalStatus::Queued => 0,
            WithdrawalStatus::Provable { .. } => 1,
            WithdrawalStatus::ReleaseEligible => 2,
            WithdrawalStatus::Frozen { .. } | WithdrawalStatus::Halted => 0,
        }
    }

    /// Safety severity: normal progress = 0, `Frozen` = 1, `Halted` = 2.
    /// Safety events (`ForkObserved`, `DeepReorg`) never lower it (tested).
    pub fn severity(&self) -> u8 {
        match self {
            WithdrawalStatus::Frozen { .. } => 1,
            WithdrawalStatus::Halted => 2,
            _ => 0,
        }
    }

    /// True for the two safety states that interrupt the happy path.
    pub fn is_safety(&self) -> bool {
        matches!(
            self,
            WithdrawalStatus::Frozen { .. } | WithdrawalStatus::Halted
        )
    }

    /// True once the bridge has HALTED for this withdrawal — an absorbing
    /// terminal state (no event ever leaves it).
    pub fn is_halted(&self) -> bool {
        matches!(self, WithdrawalStatus::Halted)
    }

    /// Total, deterministic lifecycle transition. Defined for EVERY
    /// `(state, event)` pair — it never panics and always returns a state.
    ///
    /// Invariants (all tested in this module):
    /// * **Total:** every pair maps to a state (no `todo!`, no panic).
    /// * **Halt is absorbing:** `Halted` stays `Halted` for every event.
    /// * **`DeepReorg` halts** from any non-halted state.
    /// * **`ForkObserved` freezes** any non-halted state; an already-frozen
    ///   state keeps the *earliest* (lowest) fork point it has seen.
    /// * **Depth is monotone:** a `Provable` anchor's `depth` never
    ///   decreases — stale, smaller reports are ignored.
    /// * **No state-skipping:** `ReleaseEligible` is reachable only from
    ///   `Provable` (never straight from `Queued`); re-anchoring a `Frozen`
    ///   withdrawal returns it to `Provable`, never past it.
    pub fn step(self, event: WithdrawalEvent) -> WithdrawalStatus {
        use WithdrawalEvent as E;
        use WithdrawalStatus as S;

        // Halt is absorbing: nothing here recovers a halted bridge.
        if let S::Halted = self {
            return S::Halted;
        }
        // A deep reorg halts unconditionally (from any non-halted state).
        if let E::DeepReorg = event {
            return S::Halted;
        }
        // A fork freezes any non-halted state; a `Frozen` state keeps the
        // earliest (lowest) fork point observed so far.
        if let E::ForkObserved { fork_point } = event {
            return match self {
                S::Frozen { fork_point: prev } => S::Frozen {
                    fork_point: prev.min(fork_point),
                },
                _ => S::Frozen { fork_point },
            };
        }

        match (self, event) {
            // Queued only advances on an anchor observation.
            (S::Queued, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable { commit_txid, depth }
            }
            // Queued ignores deepen / release-authorize — nothing anchored yet
            // (this is the no-state-skipping guard).
            (S::Queued, _) => S::Queued,

            // Provable: deepen (monotone), re-anchor (never regress depth),
            // or authorize release.
            (S::Provable { commit_txid, depth }, E::AnchorDeepened { depth: d }) => S::Provable {
                commit_txid,
                depth: depth.max(d),
            },
            (
                S::Provable { commit_txid, depth },
                E::AnchorObserved {
                    commit_txid: tx2,
                    depth: d2,
                },
            ) => {
                // Re-anchor: adopt the new commit only if it does not regress
                // the observed depth.
                if d2 >= depth {
                    S::Provable {
                        commit_txid: tx2,
                        depth: d2,
                    }
                } else {
                    S::Provable { commit_txid, depth }
                }
            }
            (S::Provable { .. }, E::ReleaseAuthorized) => S::ReleaseEligible,
            // Fork/DeepReorg already handled above; keep total.
            (S::Provable { commit_txid, depth }, _) => S::Provable { commit_txid, depth },

            // ReleaseEligible is idempotent under every remaining event.
            (S::ReleaseEligible, _) => S::ReleaseEligible,

            // Frozen recovers ONLY by re-anchoring -> back to Provable
            // (re-anchored and re-aged, §2 R3); all else leaves it frozen.
            (S::Frozen { .. }, E::AnchorObserved { commit_txid, depth }) => {
                S::Provable { commit_txid, depth }
            }
            (S::Frozen { fork_point }, _) => S::Frozen { fork_point },

            // Halted handled at the top; kept for exhaustiveness/totality.
            (S::Halted, _) => S::Halted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_tiers_and_boundaries() {
        let blch = |n: u64| n * ATOMS_PER_BLCH;

        // floor tier, including zero and exact boundary
        assert_eq!(
            confirmation_depth(0),
            ConfirmationRequirement::Automatic { depth: 24 }
        );
        assert_eq!(
            confirmation_depth(1),
            ConfirmationRequirement::Automatic { depth: 24 }
        );
        assert_eq!(
            confirmation_depth(blch(10)),
            ConfirmationRequirement::Automatic { depth: 24 }
        );

        // one atom over 10 BLCH -> 96
        assert_eq!(
            confirmation_depth(blch(10) + 1),
            ConfirmationRequirement::Automatic { depth: 96 }
        );
        assert_eq!(
            confirmation_depth(blch(100)),
            ConfirmationRequirement::Automatic { depth: 96 }
        );

        // one atom over 100 BLCH -> 288
        assert_eq!(
            confirmation_depth(blch(100) + 1),
            ConfirmationRequirement::Automatic { depth: 288 }
        );
        assert_eq!(
            confirmation_depth(blch(1000)),
            ConfirmationRequirement::Automatic { depth: 288 }
        );

        // above 1000 BLCH -> 288 + operator review
        assert_eq!(
            confirmation_depth(blch(1000) + 1),
            ConfirmationRequirement::OperatorReview { min_depth: 288 }
        );
        assert_eq!(
            confirmation_depth(u64::MAX),
            ConfirmationRequirement::OperatorReview { min_depth: 288 }
        );
    }

    #[test]
    fn schedule_is_monotone_in_amount() {
        // depth never decreases as value at risk grows
        let samples = [
            0u64,
            1,
            10 * ATOMS_PER_BLCH,
            10 * ATOMS_PER_BLCH + 1,
            100 * ATOMS_PER_BLCH,
            100 * ATOMS_PER_BLCH + 1,
            1000 * ATOMS_PER_BLCH,
            1000 * ATOMS_PER_BLCH + 1,
            u64::MAX,
        ];
        let mut prev = 0u32;
        for s in samples {
            let d = confirmation_depth(s).min_depth();
            assert!(d >= prev, "depth must be monotone at {s}");
            prev = d;
        }
    }

    #[test]
    fn min_depth_accessor() {
        assert_eq!(ConfirmationRequirement::Automatic { depth: 24 }.min_depth(), 24);
        assert_eq!(
            ConfirmationRequirement::OperatorReview { min_depth: 288 }.min_depth(),
            288
        );
    }

    #[test]
    fn status_variants_construct() {
        // The full §2 set exists and is matchable (type-level pin).
        let all = [
            WithdrawalStatus::Queued,
            WithdrawalStatus::Provable {
                commit_txid: [0u8; 32],
                depth: 12,
            },
            WithdrawalStatus::ReleaseEligible,
            WithdrawalStatus::Frozen { fork_point: 100 },
            WithdrawalStatus::Halted,
        ];
        assert_eq!(all.len(), 5);
        assert_ne!(all[0], all[2]);
    }

    // ---- lifecycle transition (step) invariants ----

    fn representative_states() -> Vec<WithdrawalStatus> {
        vec![
            WithdrawalStatus::Queued,
            WithdrawalStatus::Provable {
                commit_txid: [1u8; 32],
                depth: 0,
            },
            WithdrawalStatus::Provable {
                commit_txid: [1u8; 32],
                depth: 50,
            },
            WithdrawalStatus::ReleaseEligible,
            WithdrawalStatus::Frozen { fork_point: 10 },
            WithdrawalStatus::Halted,
        ]
    }

    fn representative_events() -> Vec<WithdrawalEvent> {
        vec![
            WithdrawalEvent::AnchorObserved {
                commit_txid: [2u8; 32],
                depth: 5,
            },
            WithdrawalEvent::AnchorObserved {
                commit_txid: [2u8; 32],
                depth: 100,
            },
            WithdrawalEvent::AnchorDeepened { depth: 1 },
            WithdrawalEvent::AnchorDeepened { depth: 999 },
            WithdrawalEvent::ReleaseAuthorized,
            WithdrawalEvent::ForkObserved { fork_point: 7 },
            WithdrawalEvent::ForkObserved { fork_point: 20 },
            WithdrawalEvent::DeepReorg,
        ]
    }

    #[test]
    fn step_is_total_and_halt_is_absorbing() {
        // Every (state, event) pair yields a state (no panic == total), and
        // once Halted the state is absorbing under every event.
        for s in representative_states() {
            for e in representative_events() {
                let next = s.step(e);
                if s.is_halted() {
                    assert_eq!(next, WithdrawalStatus::Halted, "halt must absorb {e:?}");
                }
            }
        }
    }

    #[test]
    fn happy_path_events_never_regress_progress() {
        // On the happy-path events (anchor / deepen / release), the progress
        // rank is non-decreasing from every non-halted state.
        let happy = [
            WithdrawalEvent::AnchorObserved {
                commit_txid: [9u8; 32],
                depth: 3,
            },
            WithdrawalEvent::AnchorDeepened { depth: 3 },
            WithdrawalEvent::ReleaseAuthorized,
        ];
        for s in representative_states() {
            if s.is_halted() {
                continue;
            }
            for e in happy {
                let before = s.progress_rank();
                let after = s.step(e).progress_rank();
                assert!(
                    after >= before,
                    "progress regressed {before}->{after} on {s:?} via {e:?}"
                );
            }
        }
    }

    #[test]
    fn safety_events_never_reduce_severity() {
        // Fork and DeepReorg never lower the safety severity of any state.
        let safety = [
            WithdrawalEvent::ForkObserved { fork_point: 7 },
            WithdrawalEvent::DeepReorg,
        ];
        for s in representative_states() {
            for e in safety {
                let before = s.severity();
                let after = s.step(e).severity();
                assert!(
                    after >= before,
                    "severity dropped {before}->{after} on {s:?} via {e:?}"
                );
            }
        }
    }

    #[test]
    fn depth_never_counts_down() {
        let base = WithdrawalStatus::Provable {
            commit_txid: [7u8; 32],
            depth: 50,
        };
        // a shallower deepen report is ignored
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDeepened { depth: 5 }),
            base
        );
        // a deeper one advances
        assert_eq!(
            base.step(WithdrawalEvent::AnchorDeepened { depth: 80 }),
            WithdrawalStatus::Provable {
                commit_txid: [7u8; 32],
                depth: 80
            }
        );
        // a re-anchor with LOWER depth is refused (keeps old commit + depth)
        assert_eq!(
            base.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [8u8; 32],
                depth: 5
            }),
            base
        );
        // a re-anchor with >= depth adopts the new commit
        assert_eq!(
            base.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [8u8; 32],
                depth: 60
            }),
            WithdrawalStatus::Provable {
                commit_txid: [8u8; 32],
                depth: 60
            }
        );
    }

    #[test]
    fn no_state_skipping_from_queued() {
        // Queued cannot jump straight to ReleaseEligible; it must anchor first.
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::ReleaseAuthorized),
            WithdrawalStatus::Queued
        );
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::AnchorDeepened { depth: 99 }),
            WithdrawalStatus::Queued
        );
        assert_eq!(
            WithdrawalStatus::Queued.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [3u8; 32],
                depth: 1
            }),
            WithdrawalStatus::Provable {
                commit_txid: [3u8; 32],
                depth: 1
            }
        );
    }

    #[test]
    fn deep_reorg_halts_from_every_non_halted_state() {
        for s in representative_states() {
            assert_eq!(
                s.step(WithdrawalEvent::DeepReorg),
                WithdrawalStatus::Halted,
                "DeepReorg must halt {s:?}"
            );
        }
    }

    #[test]
    fn fork_freezes_and_keeps_earliest_fork_point() {
        // A first fork freezes at its point...
        let frozen = WithdrawalStatus::ReleaseEligible
            .step(WithdrawalEvent::ForkObserved { fork_point: 30 });
        assert_eq!(frozen, WithdrawalStatus::Frozen { fork_point: 30 });
        // ...a later, DEEPER fork does not raise the recorded point...
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 40 }),
            WithdrawalStatus::Frozen { fork_point: 30 }
        );
        // ...but an earlier one lowers it (the more conservative point).
        assert_eq!(
            frozen.step(WithdrawalEvent::ForkObserved { fork_point: 12 }),
            WithdrawalStatus::Frozen { fork_point: 12 }
        );
    }

    #[test]
    fn frozen_recovers_only_by_reanchoring() {
        let frozen = WithdrawalStatus::Frozen { fork_point: 10 };
        // re-anchor -> back to Provable (re-anchored and re-aged, §2 R3)
        assert_eq!(
            frozen.step(WithdrawalEvent::AnchorObserved {
                commit_txid: [5u8; 32],
                depth: 2
            }),
            WithdrawalStatus::Provable {
                commit_txid: [5u8; 32],
                depth: 2
            }
        );
        // other happy-path events leave it frozen
        assert_eq!(frozen.step(WithdrawalEvent::ReleaseAuthorized), frozen);
        assert_eq!(
            frozen.step(WithdrawalEvent::AnchorDeepened { depth: 99 }),
            frozen
        );
        // a deep reorg still halts even from Frozen
        assert_eq!(
            frozen.step(WithdrawalEvent::DeepReorg),
            WithdrawalStatus::Halted
        );
    }

    #[test]
    fn nominal_happy_path_sequence() {
        // Queued -> anchor -> deepen -> authorize -> ReleaseEligible.
        let s = WithdrawalStatus::Queued;
        let s = s.step(WithdrawalEvent::AnchorObserved {
            commit_txid: [4u8; 32],
            depth: 1,
        });
        assert_eq!(
            s,
            WithdrawalStatus::Provable {
                commit_txid: [4u8; 32],
                depth: 1
            }
        );
        let s = s.step(WithdrawalEvent::AnchorDeepened { depth: 24 });
        assert_eq!(
            s,
            WithdrawalStatus::Provable {
                commit_txid: [4u8; 32],
                depth: 24
            }
        );
        let s = s.step(WithdrawalEvent::ReleaseAuthorized);
        assert_eq!(s, WithdrawalStatus::ReleaseEligible);
        // idempotent thereafter under happy-path events
        assert_eq!(s.step(WithdrawalEvent::ReleaseAuthorized), s);
        assert_eq!(
            s.step(WithdrawalEvent::AnchorDeepened { depth: 999 }),
            WithdrawalStatus::ReleaseEligible
        );
    }
}
