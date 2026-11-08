// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `BridgeKillSwitch` — drop the span without touching the door
//!
//! Revocation surface #3 (NoporIS-only, **orthogonal to signing**). This mirrors
//! the `killSwitch` object in `apps/postern-android-gate/gate-state.schema.json`:
//!
//! > "Operator kill-switch. When engaged, the wrapper MUST stop the Waydroid
//! > container and refuse to start it until disengaged. Engaging is always allowed
//! > and **never destroys wallet state in the sealed base**."
//!
//! Here, in signer terms, "stop the container" means **cut the NoporIS lane**: an
//! engaged switch makes the bridge world refuse to receive/approve, fail-closed,
//! and refuse to reopen until it is explicitly disengaged. The door (Porog) and
//! the keys are untouched — the near side survives the bridge being cut.
//!
//! ## Kill fan-out — engage SIGNALS revocation, it does not only flip a flag
//!
//! Engaging must do **two** things, in this order:
//!
//! 1. **Flip the local in-memory flag** ([`BridgeKillSwitch::engage`]) — the lane
//!    is cut fail-closed *first*, before and independent of any cross-crate call.
//! 2. **Signal the consent ledger to revoke** every live bridge consent, via the
//!    [`ConsentRevoker`] port ([`BridgeKillSwitch::engage_revoking`]). This is a
//!    cross-crate call into the orchestrator's `ConsentLedger` **public API** — a
//!    revoke, *not* a shared-file edit; the orchestrator persists the result.
//!
//! If the ledger's revoke errors, the local flag STAYS engaged — the bridge is
//! never left half-open on a downstream failure; the error is returned for the
//! orchestrator to log and persist. `ConsentRevoker` is a trait **this crate owns**
//! precisely so the fan-out needs no dependency edge on Dev B's crate and no edit
//! to its files (see the trait's docs).
//!
//! **By construction this type holds NO wallet state and NO `PairingRecord`.** It
//! is a single flag plus a timestamp. It therefore *cannot* destroy sealed wallet
//! state or either world's pairing — there is nothing here to destroy. The sealed
//! records live in `postern-pairing`'s `PairedTerminals` and are addressed only by
//! the [`unpair`](crate::pairings::WorldPairings::unpair) surface, never by this.
//!
//! HONEST LABEL: enforcement is [`EnforcementMode::ByConstruction`] — a userland,
//! in-process check, **not** an OS/kernel boundary. A rooted host defeats it.

use postern_policy::{Decision, EnforcementMode};

/// The honest enforcement mode of the bridge kill-switch: an in-process, userland
/// gate — not an OS/kernel boundary. Pinned so no surface can round it up.
pub const BRIDGE_ENFORCEMENT: EnforcementMode = EnforcementMode::ByConstruction;

/// The stable reason string the bridge kill-switch fans out to the consent ledger
/// when it engages — the SAME words on both sides of the cross-crate call, so an
/// audit trail never drifts from what the code did.
pub const BRIDGE_KILL_REVOKE_REASON: &str = "NoporIS bridge kill-switch engaged: all live \
    bridge consents revoked; the lane is cut and will not reopen until explicitly disengaged \
    (sealed wallet state and both worlds' pairings are untouched — the kill-switch holds no \
    key material and destroys none).";

/// The **port** the bridge kill-switch fans out to when it engages: the *public*
/// revoke surface of the orchestrator's `ConsentLedger` (Dev B's crate), expressed
/// as a trait THIS crate owns so the two crates stay decoupled — no dependency
/// edge, and no shared-file edit. The orchestrator adapts a `&mut ConsentLedger`
/// to this trait (or the ledger implements it directly); all this crate needs from
/// Dev B is a public `revoke_all(reason) -> count` on the ledger.
///
/// This is a **SIGNAL, not a persist.** The kill-switch flips its own in-memory
/// flag *first* (so the lane is cut fail-closed locally, independent of whether the
/// ledger call succeeds), then asks the ledger to revoke. Persisting the revoked
/// ledger is the orchestrator's job — never this crate's.
pub trait ConsentRevoker {
    /// Error the ledger's revoke may surface (e.g. a persistence write on the
    /// orchestrator's side). Use [`core::convert::Infallible`] for a pure in-memory
    /// ledger that cannot fail.
    type Error;

    /// Revoke **every** live bridge consent, monotonically, tagging the audit trail
    /// with `reason` (the kill-switch passes [`BRIDGE_KILL_REVOKE_REASON`]). Returns
    /// how many consents were revoked. Idempotent: a second call once everything is
    /// already revoked returns `0`. There is no un-revoke.
    fn revoke_all(&mut self, reason: &str) -> Result<usize, Self::Error>;
}

/// The NoporIS-only bridge kill-switch. Engaging cuts the bridge lane and refuses
/// to reopen it until disengaged; it never touches sealed wallet state or a
/// pairing (it holds neither).
#[derive(Debug, Clone, Default)]
pub struct BridgeKillSwitch {
    engaged: bool,
    /// RFC-3339 timestamp the operator engaged it (mirrors the gate schema's
    /// `engagedAtIso`). `None` while disengaged. Cosmetic/audit only.
    engaged_at_iso: Option<String>,
}

impl BridgeKillSwitch {
    /// A fresh, **disengaged** switch (the bridge lane is open, subject to the
    /// usual per-request consent — the switch is not a substitute for it).
    pub fn new() -> Self {
        BridgeKillSwitch::default()
    }

    /// Engage: cut the NoporIS bridge lane. Always allowed. Records the RFC-3339
    /// time for the audit surface. Does **not** touch wallet state or pairings.
    pub fn engage(&mut self, now_iso: impl Into<String>) {
        self.engaged = true;
        self.engaged_at_iso = Some(now_iso.into());
    }

    /// **Engage AND fan out the revocation** — the kill-switch's full signal:
    ///
    /// 1. Flip the local in-memory flag (exactly [`engage`](Self::engage), so the
    ///    NoporIS lane is cut fail-closed *first*, before and regardless of the
    ///    cross-crate call below).
    /// 2. Signal `ledger` (the orchestrator's `ConsentLedger`, via the
    ///    [`ConsentRevoker`] port) to revoke **every** live bridge consent, tagged
    ///    [`BRIDGE_KILL_REVOKE_REASON`].
    ///
    /// Returns how many consents the ledger revoked. **If the ledger's revoke
    /// errors, the local flag STAYS engaged** (this method has already flipped it)
    /// and the error is propagated for the orchestrator to log/persist — the bridge
    /// is never left half-open because a downstream persist failed. Persisting the
    /// revoked ledger is the orchestrator's job; this switch holds no ledger state.
    ///
    /// This never touches wallet state or either world's `PairingRecord` — it holds
    /// neither, and the ledger revoke is a consent revoke, not a key/pairing wipe.
    pub fn engage_revoking<R: ConsentRevoker>(
        &mut self,
        now_iso: impl Into<String>,
        ledger: &mut R,
    ) -> Result<usize, R::Error> {
        // Local fail-closed FIRST: the lane is cut even if the ledger call errors.
        self.engage(now_iso);
        // Then SIGNAL the cross-crate revoke through the public port.
        ledger.revoke_all(BRIDGE_KILL_REVOKE_REASON)
    }

    /// Disengage: allow the bridge lane to reopen. Deliberately explicit — an
    /// engaged switch never lapses on a timer.
    pub fn disengage(&mut self) {
        self.engaged = false;
        self.engaged_at_iso = None;
    }

    /// Whether the bridge lane is currently cut.
    pub fn is_engaged(&self) -> bool {
        self.engaged
    }

    /// When it was engaged (RFC-3339), if engaged.
    pub fn engaged_at(&self) -> Option<&str> {
        self.engaged_at_iso.as_deref()
    }

    /// The fail-closed bridge [`Decision`]: engaged ⇒ [`Decision::Deny`] with a
    /// reason; disengaged ⇒ [`Decision::Allow`]. The NoporIS lane consults this
    /// before receiving; the Porog lane never does.
    pub fn bridge_decision(&self) -> Decision {
        if self.engaged {
            return Decision::deny(
                "NoporIS bridge kill-switch engaged: lane cut, will not reopen until disengaged \
                 (sealed wallet state and both pairings are untouched)",
            );
        }
        Decision::Allow
    }

    /// The stable, shared honest-enforcement caveat string — delegated to
    /// `postern-policy` so every surface uses the SAME words (no drift, no
    /// round-up to a kernel boundary).
    pub fn honest_enforcement_label(&self) -> String {
        BRIDGE_ENFORCEMENT.honest_label().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disengaged_allows_engaged_denies_fail_closed() {
        let mut ks = BridgeKillSwitch::new();
        assert!(!ks.is_engaged());
        assert!(ks.bridge_decision().is_allow());

        ks.engage("2026-07-12T23:59:00Z");
        assert!(ks.is_engaged());
        assert_eq!(ks.engaged_at(), Some("2026-07-12T23:59:00Z"));
        let d = ks.bridge_decision();
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("untouched"));
    }

    #[test]
    fn disengage_is_explicit_and_reopens() {
        let mut ks = BridgeKillSwitch::new();
        ks.engage("2026-07-12T23:59:00Z");
        ks.disengage();
        assert!(!ks.is_engaged());
        assert_eq!(ks.engaged_at(), None);
        assert!(ks.bridge_decision().is_allow());
    }

    // A stand-in for Dev B's ConsentLedger public revoke surface: counts live
    // bridge consents and revokes them monotonically, recording the reason.
    #[derive(Default)]
    struct MockLedger {
        live: usize,
        revoked_calls: usize,
        last_reason: Option<String>,
    }
    impl ConsentRevoker for MockLedger {
        type Error = core::convert::Infallible;
        fn revoke_all(&mut self, reason: &str) -> Result<usize, Self::Error> {
            self.revoked_calls += 1;
            self.last_reason = Some(reason.to_string());
            let n = self.live;
            self.live = 0; // monotonic: nothing left to revoke afterward
            Ok(n)
        }
    }

    // A ledger whose revoke fails (e.g. a persistence write on the orchestrator).
    struct FailingLedger;
    impl ConsentRevoker for FailingLedger {
        type Error = &'static str;
        fn revoke_all(&mut self, _reason: &str) -> Result<usize, Self::Error> {
            Err("ledger persist failed")
        }
    }

    #[test]
    fn engage_revoking_flips_the_flag_and_fans_out_the_revoke() {
        let mut ks = BridgeKillSwitch::new();
        let mut ledger = MockLedger {
            live: 3,
            ..Default::default()
        };

        let revoked = ks.engage_revoking("2026-07-13T00:00:00Z", &mut ledger).unwrap();

        // In-memory flip happened…
        assert!(ks.is_engaged());
        assert_eq!(ks.engaged_at(), Some("2026-07-13T00:00:00Z"));
        assert!(ks.bridge_decision().is_deny());
        // …AND the cross-crate revoke fanned out with the pinned reason.
        assert_eq!(revoked, 3);
        assert_eq!(ledger.live, 0);
        assert_eq!(ledger.revoked_calls, 1);
        assert_eq!(ledger.last_reason.as_deref(), Some(BRIDGE_KILL_REVOKE_REASON));

        // Idempotent on the ledger side: a second engage revokes 0 (already empty).
        let again = ks.engage_revoking("2026-07-13T00:00:01Z", &mut ledger).unwrap();
        assert_eq!(again, 0);
    }

    #[test]
    fn a_failing_ledger_revoke_leaves_the_lane_cut_fail_closed() {
        let mut ks = BridgeKillSwitch::new();
        let mut ledger = FailingLedger;

        // The cross-crate revoke errors — but the local flip already happened, so
        // the bridge is cut, never left half-open on a downstream failure.
        let err = ks.engage_revoking("2026-07-13T00:00:00Z", &mut ledger).unwrap_err();
        assert_eq!(err, "ledger persist failed");
        assert!(ks.is_engaged(), "the lane must stay cut even if the ledger revoke failed");
        assert!(ks.bridge_decision().is_deny());
    }

    #[test]
    fn the_revoke_reason_states_it_destroys_no_keys_or_pairings() {
        assert!(BRIDGE_KILL_REVOKE_REASON.contains("untouched"));
        assert!(BRIDGE_KILL_REVOKE_REASON.contains("no key material"));
        assert!(BRIDGE_KILL_REVOKE_REASON.contains("will not reopen"));
    }

    #[test]
    fn enforcement_is_userland_and_never_rounds_up() {
        let ks = BridgeKillSwitch::new();
        assert!(!BRIDGE_ENFORCEMENT.satisfies(EnforcementMode::KernelBoundary));
        assert!(BRIDGE_ENFORCEMENT.satisfies(EnforcementMode::ByConstruction));
        assert_eq!(
            ks.honest_enforcement_label(),
            EnforcementMode::ByConstruction.honest_label()
        );
    }
}
