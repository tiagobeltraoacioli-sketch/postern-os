// SPDX-License-Identifier: MIT OR Apache-2.0
//! # The two-world signer: one keyring, two doors, one door at a time
//!
//! [`WorldSigner`] is one physical phone's presence in **one** world: a
//! `PhoneApprover` bound to that world's session and named with that world's
//! badged `peer_device`. [`TwoWorldSigner`] holds **exactly two** of them — one
//! per world — plus the NoporIS-only [`BridgeKillSwitch`]. There is deliberately
//! **no** shared approver and **no** cross-world approval primitive:
//!
//! - **Fail-closed session binding.** Each world's approver carries its own
//!   `ReplayGuard(session_id)`. A request bearing world A's `session_id` handed to
//!   world B's approver is rejected `WrongSession` — a grant (or any request) for
//!   the Google-Play peer can *never* auto-approve the Porog peer.
//! - **Grant isolation.** A grant is minted with the world-badged `peer_device`
//!   and attached to that world's approver only. `covered_by_grant` on the other
//!   world consults a *different* approver with a *different* `peer_device`, so it
//!   is `false` for two independent reasons.
//! - **World-badged WYSIWYS, no new wire data.** The rendered
//!   `Pending::wysiwys.peer_device` carries the world badge because the approver
//!   was *named* with it at construction — derived from the pairing, never from
//!   the request. [`WorldSigner::world_badge_matches`] lets a surface refuse a
//!   prompt whose badge doesn't match the lane it is drawn on.
//! - **The kill-switch never spans into the door.** [`TwoWorldSigner::receive_on`]
//!   consults the bridge kill-switch **only** for NoporIS; Porog never does.
//!
//! HONEST LABEL: by default the signer is a `ScaffoldSigner` — a deterministic
//! SHA3 stand-in, **NOT real cryptography**. The real hybrid Falcon‖ML-DSA signer
//! (`postern-mobile-signer`'s `WalletCoreSigner`) is behind the `wallet-core`
//! feature. Even there the PQ key is in RAM at sign time — software signing with
//! at-rest protection, **not a hardware wallet**. Grant enforcement is a userland,
//! in-process check, not an OS boundary. A rooted host defeats all of this.

use postern_signer_protocol::{
    ApprovalGrant, Channel, GrantScope, Pending, PhoneApprover, ProtocolError, SessionId,
    WalletSigner,
};

use crate::killswitch::{BridgeKillSwitch, ConsentRevoker};
use crate::world::World;

/// Errors from the glue layer. Cross-world misrouting surfaces here as
/// [`GlueError::Protocol`] wrapping `ProtocolError::WrongSession` — the fail-closed
/// session binding doing its job.
#[derive(Debug, thiserror::Error)]
pub enum GlueError {
    /// The underlying signer protocol refused (replay guard, undecodable payload,
    /// wrong session, declined, …). `WrongSession` here is the cross-world
    /// fail-closed.
    #[error("signer protocol: {0}")]
    Protocol(#[from] ProtocolError),

    /// The NoporIS bridge kill-switch is engaged: the lane is cut and will not
    /// reopen until disengaged. Sealed wallet state and both pairings are
    /// untouched.
    #[error(
        "NoporIS bridge kill-switch engaged: the bridge lane is cut and will not reopen until \
         disengaged; sealed wallet state and both pairings are untouched"
    )]
    BridgeCut,
}

/// One phone's presence in ONE world: a session-bound, world-named approver.
///
/// The world badge lives in `peer_device`, which is what the rendered WYSIWYS
/// carries — so it is derived from the pairing this signer was built for, never
/// from the request.
pub struct WorldSigner<S: WalletSigner> {
    world: World,
    session_id: SessionId,
    /// The world-badged peer_device string (reused as the WYSIWYS field).
    peer_device: String,
    approver: PhoneApprover<S>,
}

impl<S: WalletSigner> WorldSigner<S> {
    /// Bind `signer` to `world`'s pairing (`session_id`) and name the counterpart
    /// with the world-badged `peer_device`. `peer_nickname` is the human label the
    /// phone learned at pairing (e.g. "Tiago's Chromebook").
    pub fn new(
        world: World,
        signer: S,
        session_id: SessionId,
        peer_nickname: impl AsRef<str>,
    ) -> Self {
        let peer_device = world.peer_device(peer_nickname.as_ref());
        let approver = PhoneApprover::new(signer, session_id, peer_device.clone());
        WorldSigner {
            world,
            session_id,
            peer_device,
            approver,
        }
    }

    /// Which world this signer serves.
    pub fn world(&self) -> World {
        self.world
    }

    /// This world's session id (the pairing binding).
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The world-badged peer_device carried into every WYSIWYS from this lane.
    pub fn peer_device(&self) -> &str {
        &self.peer_device
    }

    /// The wallet address (public).
    pub fn address(&self) -> String {
        self.approver.address()
    }

    /// Mint a time-boxed, revocable **login** grant for this world only, bound to
    /// this world's badged `peer_device`. Never covers a value transfer (the
    /// scope is `LoginTo` and the tier gate is byte-derived). Because the grant's
    /// peer_device is the world-badged string, it can *only* ever match this
    /// world's approver — the other world's peer_device differs.
    pub fn set_login_grant(&mut self, org: impl Into<String>, expires_at_unix: i64) {
        let grant = ApprovalGrant::new(
            self.peer_device.clone(),
            GrantScope::LoginTo { org: org.into() },
            expires_at_unix,
        );
        self.approver.set_grant(grant);
    }

    /// **Revocation surface #1 — soft, per-world, per-scope.** "Stop auto-approving
    /// logins for this side." Monotonic; a revoked grant collapses to "never
    /// given".
    pub fn revoke_grant(&mut self) {
        self.approver.revoke_grant();
    }

    /// Receive and validate the next request on this world's channel (replay
    /// guard + WYSIWYS render), fail-closed. A request from another world's
    /// session is rejected `WrongSession` here.
    pub fn receive<C: Channel>(&mut self, channel: &mut C) -> Result<Pending, GlueError>
    where
        C::Error: std::fmt::Display,
    {
        Ok(self.approver.receive(channel)?)
    }

    /// Would a live grant auto-approve this single-tap login without a prompt?
    /// Only ever true for a single-tap login covered by *this world's* grant.
    pub fn covered_by_grant(&self, pending: &Pending, now_unix: i64) -> bool {
        self.approver.covered_by_grant(pending, now_unix)
    }

    /// Approve and sign (after the human confirmed, or a single-tap grant
    /// covered it). Sends the `Approval` on the channel.
    pub fn approve<C: Channel>(
        &mut self,
        channel: &mut C,
        pending: Pending,
    ) -> Result<postern_signer_protocol::Approval, GlueError>
    where
        C::Error: std::fmt::Display,
    {
        Ok(self.approver.approve(channel, pending)?)
    }

    /// Decline: nothing is signed and the guard is not committed (as if the
    /// request never arrived). Returns the protocol's `Declined`.
    pub fn decline(&mut self, pending: Pending) -> Result<(), GlueError> {
        Ok(self.approver.decline(pending)?)
    }

    /// Honesty guard for the UI: does this pending prompt's badge match the lane
    /// it is drawn on? A surface should refuse to render a Porog badge on the
    /// NoporIS lane (or vice-versa). Since the badge is derived from the pairing,
    /// a compromised desktop cannot mislabel its world — but this catches a wiring
    /// bug in the app layer, fail-closed.
    pub fn world_badge_matches(&self, pending: &Pending) -> bool {
        pending.wysiwys.peer_device.starts_with(self.world.badge())
    }

    /// The real WalletCore-backed constructor (feature `wallet-core`). Consumes
    /// `postern-mobile-signer`'s `WalletCoreSigner` (hybrid Falcon‖ML-DSA). Pulls
    /// the heavyweight PQ crypto; not built by default. Still NOT a hardware
    /// wallet.
    #[cfg(feature = "wallet-core")]
    pub fn from_mnemonic(
        world: World,
        phrase: &str,
        testnet: bool,
        session_id: SessionId,
        peer_nickname: impl AsRef<str>,
    ) -> Result<WorldSigner<postern_mobile_signer::WalletCoreSigner>, GlueError> {
        let signer = postern_mobile_signer::WalletCoreSigner::from_mnemonic(phrase, testnet)
            .map_err(ProtocolError::from)?;
        Ok(WorldSigner::new(world, signer, session_id, peer_nickname))
    }
}

/// One phone standing between the two worlds. Holds exactly two independent
/// [`WorldSigner`]s and the NoporIS-only [`BridgeKillSwitch`]. There is no master
/// approval that opens both doors.
pub struct TwoWorldSigner<S: WalletSigner> {
    porog: WorldSigner<S>,
    noporis: WorldSigner<S>,
    bridge_kill: BridgeKillSwitch,
}

impl<S: WalletSigner> TwoWorldSigner<S> {
    /// Assemble from the two per-world signers. Panics if the worlds are swapped —
    /// a wiring bug that must fail loudly, never silently cross the bridge.
    pub fn new(porog: WorldSigner<S>, noporis: WorldSigner<S>) -> Self {
        assert_eq!(
            porog.world(),
            World::Porog,
            "the Porog lane must serve World::Porog"
        );
        assert_eq!(
            noporis.world(),
            World::Noporis,
            "the NoporIS lane must serve World::Noporis"
        );
        TwoWorldSigner {
            porog,
            noporis,
            bridge_kill: BridgeKillSwitch::new(),
        }
    }

    /// Read-only access to one world's signer.
    pub fn world(&self, world: World) -> &WorldSigner<S> {
        match world {
            World::Porog => &self.porog,
            World::Noporis => &self.noporis,
        }
    }

    /// Mutable access to one world's signer.
    pub fn world_mut(&mut self, world: World) -> &mut WorldSigner<S> {
        match world {
            World::Porog => &mut self.porog,
            World::Noporis => &mut self.noporis,
        }
    }

    /// The NoporIS bridge kill-switch (read-only).
    pub fn bridge_kill(&self) -> &BridgeKillSwitch {
        &self.bridge_kill
    }

    /// **Revocation surface #3 — engage the bridge kill-switch.** Cuts the NoporIS
    /// lane; the door (Porog) and the keys are untouched. This is the *local-only*
    /// flip; to also fan the revocation out to the orchestrator's consent ledger
    /// (the full kill signal), use [`engage_bridge_kill_revoking`](Self::engage_bridge_kill_revoking).
    pub fn engage_bridge_kill(&mut self, now_iso: impl Into<String>) {
        self.bridge_kill.engage(now_iso);
    }

    /// **Revocation surface #3, with fan-out.** Engage the bridge kill-switch AND
    /// signal `ledger` (the orchestrator's `ConsentLedger`, via the
    /// [`ConsentRevoker`] port) to revoke every live bridge consent. The NoporIS
    /// lane is cut fail-closed first (local flip), then the cross-crate revoke fans
    /// out; a failing ledger revoke still leaves the lane cut. Returns how many
    /// consents were revoked. Porog and the keys are untouched. See
    /// [`BridgeKillSwitch::engage_revoking`].
    pub fn engage_bridge_kill_revoking<R: ConsentRevoker>(
        &mut self,
        now_iso: impl Into<String>,
        ledger: &mut R,
    ) -> Result<usize, R::Error> {
        self.bridge_kill.engage_revoking(now_iso, ledger)
    }

    /// Disengage the bridge kill-switch (explicit; never lapses on a timer).
    pub fn disengage_bridge_kill(&mut self) {
        self.bridge_kill.disengage();
    }

    /// Receive on the NAMED world's lane. The world is supplied by the caller from
    /// *which pairing/transport the channel belongs to* — never from the request
    /// bytes. For NoporIS, an engaged kill-switch cuts the lane fail-closed
    /// ([`GlueError::BridgeCut`]) before any receive; Porog never consults it.
    pub fn receive_on<C: Channel>(
        &mut self,
        world: World,
        channel: &mut C,
    ) -> Result<Pending, GlueError>
    where
        C::Error: std::fmt::Display,
    {
        if world.has_bridge_kill_switch() && self.bridge_kill.is_engaged() {
            return Err(GlueError::BridgeCut);
        }
        self.world_mut(world).receive(channel)
    }

    /// **Revocation surface #1**, routed to the named world's signer.
    pub fn revoke_grant(&mut self, world: World) {
        self.world_mut(world).revoke_grant();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postern_signer_protocol::{
        loopback, new_session_id, DesktopRequester, LoginChallenge, ScaffoldSigner,
    };

    fn scaffold(seed: &[u8]) -> ScaffoldSigner {
        ScaffoldSigner::from_seed(seed)
    }

    fn login(org: &str) -> LoginChallenge {
        LoginChallenge {
            org: org.to_string(),
            user: "tiago".to_string(),
            nonce: [7u8; 32],
            issued_at: 1_800_000_000,
        }
    }

    // Build a two-world signer with distinct sessions per world.
    fn two_worlds() -> (TwoWorldSigner<ScaffoldSigner>, SessionId, SessionId) {
        let porog_sid = new_session_id();
        let noporis_sid = new_session_id();
        let porog = WorldSigner::new(World::Porog, scaffold(b"porog-seed"), porog_sid, "ThinkPad");
        let noporis = WorldSigner::new(
            World::Noporis,
            scaffold(b"noporis-seed"),
            noporis_sid,
            "Chromebook",
        );
        (TwoWorldSigner::new(porog, noporis), porog_sid, noporis_sid)
    }

    #[test]
    fn a_request_for_one_world_fails_closed_on_the_other() {
        let (mut tws, _porog_sid, noporis_sid) = two_worlds();

        // A NoporIS-session login, delivered to the PROG lane, must be rejected
        // WrongSession — the fail-closed session binding. There is no cross-world
        // approval.
        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new(noporis_sid);
        requester.request_login(&mut desk, &login("acme")).unwrap();

        let err = tws.receive_on(World::Porog, &mut phone).unwrap_err();
        assert!(
            matches!(err, GlueError::Protocol(ProtocolError::WrongSession)),
            "cross-world request must fail closed with WrongSession, got {err:?}"
        );
    }

    #[test]
    fn a_grant_on_noporis_never_auto_approves_porog() {
        let (mut tws, porog_sid, _noporis_sid) = two_worlds();

        // Grant single-tap logins to "acme" on the NoporIS (Google-Play) side.
        let far_future = 4_102_444_800; // year 2100
        tws.world_mut(World::Noporis)
            .set_login_grant("acme", far_future);

        // A genuine PROG-session login for the same org arrives on the Porog lane.
        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new(porog_sid);
        requester.request_login(&mut desk, &login("acme")).unwrap();
        let pending = tws.receive_on(World::Porog, &mut phone).unwrap();

        // Porog has NO grant of its own, and even if it consulted NoporIS's grant
        // the peer_device (world badge) differs — so it is NOT auto-approved. It
        // must go to an explicit prompt.
        assert!(
            !tws.world(World::Porog)
                .covered_by_grant(&pending, 1_800_000_100),
            "a Google-Play-side grant must never auto-approve the Porog peer"
        );
        // The prompt is badged for the hardened world it actually arrived on.
        assert!(tws.world(World::Porog).world_badge_matches(&pending));
        assert!(pending
            .wysiwys
            .peer_device
            .starts_with(World::Porog.badge()));
    }

    #[test]
    fn a_grant_does_auto_approve_within_its_own_world() {
        let (mut tws, _porog_sid, noporis_sid) = two_worlds();
        let far_future = 4_102_444_800;
        tws.world_mut(World::Noporis)
            .set_login_grant("acme", far_future);

        // Same-world single-tap login IS covered (contrast to the isolation test).
        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new(noporis_sid);
        requester.request_login(&mut desk, &login("acme")).unwrap();
        let pending = tws.receive_on(World::Noporis, &mut phone).unwrap();

        assert!(pending.is_single_tap());
        assert!(tws
            .world(World::Noporis)
            .covered_by_grant(&pending, 1_800_000_100));
        // The NoporIS badge is on the prompt — the "less private" fact travels.
        assert!(pending.wysiwys.peer_device.contains("less private"));
    }

    #[test]
    fn kill_switch_cuts_the_bridge_but_not_the_door() {
        let (mut tws, porog_sid, noporis_sid) = two_worlds();
        tws.engage_bridge_kill("2026-07-12T23:59:00Z");

        // NoporIS lane is cut, fail-closed, before any receive.
        {
            let (mut desk, mut phone) = loopback();
            let mut requester = DesktopRequester::new(noporis_sid);
            requester.request_login(&mut desk, &login("acme")).unwrap();
            let err = tws.receive_on(World::Noporis, &mut phone).unwrap_err();
            assert!(matches!(err, GlueError::BridgeCut));
        }

        // The door (Porog) is untouched — it still receives and its keyring is
        // intact (the kill-switch holds no wallet/pairing state to destroy).
        {
            let (mut desk, mut phone) = loopback();
            let mut requester = DesktopRequester::new(porog_sid);
            requester
                .request_login(&mut desk, &login("hardened-org"))
                .unwrap();
            let pending = tws.receive_on(World::Porog, &mut phone).unwrap();
            assert!(tws.world(World::Porog).world_badge_matches(&pending));
        }
    }

    // A stand-in for Dev B's ConsentLedger public revoke surface.
    #[derive(Default)]
    struct MockLedger {
        live: usize,
        revoked: bool,
    }
    impl ConsentRevoker for MockLedger {
        type Error = core::convert::Infallible;
        fn revoke_all(&mut self, _reason: &str) -> Result<usize, Self::Error> {
            let n = self.live;
            self.live = 0;
            self.revoked = true;
            Ok(n)
        }
    }

    #[test]
    fn engaging_the_kill_fans_out_to_the_ledger_and_still_spares_the_door() {
        let (mut tws, porog_sid, noporis_sid) = two_worlds();
        let mut ledger = MockLedger {
            live: 2,
            ..Default::default()
        };

        // Full kill signal: local flip + cross-crate consent revoke.
        let revoked = tws
            .engage_bridge_kill_revoking("2026-07-13T00:00:00Z", &mut ledger)
            .unwrap();
        assert_eq!(revoked, 2, "every live bridge consent must be revoked");
        assert!(ledger.revoked);
        assert!(tws.bridge_kill().is_engaged());

        // NoporIS lane is cut, fail-closed.
        {
            let (mut desk, mut phone) = loopback();
            let mut requester = DesktopRequester::new(noporis_sid);
            requester.request_login(&mut desk, &login("acme")).unwrap();
            let err = tws.receive_on(World::Noporis, &mut phone).unwrap_err();
            assert!(matches!(err, GlueError::BridgeCut));
        }
        // The door (Porog) still receives — the fan-out never crossed the bridge.
        {
            let (mut desk, mut phone) = loopback();
            let mut requester = DesktopRequester::new(porog_sid);
            requester.request_login(&mut desk, &login("hardened")).unwrap();
            let pending = tws.receive_on(World::Porog, &mut phone).unwrap();
            assert!(tws.world(World::Porog).world_badge_matches(&pending));
        }
    }

    #[test]
    fn revoking_a_grant_collapses_it_to_never_given() {
        let (mut tws, _porog_sid, noporis_sid) = two_worlds();
        let far_future = 4_102_444_800;
        tws.world_mut(World::Noporis)
            .set_login_grant("acme", far_future);
        tws.revoke_grant(World::Noporis); // surface #1

        let (mut desk, mut phone) = loopback();
        let mut requester = DesktopRequester::new(noporis_sid);
        requester.request_login(&mut desk, &login("acme")).unwrap();
        let pending = tws.receive_on(World::Noporis, &mut phone).unwrap();
        assert!(
            !tws.world(World::Noporis)
                .covered_by_grant(&pending, 1_800_000_100),
            "a revoked grant must collapse to 'never given'"
        );
    }

    #[test]
    #[should_panic(expected = "must serve World::Porog")]
    fn swapping_the_worlds_fails_loudly() {
        // A wiring bug that would cross the bridge must panic, never silently pass.
        let a = WorldSigner::new(World::Noporis, scaffold(b"a"), new_session_id(), "x");
        let b = WorldSigner::new(World::Noporis, scaffold(b"b"), new_session_id(), "y");
        let _ = TwoWorldSigner::new(a, b);
    }
}
