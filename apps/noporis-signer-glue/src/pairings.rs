// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `WorldPairings` — two independent pairings, structurally separated
//!
//! The load-bearing honesty of the whole design: one physical phone holds **two
//! independent pairings**, one per world, and never one signer that spans the
//! bridge. This type makes that *structural* rather than a matter of discipline:
//! it holds **two separate [`PairedTerminals`] collections** — the Porog store
//! and the NoporIS store — each with its own storage KEK. A record sealed in one
//! world's store is not reachable from the other world's manager, so:
//!
//! - **Unpairing one world can never strand or expose the other**
//!   ([`WorldPairings::unpair`], revocation surface #2). It calls
//!   [`PairedTerminals::revoke`] on that world's store only — wipe the record in
//!   RAM (peer pin + `session_root`) and **delete** the sealed blob (monotonic;
//!   there is no un-revoke).
//! - A lookup for a Porog `TerminalId` in the NoporIS store simply isn't there.
//!
//! This composes `postern-pairing`; it does not reimplement any of it. The Dev
//! layer supplies each world's concrete [`RecordStore`] (`postern-vault` on
//! desktop, StrongBox/SE-wrapped on mobile); an in-memory store is fine for
//! tests/demos.

use postern_pairing::{
    PairedTerminals, PairingRecord, RecordStore, TerminalId, TerminalInfo, TerminalsError,
};

use crate::world::World;

/// The two per-world pairing collections a single phone manages. `S` is the
/// backing store type; each world gets its **own** instance and its own KEK, so
/// the two worlds are separated by construction, not by convention.
pub struct WorldPairings<S: RecordStore> {
    porog: PairedTerminals<S>,
    noporis: PairedTerminals<S>,
}

impl<S: RecordStore> WorldPairings<S> {
    /// Build the manager over two already-constructed [`PairedTerminals`], one per
    /// world. The caller seals each with its own KEK — they are never the same
    /// collection, so nothing can cross between them.
    pub fn new(porog: PairedTerminals<S>, noporis: PairedTerminals<S>) -> Self {
        WorldPairings { porog, noporis }
    }

    /// Read-only access to one world's collection.
    pub fn world(&self, world: World) -> &PairedTerminals<S> {
        match world {
            World::Porog => &self.porog,
            World::Noporis => &self.noporis,
        }
    }

    /// Mutable access to one world's collection.
    pub fn world_mut(&mut self, world: World) -> &mut PairedTerminals<S> {
        match world {
            World::Porog => &mut self.porog,
            World::Noporis => &mut self.noporis,
        }
    }

    /// Persist a freshly SAS-confirmed record into the named world's store.
    /// Returns its stable, non-secret [`TerminalId`].
    pub fn add(
        &mut self,
        world: World,
        record: &PairingRecord,
    ) -> Result<TerminalId, TerminalsError<S::Error>> {
        self.world_mut(world).add(record)
    }

    /// UI-safe summaries of one world's paired terminals (never any secret).
    pub fn list(&self, world: World) -> Result<Vec<TerminalInfo>, TerminalsError<S::Error>> {
        self.world(world).list()
    }

    /// **Revocation surface #2 — hard unpair, per world.** "Unpair the NoporIS
    /// side." Wipes the record in RAM and deletes its sealed blob from **that
    /// world's store only**. The other world's pairing is untouched — a different
    /// collection, a different KEK, a different forward-secret session.
    pub fn unpair(
        &mut self,
        world: World,
        id: &TerminalId,
    ) -> Result<(), TerminalsError<S::Error>> {
        self.world_mut(world).revoke(id)
    }

    /// Panic / duress: evict **every** paired terminal in **both** worlds at once
    /// (the hook a `postern-panic` re-lock calls). After this, every terminal in
    /// either world needs a fresh 6-digit SAS ceremony to pair again. Returns the
    /// total number of terminals evicted.
    pub fn panic_revoke_all(&mut self) -> Result<usize, TerminalsError<S::Error>> {
        let a = self.porog.panic_revoke_all()?;
        let b = self.noporis.panic_revoke_all()?;
        Ok(a + b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postern_pairing::demo::pair_and_talk; // ensures the ceremony crate is linked
    use postern_pairing::MemStore;

    // Produce a genuine custodian-side PairingRecord by running the real pairing
    // ceremony (ML-KEM-1024 + X25519 + SAS) with world/peer-specific identities.
    // PairingRecord::new is pub(crate), so a downstream crate MUST get records
    // this honest way — never by fabricating one.
    fn paired_record(world: World, peer_tag: &str) -> PairingRecord {
        use postern_pairing::transport::{LoopbackPair, Transport};
        use postern_pairing::{Pairing, PairingInit, QrPayload};

        let desktop_identity = format!("desktop-{}-{}", world.name(), peer_tag).into_bytes();
        let phone_identity = format!("phone-{}-{}", world.name(), peer_tag).into_bytes();

        let (pending, qr) = Pairing::begin_desktop(
            world.peer_device(peer_tag),
            "192.168.1.20:47001",
            desktop_identity,
        );
        let scanned = QrPayload::from_bytes(&qr.to_bytes()).unwrap();
        let (phone_confirm, init) =
            Pairing::scan_desktop_qr(&scanned, "Phone", phone_identity).unwrap();

        let (mut phone_link, mut desk_link) = LoopbackPair::new();
        phone_link.send(&init.to_bytes()).unwrap();
        let init_parsed = PairingInit::from_bytes(&desk_link.recv().unwrap()).unwrap();
        let desk_confirm = pending.accept(&init_parsed).unwrap();
        assert!(phone_confirm.sas().matches(desk_confirm.sas()));

        // The phone (custodian) side is the credential we manage.
        let (phone_rec, _ch) = phone_confirm.confirm_sas(true).unwrap();
        phone_rec
    }

    fn manager() -> WorldPairings<MemStore> {
        WorldPairings::new(
            PairedTerminals::new(MemStore::new(), [1u8; 32]),
            PairedTerminals::new(MemStore::new(), [2u8; 32]),
        )
    }

    #[test]
    fn ceremony_is_reachable_from_this_crate() {
        // Sanity: the pairing crate (and its ceremony) is linked and offline-runs.
        let got = pair_and_talk(b"hello", true).unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn unpairing_one_world_leaves_the_other_untouched() {
        let mut wp = manager();
        let porog_id = wp
            .add(World::Porog, &paired_record(World::Porog, "ThinkPad"))
            .unwrap();
        let noporis_id = wp
            .add(World::Noporis, &paired_record(World::Noporis, "Chromebook"))
            .unwrap();

        assert_eq!(wp.list(World::Porog).unwrap().len(), 1);
        assert_eq!(wp.list(World::Noporis).unwrap().len(), 1);

        // Hard-unpair the NoporIS side.
        wp.unpair(World::Noporis, &noporis_id).unwrap();

        // NoporIS gone; Porog fully intact.
        assert!(wp.list(World::Noporis).unwrap().is_empty());
        let porog = wp.list(World::Porog).unwrap();
        assert_eq!(porog.len(), 1);
        assert_eq!(porog[0].id, porog_id);
        // Monotonic: re-unpairing the now-absent NoporIS terminal is a clean
        // NotFound (no un-revoke, nothing to resurrect).
        assert_eq!(
            wp.unpair(World::Noporis, &noporis_id),
            Err(TerminalsError::NotFound)
        );
    }

    #[test]
    fn a_porog_id_is_not_reachable_in_the_noporis_store() {
        let mut wp = manager();
        let porog_id = wp
            .add(World::Porog, &paired_record(World::Porog, "ThinkPad"))
            .unwrap();
        // Structural separation: the Porog id simply is not in the NoporIS store.
        assert_eq!(
            wp.unpair(World::Noporis, &porog_id),
            Err(TerminalsError::NotFound)
        );
        // …and it is still present in its own world.
        assert_eq!(wp.list(World::Porog).unwrap().len(), 1);
    }

    #[test]
    fn panic_revoke_evicts_both_worlds() {
        let mut wp = manager();
        wp.add(World::Porog, &paired_record(World::Porog, "A"))
            .unwrap();
        wp.add(World::Noporis, &paired_record(World::Noporis, "B"))
            .unwrap();
        let n = wp.panic_revoke_all().unwrap();
        assert_eq!(n, 2);
        assert!(wp.list(World::Porog).unwrap().is_empty());
        assert!(wp.list(World::Noporis).unwrap().is_empty());
    }
}
