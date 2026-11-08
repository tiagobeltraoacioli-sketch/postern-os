//! Recipient-side anti-replay window for Courier drops.
//!
//! A [`ReplayGuard`] is state a **recipient** holds per identity (one guard,
//! reused across every sender it talks to, or one per sender — the caller's
//! choice). It answers exactly one question: "have I already seen this
//! `(nonce, timestamp)` pair recently?" — rejecting a duplicate nonce and
//! rejecting a timestamp that falls outside a configured freshness window.
//!
//! HONEST LIMITS (do not soften; read before relying on this):
//!
//! - **Recipient-side, in-process state only.** A [`ReplayGuard`] lives in the
//!   recipient process's memory. It is never written to disk and never shared
//!   between processes or machines.
//! - **Does not persist across restarts.** Restart the recipient process (or
//!   simply construct a fresh `ReplayGuard`) and every previously-recorded
//!   `(nonce, timestamp)` is forgotten — a payload replayed after a restart is
//!   accepted again as if it were new. Give a `ReplayGuard` the process
//!   lifetime you need, or persist the seen-set yourself; this module does not.
//! - **Does not protect the unsigned seal path.** A bare [`crate::SealedPayload`]
//!   produced by [`crate::seal`] carries **no nonce and no timestamp at all** —
//!   there is nothing in it for a `ReplayGuard` to check. This module only
//!   helps once a caller separately obtains a `(nonce, timestamp)` pair it is
//!   willing to trust and hands it to [`ReplayGuard::check_and_record`] (or
//!   implements [`ReplayCheckable`] on whatever typed payload carries those
//!   fields). Nothing here inspects or requires a [`crate::SealedPayload`].
//! - **Only narrows replay to inside the window.** A duplicate presented again
//!   after its original entry has aged out of the window is *not* caught —
//!   that is the deliberate bound of a windowed guard, not an oversight. A
//!   wider window catches more replays at the cost of more retained state (and
//!   a bigger allowed clock-skew target for an attacker); see
//!   [`DEFAULT_WINDOW`].
//! - **Nothing here authenticates anything.** The nonce and timestamp are
//!   whatever the caller passes in — this module does not verify they were
//!   ever bound to a specific sender or payload. That binding (a PQ signature
//!   over a transcript including the nonce and timestamp) is sender
//!   authentication, which lives in the separate, opt-in [`crate::sender_auth`]
//!   module — see the crate-level "Sender authentication is OPT-IN" honest
//!   limit. A caller who feeds this guard a nonce/timestamp it has NOT first
//!   verified via [`crate::sender_auth::verify_sealed`] gets no protection
//!   from an attacker who simply mints a fresh nonce and a current timestamp
//!   for a forged or replayed payload.
//! - **This is NOT a claim that the transport is secure.** See the crate-level
//!   docs and the `transport` module docs (behind the `onion-transport`
//!   feature): the onion drop's wire frame still has no auth and no
//!   anti-replay of its own. This module (paired with [`crate::sender_auth`])
//!   is the recipient-side, payload-layer check a recipient opts into on top —
//!   it does not harden the transport frame itself.
//!
//! # Memory safety under flooding
//!
//! A recipient that calls [`ReplayGuard::check_and_record`] once per inbound
//! nonce is exposed to a flooding peer that mints unique nonces forever.
//! `check_and_record`:
//! 1. **Prunes expired entries on every call** — anything older than the
//!    window is dropped before the new entry is considered, so a guard that is
//!    only ever fed fresh, in-window nonces self-bounds to roughly
//!    `window / (average call interval)` entries.
//! 2. **Enforces a hard cap** ([`DEFAULT_MAX_ENTRIES`], overridable via
//!    [`ReplayGuard::with_max_entries`]) independent of pruning. When recording
//!    a new entry would exceed the cap, the single **oldest** entry (by
//!    timestamp) is evicted first — documented choice over rejecting the new
//!    entry, so a burst of legitimate traffic that transiently exceeds the cap
//!    keeps working rather than hard-failing. The honest cost: under sustained
//!    flooding, evict-oldest can push a genuine recent entry out before it
//!    naturally expires, narrowing its effective protection to less than the
//!    configured window. Either way the entry count **never exceeds the cap**,
//!    so memory is bounded regardless of how many unique nonces a peer sends.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::CourierError;

/// Default anti-replay freshness window: 10 minutes. Wide enough to absorb
/// realistic clock drift and network delay for a live drop, narrow enough that
/// the guard's retained state stays small for normal traffic.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Default allowed forward clock skew: how far into the future a timestamp may
/// claim to be (relative to the recipient's clock) and still be accepted. Small
/// on purpose — this is slack for clock drift between sender and recipient,
/// not a second freshness window.
pub const DEFAULT_SKEW: Duration = Duration::from_secs(30);

/// Default hard cap on stored `(nonce, timestamp)` entries per [`ReplayGuard`].
/// Bounds worst-case memory to roughly `cap * 40 bytes` regardless of how many
/// unique nonces a flooding peer sends.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Something that carries the two fields a [`ReplayGuard`] checks — a per-drop
/// nonce and the Unix-seconds timestamp it claims to have been sealed at.
///
/// The concrete implementor in this crate is
/// [`crate::sender_auth::SignedSealedPayload`] — the opt-in PQ
/// sender-authentication wrapper whose ML-DSA-87 transcript binds the nonce
/// and timestamp to the sealed payload, so a recipient that calls
/// [`crate::sender_auth::verify_sealed`] first can trust the values it then
/// hands to [`ReplayGuard::check_and_record_payload`]. The trait stays open so
/// any future authenticated payload type can plug in unchanged; implementing
/// it does NOT by itself mean the nonce/timestamp are authenticated — that is
/// the implementor's (and its verifier's) job, never this module's.
pub trait ReplayCheckable {
    /// The per-drop nonce to check for reuse.
    fn replay_nonce(&self) -> &[u8; 32];
    /// The Unix-seconds timestamp to check against the freshness window.
    fn replay_timestamp_secs(&self) -> u64;
}

/// A recipient-side anti-replay guard: a freshness window plus a per-nonce
/// cache. See the module docs for the honest limits before relying on this.
pub struct ReplayGuard {
    window_secs: u64,
    skew_secs: u64,
    max_entries: usize,
    /// `nonce -> timestamp_secs`, for O(1) duplicate-nonce lookup.
    by_nonce: HashMap<[u8; 32], u64>,
    /// `(timestamp_secs, nonce) -> ()`, ordered so the smallest key is always
    /// the oldest (soonest to expire) entry — gives O(log n) pruning and
    /// evict-oldest instead of an O(n) scan on every call.
    by_time: BTreeMap<(u64, [u8; 32]), ()>,
}

impl ReplayGuard {
    /// A guard with the given freshness `window` and the documented defaults
    /// for everything else ([`DEFAULT_SKEW`], [`DEFAULT_MAX_ENTRIES`]). Use
    /// [`ReplayGuard::with_skew`] / [`ReplayGuard::with_max_entries`] to
    /// override either.
    pub fn new(window: Duration) -> Self {
        Self {
            window_secs: window.as_secs(),
            skew_secs: DEFAULT_SKEW.as_secs(),
            max_entries: DEFAULT_MAX_ENTRIES,
            by_nonce: HashMap::new(),
            by_time: BTreeMap::new(),
        }
    }

    /// A guard using [`DEFAULT_WINDOW`] and every other default. The
    /// recommended starting point absent a specific reason to tune it.
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_WINDOW)
    }

    /// Override the allowed forward clock skew (default [`DEFAULT_SKEW`]).
    pub fn with_skew(mut self, skew: Duration) -> Self {
        self.skew_secs = skew.as_secs();
        self
    }

    /// Override the hard cap on stored entries (default [`DEFAULT_MAX_ENTRIES`]).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.max(1);
        self
    }

    /// The number of entries currently retained (post-pruning as of the last
    /// call). Exposed for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.by_nonce.len()
    }

    /// `true` if no entries are currently retained.
    pub fn is_empty(&self) -> bool {
        self.by_nonce.is_empty()
    }

    /// Check `(nonce, timestamp_secs)` against the freshness window and the
    /// nonce cache **as of `now_secs`**, and record it on success.
    ///
    /// `now` is a parameter rather than read from the system clock so the
    /// guard's behavior is deterministic and testable; see
    /// [`ReplayGuard::check_and_record_now`] for the `SystemTime` convenience.
    ///
    /// Rejects (in this order):
    /// 1. [`CourierError::ReplayStale`] — `timestamp_secs` is older than
    ///    `now_secs - window`.
    /// 2. [`CourierError::ReplayFutureDated`] — `timestamp_secs` is further in
    ///    the future than `now_secs + skew`.
    /// 3. [`CourierError::ReplayNonceReused`] — `nonce` was already recorded
    ///    and has not yet aged out of the window.
    ///
    /// Expired entries are pruned before the checks above run, and the hard
    /// cap is enforced (evicting the single oldest entry if needed) before the
    /// new entry is recorded — see the module docs' "Memory safety under
    /// flooding" section.
    pub fn check_and_record(
        &mut self,
        nonce: &[u8; 32],
        timestamp_secs: u64,
        now_secs: u64,
    ) -> Result<(), CourierError> {
        self.prune(now_secs);

        let earliest_allowed = now_secs.saturating_sub(self.window_secs);
        if timestamp_secs < earliest_allowed {
            return Err(CourierError::ReplayStale);
        }
        let latest_allowed = now_secs.saturating_add(self.skew_secs);
        if timestamp_secs > latest_allowed {
            return Err(CourierError::ReplayFutureDated);
        }

        if self.by_nonce.contains_key(nonce) {
            return Err(CourierError::ReplayNonceReused);
        }

        if self.by_nonce.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.by_nonce.insert(*nonce, timestamp_secs);
        self.by_time.insert((timestamp_secs, *nonce), ());
        Ok(())
    }

    /// Convenience over [`ReplayGuard::check_and_record`] using the system
    /// clock for `now`. A pre-1970 (or otherwise unreadable) system clock
    /// fails **closed**: it is treated as `now_secs = 0`, which makes any real
    /// (positive) `timestamp_secs` read as future-dated rather than silently
    /// bypassing the check.
    pub fn check_and_record_now(
        &mut self,
        nonce: &[u8; 32],
        timestamp_secs: u64,
    ) -> Result<(), CourierError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.check_and_record(nonce, timestamp_secs, now_secs)
    }

    /// Convenience over [`ReplayGuard::check_and_record`] for any payload
    /// implementing [`ReplayCheckable`] — e.g. a future signed/authenticated
    /// drop type that carries a nonce and timestamp.
    pub fn check_and_record_payload<P: ReplayCheckable>(
        &mut self,
        payload: &P,
        now_secs: u64,
    ) -> Result<(), CourierError> {
        self.check_and_record(payload.replay_nonce(), payload.replay_timestamp_secs(), now_secs)
    }

    /// [`ReplayGuard::check_and_record_payload`] using the system clock for
    /// `now` (see [`ReplayGuard::check_and_record_now`] for the fail-closed
    /// clock-error behavior).
    pub fn check_and_record_payload_now<P: ReplayCheckable>(
        &mut self,
        payload: &P,
    ) -> Result<(), CourierError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.check_and_record_payload(payload, now_secs)
    }

    /// Drop every entry older than the window as of `now_secs`.
    fn prune(&mut self, now_secs: u64) {
        let earliest_allowed = now_secs.saturating_sub(self.window_secs);
        loop {
            let Some((&key, _)) = self.by_time.iter().next() else {
                break;
            };
            if key.0 >= earliest_allowed {
                break;
            }
            self.by_time.remove(&key);
            self.by_nonce.remove(&key.1);
        }
    }

    /// Evict the single oldest (smallest-timestamp) retained entry, if any.
    fn evict_oldest(&mut self) {
        if let Some((&key, _)) = self.by_time.iter().next() {
            self.by_time.remove(&key);
            self.by_nonce.remove(&key.1);
        }
    }
}

impl Default for ReplayGuard {
    /// [`ReplayGuard::with_default_window`].
    fn default() -> Self {
        Self::with_default_window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn fresh_nonce_in_window_is_accepted() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        assert!(guard.check_and_record(&nonce(1), 1_000, 1_000).is_ok());
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn second_presentation_of_same_nonce_and_timestamp_is_rejected() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        assert!(guard.check_and_record(&nonce(1), 1_000, 1_000).is_ok());
        let err = guard.check_and_record(&nonce(1), 1_000, 1_001).unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    #[test]
    fn same_nonce_with_different_timestamp_is_still_rejected() {
        // The nonce itself is the uniqueness key — an attacker replaying the
        // exact same nonce with a shifted timestamp must not slip through.
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        assert!(guard.check_and_record(&nonce(7), 1_000, 1_000).is_ok());
        let err = guard.check_and_record(&nonce(7), 1_050, 1_050).unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    #[test]
    fn stale_timestamp_is_rejected_even_with_a_fresh_nonce() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        // now = 10_000, window = 600 → anything older than 9_400 is stale.
        let err = guard.check_and_record(&nonce(2), 9_000, 10_000).unwrap_err();
        assert!(matches!(err, CourierError::ReplayStale));
        assert_eq!(guard.len(), 0, "a rejected entry must not be recorded");
    }

    #[test]
    fn future_dated_timestamp_beyond_skew_is_rejected() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600)).with_skew(Duration::from_secs(30));
        let err = guard.check_and_record(&nonce(3), 10_100, 10_000).unwrap_err();
        assert!(matches!(err, CourierError::ReplayFutureDated));
    }

    #[test]
    fn timestamp_within_skew_is_accepted() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600)).with_skew(Duration::from_secs(30));
        assert!(guard.check_and_record(&nonce(4), 10_020, 10_000).is_ok());
    }

    #[test]
    fn expired_entry_is_pruned_and_its_nonce_becomes_reusable() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        assert!(guard.check_and_record(&nonce(5), 1_000, 1_000).is_ok());
        // Advance far enough that the first entry ages out of the window —
        // pruning on the next call removes it, and the SAME nonce (now with a
        // fresh, in-window timestamp) is accepted again. This is the
        // documented "only narrows replay to inside the window" bound, not a
        // bug: a duplicate presented after expiry is not caught.
        assert!(guard.check_and_record(&nonce(5), 2_000, 2_000).is_ok());
        assert_eq!(guard.len(), 1, "the expired entry should have been pruned");
    }

    #[test]
    fn entry_count_never_exceeds_the_hard_cap_under_flooding() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600)).with_max_entries(50);
        // Flood with far more unique, always-fresh nonces than the cap, all
        // within the same instant so nothing ages out via pruning alone —
        // only the hard cap keeps this bounded.
        for i in 0u32..5_000 {
            let mut n = [0u8; 32];
            n[..4].copy_from_slice(&i.to_le_bytes());
            guard.check_and_record(&n, 1_000, 1_000).unwrap();
            assert!(guard.len() <= 50, "entry count exceeded the hard cap at i={i}");
        }
        assert_eq!(guard.len(), 50);
    }

    #[test]
    fn hard_cap_evicts_oldest_first() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600)).with_max_entries(2);
        assert!(guard.check_and_record(&nonce(1), 1_000, 1_000).is_ok());
        assert!(guard.check_and_record(&nonce(2), 1_001, 1_001).is_ok());
        // At cap; recording a third entry evicts nonce(1) (oldest timestamp).
        assert!(guard.check_and_record(&nonce(3), 1_002, 1_002).is_ok());
        assert_eq!(guard.len(), 2);
        // nonce(1) was evicted, so it is accepted again as "new" — the
        // documented cost of evict-oldest under sustained pressure.
        assert!(guard.check_and_record(&nonce(1), 1_003, 1_003).is_ok());
    }

    #[test]
    fn check_and_record_now_accepts_a_current_timestamp() {
        let mut guard = ReplayGuard::with_default_window();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(guard.check_and_record_now(&nonce(9), now).is_ok());
    }

    struct FakeSignedPayload {
        nonce: [u8; 32],
        timestamp_secs: u64,
    }

    impl ReplayCheckable for FakeSignedPayload {
        fn replay_nonce(&self) -> &[u8; 32] {
            &self.nonce
        }
        fn replay_timestamp_secs(&self) -> u64 {
            self.timestamp_secs
        }
    }

    #[test]
    fn check_and_record_payload_works_against_any_replay_checkable() {
        let mut guard = ReplayGuard::new(Duration::from_secs(600));
        let payload = FakeSignedPayload { nonce: nonce(6), timestamp_secs: 1_000 };
        assert!(guard.check_and_record_payload(&payload, 1_000).is_ok());
        let err = guard.check_and_record_payload(&payload, 1_001).unwrap_err();
        assert!(matches!(err, CourierError::ReplayNonceReused));
    }

    #[test]
    fn default_guard_uses_the_documented_default_window() {
        let mut guard = ReplayGuard::default();
        let now = 1_000_000;
        // Just inside DEFAULT_WINDOW (10 minutes) is accepted …
        assert!(guard
            .check_and_record(&nonce(10), now - DEFAULT_WINDOW.as_secs() + 1, now)
            .is_ok());
        // … one second further back is stale.
        let err = guard
            .check_and_record(&nonce(11), now - DEFAULT_WINDOW.as_secs() - 1, now)
            .unwrap_err();
        assert!(matches!(err, CourierError::ReplayStale));
    }
}
