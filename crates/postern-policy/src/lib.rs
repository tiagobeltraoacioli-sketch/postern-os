//! # postern-policy — the one shared **consent kernel**.
//!
//! `yagabona` (the "glowing skull") and `ezekiel1` (the "rims full of eyes")
//! each grew their own copy of the same four consent primitives:
//!
//! 1. a **fail-closed decision** — allow, or deny-with-a-reason, defaulting to
//!    deny where the policy is silent;
//! 2. a **grant expiry** — an RFC-3339 instant that is *required*, and must be
//!    strictly in the future at check time;
//! 3. **revocation** — a revoked or expired grant is treated as *never given*,
//!    re-checked at every access boundary;
//! 4. an honest **enforcement-boundary caveat** — "this is a userland check, not
//!    an OS sandbox" — repeated as slightly different prose in each crate.
//!
//! Carried twice, these had begun to drift: two ad-hoc expiry parsers with
//! different fail-closed behaviour, and two hand-written caveat sentences.
//! Extracting them here means the two consent surfaces **cannot diverge**: one
//! [`Decision`], one [`Expiry`], one [`Revocation`] semantics, and one
//! [`EnforcementMode`] whose [`honest_label`](EnforcementMode::honest_label)
//! gives every surface the *same words* for the same caveat.
//!
//! # Fail-closed by default
//!
//! Every primitive here defaults to the **shut door**. [`Decision::default`] is
//! a [`Decision::Deny`]; an [`Expiry`] that cannot be parsed or has passed is a
//! refusal, never an allow; a [`Revocation`] that has fired can never un-fire.
//! Silence is always "no".
//!
//! # Honesty
//!
//! This is the **userland consent kernel**, not an OS or kernel security
//! boundary. [`EnforcementMode`] is the anti-"round-up" primitive: it makes the
//! honest boundary a *type* the whole workspace shares, so no surface can
//! quietly upgrade "checked in this process" into "sandboxed by the kernel".
//! **UNAUDITED draft.**
//!
//! # Examples
//!
//! Layered, no-widening access — an inner ring may only *narrow* an outer
//! grant, and the first refusal wins with its reason intact:
//!
//! ```
//! use postern_policy::Decision;
//!
//! let outer = Decision::Allow;                       // tenant permits
//! let inner = Decision::deny("dataset is walled");   // Chinese wall narrows
//! assert_eq!(Decision::all([outer, inner]).reason(), Some("dataset is walled"));
//!
//! // An empty chain is the fail-closed silent deny — never a silent allow.
//! assert!(Decision::all([]).is_deny());
//! ```
//!
//! The round-up tripwire — refuse to emit a boundary claim stronger than the
//! enforcement actually in force:
//!
//! ```
//! use postern_policy::EnforcementMode::{self, *};
//!
//! // Real enforcement is an in-process check; claiming a kernel boundary fails.
//! assert!(!ByConstruction.satisfies(KernelBoundary));
//! assert!(ByConstruction.satisfies(ByConstruction));
//!
//! // A chain is only as honest as its weakest link.
//! assert_eq!(EnforcementMode::weakest_of([KernelBoundary, BestEffort]), BestEffort);
//! ```

#![forbid(unsafe_code)]

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// ===========================================================================
// Decision — the one fail-closed decision type.
// ===========================================================================

/// The canonical reason attached to the default, silence-is-no [`Decision`].
pub const SILENT_DENY_REASON: &str = "policy is silent; fail-closed default is deny";

/// A single fail-closed decision: [`Allow`](Decision::Allow), or
/// [`Deny`](Decision::Deny) carrying exactly one human-readable reason.
///
/// The invariant is that the **default / unknown case is [`Deny`](Decision::Deny)**.
/// [`Decision::default`] and [`Decision::silent`] both give the shut door, so
/// "silence = a closed door" has *one* implementation rather than being
/// re-derived (and possibly fumbled into an allow) at each call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The access is permitted.
    Allow,
    /// The access is refused. `reason` is never silently swallowed.
    Deny {
        /// Why the door stayed shut.
        reason: String,
    },
}

impl Decision {
    /// The one implementation of "silence = shut door": a [`Deny`](Decision::Deny)
    /// with the canonical [`SILENT_DENY_REASON`]. Use this wherever the policy
    /// simply does not speak to a request, so the default answer is identical
    /// everywhere.
    pub fn silent() -> Decision {
        Decision::Deny {
            reason: SILENT_DENY_REASON.to_string(),
        }
    }

    /// A [`Deny`](Decision::Deny) with an explicit reason.
    pub fn deny(reason: impl Into<String>) -> Decision {
        Decision::Deny {
            reason: reason.into(),
        }
    }

    /// Is this an allow?
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Is this a deny?
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// The denial reason, if this is a [`Deny`](Decision::Deny).
    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Deny { reason } => Some(reason),
        }
    }

    /// Fail-closed conjunction for **layered, no-widening** access: the combined
    /// decision is [`Allow`](Decision::Allow) only if *both* the outer (`self`)
    /// and the `inner` layer allow. The **first [`Deny`](Decision::Deny) wins**
    /// and carries its reason through unchanged: once an outer layer has shut the
    /// door, an inner layer can only ever leave it shut, never re-open it.
    ///
    /// This is the one implementation of ezekiel1's "wheels-within-wheels"
    /// invariant — an inner ring may *narrow* an outer grant but never *widen*
    /// it — so the no-widening rule is enforced by the type, not re-derived (and
    /// possibly inverted) at each nesting site.
    pub fn and(self, inner: Decision) -> Decision {
        match self {
            // Outer already shut: the inner layer cannot widen it back open.
            Decision::Deny { .. } => self,
            // Outer allows: the combined answer is exactly the inner layer's.
            Decision::Allow => inner,
        }
    }

    /// Fold a sequence of layered decisions with [`and`](Decision::and), from the
    /// outermost ring inward. An **empty** sequence is the fail-closed
    /// [`silent`](Decision::silent) deny — no layer spoke, so the door stays
    /// shut. The first [`Deny`](Decision::Deny) in the chain is the result and
    /// its reason is preserved.
    pub fn all(layers: impl IntoIterator<Item = Decision>) -> Decision {
        let mut iter = layers.into_iter();
        match iter.next() {
            None => Decision::silent(),
            Some(first) => iter.fold(first, Decision::and),
        }
    }
}

impl Default for Decision {
    /// The default is the **shut door** — silence is no.
    fn default() -> Self {
        Decision::silent()
    }
}

// ===========================================================================
// Expiry — the one required, RFC-3339, must-be-in-the-future check.
// ===========================================================================

/// Why an [`Expiry`] was rejected. Every variant is a fail-closed refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpiryError {
    /// The expiry field was absent or empty. Expiry is **required**.
    #[error("expiry is required but was missing or empty")]
    Missing,

    /// The value was present but not a valid RFC-3339 / UTC instant.
    #[error("expiry {value:?} is not a valid RFC 3339 instant: {detail}")]
    Unparseable {
        /// The raw value that failed to parse.
        value: String,
        /// The parser's detail.
        detail: String,
    },

    /// The value parsed but is not strictly in the future.
    #[error("grant is expired: expires {expires:?} is not after now {now:?}")]
    InPast {
        /// The (raw) expiry instant.
        expires: String,
        /// "Now" at check time, formatted RFC 3339.
        now: String,
    },
}

/// A parsed, required grant expiry: an RFC-3339 / UTC instant that must be
/// **strictly in the future** at check time.
///
/// This is the *single* expiry check for the workspace, replacing the two
/// ad-hoc parsers that yagabona (the Threshold Test) and ezekiel1 (per-access
/// grant evaluation) each carried. It is fail-closed at every step: a missing
/// value, an unparseable value, and a value at-or-before "now" are all
/// refusals — never a silent allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiry {
    at: OffsetDateTime,
    raw: String,
}

impl Expiry {
    /// Parse a **required** RFC-3339 expiry. An empty value is
    /// [`ExpiryError::Missing`]; a malformed value is
    /// [`ExpiryError::Unparseable`]. Does **not** yet check the clock — see
    /// [`Expiry::require_future`] and [`Expiry::checked`].
    pub fn parse(value: &str) -> Result<Expiry, ExpiryError> {
        if value.trim().is_empty() {
            return Err(ExpiryError::Missing);
        }
        let at = OffsetDateTime::parse(value, &Rfc3339).map_err(|e| ExpiryError::Unparseable {
            value: value.to_string(),
            detail: e.to_string(),
        })?;
        Ok(Expiry {
            at,
            raw: value.to_string(),
        })
    }

    /// The parsed instant.
    pub fn instant(&self) -> OffsetDateTime {
        self.at
    }

    /// The original (raw) expiry string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Has this expiry passed as of `at`? Expiry is **inclusive**: the instant
    /// of expiry itself counts as expired (strictly-in-the-future is required
    /// to be valid).
    pub fn is_expired(&self, at: OffsetDateTime) -> bool {
        self.at <= at
    }

    /// Fail-closed guard: `Ok` iff this expiry is strictly after `now`,
    /// otherwise [`ExpiryError::InPast`] (with `now` formatted RFC 3339).
    pub fn require_future(&self, now: OffsetDateTime) -> Result<(), ExpiryError> {
        if self.is_expired(now) {
            Err(ExpiryError::InPast {
                expires: self.raw.clone(),
                now: now.format(&Rfc3339).unwrap_or_else(|_| now.to_string()),
            })
        } else {
            Ok(())
        }
    }

    /// Parse **and** require-future in one call — the single replacement for the
    /// two ad-hoc "present + RFC-3339 + in-the-future" checks. Returns the
    /// validated [`Expiry`] or the first [`ExpiryError`].
    pub fn checked(value: &str, now: OffsetDateTime) -> Result<Expiry, ExpiryError> {
        let expiry = Expiry::parse(value)?;
        expiry.require_future(now)?;
        Ok(expiry)
    }
}

// ===========================================================================
// Revocation — the one "revoked/expired = never given" semantics.
// ===========================================================================

/// A monotonic revocation flag with the workspace's single revocation
/// semantics: **a revoked or expired grant is treated as if it had never been
/// given.** Revocation is monotonic — once revoked, always revoked; it never
/// flips back — and is meant to be re-checked at *every* access boundary, not
/// cached across one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocation {
    revoked: bool,
}

impl Revocation {
    /// A fresh, not-yet-revoked grant.
    pub fn new() -> Revocation {
        Revocation { revoked: false }
    }

    /// Revoke. Monotonic: calling this again is a no-op, and there is no way to
    /// un-revoke.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Has this grant been explicitly revoked?
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The access-boundary gate: fold revocation and expiry into one
    /// fail-closed [`Decision`]. Revoked **or** expired both collapse to the
    /// same "never given" denial; only a live, unexpired grant is
    /// [`Decision::Allow`].
    ///
    /// Call this at each access, passing the grant's [`Expiry`] and the current
    /// instant — never a decision cached from a previous boundary.
    pub fn gate(&self, expiry: &Expiry, now: OffsetDateTime) -> Decision {
        if self.revoked {
            return Decision::deny("grant revoked: treated as never given");
        }
        if expiry.is_expired(now) {
            return Decision::deny("grant expired: treated as never given");
        }
        Decision::Allow
    }
}

// ===========================================================================
// EnforcementMode — the #5 typed half: the honest boundary as a TYPE.
// ===========================================================================

/// How a stated boundary is *actually* enforced — the anti-"round-up"
/// primitive.
///
/// Security caveats written as prose drift and inflate: "userland check" quietly
/// becomes "sandbox", "by construction" becomes "isolated". This enum makes the
/// honest boundary a **type**, and [`honest_label`](EnforcementMode::honest_label)
/// hands every surface the *same words* for it — so no doc, log line, or UI can
/// silently upgrade what the code really guarantees.
///
/// The honest default for both `yagabona`'s `ScopedFs` and `ezekiel1`'s
/// firmament **today** is [`ByConstruction`](EnforcementMode::ByConstruction):
/// an in-process, userland check — real, tested, and explicitly *not* a kernel
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Enforced by the operating-system kernel: Linux **Landlock** /
    /// **seccomp-bpf**, dm-**verity**, the macOS sandbox, or equivalent. The
    /// process genuinely cannot cross this even by making raw syscalls.
    KernelBoundary,

    /// Enforced **by construction** in userland: the process checks itself,
    /// in-process, before each access. This is real defense-in-depth and it is
    /// the honest label for `yagabona`'s `ScopedFs` and `ezekiel1`'s firmament
    /// today — but it is **not** an OS sandbox: a compromised or buggy process,
    /// a TOCTOU-raced symlink, or a side channel can go around it.
    ByConstruction,

    /// A best-effort tripwire only: it catches obvious mistakes but makes no
    /// boundary guarantee at all (e.g. a heuristic secret scan).
    BestEffort,
}

impl EnforcementMode {
    /// The one canonical caveat string for this mode. **Stable** — surfaces and
    /// tests may pin it verbatim, and it must not change lightly, because its
    /// whole purpose is that every surface uses the *same words*.
    ///
    /// For [`ByConstruction`](EnforcementMode::ByConstruction) this single
    /// string subsumes both legacy phrasings — yagabona's "userland boundary,
    /// not an OS sandbox" and ezekiel1's "isolation by construction, not a
    /// kernel boundary".
    pub fn honest_label(&self) -> &str {
        match self {
            EnforcementMode::KernelBoundary => "OS/kernel-enforced boundary",
            EnforcementMode::ByConstruction => {
                "integrity by construction: a userland, in-process check, not an OS sandbox or kernel boundary"
            }
            EnforcementMode::BestEffort => "best-effort tripwire, not a boundary",
        }
    }

    /// Is this actually enforced by the OS/kernel? Only
    /// [`KernelBoundary`](EnforcementMode::KernelBoundary) may answer `true`;
    /// everything else is an in-process or best-effort check.
    pub fn is_os_enforced(&self) -> bool {
        matches!(self, EnforcementMode::KernelBoundary)
    }

    /// Relative strength, for **anti-round-up composition**: a higher number is a
    /// stronger guarantee. [`KernelBoundary`](EnforcementMode::KernelBoundary)
    /// (2) > [`ByConstruction`](EnforcementMode::ByConstruction) (1) >
    /// [`BestEffort`](EnforcementMode::BestEffort) (0).
    ///
    /// This is deliberately *not* a `#[derive(Ord)]`: the enum's declaration
    /// order would rank the **weakest** mode highest and silently invert every
    /// comparison — the exact round-up bug this type exists to prevent.
    pub fn strength(&self) -> u8 {
        match self {
            EnforcementMode::KernelBoundary => 2,
            EnforcementMode::ByConstruction => 1,
            EnforcementMode::BestEffort => 0,
        }
    }

    /// Does the enforcement *actually in force* (`self`) satisfy a `claimed`
    /// mode? True iff the real guarantee is **at least as strong** as what is
    /// claimed. This is the round-up tripwire: a surface that claims
    /// [`KernelBoundary`](EnforcementMode::KernelBoundary) while only
    /// [`ByConstruction`](EnforcementMode::ByConstruction) is really in force
    /// gets `false` — the code can assert this and refuse to emit the claim.
    pub fn satisfies(&self, claimed: EnforcementMode) -> bool {
        self.strength() >= claimed.strength()
    }

    /// The honest end-to-end label for a **chain** of layers is its *weakest
    /// link*. When access must survive every layer and any single link failing
    /// leaks, a kernel boundary wrapped around a best-effort check still only
    /// honestly guarantees best-effort end-to-end. Folds to the minimum
    /// strength; an **empty** chain claims nothing and is
    /// [`BestEffort`](EnforcementMode::BestEffort).
    pub fn weakest_of(modes: impl IntoIterator<Item = EnforcementMode>) -> EnforcementMode {
        modes
            .into_iter()
            .min_by_key(|m| m.strength())
            .unwrap_or(EnforcementMode::BestEffort)
    }
}

// ===========================================================================
// Tests.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    // --- Decision -----------------------------------------------------------

    #[test]
    fn decision_defaults_closed() {
        // The load-bearing invariant: the default/unknown case is Deny.
        assert!(Decision::default().is_deny());
        assert!(!Decision::default().is_allow());
        assert_eq!(Decision::default(), Decision::silent());
        assert_eq!(Decision::default().reason(), Some(SILENT_DENY_REASON));
    }

    #[test]
    fn decision_deny_carries_reason_and_allow_does_not() {
        let d = Decision::deny("nope");
        assert!(d.is_deny());
        assert_eq!(d.reason(), Some("nope"));
        assert_eq!(Decision::Allow.reason(), None);
        assert!(Decision::Allow.is_allow());
    }

    #[test]
    fn and_is_fail_closed_and_first_deny_wins() {
        // Allow ∧ Allow = Allow (both rings open).
        assert!(Decision::Allow.and(Decision::Allow).is_allow());

        // Any deny shuts the door; an inner allow cannot widen an outer deny.
        assert!(Decision::deny("outer").and(Decision::Allow).is_deny());
        assert!(Decision::Allow.and(Decision::deny("inner")).is_deny());

        // The FIRST deny's reason is the one that survives.
        let outer_first = Decision::deny("outer").and(Decision::deny("inner"));
        assert_eq!(outer_first.reason(), Some("outer"));
        // Outer allows, inner denies: the inner reason is surfaced.
        assert_eq!(
            Decision::Allow.and(Decision::deny("inner")).reason(),
            Some("inner")
        );
    }

    #[test]
    fn all_folds_layers_and_empty_is_closed() {
        // No layers spoke → fail-closed silent deny (never a silent allow).
        assert_eq!(Decision::all([]), Decision::silent());

        // All allow → allow.
        assert!(Decision::all([Decision::Allow, Decision::Allow, Decision::Allow]).is_allow());

        // One deny anywhere in the chain shuts it, keeping that reason.
        let chained = Decision::all([
            Decision::Allow,
            Decision::deny("ring-2 narrowed"),
            Decision::Allow,
        ]);
        assert!(chained.is_deny());
        assert_eq!(chained.reason(), Some("ring-2 narrowed"));
    }

    // --- Expiry -------------------------------------------------------------

    const NOW: OffsetDateTime = datetime!(2026-07-11 00:00:00 UTC);

    #[test]
    fn future_expiry_is_allowed() {
        let e = Expiry::checked("2026-07-11T00:00:01Z", NOW).unwrap();
        assert!(!e.is_expired(NOW));
        assert_eq!(e.raw(), "2026-07-11T00:00:01Z");
    }

    #[test]
    fn past_expiry_is_denied() {
        let err = Expiry::checked("2026-07-10T23:59:59Z", NOW).unwrap_err();
        assert!(matches!(err, ExpiryError::InPast { .. }));
    }

    #[test]
    fn expiry_exactly_now_is_expired_strictly_future_required() {
        // Inclusive: the instant of expiry itself counts as expired.
        let e = Expiry::parse("2026-07-11T00:00:00Z").unwrap();
        assert!(e.is_expired(NOW));
        assert!(matches!(
            e.require_future(NOW),
            Err(ExpiryError::InPast { .. })
        ));
    }

    #[test]
    fn missing_expiry_is_rejected() {
        assert!(matches!(Expiry::parse(""), Err(ExpiryError::Missing)));
        assert!(matches!(Expiry::parse("   "), Err(ExpiryError::Missing)));
    }

    #[test]
    fn unparseable_expiry_is_rejected() {
        let err = Expiry::parse("not-a-date").unwrap_err();
        assert!(matches!(err, ExpiryError::Unparseable { .. }));
    }

    #[test]
    fn expiry_compares_by_instant_not_by_offset() {
        // 2026-07-11T01:30:00+02:00 is the SAME instant as 2026-07-10T23:30:00Z,
        // which is BEFORE NOW (2026-07-11T00:00:00Z). A string comparison would
        // be fooled by the "01:30" wall-clock; the instant comparison must not.
        let e = Expiry::parse("2026-07-11T01:30:00+02:00").unwrap();
        assert!(e.is_expired(NOW), "non-UTC offset must be normalised to its instant");
        assert!(matches!(e.require_future(NOW), Err(ExpiryError::InPast { .. })));

        // And a +02:00 stamp that is genuinely still in the future is allowed.
        let future = Expiry::parse("2026-07-11T03:00:00+02:00").unwrap(); // 01:00Z
        assert!(!future.is_expired(NOW));
    }

    // --- Revocation ---------------------------------------------------------

    #[test]
    fn revocation_is_monotonic() {
        let mut r = Revocation::new();
        assert!(!r.is_revoked());
        r.revoke();
        assert!(r.is_revoked());
        r.revoke(); // idempotent; there is no un-revoke.
        assert!(r.is_revoked());
    }

    #[test]
    fn gate_allows_only_live_unexpired_grants() {
        let future = Expiry::parse("2026-07-11T00:00:01Z").unwrap();
        let past = Expiry::parse("2026-07-10T00:00:00Z").unwrap();

        // Live + unexpired: allow.
        assert!(Revocation::new().gate(&future, NOW).is_allow());

        // Expired = never given.
        let denied = Revocation::new().gate(&past, NOW);
        assert!(denied.is_deny());
        assert!(denied.reason().unwrap().contains("never given"));

        // Revoked = never given, even if unexpired.
        let mut r = Revocation::new();
        r.revoke();
        let denied = r.gate(&future, NOW);
        assert!(denied.is_deny());
        assert!(denied.reason().unwrap().contains("never given"));
    }

    // --- EnforcementMode ----------------------------------------------------

    #[test]
    fn enforcement_labels_are_stable() {
        // Pinned verbatim: these strings are the shared caveat words. Changing
        // them is a deliberate, reviewed act — this test is the tripwire.
        assert_eq!(
            EnforcementMode::KernelBoundary.honest_label(),
            "OS/kernel-enforced boundary"
        );
        assert_eq!(
            EnforcementMode::ByConstruction.honest_label(),
            "integrity by construction: a userland, in-process check, not an OS sandbox or kernel boundary"
        );
        assert_eq!(
            EnforcementMode::BestEffort.honest_label(),
            "best-effort tripwire, not a boundary"
        );
    }

    #[test]
    fn only_kernel_boundary_is_os_enforced() {
        assert!(EnforcementMode::KernelBoundary.is_os_enforced());
        assert!(!EnforcementMode::ByConstruction.is_os_enforced());
        assert!(!EnforcementMode::BestEffort.is_os_enforced());
    }

    #[test]
    fn strength_orders_kernel_above_construction_above_besteffort() {
        // Strength must NOT follow declaration order (which would rank the
        // weakest highest). Kernel is strongest.
        assert!(
            EnforcementMode::KernelBoundary.strength()
                > EnforcementMode::ByConstruction.strength()
        );
        assert!(
            EnforcementMode::ByConstruction.strength()
                > EnforcementMode::BestEffort.strength()
        );
    }

    #[test]
    fn satisfies_is_the_round_up_tripwire() {
        use EnforcementMode::*;
        // Equal or stronger satisfies the claim.
        assert!(KernelBoundary.satisfies(KernelBoundary));
        assert!(KernelBoundary.satisfies(ByConstruction));
        assert!(ByConstruction.satisfies(ByConstruction));
        // Claiming stronger than reality is the bug this catches: false.
        assert!(!ByConstruction.satisfies(KernelBoundary));
        assert!(!BestEffort.satisfies(ByConstruction));
    }

    #[test]
    fn weakest_of_is_the_honest_chain_label() {
        use EnforcementMode::*;
        // A kernel boundary wrapped around a best-effort check honestly
        // guarantees only best-effort end-to-end.
        assert_eq!(weakest_of([KernelBoundary, BestEffort]), BestEffort);
        assert_eq!(weakest_of([KernelBoundary, ByConstruction]), ByConstruction);
        assert_eq!(weakest_of([KernelBoundary, KernelBoundary]), KernelBoundary);
        // An empty chain claims nothing.
        assert_eq!(weakest_of([]), BestEffort);
    }
}

// A free-function alias so `weakest_of` reads naturally in the tests above,
// which `use EnforcementMode::*` for the variants (that glob does not bring the
// associated function into scope). Test-only; no cost in the shipped crate.
#[cfg(test)]
fn weakest_of(modes: impl IntoIterator<Item = EnforcementMode>) -> EnforcementMode {
    EnforcementMode::weakest_of(modes)
}
