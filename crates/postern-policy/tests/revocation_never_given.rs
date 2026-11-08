//! Fail-closed integration test coverage for invariant (b) of the shared
//! consent kernel: **revocation is treated as if the grant had never been
//! given** — not merely "currently withdrawn".
//!
//! This is a **black-box** integration test: it exercises only
//! `postern_policy`'s public API (`Revocation::gate`, `Expiry`, `Decision`),
//! no `#[cfg(test)]` internals.
//!
//! Honesty, stated up front: this file asserts that both the revoked-grant
//! reason and the expired-grant reason *contain* the substring "never given",
//! and that both land in the same fail-closed `Decision` class as a grant
//! that was never created at all. It does **not** assert that the two reason
//! strings are byte-identical — they are not ("grant revoked: ..." vs "grant
//! expired: ..."), and claiming otherwise would overstate what the kernel
//! guarantees. It also does not assert anything about tamper-proof storage of
//! the `revoked` flag; `Revocation` is an in-memory struct, and the only
//! guarantee under test is the *value semantics* of its public API.

use postern_policy::{Decision, Expiry, Revocation};
use time::macros::datetime;
use time::OffsetDateTime;

const NOW: OffsetDateTime = datetime!(2026-07-14 00:00:00 UTC);

fn still_future_expiry() -> Expiry {
    // Strictly after NOW: on its own (unrevoked), this expiry would allow.
    Expiry::parse("2026-07-14T00:00:01Z").unwrap()
}

fn already_past_expiry() -> Expiry {
    Expiry::parse("2026-07-13T23:59:59Z").unwrap()
}

/// Core of invariant (b): a **revoked** grant gates to `Deny` whose reason
/// contains "never given" — even though its `Expiry` is still strictly in
/// the future. Revocation, not expiry, is the thing under test here.
#[test]
fn revoked_grant_with_future_expiry_gates_to_never_given_deny() {
    let future = still_future_expiry();

    // Sanity: on its own, this expiry would allow (proves the deny below is
    // caused by revocation, not by an accidentally-past expiry).
    assert!(
        Revocation::new().gate(&future, NOW).is_allow(),
        "precondition: an unrevoked grant with a future expiry must allow"
    );

    let mut r = Revocation::new();
    r.revoke();
    let decision = r.gate(&future, NOW);

    assert!(decision.is_deny(), "a revoked grant must gate to Deny");
    assert!(!decision.is_allow(), "a revoked grant must never gate to Allow");
    let reason = decision
        .reason()
        .expect("a Deny decision must carry a reason");
    assert!(
        reason.contains("never given"),
        "revoked reason must say the grant is treated as never given, got: {reason:?}"
    );
}

/// Revoked, expired, and never-created grants are three different histories
/// that must all land in the **same fail-closed Decision class**: `is_deny()
/// == true`, `is_allow() == false`. This is the "never given" equivalence
/// class the invariant promises, checked at the class level (not the byte
/// level — see the module docs and the dedicated test below).
#[test]
fn revoked_expired_and_never_created_share_the_same_deny_class() {
    // Revoked (future expiry, so expiry alone would not deny).
    let mut revoked = Revocation::new();
    revoked.revoke();
    let revoked_decision = revoked.gate(&still_future_expiry(), NOW);

    // Expired (never revoked, so revocation alone would not deny).
    let expired_decision = Revocation::new().gate(&already_past_expiry(), NOW);

    // Never created at all: no `Revocation`, no `Expiry`, just the type's
    // fail-closed default — standing in for a grant that was never issued.
    let never_created_decision = Decision::default();

    for (label, decision) in [
        ("revoked", &revoked_decision),
        ("expired", &expired_decision),
        ("never-created", &never_created_decision),
    ] {
        assert!(decision.is_deny(), "{label} decision must be Deny");
        assert!(!decision.is_allow(), "{label} decision must never be Allow");
    }

    // Honesty: revoked and expired reasons both contain "never given" — the
    // shared vocabulary of the invariant — but they are NOT asserted to be
    // byte-identical. They differ by construction ("revoked" vs "expired"),
    // and this test must not overclaim indistinguishability that the crate
    // does not provide.
    let revoked_reason = revoked_decision.reason().unwrap();
    let expired_reason = expired_decision.reason().unwrap();
    assert!(revoked_reason.contains("never given"));
    assert!(expired_reason.contains("never given"));
    assert_ne!(
        revoked_reason, expired_reason,
        "revoked and expired reasons are expected to differ in wording \
         (e.g. \"grant revoked: ...\" vs \"grant expired: ...\"); this test \
         does not claim byte-level indistinguishability, only that both \
         belong to the same fail-closed deny class and both say \"never given\""
    );

    // The never-created decision, being the type's own default, carries the
    // crate's canonical silent-deny reason rather than either "revoked" or
    // "expired" wording — it is a third, distinct history, deliberately not
    // asserted to share exact wording with the other two.
    assert!(never_created_decision.reason().is_some());
}

/// Revocation is monotonic: revoking twice leaves the grant exactly as
/// revoked as revoking once, and the public API exposes no operation that
/// clears `revoked` back to `false`. This test proves monotonicity by
/// repeated revocation, not by inspecting private state.
#[test]
fn revocation_is_monotonic_across_repeated_revoke_calls() {
    let mut r = Revocation::new();
    assert!(!r.is_revoked(), "a fresh grant must start unrevoked");

    r.revoke();
    assert!(r.is_revoked());

    // Revoke again (and again): still revoked, no panic, no change in
    // observable state beyond "still revoked".
    r.revoke();
    assert!(r.is_revoked(), "revoking twice must still be revoked");
    r.revoke();
    assert!(r.is_revoked(), "revoking a third time must still be revoked");

    // The gate reflects the same monotonic deny after any number of revokes.
    let future = still_future_expiry();
    let decision = r.gate(&future, NOW);
    assert!(decision.is_deny());
    assert!(decision.reason().unwrap().contains("never given"));

    // No un-revoke path exists in the public API: `Revocation` exposes only
    // `new`, `revoke`, `is_revoked`, and `gate`. There is no `unrevoke`,
    // `reset`, `clear`, or field-level mutation available from outside the
    // crate — the only way to reach a fresh, unrevoked `Revocation` is to
    // construct a brand-new one.
    let fresh = Revocation::new();
    assert!(!fresh.is_revoked(), "only a NEW Revocation is unrevoked");
    assert!(r.is_revoked(), "the original, once-revoked value is untouched by creating a new one");
}

/// Fail-closed construction: `Revocation` derives `Default`, and that derived
/// default must be an **unrevoked** grant, indistinguishable from
/// `Revocation::new()`. This pins that a value materialised via `Default`
/// (e.g. `#[derive(Default)]` on an enclosing grant struct, or
/// `Revocation::default()` at a call site) starts in the not-yet-revoked
/// state and gates identically to a freshly-`new()`ed one — so the two
/// construction paths can never drift into different starting semantics.
///
/// Note this is the one place fail-closed points *toward* Allow: a fresh grant
/// must be usable until something revokes or expires it. The safety net is
/// that revocation and expiry both still collapse to deny (covered above);
/// this test just proves the derived default is a real, gate-able starting
/// value and not, say, silently pre-revoked in a way that would surprise a
/// caller relying on `Default`.
#[test]
fn default_revocation_equals_new_and_starts_unrevoked() {
    let defaulted = Revocation::default();
    let constructed = Revocation::new();

    assert!(!defaulted.is_revoked(), "Revocation::default() must start unrevoked");
    assert_eq!(
        defaulted, constructed,
        "Revocation::default() must be indistinguishable from Revocation::new()"
    );

    // Both construction paths gate identically at the same boundary.
    let future = still_future_expiry();
    assert_eq!(
        defaulted.gate(&future, NOW),
        constructed.gate(&future, NOW),
        "default() and new() must gate to the same Decision"
    );
    assert!(defaulted.gate(&future, NOW).is_allow());

    // And the derived default is still subject to the fail-closed collapses:
    // an expired expiry denies even a default-constructed, unrevoked grant.
    let expired = already_past_expiry();
    let denied = Revocation::default().gate(&expired, NOW);
    assert!(denied.is_deny());
    assert!(denied.reason().unwrap().contains("never given"));
}

/// `gate` must be **re-evaluated at every access boundary**, never cached
/// from an earlier call: the same `Revocation` value, checked against the
/// same `Expiry`, must allow before revocation and deny after — proving that
/// an earlier `Allow` is not memoized or treated as a standing grant.
#[test]
fn gate_is_re_evaluated_per_boundary_not_cached_from_an_earlier_allow() {
    let expiry = still_future_expiry();
    let mut r = Revocation::new();

    // Boundary 1: not yet revoked — the same (Revocation, Expiry) pair
    // allows access.
    let first_boundary = r.gate(&expiry, NOW);
    assert!(
        first_boundary.is_allow(),
        "before revocation, the live unexpired grant must allow"
    );

    // Revoke between boundaries — nothing about `expiry` or `NOW` changes.
    r.revoke();

    // Boundary 2: the SAME Revocation value (now revoked) and the SAME
    // Expiry, re-gated. If `gate` (or a caller) cached the first boundary's
    // Allow, this would incorrectly still allow. It must not.
    let second_boundary = r.gate(&expiry, NOW);
    assert!(
        second_boundary.is_deny(),
        "after revocation, re-evaluating the same pair at a later boundary must deny"
    );
    assert!(!second_boundary.is_allow());
    assert!(second_boundary.reason().unwrap().contains("never given"));

    // A third boundary, re-checked again, must still deny — re-evaluation is
    // idempotent under repetition, not a one-shot transition.
    let third_boundary = r.gate(&expiry, NOW);
    assert!(third_boundary.is_deny());
    assert_eq!(second_boundary, third_boundary);
}
