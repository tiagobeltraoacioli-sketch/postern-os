//! Integration coverage for invariant (c) of the shared consent kernel:
//!
//! > a **grant expiry** is an RFC-3339 instant that is *required*, and must be
//! > strictly in the future at check time.
//!
//! This file locks in the *boundary* behaviour of [`Expiry`] against a single
//! fixed `NOW` (via `time::macros::datetime!`, so the suite is deterministic
//! and does not depend on the wall clock — except for one clearly-marked
//! bonus test using a far-future stamp against real `OffsetDateTime::now_utc()`).
//!
//! The invariant under test, restated as the fail-closed contract: **every
//! failure path is a typed [`ExpiryError`], never a silent [`Decision::Allow`]**.
//! Missing, unparseable, exactly-at-expiry, and past-expiry values must all be
//! refusals; only a value strictly after `now` may be `Ok`/`Allow`.

use postern_policy::{Decision, Expiry, ExpiryError, Revocation};
use time::macros::datetime;
use time::OffsetDateTime;

/// The single fixed "now" every test in this file checks against. Picking one
/// constant (rather than reusing the unit-test suite's `NOW`) keeps this
/// integration file self-contained and its boundary arithmetic easy to audit
/// by inspection: `NOW == 2030-06-15T12:00:00Z`.
const NOW: OffsetDateTime = datetime!(2030-06-15 12:00:00 UTC);

/// Raw RFC-3339 form of `NOW` itself — used to build the exactly-at-expiry
/// boundary case.
const NOW_RAW: &str = "2030-06-15T12:00:00Z";

/// Assert every possible failure shape is a typed refusal: `Expiry::checked`
/// must never return `Ok` for a raw value that is supposed to fail, and
/// `Revocation::gate` must never return `Decision::Allow` for an expiry that
/// has failed `require_future`. This is the load-bearing assertion of the
/// whole file — fail-closed means "typed error", never "allow by accident".
fn assert_typed_refusal_never_allow(expiry: &Expiry, now: OffsetDateTime) {
    assert!(
        expiry.is_expired(now),
        "expiry {:?} expected to be expired at {now:?}",
        expiry.raw()
    );
    assert!(matches!(
        expiry.require_future(now),
        Err(ExpiryError::InPast { .. })
    ));
    let gated = Revocation::new().gate(expiry, now);
    assert!(
        gated.is_deny(),
        "gate() must never Allow an expired grant, got {gated:?}"
    );
    assert!(matches!(gated, Decision::Deny { .. }));
}

// ===========================================================================
// (1) Strictly before expiry: Ok, not expired, gate allows.
// ===========================================================================

#[test]
fn strictly_before_expiry_one_second_out_is_allowed() {
    let raw = "2030-06-15T12:00:01Z"; // NOW + 1s
    let expiry = Expiry::checked(raw, NOW).expect("one second in the future must be Ok");
    assert!(!expiry.is_expired(NOW));
    assert!(expiry.require_future(NOW).is_ok());
    assert!(Revocation::new().gate(&expiry, NOW).is_allow());
}

#[test]
fn strictly_before_expiry_far_future_is_allowed() {
    let raw = "2099-01-01T00:00:00Z"; // far future relative to NOW
    let expiry = Expiry::checked(raw, NOW).expect("far future must be Ok");
    assert!(!expiry.is_expired(NOW));
    assert!(expiry.require_future(NOW).is_ok());
    assert!(Revocation::new().gate(&expiry, NOW).is_allow());
}

// ===========================================================================
// (2) Exactly at expiry: raw == NOW. Inclusive — the expiry instant itself
//     is expired, never valid.
// ===========================================================================

#[test]
fn exactly_at_expiry_is_expired_and_denied() {
    // Parse succeeds (the string is well-formed RFC 3339); only the
    // future-ness check is expected to fail.
    let expiry = Expiry::parse(NOW_RAW).expect("well-formed RFC 3339 must parse");
    assert_eq!(expiry.instant(), NOW);

    assert_typed_refusal_never_allow(&expiry, NOW);

    // checked() folds parse + require_future into one call and must reject too.
    let err = Expiry::checked(NOW_RAW, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));
}

// ===========================================================================
// (3) After expiry: NOW - 1s and NOW - 1 day.
// ===========================================================================

#[test]
fn after_expiry_one_second_past_is_denied() {
    let raw = "2030-06-15T11:59:59Z"; // NOW - 1s
    let err = Expiry::checked(raw, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));

    let expiry = Expiry::parse(raw).unwrap();
    assert_typed_refusal_never_allow(&expiry, NOW);
}

#[test]
fn after_expiry_one_day_past_is_denied() {
    let raw = "2030-06-14T12:00:00Z"; // NOW - 1 day
    let err = Expiry::checked(raw, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));

    let expiry = Expiry::parse(raw).unwrap();
    assert_typed_refusal_never_allow(&expiry, NOW);
}

// ===========================================================================
// (4) Missing / whitespace-only: ExpiryError::Missing, from both parse() and
//     checked() (checked() must propagate parse()'s error, never widen it).
// ===========================================================================

#[test]
fn missing_expiry_values_are_typed_missing_never_ok() {
    for raw in ["", "   ", "\t", "\n", "  \t\n  "] {
        assert!(
            matches!(Expiry::parse(raw), Err(ExpiryError::Missing)),
            "parse({raw:?}) should be Missing"
        );
        assert!(
            matches!(Expiry::checked(raw, NOW), Err(ExpiryError::Missing)),
            "checked({raw:?}) should be Missing"
        );
    }
}

// ===========================================================================
// (5) Malformed: not RFC-3339 at all, an out-of-range calendar date, and a
//     date/time with no offset (RFC 3339 requires one). All Unparseable.
// ===========================================================================

#[test]
fn malformed_non_date_string_is_unparseable() {
    let err = Expiry::parse("not-a-date").unwrap_err();
    assert!(matches!(err, ExpiryError::Unparseable { .. }));
    let err = Expiry::checked("not-a-date", NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::Unparseable { .. }));
}

#[test]
fn malformed_out_of_range_calendar_date_is_unparseable() {
    // Month 13, day 99: syntactically date-shaped but not a real calendar
    // instant. Must be a typed Unparseable, never silently clamped/accepted.
    let err = Expiry::parse("2026-13-99T00:00:00Z").unwrap_err();
    assert!(matches!(err, ExpiryError::Unparseable { .. }));
}

#[test]
fn malformed_date_without_offset_is_unparseable() {
    // RFC 3339 requires an explicit offset (Z or +hh:mm/-hh:mm). A bare local
    // datetime with no offset is not a valid instant per this parser and must
    // be refused, not silently assumed-UTC.
    let err = Expiry::parse("2030-06-15T12:00:00").unwrap_err();
    assert!(matches!(err, ExpiryError::Unparseable { .. }));
}

// ===========================================================================
// (6) Non-UTC offset normalization at the boundary: the check must compare
//     INSTANTS, not raw wall-clock digits.
// ===========================================================================

#[test]
fn offset_stamp_whose_instant_equals_now_is_expired() {
    // 2030-06-15T14:00:00+02:00 is the SAME instant as NOW
    // (2030-06-15T12:00:00Z). A naive string/wall-clock comparison would see
    // "14:00 > 12:00" and wrongly call this future; the instant comparison
    // must not be fooled and must treat it as exactly-at-expiry (expired).
    let raw = "2030-06-15T14:00:00+02:00";
    let expiry = Expiry::parse(raw).unwrap();
    assert_eq!(expiry.instant(), NOW, "offset stamp must normalize to the same instant as NOW");

    assert_typed_refusal_never_allow(&expiry, NOW);
    let err = Expiry::checked(raw, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));
}

#[test]
fn offset_stamp_one_second_after_now_instant_is_allowed() {
    // 2030-06-15T14:00:01+02:00 == 2030-06-15T12:00:01Z, one second strictly
    // after NOW's instant: valid, and the gate allows.
    let raw = "2030-06-15T14:00:01+02:00";
    let expiry = Expiry::checked(raw, NOW).expect("instant strictly after NOW must be Ok");
    assert!(!expiry.is_expired(NOW));
    assert!(Revocation::new().gate(&expiry, NOW).is_allow());
}

#[test]
fn offset_stamp_one_second_before_now_instant_is_denied() {
    // 2030-06-15T13:59:59+02:00 == 2030-06-15T11:59:59Z, one second strictly
    // before NOW's instant: expired, denied.
    let raw = "2030-06-15T13:59:59+02:00";
    let err = Expiry::checked(raw, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));
}

// ===========================================================================
// (7) Sub-second boundary precision. Every case above lands on a whole-second
//     grid; a bug that truncated the comparison to whole seconds would still
//     pass them all while silently allowing a grant that expired up to 999ms
//     ago (or denying one still valid for another 999ms). These pin that the
//     "strictly in the future" boundary is honoured at fractional-second
//     resolution — the grid the real clock actually ticks on.
// ===========================================================================

#[test]
fn sub_second_after_now_is_allowed_not_truncated_to_the_whole_second() {
    // NOW + 1ms. Truncating to whole seconds would read this as == NOW and
    // deny it; the instant comparison must see it as strictly future.
    let raw = "2030-06-15T12:00:00.001Z";
    let expiry = Expiry::checked(raw, NOW).expect("one millisecond in the future must be Ok");
    assert!(!expiry.is_expired(NOW));
    assert!(expiry.require_future(NOW).is_ok());
    assert!(Revocation::new().gate(&expiry, NOW).is_allow());
}

#[test]
fn sub_second_before_now_is_denied_not_truncated_up_to_the_whole_second() {
    // NOW - 1ms (i.e. 11:59:59.999Z). Truncating to whole seconds would round
    // this up to 12:00:00 == NOW and might mis-handle it; it must be treated
    // as strictly past — a typed refusal, never an allow.
    let raw = "2030-06-15T11:59:59.999Z";
    let err = Expiry::checked(raw, NOW).unwrap_err();
    assert!(matches!(err, ExpiryError::InPast { .. }));

    let expiry = Expiry::parse(raw).unwrap();
    assert_typed_refusal_never_allow(&expiry, NOW);
}

#[test]
fn sub_second_boundary_holds_against_a_fractional_now() {
    // Now shift NOW itself off the whole-second grid to 12:00:00.500Z and probe
    // both sides of the boundary at millisecond resolution.
    let now_frac: OffsetDateTime = datetime!(2030-06-15 12:00:00.500 UTC);

    // 1ms after the fractional now: allowed.
    let after = Expiry::checked("2030-06-15T12:00:00.501Z", now_frac)
        .expect("1ms after a fractional now must be Ok");
    assert!(!after.is_expired(now_frac));
    assert!(Revocation::new().gate(&after, now_frac).is_allow());

    // Exactly at the fractional now: inclusive expiry → expired, denied.
    let at = Expiry::parse("2030-06-15T12:00:00.500Z").unwrap();
    assert_eq!(at.instant(), now_frac);
    assert_typed_refusal_never_allow(&at, now_frac);

    // 1ms before the fractional now: expired, denied.
    let before = Expiry::parse("2030-06-15T12:00:00.499Z").unwrap();
    assert_typed_refusal_never_allow(&before, now_frac);
}

// ===========================================================================
// Bonus: a real wall-clock read, but pinned against a stamp so far in the
// future (year 9999) that the assertion is deterministic in practice for the
// lifetime of this codebase. This is the ONE test in the file allowed to call
// OffsetDateTime::now_utc(), per the "no wall-clock reads except optionally
// one extra far-future test" scope.
// ===========================================================================

#[test]
fn far_future_stamp_is_allowed_against_real_now() {
    let raw = "9999-12-31T23:59:59Z";
    let now = OffsetDateTime::now_utc();
    let expiry = Expiry::checked(raw, now).expect("year 9999 must be Ok against real now()");
    assert!(!expiry.is_expired(now));
    assert!(Revocation::new().gate(&expiry, now).is_allow());
}
