//! Fail-closed integration test coverage for the shared consent kernel.
//!
//! This is a **black-box** integration test: it exercises only
//! `postern_policy`'s public API (no `#[cfg(test)]` internals), locking in
//! the one invariant the whole crate exists to guarantee — **silence is
//! deny, and no fold or combinator can ever turn a `Deny` into an `Allow`.**
//!
//! Scope, honestly stated: these assertions pin the *type-level* fail-closed
//! default of [`Decision`] — they do not, and do not claim to, exercise any
//! OS/kernel enforcement boundary. `postern-policy` is a userland consent
//! kernel (see [`EnforcementMode`] in the crate root); this file makes no
//! claim beyond that.

use postern_policy::{Decision, SILENT_DENY_REASON};

/// `Decision::default()` must be the shut door: `Deny`, never `Allow`, and it
/// must carry exactly the canonical [`SILENT_DENY_REASON`] — not some other
/// ad-hoc string that could drift from the one silence-is-no reason the
/// crate promises every call site shares.
#[test]
fn default_is_deny_with_the_canonical_silent_reason() {
    let d = Decision::default();

    assert!(d.is_deny(), "Decision::default() must be a Deny");
    assert!(!d.is_allow(), "Decision::default() must never be Allow");
    assert_eq!(
        d.reason(),
        Some(SILENT_DENY_REASON),
        "Decision::default() must carry exactly SILENT_DENY_REASON"
    );
}

/// `Decision::silent()` is the explicit spelling of the same shut door as
/// `Decision::default()`. The two must be indistinguishable: one
/// implementation of "silence = deny", not two that could drift apart.
#[test]
fn silent_is_deny_with_the_canonical_silent_reason_and_equals_default() {
    let s = Decision::silent();

    assert!(s.is_deny(), "Decision::silent() must be a Deny");
    assert!(!s.is_allow(), "Decision::silent() must never be Allow");
    assert_eq!(
        s.reason(),
        Some(SILENT_DENY_REASON),
        "Decision::silent() must carry exactly SILENT_DENY_REASON"
    );

    assert_eq!(
        Decision::default(),
        Decision::silent(),
        "default() and silent() must be the same fail-closed value"
    );
}

/// An **empty** policy chain has, by construction, no layer that spoke — so
/// it must fold to the silent deny, never a permissive default. This is the
/// guard against "no policy configured" ever being read as "everything is
/// allowed".
#[test]
fn all_of_empty_chain_is_the_silent_deny_never_a_permissive_default() {
    let result = Decision::all([]);

    assert!(result.is_deny(), "Decision::all([]) must be a Deny");
    assert!(!result.is_allow(), "Decision::all([]) must never be Allow");
    assert_eq!(
        result,
        Decision::silent(),
        "Decision::all([]) must be exactly the silent deny"
    );
    assert_eq!(result.reason(), Some(SILENT_DENY_REASON));
}

/// `and` is the no-widening fold: once the outer layer has shut the door, no
/// inner layer — however permissive — can pry it back open. This covers both
/// orderings (`Deny.and(Allow)` and `Allow.and(Deny)`) so there is no
/// argument-order asymmetry that could accidentally widen access.
#[test]
fn and_never_widens_deny_into_allow() {
    let outer_deny_inner_allow = Decision::deny("outer shut").and(Decision::Allow);
    assert!(
        outer_deny_inner_allow.is_deny(),
        "an inner Allow must never widen an outer Deny"
    );
    assert!(!outer_deny_inner_allow.is_allow());

    let outer_allow_inner_deny = Decision::Allow.and(Decision::deny("inner shut"));
    assert!(
        outer_allow_inner_deny.is_deny(),
        "an inner Deny must still close an outer Allow"
    );
    assert!(!outer_allow_inner_deny.is_allow());

    // Both layers allowing is the only path to Allow.
    assert!(Decision::Allow.and(Decision::Allow).is_allow());
}

/// When the outer layer is already `Deny`, its reason is the one that must
/// survive the fold — an inner layer, allow or deny, must never overwrite or
/// discard *why* the door was shut.
#[test]
fn and_preserves_the_first_denys_reason() {
    let first_deny_then_allow = Decision::deny("first reason").and(Decision::Allow);
    assert_eq!(first_deny_then_allow.reason(), Some("first reason"));

    let first_deny_then_deny = Decision::deny("first reason").and(Decision::deny("second reason"));
    assert_eq!(
        first_deny_then_deny.reason(),
        Some("first reason"),
        "the first Deny in the fold must win, not the later one"
    );
}

/// The same no-widening, first-Deny-wins guarantee must hold across
/// `Decision::all`'s fold over an arbitrary-length chain, not just a single
/// pairwise `and`.
#[test]
fn all_folds_multiple_layers_without_ever_widening_a_deny() {
    let chain = Decision::all([
        Decision::Allow,
        Decision::deny("ring-2 narrowed"),
        Decision::Allow,
        Decision::Allow,
    ]);

    assert!(chain.is_deny());
    assert!(!chain.is_allow());
    assert_eq!(chain.reason(), Some("ring-2 narrowed"));

    // A deny as the very first layer must also survive to the end of a
    // longer chain of subsequent allows.
    let deny_first = Decision::all([
        Decision::deny("ring-0 shut"),
        Decision::Allow,
        Decision::Allow,
    ]);
    assert!(deny_first.is_deny());
    assert_eq!(deny_first.reason(), Some("ring-0 shut"));
}

/// The load-bearing end-to-end case: a `Decision` built only from defaults —
/// standing in for an unknown or absent grant path that no policy layer ever
/// spoke to — can never produce `is_allow() == true`. This is the fail-closed
/// promise the whole crate exists to keep.
#[test]
fn unknown_grant_path_built_only_from_defaults_can_never_be_allow() {
    // A single unspoken-for decision.
    let unknown: Decision = Default::default();
    assert!(!unknown.is_allow());
    assert!(unknown.is_deny());

    // A chain of several "nobody spoke" layers is still fail-closed.
    let unknown_chain = Decision::all([Decision::default(), Decision::default(), Decision::silent()]);
    assert!(!unknown_chain.is_allow());
    assert!(unknown_chain.is_deny());
    assert_eq!(unknown_chain.reason(), Some(SILENT_DENY_REASON));

    // Folding a default/silent decision into an otherwise-allowing chain via
    // `and` must still close the door — silence never widens.
    let allow_then_unknown = Decision::Allow.and(Decision::default());
    assert!(!allow_then_unknown.is_allow());
    assert!(allow_then_unknown.is_deny());
    assert_eq!(allow_then_unknown.reason(), Some(SILENT_DENY_REASON));
}
