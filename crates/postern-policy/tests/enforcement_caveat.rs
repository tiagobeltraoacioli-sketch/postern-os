//! Integration coverage for invariant (d) of the shared consent kernel: the
//! typed [`EnforcementMode`] caveat and the honesty constitution behind it —
//! "this is a userland, in-process check, not an OS sandbox or kernel
//! boundary."
//!
//! This is a **black-box** integration test: it exercises only
//! `postern_policy`'s public API (no `#[cfg(test)]` internals), and pins two
//! things at once:
//!
//! 1. the exact words of [`EnforcementMode::honest_label`] for all three
//!    variants, byte-for-byte, so no surface can silently reword its way into
//!    a stronger-sounding claim; and
//! 2. the round-up tripwire itself — [`EnforcementMode::is_os_enforced`],
//!    [`EnforcementMode::satisfies`], and [`EnforcementMode::weakest_of`] —
//!    so a chain can never claim more than its weakest link actually
//!    guarantees.
//!
//! Honesty, stated up front: this file does **not** exercise any real OS or
//! kernel enforcement (no Landlock, no seccomp-bpf, no sandbox profile is
//! installed or probed here). It only pins the *type-level* honesty
//! contract: that `postern-policy`'s own honest mode today,
//! [`EnforcementMode::ByConstruction`], is never confused — by label, by
//! `satisfies`, or by a `weakest_of` fold — with an OS/kernel boundary claim
//! it does not make.

use postern_policy::EnforcementMode::{self, BestEffort, ByConstruction, KernelBoundary};

// ===========================================================================
// 1. honest_label() pinned verbatim for all three variants.
// ===========================================================================

/// `KernelBoundary`'s label, pinned byte-for-byte. This is the one variant
/// that may honestly say "OS/kernel-enforced" — the words must stay exactly
/// this, not a looser paraphrase that other variants could later slide into.
#[test]
fn honest_label_kernel_boundary_pinned_verbatim() {
    assert_eq!(
        KernelBoundary.honest_label(),
        "OS/kernel-enforced boundary"
    );
}

/// `ByConstruction`'s label, pinned byte-for-byte — including the negation
/// clause. This is the consent kernel's own honest mode **today**, and the
/// caveat's entire job is to say, in the same words every surface shares,
/// that this is *not* a kernel boundary.
#[test]
fn honest_label_by_construction_pinned_verbatim() {
    assert_eq!(
        ByConstruction.honest_label(),
        "integrity by construction: a userland, in-process check, not an OS sandbox or kernel boundary"
    );
}

/// `BestEffort`'s label, pinned byte-for-byte.
#[test]
fn honest_label_best_effort_pinned_verbatim() {
    assert_eq!(
        BestEffort.honest_label(),
        "best-effort tripwire, not a boundary"
    );
}

// ===========================================================================
// 2. is_os_enforced() is true ONLY for KernelBoundary.
// ===========================================================================

/// The OS-enforcement bit must fire for exactly one variant. If any other
/// variant ever answers `true` here, some surface could round its userland
/// or best-effort check up into an "OS-enforced" claim.
#[test]
fn is_os_enforced_true_only_for_kernel_boundary() {
    assert!(KernelBoundary.is_os_enforced());
    assert!(!ByConstruction.is_os_enforced());
    assert!(!BestEffort.is_os_enforced());

    // Exhaustively confirm exactly one of the three variants is OS-enforced,
    // so a future fourth variant can't silently duplicate the `true` case.
    let os_enforced_count = [KernelBoundary, ByConstruction, BestEffort]
        .iter()
        .filter(|m| m.is_os_enforced())
        .count();
    assert_eq!(os_enforced_count, 1);
}

// ===========================================================================
// 3. The round-up tripwire: satisfies().
// ===========================================================================

/// `ByConstruction` must NOT satisfy a `KernelBoundary` claim — claiming a
/// kernel boundary while only an in-process check is really in force is
/// exactly the round-up bug this type exists to catch.
#[test]
fn by_construction_does_not_satisfy_kernel_boundary_claim() {
    assert!(!ByConstruction.satisfies(KernelBoundary));
}

/// `BestEffort` must NOT satisfy a `ByConstruction` claim — a heuristic
/// tripwire cannot honestly stand in for "checked in-process before every
/// access".
#[test]
fn best_effort_does_not_satisfy_by_construction_claim() {
    assert!(!BestEffort.satisfies(ByConstruction));
}

/// `BestEffort` must NOT satisfy a `KernelBoundary` claim either — the same
/// round-up failure, two strength levels apart.
#[test]
fn best_effort_does_not_satisfy_kernel_boundary_claim() {
    assert!(!BestEffort.satisfies(KernelBoundary));
}

/// Equal-or-stronger enforcement DOES satisfy the claim: every variant
/// satisfies a claim of itself, and a strictly stronger mode satisfies a
/// weaker claim.
#[test]
fn equal_or_stronger_enforcement_satisfies_the_claim() {
    // Equal satisfies equal, for all three variants.
    assert!(KernelBoundary.satisfies(KernelBoundary));
    assert!(ByConstruction.satisfies(ByConstruction));
    assert!(BestEffort.satisfies(BestEffort));

    // Strictly stronger satisfies a weaker claim.
    assert!(KernelBoundary.satisfies(ByConstruction));
    assert!(KernelBoundary.satisfies(BestEffort));
    assert!(ByConstruction.satisfies(BestEffort));
}

// ===========================================================================
// 4. weakest_of(): a chain is only as honest as its weakest link.
// ===========================================================================

/// Any chain containing `BestEffort` collapses to `BestEffort`, regardless
/// of how strong the other links are or where in the chain it sits.
#[test]
fn weakest_of_collapses_any_chain_containing_best_effort() {
    assert_eq!(
        EnforcementMode::weakest_of([KernelBoundary, BestEffort]),
        BestEffort
    );
    assert_eq!(
        EnforcementMode::weakest_of([BestEffort, KernelBoundary]),
        BestEffort
    );
    assert_eq!(
        EnforcementMode::weakest_of([KernelBoundary, ByConstruction, BestEffort]),
        BestEffort
    );
    assert_eq!(
        EnforcementMode::weakest_of([BestEffort, BestEffort, BestEffort]),
        BestEffort
    );
}

/// A chain containing `ByConstruction` but no `BestEffort` collapses to
/// `ByConstruction` — a kernel boundary wrapped around an in-process check
/// still only honestly guarantees the in-process check end-to-end.
#[test]
fn weakest_of_collapses_chain_containing_by_construction_but_no_best_effort() {
    assert_eq!(
        EnforcementMode::weakest_of([KernelBoundary, ByConstruction]),
        ByConstruction
    );
    assert_eq!(
        EnforcementMode::weakest_of([ByConstruction, KernelBoundary]),
        ByConstruction
    );
    assert_eq!(
        EnforcementMode::weakest_of([ByConstruction, ByConstruction]),
        ByConstruction
    );
}

/// A chain of nothing but `KernelBoundary` stays `KernelBoundary` — the
/// weakest-link fold does not manufacture weakness that isn't there.
#[test]
fn weakest_of_all_kernel_boundary_stays_kernel_boundary() {
    assert_eq!(
        EnforcementMode::weakest_of([KernelBoundary, KernelBoundary, KernelBoundary]),
        KernelBoundary
    );
}

/// An empty chain claims nothing, and the fail-closed honest answer for
/// "nothing was claimed" is `BestEffort` — the weakest label, never a silent
/// upgrade to `KernelBoundary` or `ByConstruction`.
#[test]
fn weakest_of_empty_chain_is_best_effort() {
    assert_eq!(EnforcementMode::weakest_of([]), BestEffort);
    assert_eq!(EnforcementMode::weakest_of(std::iter::empty()), BestEffort);
}

// ===========================================================================
// 5. The doc-vs-tests overclaim guard: the consent kernel's own honest mode
//    today does not claim to be a kernel boundary, and its label does not
//    make "sandbox" a positive claim.
// ===========================================================================

/// `postern-policy`'s own honest enforcement mode **today** is
/// `ByConstruction` (see the crate-root doc comment and the `EnforcementMode`
/// doc comment). This test is the guard that keeps that claim honest going
/// forward: `ByConstruction` must never satisfy a `KernelBoundary` claim, and
/// it must never be reported as OS-enforced. If this test ever needs to
/// change to pass, that is a signal the crate's own enforcement claim has
/// been silently rounded up — the change must be deliberate and reviewed,
/// not incidental.
#[test]
fn consent_kernels_own_honest_mode_today_is_not_a_kernel_boundary_claim() {
    let todays_honest_mode = ByConstruction;

    assert!(
        !todays_honest_mode.satisfies(KernelBoundary),
        "the consent kernel's honest mode today must not satisfy a KernelBoundary claim"
    );
    assert!(
        !todays_honest_mode.is_os_enforced(),
        "the consent kernel's honest mode today must not report itself as OS-enforced"
    );
}

/// The word "sandbox" may appear in `ByConstruction`'s label **only** inside
/// the negation "not an OS sandbox" — never as a free-standing positive
/// claim. This is the test that keeps docs/tests from overclaiming: it
/// parses the label itself (not a paraphrase of it) so a future edit that
/// drops the negation, or that adds "sandbox" as a positive claim elsewhere
/// in the string, fails loudly here.
#[test]
fn by_construction_label_uses_sandbox_only_inside_the_negation() {
    let label = ByConstruction.honest_label();

    assert!(
        label.contains("sandbox"),
        "expected the label to mention \"sandbox\" at all (inside the negation): {label:?}"
    );

    // The only occurrence of "sandbox" must be as part of the exact negation
    // clause "not an OS sandbox" — i.e. immediately preceded by "not an OS ".
    // Byte-offset walk rather than a single `contains` so that if a second,
    // free-standing "sandbox" is ever added anywhere in the string (a
    // positive claim slipped in beside the honest negation), this test
    // catches it instead of passing on the first match alone.
    let negation_clause = "not an OS sandbox";
    assert!(
        label.contains(negation_clause),
        "expected the exact negation clause {negation_clause:?} in the label: {label:?}"
    );

    let sandbox_occurrences: Vec<usize> = label
        .match_indices("sandbox")
        .map(|(idx, _)| idx)
        .collect();
    assert_eq!(
        sandbox_occurrences.len(),
        1,
        "\"sandbox\" must appear exactly once in the label, and only inside the negation: {label:?}"
    );

    let negation_start = label.find(negation_clause).unwrap();
    let sandbox_idx = sandbox_occurrences[0];
    let expected_sandbox_idx = negation_start + "not an OS ".len();
    assert_eq!(
        sandbox_idx, expected_sandbox_idx,
        "the sole \"sandbox\" occurrence must sit inside \"not an OS sandbox\", not stand alone as a positive claim: {label:?}"
    );

    // And the crate must not claim "sandbox" as an enforcement fact anywhere
    // else in the public label surface for the other two variants either —
    // a positive "sandbox" claim on any variant would be a new, unaudited
    // enforcement guarantee this kernel does not make.
    assert!(!KernelBoundary.honest_label().contains("sandbox"));
    assert!(!BestEffort.honest_label().contains("sandbox"));
}
