// SPDX-License-Identifier: MIT OR Apache-2.0
//! # porog-tor-glue — Tor egress glue for the **Porog** container
//!
//! **Porog** (Slavic: *threshold / soleira* — the door between two worlds, per
//! the Izbushka tale) is the **PROPOSED** product name for the stock-Android
//! managed-profile container, **pending formal trademark clearance**. "Postern"
//! stays the suite brand; "Porog" is this app.
//!
//! ## What this crate is (and is NOT)
//!
//! It is **glue only**. It composes two existing crates *without editing either
//! one's internals*:
//!
//! - [`postern_tor`] — the in-process, **client-only** Tor layer (an `arti`
//!   wrapper). We call its public API; we do not touch its internals.
//! - [`postern_policy`] — the one shared, **fail-closed** consent kernel. Its
//!   [`Decision`] and [`EnforcementMode`] give us the honest vocabulary so the
//!   egress gate cannot quietly "round up" what it really guarantees.
//!
//! The job: turn "is a Tor circuit up?" into a **fail-closed egress
//! [`Decision`]**, and give the container a **circuit-isolated Tor identity** of
//! its own so its traffic never shares a circuit with the wallet or messenger
//! identities.
//!
//! ## Honesty rails (kept verbatim in code, not just prose)
//!
//! - **Tor here is CLIENT-ONLY.** [`postern_tor`] connects to the network / to
//!   `.onion` services; it does **not** host one. No hosting path exists.
//! - **Hardened, not anonymous.** Tor reduces network metadata. It does **not**
//!   make the container anonymous against a compromised/rooted host, a coerced
//!   user, or on-device correlation.
//! - **Userland, not a kernel boundary.** The egress gate is
//!   [`EnforcementMode::ByConstruction`] — an in-process check. A rooted host or
//!   a leak *below* this glue defeats it. See [`honest_enforcement_label`].
//! - **Fail-closed.** Until Tor reports a usable circuit, egress is **denied**.
//!   A half-open Tor is treated as no Tor.
//! - **This is not the attested workspace.** Routing egress over Tor says
//!   nothing about attestation: the container attests the *phone* (key-attested
//!   device), **not the workspace**. Never "measured-boot workspace".
//! - **UNAUDITED reference-prototype.** No security claim until an audit gate.
//!   The live Tor path (feature `live`) pulls `arti` and is **not built in this
//!   sandbox** — exactly as [`postern_tor`]'s own live bootstrap is an ignored
//!   test.
//!
//! ## The seam to the consent gate
//!
//! The single boolean this glue produces —"is a container Tor circuit up?"— is
//! what the wrapper writes into the Sloboda-gate state as `egress.torBootstrapped`
//! (see `apps/sloboda-gate`). The gate's `egressAllowed()` and this
//! crate's [`egress_decision`] are the **same fail-closed rule** on the two
//! sides of the FFI seam: no consent or no live Tor ⇒ no egress.

#![forbid(unsafe_code)]

use postern_policy::{Decision, EnforcementMode};

/// The honest enforcement mode of the egress gate: an in-process, userland
/// check — real defense-in-depth, but **not** an OS/kernel network boundary.
/// Pinned so no surface can claim a stronger guarantee than is in force.
pub const EGRESS_ENFORCEMENT: EnforcementMode = EnforcementMode::ByConstruction;

/// The one fail-closed egress rule, shared with the JS gate's `egressAllowed()`.
///
/// `tor_ready` is the live signal from [`postern_tor`] — `true` **only** while a
/// usable circuit exists. When it is `false`, egress is a [`Decision::Deny`]
/// with a reason; there is no "open anyway" path, and there is deliberately no
/// clearnet fallback exposed anywhere in this crate.
///
/// Note this decision answers *"may the container touch the network at all?"* —
/// consent + kill-switch are enforced upstream by the gate (`containerAllowed`);
/// this layer adds the **Tor-only, Tor-must-be-live** half of the same
/// fail-closed chain.
pub fn egress_decision(tor_ready: bool) -> Decision {
    if !tor_ready {
        return Decision::deny(
            "tor not bootstrapped: container egress is fail-closed until a circuit is up",
        );
    }
    Decision::Allow
}

/// The single stable caveat string for the egress gate, delegated to
/// [`postern_policy`] so every surface uses the *same words* for the same
/// honest boundary (no drift, no round-up).
pub fn honest_enforcement_label() -> String {
    EGRESS_ENFORCEMENT.honest_label().to_string()
}

/// Anti-round-up guard: assert, in code, that the egress gate never claims a
/// stronger enforcement than it actually provides. Returns `true` iff the real
/// [`EGRESS_ENFORCEMENT`] is at least as strong as `claimed`. A surface that
/// wants to print "kernel-enforced" must get `false` here and refuse.
pub fn egress_can_claim(claimed: EnforcementMode) -> bool {
    EGRESS_ENFORCEMENT.satisfies(claimed)
}

// ===========================================================================
// Live Tor path — feature `live` (pulls arti; not built in this sandbox).
// ===========================================================================

#[cfg(feature = "live")]
mod live {
    use super::*;
    use postern_tor::{IsolationToken, PosternTor};

    /// A bootstrapped, **circuit-isolated** Tor handle dedicated to the Porog
    /// container identity. Because it can only be built from a live
    /// [`PosternTor`], holding one *is* the "Tor is up" signal the gate needs
    /// (see [`ContainerTor::gate_tor_bootstrapped`]).
    pub struct ContainerTor {
        /// A `for_identity()` handle — its streams never share a circuit with
        /// any other Postern identity (wallet, messenger).
        tor: PosternTor,
        /// One isolation token pinned to the container identity, passed on every
        /// stream so the container's own streams may share circuits with each
        /// other and with nothing else.
        token: IsolationToken,
    }

    /// Egress errors on the live path.
    #[derive(Debug, thiserror::Error)]
    pub enum EgressError {
        /// The fail-closed policy refused the connection (Tor down / not ready).
        #[error("egress denied by policy: {0}")]
        Denied(String),
        /// The underlying Tor layer failed to connect.
        #[error(transparent)]
        Tor(#[from] postern_tor::TorError),
    }

    impl ContainerTor {
        /// Bootstrap a fresh in-process Tor client and derive the container's
        /// circuit-isolated identity from it. Blocks until Tor has a usable view
        /// of the network (seconds on a good link). Client-only.
        pub async fn bootstrap() -> Result<Self, EgressError> {
            let base = PosternTor::bootstrap().await?;
            Ok(Self::for_container(&base))
        }

        /// Derive the container identity from an already-bootstrapped, shared
        /// [`PosternTor`] (e.g. one the app boots once for the whole process).
        /// The container gets its **own** isolated circuits and token.
        pub fn for_container(shared: &PosternTor) -> Self {
            Self {
                tor: shared.for_identity(),
                token: IsolationToken::new(),
            }
        }

        /// The fail-closed egress [`Decision`] for this live handle. Since a
        /// `ContainerTor` only exists once Tor bootstrapped, this is
        /// `Decision::Allow` — but it goes through the *same* [`egress_decision`]
        /// rule the gate uses, so the two sides can never diverge.
        pub fn egress_decision(&self) -> Decision {
            super::egress_decision(self.gate_tor_bootstrapped())
        }

        /// The single boolean the wrapper writes into the gate state as
        /// `egress.torBootstrapped`. `true` while this handle is alive.
        pub fn gate_tor_bootstrapped(&self) -> bool {
            true
        }

        /// Open a Tor-anonymised, container-circuit-isolated TCP stream to
        /// `host:port`, **after** the fail-closed egress gate allows it. `host`
        /// is resolved at the exit/onion, never locally (no DNS leak). Layer
        /// TLS/HTTP on top; prefer `.onion` nodes (a clearnet exit is an active
        /// MITM — see [`postern_tor`]).
        pub async fn connect(
            &self,
            host: &str,
            port: u16,
        ) -> Result<arti_client::DataStream, EgressError> {
            if let Some(reason) = self.egress_decision().reason() {
                return Err(EgressError::Denied(reason.to_string()));
            }
            let stream = self
                .tor
                .connect_isolated(host, port, self.token)
                .await?;
            Ok(stream)
        }
    }
}

#[cfg(feature = "live")]
pub use live::{ContainerTor, EgressError};

// ===========================================================================
// Tests — pure, offline. The live Tor path is covered by postern-tor's own
// ignored integration test; here we prove the fail-closed policy + honest label.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_is_fail_closed_until_tor_is_up() {
        assert!(egress_decision(false).is_deny(), "no Tor must be a deny");
        assert!(
            egress_decision(false).reason().unwrap().contains("fail-closed"),
            "the deny must carry an honest reason"
        );
        assert!(egress_decision(true).is_allow(), "live Tor allows egress");
    }

    #[test]
    fn egress_never_rounds_up_to_a_kernel_boundary() {
        // The gate is a userland, in-process check — it must refuse to claim an
        // OS/kernel boundary, and accept only claims at or below its real mode.
        assert!(!egress_can_claim(EnforcementMode::KernelBoundary));
        assert!(egress_can_claim(EnforcementMode::ByConstruction));
        assert!(egress_can_claim(EnforcementMode::BestEffort));
    }

    #[test]
    fn honest_label_is_the_shared_words() {
        // Delegated verbatim to postern-policy so no drift is possible.
        assert_eq!(
            honest_enforcement_label(),
            EnforcementMode::ByConstruction.honest_label()
        );
        assert!(honest_enforcement_label().contains("not an OS sandbox"));
    }

    #[test]
    fn egress_decision_is_a_pure_fail_closed_function() {
        // Same input, same verdict — no hidden state, no "open anyway" drift.
        // The deny path always carries an honest, Tor-naming reason; the allow
        // path never carries one.
        assert!(egress_decision(false).is_deny() && egress_decision(false).is_deny());
        assert!(egress_decision(true).is_allow() && egress_decision(true).is_allow());
        let reason = egress_decision(false).reason().unwrap().to_string();
        assert!(reason.contains("tor"), "deny reason must name Tor");
        assert!(
            egress_decision(true).reason().is_none(),
            "an allow must not smuggle a deny reason"
        );
    }

    #[test]
    fn egress_label_never_overclaims_anonymity() {
        // Anti-round-up on the WORDS: Tor here is metadata-reduction, not
        // anonymity. The honest label must not claim the container is anonymous,
        // and it must not claim to BE an OS sandbox / kernel boundary — the
        // enforcement mode is the weaker ByConstruction and says so ("not an OS
        // sandbox").
        let label = honest_enforcement_label().to_lowercase();
        assert!(!label.contains("anonymous"), "label must not claim anonymity");
        assert!(
            label.contains("not an os sandbox"),
            "label must disclaim being an OS sandbox / kernel boundary"
        );
        assert!(
            !egress_can_claim(EnforcementMode::KernelBoundary),
            "the egress gate must refuse to claim a kernel boundary"
        );
    }
}

// ===========================================================================
// Live-feature tests — feature `live`, still offline. These compile- and
// behavior-verify the arti-backed path's *types* (the `EgressError` enum and
// its `#[from] postern_tor::TorError` conversion) and re-prove the shared
// fail-closed rule under the `live` feature, without ever calling
// `ContainerTor::bootstrap()` or touching the network. The live bootstrap
// itself remains "not built in this sandbox" — not exercised here, exactly
// as documented in the module-level honesty rails above.
// ===========================================================================
#[cfg(all(test, feature = "live"))]
mod live_tests {
    use super::*;

    #[test]
    fn denied_error_display_carries_the_policy_prefix() {
        let err = EgressError::Denied("tor not bootstrapped".to_string());
        assert!(
            err.to_string().starts_with("egress denied by policy: "),
            "EgressError::Denied must carry the honest policy-denial prefix, got: {err}"
        );
    }

    #[test]
    fn tor_error_converts_into_egress_error_via_from() {
        // postern_tor::TorError::Bootstrap(String) is a plain data-carrying
        // variant with no network side effect to construct — safe and offline.
        let tor_err = postern_tor::TorError::Bootstrap("no network in sandbox".to_string());
        let egress_err: EgressError = tor_err.into();
        match egress_err {
            EgressError::Tor(inner) => {
                assert!(inner.to_string().contains("tor bootstrap failed"));
            }
            other => panic!("expected EgressError::Tor via #[from], got {other:?}"),
        }
    }

    #[test]
    fn from_impl_exists_as_a_fn_pointer_type_check() {
        // Belt-and-suspenders compile-time proof that `From<postern_tor::TorError>
        // for EgressError` exists, independent of the runtime assertion above.
        // (Kept even though TorError::Bootstrap above is directly constructible,
        // per the task's fallback instruction, so the From impl itself — not
        // just one variant's Display — is pinned at compile time.)
        let _from_fn: fn(postern_tor::TorError) -> EgressError = EgressError::from;
    }

    #[test]
    fn egress_decision_rule_is_identical_under_the_live_feature() {
        // The shared fail-closed rule must not diverge between feature
        // configurations: same crate function, same answer, `live` feature on.
        assert!(
            egress_decision(false).is_deny(),
            "no Tor must be a deny under the `live` feature too"
        );
    }
}
