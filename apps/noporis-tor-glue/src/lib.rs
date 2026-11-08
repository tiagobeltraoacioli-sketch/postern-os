// SPDX-License-Identifier: MIT OR Apache-2.0
//! # noporis-tor-glue — per-persona Tor identity glue for **NoporIS**
//!
//! **NoporIS** is the guarded bridge between **two personas** on one stock-Android
//! handset: a **clean/business** persona (GMS-free, can be Tor-only) and a
//! **Google-Play** persona (GMS enabled — the *less-private* side by construction).
//! Porog is the *door into* a hardened container; NoporIS is the *bridge between*
//! two worlds that both keep existing.
//!
//! ## What this crate is (and is NOT)
//!
//! It is **glue only**. It composes two existing crates *without editing either
//! one's internals*:
//!
//! - [`postern_tor`] — the in-process, **client-only** Tor layer (an `arti`
//!   wrapper). We call [`PosternTor::for_identity`] and nothing more; we do not
//!   touch its internals.
//! - [`postern_policy`] — the one shared, **fail-closed** consent kernel. Its
//!   [`Decision`] and [`EnforcementMode`] give the honest vocabulary so the
//!   egress gate cannot quietly "round up" what it really guarantees.
//!
//! The job: give **EACH persona its own circuit-isolated Tor identity** — a
//! distinct [`PosternTor::for_identity`] handle plus a pinned
//! [`IsolationToken`](postern_tor::IsolationToken) — so the two worlds' egress
//! **does not trivially correlate at the Tor layer** (no shared circuit, no shared
//! exit, no shared-timing linkage between "the clean world" and "the Google
//! world"). For the clean persona it also turns "is a Tor circuit up?" into a
//! **fail-closed, Tor-only egress [`Decision`]**.
//!
//! This is a **DIFFERENT** concern from `apps/noporis-bridge-glue` (the N-channel
//! *cross-persona* bridge). This crate is only the **egress / Tor-identity** seam.
//!
//! ## The honest ceiling — pinned here so no surface can soften it
//!
//! Per-persona Tor isolation is worth having, but it is **narrow**. State every
//! limit below verbatim in any surface that describes it (see
//! [`CORRELATION_CEILING`] and [`GMS_OUT_OF_SCOPE`]):
//!
//! - **It stops *Tor-layer* correlation only.** Distinct
//!   [`for_identity`](PosternTor::for_identity) handles mean the two personas'
//!   streams never share a circuit or an exit relay — so an exit/destination
//!   cannot link them *by shared circuit*. That is the whole guarantee.
//! - **It does NOT stop device-level or network-level correlation.** Same public
//!   IP (unless *every* persona is fully Tor-routed — the Google persona by design
//!   is **not**), same IMEI / SIM / phone number / hardware serial, same modem.
//!   Google, a carrier, or a network observer can still tell the two personas are
//!   **one physical phone**. Separation of *circuits* is **not** separation of
//!   *device identity*.
//! - **The Google-Play persona's GMS egress is OUT OF SCOPE for containment.**
//!   Google Play Services phones home **regardless** of anything here; it uses the
//!   persona's normal networking, **not** this glue's Tor identity. NoporIS sells
//!   **separation + convenience, NOT privacy on the Google side.** It cannot make
//!   a Google-Android persona private, and this crate never claims to.
//! - **Tor here is CLIENT-ONLY.** [`postern_tor`] connects *to* the network / to
//!   `.onion` services; it does **not** host one. No hosting path exists here.
//! - **Hardened, not anonymous.** Tor reduces network metadata. It does **not**
//!   make a persona anonymous against a compromised/rooted host, a coerced user,
//!   or on-device correlation.
//! - **Userland, not a kernel boundary.** The egress gate is
//!   [`EnforcementMode::ByConstruction`] — an in-process check. The *profile*
//!   boundary (separate FBE keys + SELinux) is the kernel's and is **not** this
//!   crate's; a rooted host or a leak *below* this glue defeats the gate. See
//!   [`honest_enforcement_label`].
//! - **Not the attested workspace.** Routing egress over Tor says nothing about
//!   attestation: NoporIS attests the *phone* (key-attested device), **not the
//!   workspace/persona**. Never "measured-boot persona".
//! - **UNAUDITED reference-prototype.** No security claim until an audit gate. The
//!   coin is worthless and is **not a security**; personal use is free; this is
//!   **not legal advice**; NoporIS is an app on stock Android, **never "Postern
//!   OS."** The live Tor path (feature `live`) pulls `arti` and is **not built in
//!   this sandbox** — exactly as [`postern_tor`]'s own live bootstrap is ignored.

#![forbid(unsafe_code)]

use postern_policy::{Decision, EnforcementMode};

/// The two worlds NoporIS bridges on one handset. The platform enforces **exactly
/// two** (Android permits one managed profile per user); NoporIS is the bridge
/// between them, and this crate gives each its own Tor identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persona {
    /// The **clean / business** persona — GMS-free, wallet-side. It can be
    /// **Tor-only**: this glue is its egress path and it is **fail-closed** (no
    /// live circuit ⇒ no egress). This is the more-private side.
    Clean,

    /// The **Google-Play** persona — GMS + Play Store enabled, signed into a
    /// Google account. It is the **LESS-PRIVATE side by construction**: it uses
    /// **normal profile networking** and its GMS egress **phones home regardless**
    /// (out of scope for this glue — see [`GMS_OUT_OF_SCOPE`]). NoporIS gives it a
    /// distinct Tor identity for the traffic it *chooses* to route over Tor, so
    /// that traffic still does not share a circuit with the clean world — but it
    /// **cannot** contain GMS. Separation, not privacy.
    GooglePlay,
}

impl Persona {
    /// Is this persona **Tor-only** (this glue is its whole egress, fail-closed)?
    /// Only [`Persona::Clean`] is. The Google-Play persona is **not** — it has
    /// normal networking by design and gating GMS on Tor would be a false claim.
    pub fn is_tor_only(self) -> bool {
        matches!(self, Persona::Clean)
    }

    /// Does this persona run **GMS that phones home regardless** of this glue?
    /// Only [`Persona::GooglePlay`]. When `true`, no Tor identity here contains
    /// that egress — label it [`GMS_OUT_OF_SCOPE`].
    pub fn gms_phones_home(self) -> bool {
        matches!(self, Persona::GooglePlay)
    }

    /// A short, stable, honest label for UI/logs. Never rounds up: the Google side
    /// is named *less-private* every time.
    pub fn honest_label(self) -> &'static str {
        match self {
            Persona::Clean => "clean persona — Tor-only, fail-closed egress",
            Persona::GooglePlay => {
                "Google-Play persona — LESS-PRIVATE, GMS phones home (separation, not privacy)"
            }
        }
    }

    /// The **primary** per-persona containment caveat — the one that most defines
    /// this persona's honest limit, so a one-line surface uses the same words every
    /// time. The clean persona's defining limit is the Tor-layer ceiling; the
    /// Google persona's is the GMS phone-home.
    ///
    /// This is the *headline* caveat only. The Google persona is subject to **both**
    /// [`GMS_OUT_OF_SCOPE`] *and* [`CORRELATION_CEILING`] (the correlation ceiling
    /// applies to any traffic it routes over Tor, on top of GMS phoning home). A
    /// surface that has room for the full set must use [`containment_caveats`] so it
    /// cannot silently drop the ceiling on the less-private side.
    pub fn containment_caveat(self) -> &'static str {
        match self {
            Persona::Clean => CORRELATION_CEILING,
            Persona::GooglePlay => GMS_OUT_OF_SCOPE,
        }
    }

    /// The **full** ordered set of containment caveats that must travel with this
    /// persona — never rounds down. The clean persona carries the Tor-layer ceiling
    /// alone. The **Google-Play persona carries BOTH** [`GMS_OUT_OF_SCOPE`] (its GMS
    /// phones home regardless) **and** [`CORRELATION_CEILING`] (the Tor identity it
    /// gets for chosen traffic still only buys Tor-layer un-correlation, never
    /// device/network un-correlation). Pinned so no surface can show the Google
    /// side's `Allow` with only half its honesty.
    pub fn containment_caveats(self) -> &'static [&'static str] {
        match self {
            Persona::Clean => &[CORRELATION_CEILING],
            Persona::GooglePlay => &[GMS_OUT_OF_SCOPE, CORRELATION_CEILING],
        }
    }
}

/// The honest enforcement mode of the egress gate: an in-process, userland check —
/// real defense-in-depth, but **not** an OS/kernel network boundary (that is the
/// managed-profile's FBE+SELinux boundary, which this crate does not implement).
/// Pinned so no surface can claim a stronger guarantee than is in force.
pub const EGRESS_ENFORCEMENT: EnforcementMode = EnforcementMode::ByConstruction;

/// The core honest limit of per-persona Tor isolation — the exact words every
/// surface must use. It buys **Tor-layer** un-correlation only, never device or
/// network un-correlation.
pub const CORRELATION_CEILING: &str = "per-persona Tor identities keep the two worlds' \
    streams off a shared circuit/exit — Tor-LAYER correlation only. It does NOT stop \
    device- or network-level correlation: same public IP (unless every persona is fully \
    Tor-routed), same IMEI/SIM/phone-number/hardware-serial, same modem. Separation of \
    circuits is not separation of device identity. Hardened, not anonymous.";

/// The Google-Play persona's phone-home caveat — GMS egress is out of scope for
/// containment. Pinned so the "less-private side" is never softened.
pub const GMS_OUT_OF_SCOPE: &str = "the Google-Play persona's GMS egress is OUT OF SCOPE \
    for containment: Google Play Services phones home regardless, over the persona's normal \
    networking, NOT this glue's Tor identity. NoporIS gives separation + convenience, NOT \
    privacy on the Google side — it cannot make a Google-Android persona private.";

/// The **fail-closed, Tor-only** egress rule for a persona — the same shape as
/// `porog-tor-glue::egress_decision`, generalized per persona.
///
/// - [`Persona::Clean`] is **Tor-only**: `tor_ready == false` ⇒ [`Decision::Deny`]
///   with a reason; there is no "open anyway" path and no clearnet fallback exposed
///   anywhere in this crate. A half-open Tor is treated as no Tor.
/// - [`Persona::GooglePlay`] has **normal networking by design**, so this glue does
///   **not** gate its egress on Tor — that would be a false "we contained GMS"
///   claim. It returns [`Decision::Allow`], but that Allow is a **separation**
///   statement, **not** a privacy one: pair it with [`GMS_OUT_OF_SCOPE`]. Use
///   [`persona_egress_note`] to get the honest caveat alongside the decision.
///
/// This answers *"may this persona touch the network under NoporIS's egress
/// policy?"* — consent + kill-switch for the *cross-persona bridge* are enforced
/// elsewhere (`apps/noporis-bridge-glue`), not here.
pub fn persona_egress_decision(persona: Persona, tor_ready: bool) -> Decision {
    match persona {
        Persona::Clean => {
            if !tor_ready {
                return Decision::deny(
                    "clean persona is Tor-only: egress is fail-closed until a circuit is up",
                );
            }
            Decision::Allow
        }
        // The Google persona is not Tor-gated (it has normal networking by design);
        // the honesty lives in the caveat, not in a false deny.
        Persona::GooglePlay => Decision::Allow,
    }
}

/// The egress [`Decision`] *and* the honest caveat that must travel with it. Use
/// this rather than [`persona_egress_decision`] alone when rendering a surface, so
/// an `Allow` for the Google persona can never be shown as a privacy claim.
pub fn persona_egress_note(persona: Persona, tor_ready: bool) -> (Decision, &'static str) {
    (persona_egress_decision(persona, tor_ready), persona.containment_caveat())
}

/// The egress [`Decision`] with the **full** ordered set of caveats that must
/// travel with it (see [`Persona::containment_caveats`]). Prefer this over
/// [`persona_egress_note`] on any surface with room for more than one line: the
/// Google persona's `Allow` then carries **both** [`GMS_OUT_OF_SCOPE`] and
/// [`CORRELATION_CEILING`], never just one.
pub fn persona_egress_full_note(
    persona: Persona,
    tor_ready: bool,
) -> (Decision, &'static [&'static str]) {
    (persona_egress_decision(persona, tor_ready), persona.containment_caveats())
}

/// The single stable caveat string for the egress **gate's enforcement mode**,
/// delegated to [`postern_policy`] so every surface uses the *same words* for the
/// same honest boundary (no drift, no round-up).
pub fn honest_enforcement_label() -> String {
    EGRESS_ENFORCEMENT.honest_label().to_string()
}

/// Anti-round-up guard: assert, in code, that the egress gate never claims a
/// stronger enforcement than it actually provides. Returns `true` iff the real
/// [`EGRESS_ENFORCEMENT`] is at least as strong as `claimed`. A surface that wants
/// to print "kernel-enforced" must get `false` here and refuse. (The kernel
/// boundary is the managed profile's, not this glue's.)
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

    /// A bootstrapped, **circuit-isolated** Tor handle dedicated to **one
    /// persona**. Built from a single shared [`PosternTor`] via
    /// [`PosternTor::for_identity`] + a pinned [`IsolationToken`], so this
    /// persona's streams never share a circuit with the *other* persona (or with
    /// the wallet/messenger identities elsewhere in the suite).
    ///
    /// Holding one means "Tor is up" for this persona (see
    /// [`PersonaTor::gate_tor_bootstrapped`]).
    pub struct PersonaTor {
        /// Which world this handle serves — decides the egress policy.
        persona: Persona,
        /// A `for_identity()` handle — its streams never share a circuit with any
        /// other Postern identity, including the sibling persona.
        tor: PosternTor,
        /// One isolation token pinned to this persona, passed on every stream so
        /// this persona's own streams may share circuits with each other and with
        /// nothing else.
        token: IsolationToken,
    }

    /// Egress errors on the live path.
    #[derive(Debug, thiserror::Error)]
    pub enum EgressError {
        /// The fail-closed policy refused the connection (clean persona, Tor down).
        #[error("egress denied by policy: {0}")]
        Denied(String),
        /// The underlying Tor layer failed to connect.
        #[error(transparent)]
        Tor(#[from] postern_tor::TorError),
    }

    impl PersonaTor {
        /// Derive a persona's circuit-isolated identity from an
        /// already-bootstrapped, shared [`PosternTor`] (one the app boots once for
        /// the whole process). This persona gets its **own** isolated circuits and
        /// token — disjoint from every other persona built the same way.
        pub fn for_persona(shared: &PosternTor, persona: Persona) -> Self {
            Self {
                persona,
                tor: shared.for_identity(),
                token: IsolationToken::new(),
            }
        }

        /// Which world this handle serves.
        pub fn persona(&self) -> Persona {
            self.persona
        }

        /// The fail-closed egress [`Decision`] for this live handle, computed by
        /// the **same** [`persona_egress_decision`] rule any surface uses — so the
        /// live path and the policy layer can never diverge. For a live handle
        /// `gate_tor_bootstrapped()` is `true`, so the clean persona resolves to
        /// `Allow`; the Google persona is `Allow` by design (normal networking).
        pub fn egress_decision(&self) -> Decision {
            super::persona_egress_decision(self.persona, self.gate_tor_bootstrapped())
        }

        /// The egress decision **with** its honest caveat (see
        /// [`persona_egress_note`]) — the Google persona's `Allow` must never be
        /// rendered without [`GMS_OUT_OF_SCOPE`].
        pub fn egress_note(&self) -> (Decision, &'static str) {
            super::persona_egress_note(self.persona, self.gate_tor_bootstrapped())
        }

        /// `true` while this handle is alive — the boolean a wrapper writes into
        /// the persona's gate state as `egress.torBootstrapped`.
        pub fn gate_tor_bootstrapped(&self) -> bool {
            true
        }

        /// Open a Tor-anonymised, **persona-circuit-isolated** TCP stream to
        /// `host:port`, **after** the fail-closed egress gate allows it. `host` is
        /// resolved at the exit/onion, never locally (no DNS leak). Layer TLS/HTTP
        /// on top; prefer `.onion` nodes (a clearnet exit is an active MITM — see
        /// [`postern_tor`]).
        ///
        /// SCOPE, stated not solved: for [`Persona::GooglePlay`] this covers
        /// **only** the traffic the app *chooses* to route through this handle.
        /// GMS does **not** come through here — it phones home over the persona's
        /// normal networking regardless ([`GMS_OUT_OF_SCOPE`]). This method cannot
        /// and does not contain it.
        pub async fn connect(
            &self,
            host: &str,
            port: u16,
        ) -> Result<arti_client::DataStream, EgressError> {
            if let Some(reason) = self.egress_decision().reason() {
                return Err(EgressError::Denied(reason.to_string()));
            }
            let stream = self.tor.connect_isolated(host, port, self.token).await?;
            Ok(stream)
        }
    }

    /// Both worlds' Tor identities, each isolated from the other, derived from one
    /// shared bootstrapped Tor. This is the crate's headline: two personas, two
    /// disjoint circuit families, from a single client-only Tor.
    pub struct PersonaWorlds {
        /// The clean/business persona — Tor-only, fail-closed egress.
        pub clean: PersonaTor,
        /// The Google-Play persona — distinct Tor identity, but LESS-PRIVATE:
        /// GMS phones home outside this handle ([`GMS_OUT_OF_SCOPE`]).
        pub google_play: PersonaTor,
    }

    impl PersonaWorlds {
        /// Bootstrap a fresh in-process, client-only Tor and derive **both**
        /// personas' circuit-isolated identities from it. Blocks until Tor has a
        /// usable view of the network (seconds on a good link).
        pub async fn bootstrap() -> Result<Self, EgressError> {
            let base = PosternTor::bootstrap().await?;
            Ok(Self::from_shared(&base))
        }

        /// Derive both personas from an already-bootstrapped shared [`PosternTor`].
        /// Each persona gets its own [`PosternTor::for_identity`] handle and its
        /// own [`IsolationToken`], so the two worlds' streams are guaranteed to
        /// live on **disjoint circuits**.
        pub fn from_shared(shared: &PosternTor) -> Self {
            Self {
                clean: PersonaTor::for_persona(shared, Persona::Clean),
                google_play: PersonaTor::for_persona(shared, Persona::GooglePlay),
            }
        }
    }
}

#[cfg(feature = "live")]
pub use live::{EgressError, PersonaTor, PersonaWorlds};

// ===========================================================================
// Tests — pure, offline by default. The live Tor path ALSO gets its own
// compile-exercised, ignored-by-default smoke test below (`live_tests`,
// feature `live`) that proves reachability only — not anonymity or isolation
// strength; postern-tor's own ignored integration test still separately
// covers its lower-level bootstrap path. Here we prove the per-persona
// fail-closed policy, the anti-round-up guard, and that the honesty caveats
// are pinned.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_persona_is_fail_closed_until_tor_is_up() {
        assert!(
            persona_egress_decision(Persona::Clean, false).is_deny(),
            "clean persona with no Tor must be a deny"
        );
        assert!(
            persona_egress_decision(Persona::Clean, false)
                .reason()
                .unwrap()
                .contains("fail-closed"),
            "the deny must carry an honest reason"
        );
        assert!(
            persona_egress_decision(Persona::Clean, true).is_allow(),
            "live Tor allows the clean persona's egress"
        );
    }

    #[test]
    fn google_play_persona_is_not_tor_gated_but_is_labelled_less_private() {
        // The Google persona has normal networking by design — no false Tor gate.
        assert!(persona_egress_decision(Persona::GooglePlay, false).is_allow());
        assert!(persona_egress_decision(Persona::GooglePlay, true).is_allow());
        // ...but its Allow always travels with the GMS phone-home caveat.
        let (decision, caveat) = persona_egress_note(Persona::GooglePlay, true);
        assert!(decision.is_allow());
        assert_eq!(caveat, GMS_OUT_OF_SCOPE);
        assert!(caveat.contains("phones home"));
        assert!(caveat.contains("NOT"));
    }

    #[test]
    fn persona_flags_never_round_up() {
        assert!(Persona::Clean.is_tor_only());
        assert!(!Persona::Clean.gms_phones_home());
        assert!(!Persona::GooglePlay.is_tor_only());
        assert!(Persona::GooglePlay.gms_phones_home());
        // The Google side is named less-private every time.
        assert!(Persona::GooglePlay.honest_label().contains("LESS-PRIVATE"));
    }

    #[test]
    fn google_persona_carries_both_caveats_and_never_rounds_down() {
        // The less-private side's Allow must travel with BOTH honesty caveats:
        // GMS phones home (out of scope) AND the Tor-layer correlation ceiling.
        let (decision, caveats) = persona_egress_full_note(Persona::GooglePlay, true);
        assert!(decision.is_allow());
        assert_eq!(caveats, &[GMS_OUT_OF_SCOPE, CORRELATION_CEILING]);
        assert!(caveats.contains(&GMS_OUT_OF_SCOPE));
        assert!(caveats.contains(&CORRELATION_CEILING));
        // The clean side carries the ceiling alone (no GMS caveat — no GMS).
        let (_, clean_caveats) = persona_egress_full_note(Persona::Clean, true);
        assert_eq!(clean_caveats, &[CORRELATION_CEILING]);
        assert!(!clean_caveats.contains(&GMS_OUT_OF_SCOPE));
        // The one-line headline caveat stays each persona's defining limit.
        assert_eq!(Persona::GooglePlay.containment_caveat(), GMS_OUT_OF_SCOPE);
        assert_eq!(Persona::Clean.containment_caveat(), CORRELATION_CEILING);
    }

    #[test]
    fn correlation_ceiling_states_the_device_level_limit() {
        // The core honest limit: Tor-LAYER only, NOT device/network correlation.
        let caveat = Persona::Clean.containment_caveat();
        assert_eq!(caveat, CORRELATION_CEILING);
        assert!(caveat.contains("Tor-LAYER correlation only"));
        assert!(caveat.contains("IMEI"));
        assert!(caveat.contains("same public IP"));
        assert!(caveat.contains("not separation of device identity"));
    }

    #[test]
    fn egress_never_rounds_up_to_a_kernel_boundary() {
        // The egress gate is a userland, in-process check — it must refuse to
        // claim an OS/kernel boundary (the profile boundary is the kernel's, not
        // this glue's), and accept only claims at or below its real mode.
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
}

// ===========================================================================
// Live-path smoke test — feature `live`, network-dependent, IGNORED BY
// DEFAULT. It compile-exercises the live path (`PersonaWorlds::bootstrap`
// over a REAL, in-process, client-only Tor) so the wiring in `mod live`
// above is not just type-checked but actually run at least once, on demand.
//
// What this test proves, and NOTHING more: that a live `PosternTor::bootstrap`
// succeeds and that this crate's per-persona wiring on top of it still
// resolves to the expected `Decision`s and caveat. It does NOT prove
// anonymity, does NOT prove isolation strength (that the two personas'
// circuits are actually disjoint on the wire), and does NOT prove anything
// about the Google-Play persona's GMS egress — see [`CORRELATION_CEILING`]
// and [`GMS_OUT_OF_SCOPE`] for the real, unchanged ceiling. This module adds
// reachability coverage only.
// ===========================================================================
#[cfg(all(test, feature = "live"))]
mod live_tests {
    use super::*;

    /// Live smoke test: bootstraps a REAL client-only Tor via
    /// [`PersonaWorlds::bootstrap`] and asserts both personas resolve to
    /// [`Decision::Allow`], with the Google-Play persona's [`GMS_OUT_OF_SCOPE`]
    /// caveat still attached to that `Allow`.
    ///
    /// IGNORED BY DEFAULT — not run by plain `cargo test --features live`.
    /// Needs a live network path and bootstraps a real (unaudited) Tor
    /// client, which can take seconds to minutes and talks to the real Tor
    /// network. It proves **reachability only**: that the live bootstrap
    /// path compiles, runs, and still returns the same honest `Decision`s
    /// and caveats as the pure/offline tests above — **not** anonymity, and
    /// **not** isolation strength (it does not inspect circuits/exits to
    /// confirm the two personas are actually on disjoint paths on the wire).
    /// Run explicitly: `cargo test --features live -- --ignored`.
    #[test]
    #[ignore = "needs network: bootstraps a real client-only Tor; unaudited"]
    fn live_smoke_bootstrap_reaches_the_network() {
        // No #[tokio::test] macro: the `live` feature's tokio dependency only
        // declares io-util/net/rt (no `macros`), so the async bootstrap is
        // driven from a plain #[test] via a manually built current-thread
        // runtime, per this crate's existing optional tokio dep.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a current-thread tokio runtime for the live smoke test");

        rt.block_on(async {
            let worlds = PersonaWorlds::bootstrap()
                .await
                .expect("live PersonaWorlds::bootstrap over a real client-only Tor");

            assert!(
                worlds.clean.egress_decision().is_allow(),
                "clean persona must resolve Allow once a live circuit is up"
            );
            assert!(
                worlds.google_play.egress_decision().is_allow(),
                "Google-Play persona is Allow by design (normal networking)"
            );

            let (decision, caveat) = worlds.google_play.egress_note();
            assert!(decision.is_allow());
            assert_eq!(
                caveat, GMS_OUT_OF_SCOPE,
                "the Google-Play persona's Allow must still carry the GMS out-of-scope caveat"
            );
        });
    }
}
