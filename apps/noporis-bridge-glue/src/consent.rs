// SPDX-License-Identifier: MIT OR Apache-2.0
//! The N-gate consent seam — the far-side, deny-by-default authority.
//!
//! **Ownership:** the real per-capability consent decision lives in Dev N-gate's
//! `apps/noporis-gate/` (the on-device port of `apps/sloboda-gate`'s
//! deny-by-default kernel: consent-accepted + kill-switch + five per-capability
//! bridges + `normalize()`-to-deny). This crate does **not** own, edit, or
//! duplicate that gate. It **consumes** its verdict through the [`GateConsent`]
//! seam — one query per crossing, evaluated on the *receiving* side, so nothing
//! is delivered to a persona the gate has not, right now, opened for it.
//!
//! [`ReferenceGate`] below is a **test/reference stand-in** for that gate — it
//! reproduces the gate-store *semantics* so this crate builds, tests, and demos
//! standalone. It is NOT the N-gate and must be replaced by the real
//! `apps/noporis-gate/` decision on device.

use std::collections::BTreeMap;

use crate::capability::Capability;
use crate::error::DenyReason;
use crate::persona::Persona;

/// The gate's verdict for one crossing. Deny-by-default: the ONLY way to `Allow`
/// is an explicit, live, per-capability yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentDecision {
    /// This capability may cross to `to` right now.
    Allow,
    /// Refused, with the honest reason.
    Deny(DenyReason),
}

impl ConsentDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, ConsentDecision::Allow)
    }
}

/// The seam Dev N-gate implements. One method: decide, deny-by-default, whether a
/// `capability` may cross from `from` to `to` *at this instant*. The glue calls it
/// on every crossing; a `Deny` (or a panic-free absence of `Allow`) stops delivery.
pub trait GateConsent {
    /// Decide a single crossing. MUST default to `Deny` for anything not an
    /// explicit, live yes.
    fn decide(&self, capability: Capability, from: Persona, to: Persona) -> ConsentDecision;
}

/// A reference, deny-by-default gate that mirrors `gate-store.mjs` semantics.
///
/// **This is a stand-in for Dev N-gate's `apps/noporis-gate/`, for tests/demos
/// only.** It exists so the crossing glue is exercisable end-to-end without the
/// real on-device gate. Semantics ported verbatim:
///
/// - `containerAllowed()` = consent accepted **and** kill-switch clear.
/// - each of the five bridges is `false` until an explicit, disclosed toggle
///   (`asBool`: anything not exactly `true` is deny).
/// - a malformed state collapses to full-deny (modelled by [`ReferenceGate::poisoned`]).
#[derive(Debug, Clone)]
pub struct ReferenceGate {
    consent_accepted: bool,
    kill_switch_engaged: bool,
    /// A corrupt/`normalize()`-tripped state: everything denies regardless.
    poisoned: bool,
    bridges: BTreeMap<Capability, bool>,
}

impl Default for ReferenceGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceGate {
    /// A fresh gate: not consented, kill-switch clear, every bridge closed.
    pub fn new() -> Self {
        let mut bridges = BTreeMap::new();
        for cap in Capability::ALL {
            bridges.insert(cap, false); // deny-by-default
        }
        ReferenceGate {
            consent_accepted: false,
            kill_switch_engaged: false,
            poisoned: false,
            bridges,
        }
    }

    /// Show-and-accept the first-entry crossing disclosure (this session).
    pub fn accept_consent(&mut self) -> &mut Self {
        self.consent_accepted = true;
        self
    }

    /// Engage the operator kill-switch: cut the span. Never destroys wallet state
    /// in the sealed base (that lives behind Porog, untouched here).
    pub fn engage_kill_switch(&mut self) -> &mut Self {
        self.kill_switch_engaged = true;
        self
    }

    /// Throw one capability lever open (an explicit, disclosed toggle).
    pub fn open(&mut self, capability: Capability) -> &mut Self {
        self.bridges.insert(capability, true);
        self
    }

    /// Close one capability lever (revoke the lane).
    pub fn close(&mut self, capability: Capability) -> &mut Self {
        self.bridges.insert(capability, false);
        self
    }

    /// Model a corrupt/malformed gate state: `normalize()` collapses it to
    /// full-deny + not-consented — a corrupt file can never silently open a lane.
    pub fn poison(&mut self) -> &mut Self {
        self.poisoned = true;
        self
    }
}

impl GateConsent for ReferenceGate {
    fn decide(&self, capability: Capability, _from: Persona, _to: Persona) -> ConsentDecision {
        if self.poisoned {
            return ConsentDecision::Deny(DenyReason::Malformed);
        }
        if self.kill_switch_engaged {
            return ConsentDecision::Deny(DenyReason::KillSwitchEngaged);
        }
        if !self.consent_accepted {
            return ConsentDecision::Deny(DenyReason::ConsentNotAccepted);
        }
        // `asBool`: anything not exactly `true` is deny.
        match self.bridges.get(&capability) {
            Some(true) => ConsentDecision::Allow,
            _ => ConsentDecision::Deny(DenyReason::CapabilityClosed),
        }
    }
}
