// SPDX-License-Identifier: MIT OR Apache-2.0
//! The **structural denylist** — key material the type system refuses to put on
//! the wire.
//!
//! Security memo §5.1 (the bright line): *private key material MUST NEVER cross
//! the channel — encrypted or not.* This module makes that a **type-level wall**,
//! not a convention:
//!
//! * The secret types here ([`SeedPhrase`], [`SecretKey`]) deliberately do **not**
//!   implement [`serde::Serialize`]/[`Deserialize`], so they *cannot* be a field
//!   of a wire message and cannot be encoded onto a [`crate::Channel`]. There is
//!   no `Serialize` to derive against them; a future edit that tried to add one
//!   would be a visible, reviewable act — and the golden test in
//!   `tests/golden_denylist.rs` would still fail the build if any secret byte
//!   reached a serialized message.
//! * They wipe on [`Drop`] (the `WalletCore` hygiene), and their bytes are only
//!   reachable through a borrowing accessor that never yields ownership.
//! * Every protocol message implements the sealed [`WireSafe`] marker; secret
//!   types cannot (the trait is sealed in this crate). [`assert_wire_safe`] is a
//!   compile-time census: it will not build unless every message is `WireSafe`.
//!
//! The phone signs; only **signatures** and **public keys** (both public) cross
//! the channel. The seed and the hybrid Falcon‖ML-DSA secret stay on the device.

use zeroize::Zeroize;

/// A BIP39 seed / mnemonic. **Never** serializable, **never** on the wire.
///
/// Mirrors `WalletCore.seed` (`mobile/core`). Held only so the scaffold signer
/// can derive a deterministic pseudo-signature in tests; a real signer keeps the
/// seed inside `WalletCore` behind StrongBox/Secure-Enclave at rest. There is no
/// `Serialize`/`Deserialize` impl and there never will be one — that absence is
/// the wall.
pub struct SeedPhrase {
    bytes: Vec<u8>,
}

impl SeedPhrase {
    /// Wrap raw seed bytes. Consumes the input; the only way back out is a
    /// borrow via [`expose`](SeedPhrase::expose) — never an owned `Vec`, so the
    /// secret cannot be moved into a wire type by accident.
    pub fn new(bytes: Vec<u8>) -> Self {
        SeedPhrase { bytes }
    }

    /// Borrow the raw bytes for an on-device cryptographic operation only.
    /// Named `expose` so every call site reads as a deliberate unsealing.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SeedPhrase {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// The hybrid Falcon‖ML-DSA **secret key**. Same wall as [`SeedPhrase`]:
/// no `Serialize`, wiped on drop, borrow-only.
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl SecretKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretKey { bytes }
    }

    /// Borrow for an on-device sign only.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// ── The sealed WireSafe marker ────────────────────────────────────────────────

pub(crate) mod sealed {
    /// Sealed so only this crate can decide what is allowed on the wire. A
    /// downstream crate cannot bless a new type as `WireSafe`, and the secret
    /// types above are not (and can never be) members.
    pub trait Sealed {}
}

/// Marker for a type that is safe to serialize onto a [`crate::Channel`]: it
/// carries only **public** material (public keys, signatures, digests, nonces,
/// counters, decoded intent for display). It is sealed and requires
/// [`serde::Serialize`], so a secret type — which has no `Serialize` — can never
/// satisfy it.
pub trait WireSafe: serde::Serialize + sealed::Sealed {}

/// Bless a wire message. `#[allow(unused)]` because the blessing is the point,
/// not any call.
macro_rules! wire_safe {
    ($($t:ty),+ $(,)?) => {
        $(
            impl $crate::secret::sealed::Sealed for $t {}
            impl $crate::secret::WireSafe for $t {}
        )+
    };
}
pub(crate) use wire_safe;

/// Compile-time census of the wire surface. If a protocol message ever loses its
/// `WireSafe` blessing — or a secret type is smuggled into a message — this stops
/// compiling. Called from a `const` in `lib.rs` so it is checked on every build.
pub fn assert_wire_safe<T: WireSafe>() {}
