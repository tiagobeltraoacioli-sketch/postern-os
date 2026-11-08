//! Postern Office — the Postern-branded desktop **shell** (proposed codename
//! **"Svitok"**, Russian свиток "scroll"; the suite name stays the plan's
//! **"Kanzel / Kantselyariya"** chancery). Everything here is an UNAUDITED
//! reference-prototype and NOT a finished Microsoft-Office competitor.
//!
//! ## What this is — and the one honest caveat
//!
//! The customization is **shell / theme / templates ONLY**. The document engine
//! is **unmodified LibreOffice, aggregated** (spawned out-of-process, never
//! linked, forked, or patched) — mirroring the exact seam
//! `postern-quarantine` already ships for `soffice --headless`. LibreOffice is
//! **not present in this build**; the editor/conversion step is an **injected,
//! mockable seam** (`editor.rs`), and all offline tests drive a mock editor.
//!
//! **The at-rest file is ALWAYS ciphertext** — the canonical Postern seal from
//! [`postern_core::aead`] (XChaCha20-Poly1305 **v2**, key-committing,
//! context-bound to [`session::OFFICE_CONTEXT`]). No plaintext document is ever
//! written to the durable store.
//!
//! **BUT there is an unavoidable plaintext-while-editing window.** To edit a
//! document, the sealed bytes are decrypted into a **secured scratch file**
//! ([`session::ScratchGuard`]); while that scratch exists, the plaintext lives
//! on a filesystem, in the clear. This crate does NOT and CANNOT claim "zero
//! plaintext" / "never plaintext anywhere". What it does is **minimize and
//! collapse** that window:
//!
//! - put the scratch on **tmpfs / a no-swap RAM-backed dir** (caller's choice of
//!   `scratch_dir`),
//! - **secure-delete** the scratch (overwrite passes + remove) on every teardown,
//! - and wire a **panic-lock eviction** — [`session::OfficeSession::panic`] —
//!   that collapses the plaintext window on demand: it secure-deletes the
//!   scratch and drops/zeroizes the session key, leaving only the at-rest
//!   ciphertext.
//!
//! ## Panic-lock honesty (from `postern-panic`)
//!
//! [`session::OfficeSession::panic`] is a **denial-of-access re-lock**, the same
//! honest contract as [`postern_panic`]: the data is **not destroyed**, only
//! made unreadable until the key returns; the locked state is **observable**
//! ([`session::OfficeSession::is_locked`] returns `true`); it is **NOT a duress
//! or deniable feature** — a coercer can compel the one real key. Do not market
//! it as "seal under duress" or "deniable".
//!
//! ## Import / export live elsewhere
//!
//! Sanitizing an *inbound* untrusted document is `postern-quarantine`; scrubbing
//! metadata on *export* is `postern-hygiene`. This crate does NOT reimplement
//! either — it is the session/scratch/panic layer only.

pub mod editor;
pub mod session;

pub use session::{OfficeError, OfficeSession, ScratchGuard, OFFICE_CONTEXT};
