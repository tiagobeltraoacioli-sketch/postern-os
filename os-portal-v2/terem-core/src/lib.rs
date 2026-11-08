// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. This crate now
// CONTAINS a real spawn path ([`spawn`]), gated OFF by default: the
// license-safe default `TeremConfig` is refused at BOTH plan time and spawn
// time, and no other module starts any process. A real guest has never been
// booted in CI — the only #[ignore]-gated real-QEMU test requires an
// operator-supplied binary and images. Product name "Terem" is proposed
// only, pending trademark clearance.

//! # terem-core — host-testable type skeleton for Terem v2 (DESIGN PREVIEW)
//!
//! **Status: DESIGN PREVIEW. UNAUDITED. The spawn path is opt-in and OFF by
//! default; a real guest has never been booted in CI.**
//! `written ≠ built`, `built ≠ booted`, `designed ≠ audited`.
//!
//! This is the smallest honestly-shippable slice of
//! `docs/os-portal-v2/POC-SCOPE.md` — the §2.1 type skeleton plus
//! **dry-run/mock-tested** launch plumbing — chosen because it is fully
//! testable on a plain workstation with **no QEMU installed, no KVM, no
//! Linux box**:
//!
//! * [`resolve`] — pinned-name binary resolution for `qemu-system-x86_64`
//!   and `qemu-img`, a direct reuse of the tested `resolve_node_binary`
//!   shape from `desktop/src-tauri/src/main.rs` (name + location +
//!   canonicalize + exec-bit). Unit-tested against fake binaries in a temp
//!   dir; no real QEMU is needed or touched.
//! * [`config`] — [`config::TeremConfig`] with the license-safe defaults
//!   `docs/os-portal-v2/LICENSE-DECISION.md` §2 decided: every GPL-adjacent
//!   feature (`full_vm_qemu`, `wine_proton`) defaults **OFF**, opt-in only.
//!   QEMU/Wine are external operator-supplied processes, never linked.
//! * [`guest`] — the §2.1 data-shape skeleton ([`guest::GuestSpec`],
//!   [`guest::GuestHandle`], [`guest::GuestStatus`]). [`guest::GuestHandle`]
//!   carries a plain-data PID field; the only code path that fills it with
//!   a real value is [`spawn::SpawnedGuest::handle`], behind the opt-in
//!   gates below.
//! * [`qmp`] — QMP wire-framing types (greeting / command / response) with
//!   serialize/parse round-trip tests for the only two commands POC v1
//!   needs: `query-status` and `system_powerdown`.
//!
//! On top of that skeleton, this slice adds launch plumbing:
//!
//! * [`launch`] — [`launch::LaunchPlan`] builds the deterministic
//!   `qemu-system-x86_64` argv (memory/smp/virtio disk/serial-to-file/
//!   `-qmp unix:<sock>,server,nowait`/display-off) from a resolved binary
//!   path + [`guest::GuestSpec`] + [`config::TeremConfig`], **as data**.
//!   The only [`launch::LaunchMode`] is `DryRun`: [`launch`] itself returns
//!   the plan and never executes it. A plan is refused outright unless the
//!   operator opted in via `full_vm_qemu` (license-safe default OFF).
//!   The argv has been pinned byte-for-byte in tests but **never handed to
//!   a real QEMU in CI**.
//! * [`spawn`] — the crate's ONLY spawn path: [`spawn::spawn_plan`] turns a
//!   built plan into a real `std::process::Child`, re-checking BOTH gates
//!   (license opt-in + program-name pin) at spawn time, defense in depth.
//!   [`spawn::SpawnedGuest`] owns the child and kills+reaps it on drop.
//!   Hermetic tests spawn only a fake sleeper script carrying the pinned
//!   name; the real-QEMU integration test is `#[ignore]`-gated and has
//!   never run in CI — **a real guest has never been booted**.
//! * [`qmp_client`] — [`qmp_client::QmpClient`], the socket-I/O half of the
//!   QMP control plane (POC-SCOPE §3 step 4's shape), generic over any
//!   `Read + Write`: greeting → `qmp_capabilities` negotiation →
//!   `query-status` / `system_powerdown`, skipping async event lines.
//!   Tested ONLY against in-process mocks (a scripted in-memory stream and
//!   a `UnixStream::pair` mock-server thread) — **never against a live
//!   QEMU**.
//!
//! ## What this crate is NOT
//!
//! * It is **not** wired into the Tauri shell (`desktop/`) — POC-SCOPE §1.3
//!   defers that, along with `os/terem-compat.nix`, every bridge crossing,
//!   Windows guests, Wine/App Mode, snapshots, and multi-guest state.
//! * It does **not** bundle, link, vendor, or ship QEMU (GPL-2.0) or Wine
//!   (LGPL-2.1). Per LICENSE-DECISION.md §1–2, those are opt-in external
//!   processes an operator supplies themselves; Postern's default attested
//!   build ships zero GPL/LGPL/AGPL code, and this crate's dependency tree
//!   is serde/serde_json only (MIT OR Apache-2.0).
//! * It is **not** a security control. Nothing here has been audited.

pub mod config;
pub mod guest;
pub mod launch;
pub mod qmp;
pub mod qmp_client;
pub mod resolve;
pub mod spawn;
