// SPDX-License-Identifier: MIT OR Apache-2.0
//! # `noporis-orchestrator` — the NoporIS daemon's `[[bin]]` entrypoint
//!
//! ## ⚠️ SCAFFOLD / reference-prototype — UNAUDITED. Certifies nothing.
//!
//! This is the thin CLI shell around [`noporis_bridge_glue::daemon::Daemon`] —
//! the composed state machine ([`Orchestrator`] persona-lifecycle reconcile +
//! per-`Direction` [`CrossingReceiver`]/[`ConsentLedger`] crossing decisions).
//! On a real device this is what an `init`/systemd unit execs; **on host it
//! runs entirely over the default `host-stub` feature's in-memory seams
//! (`HostStubDpc`) and never touches Android or Waydroid.**
//!
//! This binary wires **zero crossing lanes** by itself — a real device wires
//! its paired session's lane(s) in once pairing completes (that composition
//! step is out of this scaffold's scope; see [`noporis_bridge_glue::daemon`]'s
//! module doc for the `Daemon::add_lane` surface a real integration or F2's
//! E2E test drives). With no lanes, the daemon still does real, meaningful
//! work every tick: it reads the gate's posture, reconciles the persona
//! substrate (create/switch/kill), and is the sole runtime writer of
//! `state.json` + `sloboda-bridge.state` — the "spine" the PARTITION brief
//! asks for.
//!
//! ## Usage
//!
//! ```text
//! noporis-orchestrator --once [--state-dir <path>] [--now <unix-seconds>] [--steal-lock]
//! noporis-orchestrator --watch <ms> [--state-dir <path>] [--now <unix-seconds>] [--max-ticks <n>] [--steal-lock]
//! ```
//!
//! - `--once` — a single tick, then exit `0`. For scripted host tests (see
//!   `docs/bucketF/TEST-GATE.md`'s F1 smoke command).
//! - `--watch <ms>` — a bounded- or unbounded-iteration loop, ticking every
//!   `<ms>` milliseconds. `--max-ticks <n>` bounds it (required for
//!   deterministic host tests); omitted, it runs until killed — the real
//!   daemon behavior a systemd unit expects.
//! - `--state-dir <path>` — root both state files under `<path>` (host
//!   tests / a sandboxed run); omitted, uses the canonical device paths
//!   (`/var/lib/postern/noporis-gate/state.json`,
//!   `/run/postern/consent/sloboda-bridge.state`).
//! - `--now <unix-seconds>` — an injectable clock: fixes the first tick's
//!   instant instead of reading the wall clock, and (in `--watch` mode)
//!   advances it deterministically by the tick interval rather than
//!   re-reading the wall clock — keeps a scripted `--watch --max-ticks`
//!   run fully deterministic, no real-time dependency.
//! - `--steal-lock` — explicit crash-recovery: remove a stale
//!   [`WriterLock`](noporis_bridge_glue::WriterLock) left behind by a killed
//!   prior process for this `--state-dir`, then acquire fresh. Only pass this
//!   after establishing out of band that no other writer for the same
//!   `--state-dir` is still live — there is no automatic staleness check (see
//!   [`WriterLock::steal`](noporis_bridge_glue::WriterLock::steal)'s doc).
//!   Without it, a held lock is a hard, fail-closed refusal to start.
//!
//! ## Sole-writer enforcement
//!
//! Plan §5 says this orchestrator is the sole runtime writer of
//! `state.json` + `sloboda-bridge.state`. `main` now makes that a runtime
//! guarantee, not just a documented convention: before the first tick, it
//! acquires a [`WriterLock`](noporis_bridge_glue::WriterLock) for the
//! resolved `StatePaths` and holds it for the process's lifetime (its `Drop`
//! releases the lock file on any normal exit, including breaking out of
//! `--watch`). A second process pointed at the same `--state-dir` gets an
//! immediate, loud refusal (nonzero exit) instead of silently interleaving
//! writes with the first — see `--steal-lock` above for the explicit
//! crash-recovery path.
//!
//! ## Honesty rails (carried verbatim from the crate root)
//!
//! Reference-prototype, UNAUDITED. The per-crossing gate is a userland,
//! in-process check, NOT an OS/kernel boundary. This is an app on stock
//! Android, NEVER "Postern OS". The guardian is Yagabona, never "Baba Yaga".
//! The coin (BLCH) is not a security and buys no software.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noporis_bridge_glue::daemon::{unix_to_iso8601, Daemon, DaemonConfig};
use noporis_bridge_glue::{
    HostStubDpc, ManagedProfileSubstrate, Orchestrator, Persona, ReferenceGate, StatePaths,
    WriterLock,
};
use postern_pairing::transport::LoopbackTransport;

#[derive(Debug)]
enum Mode {
    Once,
    Watch { interval_ms: u64 },
}

#[derive(Debug)]
struct Cli {
    mode: Mode,
    paths: StatePaths,
    max_ticks: Option<u64>,
    now: Option<i64>,
    steal_lock: bool,
}

const USAGE: &str = "usage: noporis-orchestrator (--once | --watch <ms>) [--state-dir <path>] [--max-ticks <n>] [--now <unix-seconds>] [--steal-lock]";

fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Result<Cli, String> {
    let mut mode: Option<Mode> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut max_ticks: Option<u64> = None;
    let mut now: Option<i64> = None;
    let mut steal_lock = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => mode = Some(Mode::Once),
            "--watch" => {
                let ms = args.next().ok_or("--watch requires a millisecond interval")?;
                let ms: u64 = ms
                    .parse()
                    .map_err(|_| "--watch interval must be a non-negative integer number of milliseconds".to_string())?;
                mode = Some(Mode::Watch { interval_ms: ms });
            }
            "--state-dir" => {
                let dir = args.next().ok_or("--state-dir requires a path")?;
                state_dir = Some(PathBuf::from(dir));
            }
            "--max-ticks" => {
                let n = args.next().ok_or("--max-ticks requires a count")?;
                max_ticks = Some(n.parse().map_err(|_| "--max-ticks must be a non-negative integer".to_string())?);
            }
            "--now" => {
                let n = args.next().ok_or("--now requires a unix-seconds integer")?;
                now = Some(n.parse().map_err(|_| "--now must be an integer".to_string())?);
            }
            "--steal-lock" => steal_lock = true,
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let mode = mode.ok_or_else(|| "one of --once or --watch <ms> is required".to_string())?;
    let paths = match state_dir {
        Some(dir) => StatePaths::under(dir),
        None => StatePaths::default(),
    };
    Ok(Cli {
        mode,
        paths,
        max_ticks,
        now,
        steal_lock,
    })
}

/// The real wall clock, in unix seconds. Falls back to `0` only if the
/// system clock is somehow before the epoch (never on any real host) — never
/// panics.
fn wall_clock_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let cli = match parse_args(env::args().skip(1)) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("noporis-orchestrator: {msg}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // Sole-writer enforcement (see the module doc's "Sole-writer enforcement"
    // section): acquire the advisory WriterLock for this --state-dir BEFORE
    // touching state.json/sloboda-bridge.state at all. A held lock is a hard,
    // fail-closed refusal to start — never a silent second writer. Held in
    // `_writer_lock` for the rest of `main`; its Drop releases the lock file
    // on any normal return (including breaking out of --watch).
    let _writer_lock = if cli.steal_lock {
        WriterLock::steal(&cli.paths)
    } else {
        WriterLock::acquire(&cli.paths)
    };
    let _writer_lock = match _writer_lock {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!(
                "noporis-orchestrator: could not acquire the sole-writer lock for {:?}: {e} \
                 (another orchestrator process may already be running against this --state-dir; \
                 if you have confirmed no other writer is live, re-run with --steal-lock)",
                cli.paths.state_json
            );
            return ExitCode::from(1);
        }
    };

    // Compose the already-tested pieces: one Orchestrator over the near-side
    // managed-profile substrate (the default `host-stub` seam — isolates
    // nothing, offline by construction), isolating the far, less-private
    // Google-Play persona. No crossing lanes are registered here — see the
    // module doc above. `ReferenceGate`/`LoopbackTransport` only fix the
    // Daemon's generic parameters (there being zero lanes, no instance of
    // either is ever constructed or used).
    let orchestrator = Orchestrator::new(ManagedProfileSubstrate::<HostStubDpc>::new(Persona::GooglePlay));
    let config = DaemonConfig {
        paths: cli.paths,
        max_crossings_per_tick: 64,
    };
    let mut daemon: Daemon<ManagedProfileSubstrate<HostStubDpc>, ReferenceGate, LoopbackTransport> =
        Daemon::new(orchestrator, config);

    // Fail-closed schema-preflight (see Daemon::preflight): before the first
    // tick becomes the sole writer of `sloboda-bridge.state`, refuse to start if
    // an EXISTING projection carries a schema this orchestrator does not
    // understand — never silently clobber a file a foreign/older/newer writer
    // may still own. Surfaced in the exit code exactly like the WriterLock
    // refusal above. (Absent = first boot = fine; each tick re-checks too.)
    if let Err(e) = daemon.preflight() {
        eprintln!(
            "noporis-orchestrator: refusing to start — the existing sloboda-bridge.state \
             projection failed the schema-preflight: {e}"
        );
        return ExitCode::from(1);
    }

    match cli.mode {
        Mode::Once => {
            let now = cli.now.unwrap_or_else(wall_clock_unix);
            let iso = unix_to_iso8601(now);
            let report = daemon.tick(now, &iso);
            println!("{report}");
            ExitCode::SUCCESS
        }
        Mode::Watch { interval_ms } => {
            let injected_clock = cli.now.is_some();
            let mut now = cli.now.unwrap_or_else(wall_clock_unix);
            let mut ticks_run: u64 = 0;
            loop {
                let iso = unix_to_iso8601(now);
                let report = daemon.tick(now, &iso);
                println!("{report}");
                ticks_run += 1;

                if let Some(max) = cli.max_ticks {
                    if ticks_run >= max {
                        break;
                    }
                }
                if interval_ms > 0 {
                    sleep(Duration::from_millis(interval_ms));
                }
                now = if injected_clock {
                    // Deterministic clock: advance by the tick interval,
                    // never touch the wall clock, so a scripted
                    // `--watch --max-ticks` run is fully reproducible.
                    now + (interval_ms as i64 / 1000).max(1)
                } else {
                    wall_clock_unix()
                };
            }
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_parses() {
        let cli = parse_args(["--once".to_string()].into_iter()).unwrap();
        assert!(matches!(cli.mode, Mode::Once));
    }

    #[test]
    fn watch_requires_a_value() {
        let err = parse_args(["--watch".to_string()].into_iter()).unwrap_err();
        assert!(err.contains("--watch requires"));
    }

    #[test]
    fn state_dir_and_max_ticks_and_now_parse() {
        let cli = parse_args(
            [
                "--watch".to_string(),
                "50".to_string(),
                "--state-dir".to_string(),
                "/tmp/noporis-test".to_string(),
                "--max-ticks".to_string(),
                "3".to_string(),
                "--now".to_string(),
                "1752000000".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(matches!(cli.mode, Mode::Watch { interval_ms: 50 }));
        assert_eq!(cli.max_ticks, Some(3));
        assert_eq!(cli.now, Some(1_752_000_000));
        assert_eq!(cli.paths, StatePaths::under("/tmp/noporis-test"));
        assert!(!cli.steal_lock, "--steal-lock defaults to false when not passed");
    }

    #[test]
    fn unrecognized_flag_is_rejected() {
        let err = parse_args(["--bogus".to_string()].into_iter()).unwrap_err();
        assert!(err.contains("unrecognized argument"));
    }

    #[test]
    fn missing_mode_is_rejected() {
        let err = parse_args(std::iter::empty()).unwrap_err();
        assert!(err.contains("--once or --watch"));
    }

    #[test]
    fn steal_lock_flag_parses() {
        let cli = parse_args(["--once".to_string(), "--steal-lock".to_string()].into_iter()).unwrap();
        assert!(cli.steal_lock);
    }
}
