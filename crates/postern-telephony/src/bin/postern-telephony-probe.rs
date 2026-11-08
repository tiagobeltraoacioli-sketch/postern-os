// SPDX-License-Identifier: MIT OR Apache-2.0
//! `postern-telephony-probe` — the roadmap B4 telephony device-path smoke check
//! for Postern OS Mobile.
//!
//! Read-only: it enumerates modems via ModemManager over the system D-Bus and
//! prints what it found. It never sends an SMS or dials. Exit codes let a boot
//! harness / CI branch on the result:
//!   0  at least one modem is present (the live path is reachable)
//!   3  no modem (QEMU `-M virt`, or a host with no SIM) — the expected off-device case
//!   2  no system bus / ModemManager not running (expected on a non-phone host)
//!
//! HONESTY: a modem being *present* is not "private". Carrier SMS/voice is
//! plaintext to the operator, lawful-intercept-accessible, and the tower always
//! sees location + IMEI/IMSI. For anything sensitive, use the E2EE messenger.

use postern_telephony::{probe, TelephonyError};
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    println!("Postern OS Mobile — telephony device-path probe (roadmap B4)");
    println!("Enumerating modems via ModemManager on the system D-Bus…\n");

    match probe::discover().await {
        Ok(modems) if modems.is_empty() => {
            eprintln!("no modem exported by ModemManager.");
            eprintln!("Expected under QEMU (-M virt models no modem) and on any host");
            eprintln!("without a SIM. The live telephony path proves out only on real");
            eprintln!("hardware (PinePhone) — QEMU ≠ hardware.");
            ExitCode::from(3)
        }
        Ok(modems) => {
            for m in &modems {
                println!("● {}", m.path);
                println!(
                    "    vendor/model : {} / {}",
                    m.manufacturer.as_deref().unwrap_or("?"),
                    m.model.as_deref().unwrap_or("?")
                );
                println!("    IMEI         : {}", m.equipment_id.as_deref().unwrap_or("?"));
                println!("    state        : {}", m.state_name());
                println!("    voice path   : {}", if m.has_voice { "present" } else { "absent" });
                println!("    SMS path     : {}", if m.has_messaging { "present" } else { "absent" });
            }
            println!(
                "\n{} modem(s) found. Carrier SMS/voice is NOT private on the wire.",
                modems.len()
            );
            ExitCode::SUCCESS
        }
        Err(TelephonyError::NoModem) => {
            eprintln!("no modem available (ModemManager present, but no device/SIM).");
            ExitCode::from(3)
        }
        Err(e) => {
            eprintln!("probe could not reach ModemManager: {e}");
            eprintln!("(no system bus / daemon not running — expected off a Linux phone.)");
            ExitCode::from(2)
        }
    }
}
