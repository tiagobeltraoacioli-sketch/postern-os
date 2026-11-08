// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DESIGN PREVIEW — written ≠ built ≠ booted. UNAUDITED. This file has two
// halves with two very different honesty labels:
//
// * The FIXTURE BUILDER + hermetic tests (never `#[ignore]`d) construct and
//   byte-check a 512-byte BIOS boot sector wrapped in a minimal El Torito
//   ISO — pure `std`, zero downloads, zero new dependencies, authored
//   in-repo under MIT OR Apache-2.0 (fully license-safe; nothing here is
//   derived from, links, bundles, or fetches QEMU or any GPL code). These
//   run in every `cargo test` with no QEMU anywhere.
//
// * The LIVE test is `#[ignore]`-gated AND double-gated on
//   `TEREM_LIVE_QEMU=1`, and it SKIPs (never fails) when QEMU is absent —
//   it never runs in CI, and as of this writing it has never been executed
//   in CI. When an operator does run it, SUCCESS MEANS EXACTLY THIS:
//   "SeaBIOS executed our 512-byte fixture sector to a serial marker under
//   an operator-supplied QEMU". It is NOT "an OS booted", it is NOT an
//   isolation/TEE/security claim, and it says nothing about any real guest
//   workload. QEMU (GPL-2.0) stays an external, operator-installed,
//   opt-in process per docs/os-portal-v2/LICENSE-DECISION.md §2 — never
//   fetched, bundled, linked, or vendored by this repo.
//
// Product name "Terem" is proposed only, pending trademark clearance.

//! POC-SCOPE.md §2.2's marker-boot fixture, in-repo and hermetic, plus the
//! opt-in live boot-to-serial-marker test.
//!
//! Fixture: a hand-assembled real-mode boot sector that polls the COM1 Line
//! Status Register and writes `TEREM-LIVE-QEMU-MARKER-V1` to the COM1
//! Transmitter Holding Register, then halts — wrapped into a minimal
//! El Torito no-emulation ISO9660 so it can ride the launch plan's existing
//! `-cdrom <boot> -boot d` argv unchanged (no src/ edits).
//!
//! Live run (operator's explicit act, never CI):
//!
//! ```text
//! TEREM_LIVE_QEMU=1 cargo test --test live_qemu_boot_marker -- --ignored --nocapture
//! ```
//!
//! optionally with `TEREM_QEMU_BIN` / `TEREM_QEMU_IMG_BIN` pointing at the
//! operator's binaries; otherwise the pinned names are probed on `$PATH`
//! via `resolve_qemu_binary` / `resolve_qemu_img_binary`. Contrast with
//! `tests/real_spawn.rs`, which panics loudly without its env vars and
//! asserts only "emulator came up", not a boot marker.

use std::path::PathBuf;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Part 1: the fixture builder (pure std; nothing here touches QEMU)
// ---------------------------------------------------------------------------

/// The serial boot marker (POC-SCOPE §2.2). Single-sourced: the boot-sector
/// code streams exactly these bytes to COM1, and the live test greps the
/// serial log for exactly these bytes.
const MARKER: &[u8] = b"TEREM-LIVE-QEMU-MARKER-V1";

/// ISO9660 logical sector size.
const ISO_SECTOR: usize = 2048;

/// Hand-assembled 16-bit real-mode code, loaded by the BIOS at 0000:7C00.
/// It needs no BIOS services, no stack, and no serial-port init: on QEMU's
/// emulated 16550, LSR bit 5 (THR empty) and THR writes deliver bytes to
/// the `-serial file:` backend regardless of baud/line configuration.
///
/// Assembly (NASM syntax, `org 0x7C00`), byte-for-byte:
///
/// ```asm
///         cli                 ; FA          no interrupts; we poll
///         xor  ax, ax         ; 31 C0
///         mov  ds, ax         ; 8E D8       DS=0 so [si] is linear
///         mov  si, msg        ; BE 23 7C    msg = 0x7C00 + 35 = 0x7C23
/// next:   lodsb               ; AC          al = next message byte
///         test al, al         ; 84 C0
///         jz   halt           ; 74 12       NUL terminator -> halt
///         mov  bl, al         ; 88 C3       save char (in/out clobber al)
/// wait:   mov  dx, 0x3FD      ; BA FD 03    COM1 LSR
///         in   al, dx         ; EC
///         test al, 0x20       ; A8 20       bit 5: THR empty?
///         jz   wait           ; 74 F8       not yet -> poll again
///         mov  dx, 0x3F8      ; BA F8 03    COM1 THR
///         mov  al, bl         ; 88 D8
///         out  dx, al         ; EE          transmit the byte
///         jmp  next           ; EB E9
/// halt:   cli                 ; FA
///         hlt                 ; F4
///         jmp  halt           ; EB FC       hlt loop forever
/// msg:    db  "TEREM-LIVE-QEMU-MARKER-V1", 0x0D, 0x0A, 0
/// ```
const BOOT_CODE: [u8; 35] = [
    0xFA, // cli
    0x31, 0xC0, // xor ax, ax
    0x8E, 0xD8, // mov ds, ax
    0xBE, 0x23, 0x7C, // mov si, 0x7C23 (msg; keep in sync with BOOT_CODE.len())
    0xAC, // next: lodsb
    0x84, 0xC0, // test al, al
    0x74, 0x12, // jz halt (+18)
    0x88, 0xC3, // mov bl, al
    0xBA, 0xFD, 0x03, // wait: mov dx, 0x3FD (COM1 LSR)
    0xEC, // in al, dx
    0xA8, 0x20, // test al, 0x20 (THR empty)
    0x74, 0xF8, // jz wait (-8)
    0xBA, 0xF8, 0x03, // mov dx, 0x3F8 (COM1 THR)
    0x88, 0xD8, // mov al, bl
    0xEE, // out dx, al
    0xEB, 0xE9, // jmp next (-23)
    0xFA, // halt: cli
    0xF4, // hlt
    0xEB, 0xFC, // jmp halt (-4)
];

/// The 512-byte BIOS boot sector: code, then the NUL-terminated marker
/// message the code streams, zero padding, and the 0xAA55 signature at
/// offset 510.
fn boot_sector() -> [u8; 512] {
    let mut sector = [0u8; 512];
    sector[..BOOT_CODE.len()].copy_from_slice(&BOOT_CODE);
    let msg_at = BOOT_CODE.len(); // 35 == the 0x7C23 the code's `mov si` pins
    sector[msg_at..msg_at + MARKER.len()].copy_from_slice(MARKER);
    sector[msg_at + MARKER.len()..msg_at + MARKER.len() + 3].copy_from_slice(b"\r\n\0");
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
}

/// Both-endian (LSB then MSB) u16, ISO9660's 7.2.3 / 7.3.3-style fields.
fn both_endian_u16(v: u16) -> [u8; 4] {
    let le = v.to_le_bytes();
    let be = v.to_be_bytes();
    [le[0], le[1], be[0], be[1]]
}

/// Both-endian (LSB then MSB) u32.
fn both_endian_u32(v: u32) -> [u8; 8] {
    let le = v.to_le_bytes();
    let be = v.to_be_bytes();
    [le[0], le[1], le[2], le[3], be[0], be[1], be[2], be[3]]
}

/// Wrap the boot sector into a minimal El Torito no-emulation ISO9660
/// image. Layout (2048-byte sectors):
///
/// * 0..=15  — system area (zeros)
/// * 16      — Primary Volume Descriptor (`CD001`)
/// * 17      — Boot Record Volume Descriptor (`EL TORITO SPECIFICATION`),
///             pointing at the boot catalog in sector 19
/// * 18      — Volume Descriptor Set Terminator
/// * 19      — boot catalog: validation entry (words sum to 0, key bytes
///             0x55/0xAA) + initial/default entry (bootable 0x88,
///             no-emulation, load segment 0 → 0x7C00, 4 × 512-byte virtual
///             sectors, image at sector 20)
/// * 20      — the 512-byte boot sector, zero-padded to one ISO sector
///
/// The PVD is the minimal shape a BIOS El Torito boot path needs; this ISO
/// is a boot fixture, not a mountable filesystem, and claims nothing more.
fn build_marker_iso() -> Vec<u8> {
    const TOTAL_SECTORS: usize = 21;
    const CATALOG_SECTOR: u32 = 19;
    const BOOT_IMAGE_SECTOR: u32 = 20;

    let mut iso = vec![0u8; TOTAL_SECTORS * ISO_SECTOR];

    // --- Sector 16: Primary Volume Descriptor ---
    {
        let pvd = &mut iso[16 * ISO_SECTOR..17 * ISO_SECTOR];
        pvd[0] = 0x01; // type: PVD
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 0x01; // version
        pvd[8..40].copy_from_slice(&[b' '; 32]); // system identifier
        let mut vol_id = [b' '; 32];
        vol_id[..12].copy_from_slice(b"TEREM_MARKER");
        pvd[40..72].copy_from_slice(&vol_id); // volume identifier
        pvd[80..88].copy_from_slice(&both_endian_u32(TOTAL_SECTORS as u32)); // volume space size
        pvd[120..124].copy_from_slice(&both_endian_u16(1)); // volume set size
        pvd[124..128].copy_from_slice(&both_endian_u16(1)); // volume sequence number
        pvd[128..132].copy_from_slice(&both_endian_u16(ISO_SECTOR as u16)); // logical block size
    }

    // --- Sector 17: Boot Record Volume Descriptor (El Torito) ---
    {
        let brvd = &mut iso[17 * ISO_SECTOR..18 * ISO_SECTOR];
        brvd[0] = 0x00; // type: boot record
        brvd[1..6].copy_from_slice(b"CD001");
        brvd[6] = 0x01; // version
        let boot_sys_id = b"EL TORITO SPECIFICATION";
        brvd[7..7 + boot_sys_id.len()].copy_from_slice(boot_sys_id); // NUL-padded to 32
        brvd[0x47..0x4B].copy_from_slice(&CATALOG_SECTOR.to_le_bytes()); // catalog pointer
    }

    // --- Sector 18: Volume Descriptor Set Terminator ---
    {
        let term = &mut iso[18 * ISO_SECTOR..19 * ISO_SECTOR];
        term[0] = 0xFF; // type: terminator
        term[1..6].copy_from_slice(b"CD001");
        term[6] = 0x01; // version
    }

    // --- Sector 19: boot catalog ---
    {
        let cat = &mut iso[19 * ISO_SECTOR..20 * ISO_SECTOR];

        // Validation entry (bytes 0..32).
        cat[0] = 0x01; // header ID
        cat[1] = 0x00; // platform: 80x86
        // bytes 2..4 reserved; 4..28 ID string (zeros); 28..30 checksum below
        cat[0x1E] = 0x55; // key byte
        cat[0x1F] = 0xAA; // key byte
        // Checksum: set so the sixteen little-endian words sum to 0 mod 2^16.
        let sum: u16 = cat[..32]
            .chunks_exact(2)
            .map(|w| u16::from_le_bytes([w[0], w[1]]))
            .fold(0u16, u16::wrapping_add);
        cat[28..30].copy_from_slice(&(0u16.wrapping_sub(sum)).to_le_bytes());

        // Initial/default entry (bytes 32..64).
        cat[32] = 0x88; // bootable
        cat[33] = 0x00; // media type: no emulation
        cat[34..36].copy_from_slice(&0u16.to_le_bytes()); // load segment 0 → 0x7C00 default
        cat[36] = 0x00; // system type
        cat[38..40].copy_from_slice(&4u16.to_le_bytes()); // 4 × 512-byte virtual sectors
        cat[40..44].copy_from_slice(&BOOT_IMAGE_SECTOR.to_le_bytes()); // load RBA
    }

    // --- Sector 20: the boot image, padded to one ISO sector ---
    iso[20 * ISO_SECTOR..20 * ISO_SECTOR + 512].copy_from_slice(&boot_sector());

    iso
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Part 2: hermetic fixture tests — run in EVERY `cargo test`, no QEMU, no
// processes, no network, no #[ignore].
// ---------------------------------------------------------------------------

#[test]
fn iso_is_sector_aligned_with_expected_layout() {
    let iso = build_marker_iso();
    assert_eq!(iso.len() % ISO_SECTOR, 0, "ISO must be a whole number of 2048-byte sectors");
    assert_eq!(iso.len(), 21 * ISO_SECTOR, "layout is exactly 21 sectors");
    // System area (sectors 0..16) stays all zeros.
    assert!(iso[..16 * ISO_SECTOR].iter().all(|&b| b == 0));
}

#[test]
fn volume_descriptors_carry_cd001_at_pinned_offsets() {
    let iso = build_marker_iso();
    // PVD at 0x8000: type 1, then "CD001" at 0x8000+1.
    assert_eq!(iso[0x8000], 0x01);
    assert_eq!(&iso[0x8000 + 1..0x8000 + 6], b"CD001");
    // Boot Record Volume Descriptor at 0x8800: type 0, "CD001" at 0x8800+1.
    assert_eq!(iso[0x8800], 0x00);
    assert_eq!(&iso[0x8800 + 1..0x8800 + 6], b"CD001");
    // Set terminator at 0x9000: type 0xFF, "CD001".
    assert_eq!(iso[0x9000], 0xFF);
    assert_eq!(&iso[0x9000 + 1..0x9000 + 6], b"CD001");
}

#[test]
fn boot_record_names_el_torito_and_points_at_the_catalog() {
    let iso = build_marker_iso();
    let brvd = &iso[0x8800..0x8800 + ISO_SECTOR];
    assert_eq!(&brvd[7..7 + 23], b"EL TORITO SPECIFICATION");
    // Boot-system-identifier field is NUL-padded to 32 bytes.
    assert!(brvd[7 + 23..7 + 32].iter().all(|&b| b == 0));
    let catalog = u32::from_le_bytes([brvd[0x47], brvd[0x48], brvd[0x49], brvd[0x4A]]);
    assert_eq!(catalog, 19, "boot catalog lives in sector 19");
}

#[test]
fn validation_entry_checksums_to_zero_with_55aa_keys() {
    let iso = build_marker_iso();
    let validation = &iso[19 * ISO_SECTOR..19 * ISO_SECTOR + 32];
    assert_eq!(validation[0], 0x01, "header ID");
    assert_eq!(validation[1], 0x00, "platform 80x86");
    assert_eq!(validation[0x1E], 0x55, "key byte");
    assert_eq!(validation[0x1F], 0xAA, "key byte");
    let sum: u16 = validation
        .chunks_exact(2)
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
        .fold(0u16, u16::wrapping_add);
    assert_eq!(sum, 0, "the sixteen words of the validation entry must sum to 0 mod 2^16");
}

#[test]
fn default_entry_is_bootable_no_emulation_at_sector_20() {
    let iso = build_marker_iso();
    let entry = &iso[19 * ISO_SECTOR + 32..19 * ISO_SECTOR + 64];
    assert_eq!(entry[0], 0x88, "bootable");
    assert_eq!(entry[1], 0x00, "no-emulation media type");
    assert_eq!(u16::from_le_bytes([entry[2], entry[3]]), 0, "load segment 0 → 0x7C00 default");
    assert_eq!(u16::from_le_bytes([entry[6], entry[7]]), 4, "4 × 512-byte virtual sectors");
    assert_eq!(
        u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]),
        20,
        "boot image load RBA"
    );
}

#[test]
fn boot_sector_carries_aa55_signature_and_marker_exactly_once() {
    let sector = boot_sector();
    assert_eq!(sector[510], 0x55);
    assert_eq!(sector[511], 0xAA);
    assert_eq!(
        count_occurrences(&sector, MARKER),
        1,
        "the marker string must appear exactly once in the boot image"
    );
    // The `mov si, 0x7C23` immediate must agree with where the message
    // actually landed (0x7C00 + BOOT_CODE.len()).
    let si = u16::from_le_bytes([BOOT_CODE[6], BOOT_CODE[7]]);
    assert_eq!(si as usize, 0x7C00 + BOOT_CODE.len(), "si immediate points at msg");
    assert_eq!(&sector[BOOT_CODE.len()..BOOT_CODE.len() + MARKER.len()], MARKER);
    // NUL terminator after the CRLF so the lodsb loop halts.
    assert_eq!(sector[BOOT_CODE.len() + MARKER.len() + 2], 0);
    // And the whole boot image sits, once, inside the ISO at sector 20.
    let iso = build_marker_iso();
    assert_eq!(&iso[20 * ISO_SECTOR..20 * ISO_SECTOR + 512], &sector[..]);
    assert_eq!(count_occurrences(&iso, MARKER), 1);
}

// ---------------------------------------------------------------------------
// Part 3: the live test — #[ignore]-gated AND TEREM_LIVE_QEMU=1-gated,
// SKIPs (never fails) when QEMU is absent. Never runs in CI; never has.
// ---------------------------------------------------------------------------

use terem_core::config::TeremConfig;
use terem_core::guest::GuestSpec;
use terem_core::launch::{LaunchMode, LaunchPlan};
use terem_core::qmp_client::QmpClient;
use terem_core::resolve::{
    resolve_qemu_binary, resolve_qemu_img_binary, QEMU_IMG_BIN_NAME, QEMU_SYSTEM_BIN_NAME,
};
use terem_core::spawn::spawn_plan;

/// Same scratch pattern as tests/real_spawn.rs.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "terem-core-live-marker-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Resolve one of the two pinned QEMU tools: an explicit operator-supplied
/// path from `env_override` if set, else the bare pinned name probed on
/// `$PATH` — both through the crate's vetting resolvers.
fn resolve_operator_binary(
    env_override: &str,
    pinned_name: &str,
    resolve: fn(&str) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let requested =
        std::env::var(env_override).unwrap_or_else(|_| pinned_name.to_string());
    resolve(&requested)
}

#[test]
#[ignore = "live QEMU: set TEREM_LIVE_QEMU=1 on a host with operator-installed qemu-system-x86_64 + qemu-img; never runs in CI"]
fn live_qemu_boots_fixture_sector_to_serial_marker() {
    // Gate 1 of 2 (besides #[ignore]): explicit opt-in env var. A blanket
    // `cargo test -- --ignored` without it SKIPs quietly — never panics,
    // never fails.
    if std::env::var("TEREM_LIVE_QEMU").as_deref() != Ok("1") {
        eprintln!(
            "SKIP live_qemu_boots_fixture_sector_to_serial_marker: \
             TEREM_LIVE_QEMU is not '1'. This test spawns a REAL \
             operator-installed QEMU; set TEREM_LIVE_QEMU=1 (and optionally \
             TEREM_QEMU_BIN / TEREM_QEMU_IMG_BIN) to run it. Never runs in CI."
        );
        return;
    }

    // Gate 2: both operator-installed tools must resolve, or SKIP (not
    // fail) — QEMU's absence is an environment fact, not a test failure.
    let qemu_bin = match resolve_operator_binary(
        "TEREM_QEMU_BIN",
        QEMU_SYSTEM_BIN_NAME,
        resolve_qemu_binary,
    ) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("SKIP: no operator-installed {QEMU_SYSTEM_BIN_NAME}: {e}");
            return;
        }
    };
    let qemu_img_bin = match resolve_operator_binary(
        "TEREM_QEMU_IMG_BIN",
        QEMU_IMG_BIN_NAME,
        resolve_qemu_img_binary,
    ) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("SKIP: no operator-installed {QEMU_IMG_BIN_NAME}: {e}");
            return;
        }
    };

    // Scratch state: the marker ISO (written from the hermetic builder
    // above — no downloads) and a small qcow2 for the plan's -drive.
    let state = scratch("state");
    let iso_path = state.join("marker-boot.iso");
    std::fs::write(&iso_path, build_marker_iso()).expect("write marker ISO");

    let disk_path = state.join("guest0.qcow2");
    let img_out = std::process::Command::new(&qemu_img_bin)
        .args(["create", "-f", "qcow2"])
        .arg(&disk_path)
        .arg("16M")
        .output()
        .expect("qemu-img should run");
    assert!(
        img_out.status.success(),
        "qemu-img create failed: {}",
        String::from_utf8_lossy(&img_out.stderr)
    );

    // The explicit opt-in act — the DEFAULT TeremConfig must keep refusing
    // at both plan and spawn time (LICENSE-DECISION.md §2).
    let config = TeremConfig { full_vm_qemu: true, wine_proton: false };
    let spec = GuestSpec { disk_path, disk_size_mb: 16, boot_image: iso_path };
    let qmp_sock = state.join("guest0.qmp.sock");
    let serial_log = state.join("guest0.serial.log");
    let plan = LaunchPlan::build(
        LaunchMode::DryRun, // the only mode: build the argv as data
        &config,
        &qemu_bin,
        &spec,
        &qmp_sock,
        &serial_log,
    )
    .expect("opted-in plan should build");

    let mut guest = spawn_plan(&config, &plan).expect("real QEMU should spawn");
    let pid = guest.pid();

    // Poll: the serial log must come to CONTAIN the marker string while the
    // process stays alive. TCG (no -accel/KVM in the plan) is plenty for a
    // 512-byte sector, but SeaBIOS + option-ROM scan can take a while cold.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut marker_seen = false;
    while Instant::now() < deadline {
        assert!(
            guest.status().running,
            "QEMU (pid {pid}) exited early — check stderr above for QEMU's own diagnostics"
        );
        if let Ok(log) = std::fs::read(&serial_log) {
            if count_occurrences(&log, MARKER) >= 1 {
                marker_seen = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        marker_seen,
        "serial log {} did not contain the boot marker within 60s while QEMU (pid {pid}) ran",
        serial_log.display()
    );
    assert!(guest.status().running, "QEMU (pid {pid}) must still be alive after the marker");

    // Optional extra signal (kept optional: QMP hiccups log, never fail the
    // marker assertion): handshake on the plan's QMP socket + query-status.
    #[cfg(unix)]
    {
        match std::os::unix::net::UnixStream::connect(&qmp_sock)
            .map_err(|e| format!("QMP connect failed: {e}"))
            .and_then(QmpClient::handshake)
            .and_then(|mut client| client.query_status())
        {
            Ok(vm_state) => eprintln!(
                "live QMP query-status: running={} status={}",
                vm_state.running, vm_state.status
            ),
            Err(e) => eprintln!("optional QMP probe skipped: {e}"),
        }
    }

    // Tear down: kill + reap, confirm gone, clean the scratch dir.
    guest.kill_and_wait().expect("kill_and_wait should succeed");
    assert!(!guest.status().running);
    let _ = std::fs::remove_dir_all(&state);

    eprintln!(
        "live marker test passed. Honest scope of this success: SeaBIOS \
         executed our 512-byte fixture sector to a serial marker under an \
         operator-supplied QEMU. It is NOT 'an OS booted', NOT an \
         isolation/TEE claim, and this test has never run in CI."
    );
}
