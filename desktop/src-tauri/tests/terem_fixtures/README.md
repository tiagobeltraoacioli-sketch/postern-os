<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Terem marker-boot fixture

The standard "QEMU CI smoke test" shape `docs/os-portal-v2/POC-SCOPE.md` §2.2
names: a real Linux kernel + a from-scratch busybox-static initramfs whose
`/init` (PID 1) mounts `/proc`+`/sys`, prints `TEREM-POC-BOOT-OK` to the
serial console, then `poweroff -f`s. Booted via QEMU's direct-kernel-boot
flags (`-kernel bzImage -initrd initramfs.cpio.gz`) — no bootloader, no disk
image, no installer flow. Proves the QMP control plane
(`desktop/src-tauri/tests/terem_lifecycle.rs`), nothing more.

## Files

- `bzImage` — Alpine Linux `v3.20`'s official `netboot/vmlinuz-lts` x86_64
  kernel, downloaded unmodified from
  `https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/vmlinuz-lts`.
- `initramfs/bin/busybox` — the official static x86_64/musl busybox binary,
  downloaded unmodified from
  `https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox`.
- `initramfs/init` — the only Postern-authored file here: a ~10-line shell
  script (PID 1) that prints the marker line and powers off. See its own
  header comment.
- `initramfs.cpio.gz` — `initramfs/` packed as a gzipped `newc`-format cpio
  archive: `(cd initramfs && find . | cpio -o -H newc | gzip -9) > ../initramfs.cpio.gz`.

## Licensing note (carried from `POC-SCOPE.md` §2.2 / `01-architecture.md` §2.1)

Both the Linux kernel and busybox are GPL-2.0. Neither is linked, forked, or
embedded into any Postern binary — they ship here purely as **prebuilt boot
artifacts** for a test fixture, the same "external, unforked, never linked"
exception this repo's own licensing rule already grants the Linux kernel
itself (`docs/specs/POSTERN-CLOUD.md` §8) and the GPL telephony daemons
(`docs/specs/POSTERN-TELEPHONY.md`). Not a Postern OS component; not shipped
to end users; test-only.

## Rebuilding

Re-run the download + pack commands above (any Alpine `netboot/vmlinuz-lts`
release and any static busybox build for the host architecture QEMU is
emulating will work — the marker fixture only needs *some* deterministic
boot-to-marker signal, not a specific kernel/busybox version, per
`POC-SCOPE.md` §2.2).
