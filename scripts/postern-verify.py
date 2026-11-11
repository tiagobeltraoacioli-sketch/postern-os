#!/usr/bin/env python3
"""Boot a real ISO in a bounded, offline QEMU guest and retain evidence."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import socket
import subprocess
import tempfile
import textwrap
import time


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path)
    parser.add_argument("--profile", choices=("compute", "desktop", "mobile"), required=True)
    parser.add_argument("--output", type=Path, help="New evidence directory; must not exist")
    parser.add_argument("--timeout", type=int, default=900, help="Boot/test deadline, seconds")
    parser.add_argument("--memory-mib", type=int, default=2048)
    parser.add_argument("--cpus", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.cpus <= 2 or not 1024 <= args.memory_mib <= 2048:
        parser.error("This harness permits at most 2 vCPUs and 2048 MiB RAM")
    if not 60 <= args.timeout <= 1800:
        parser.error("Timeout must be between 60 and 1800 seconds")
    args.iso = args.iso.resolve(strict=True)
    if not args.iso.is_file() or args.iso.suffix != ".iso":
        parser.error("Input must be an existing .iso file")
    if not shutil.which("qemu-system-x86_64"):
        parser.error("qemu-system-x86_64 is required (use nix develop)")
    return args


def guest_test(profile):
    script = r"""set -eu
test -s /etc/postern/release.json
grep -F 'Postern OS' /etc/postern/release.json
awk -F: '$1 == "root" || $1 == "nixos" {n++; if ($2 != "!") bad=1} END {exit (n != 2 || bad)}' /etc/shadow
command -v postern-data
postern-status
test "$(postern-status --json | jq -r '.summary.fail + .summary.unknown')" = 0
grep -F '"version":"0.3.1-dev"' /etc/postern/release.json
test "$(sysctl -n kernel.dmesg_restrict)" = 1
test "$(sysctl -n kernel.kptr_restrict)" = 2
test "$(sysctl -n fs.suid_dumpable)" = 0
case "$(sysctl -n kernel.core_pattern)" in '|'/nix/store/*/bin/false) ;; *) exit 31 ;; esac
systemctl is-active --quiet firewall.service
systemctl is-active --quiet apparmor.service
test "$(cat /sys/module/apparmor/parameters/enabled)" = Y
grep -E '(^|,)apparmor(,|$)' /sys/kernel/security/lsm
grep -E '(^| )mitigations=auto( |$)' /proc/cmdline
grep -E '(^| )systemd.gpt_auto=0( |$)' /proc/cmdline
grep -E '(^| )rd.systemd.gpt_auto=0( |$)' /proc/cmdline
awk 'NR > 1 && $1 !~ /^\/dev\/zram[0-9]+$/ {bad=1} END {exit bad}' /proc/swaps
if grep -E '(^| )mitigations=off( |$)' /proc/cmdline; then exit 35; fi
for unit in sshd.service sshd.socket avahi-daemon.service avahi-daemon.socket geoclue.service gnome-remote-desktop.service; do
  if systemctl is-active --quiet "$unit"; then exit 32; fi
done
if ss -ltnH | grep -E '(:22|:3389)[[:space:]]'; then exit 33; fi
test "$(findmnt -n -o FSTYPE /tmp)" = tmpfs
test ! -d /var/log/journal || test -z "$(find /var/log/journal -type f -print -quit)"
umask 077
smoke_dir=$(mktemp -d /tmp/postern-smoke.XXXXXX)
trap 'rm -rf -- "$smoke_dir"' EXIT
mkdir "$smoke_dir/input"
printf 'Postern offline fixture A\n' > "$smoke_dir/input/a.txt"
printf 'Postern offline fixture B\n' > "$smoke_dir/input/b.txt"
postern-data scan "$smoke_dir/input" --output "$smoke_dir/sequential.jsonl" --workers 1
postern-data scan "$smoke_dir/input" --output "$smoke_dir/parallel.jsonl" --workers 2
cmp "$smoke_dir/sequential.jsonl" "$smoke_dir/parallel.jsonl"
test "$(stat -c %a "$smoke_dir/parallel.jsonl")" = 600
postern-data verify "$smoke_dir/input" "$smoke_dir/parallel.jsonl" --workers 2
printf 'changed\n' >> "$smoke_dir/input/a.txt"
if postern-data verify "$smoke_dir/input" "$smoke_dir/parallel.jsonl" --workers 2; then exit 34; else test "$?" -eq 1; fi
"""
    if profile == "desktop":
        script += r"""
found_wayland=no
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet graphical.target &&
     systemctl is-active --quiet display-manager.service; then
    for session in $(loginctl list-sessions --no-legend | awk '{print $1}'); do
      if test "$(loginctl show-session "$session" -p Name --value)" = nixos &&
         test "$(loginctl show-session "$session" -p Type --value)" = wayland; then
        found_wayland=yes
        break
      fi
    done
  fi
  test "$found_wayland" = yes && break
  sleep 2
done
test "$found_wayland" = yes
"""
    if profile == "mobile":
        script += r"""
found_shell=no
for attempt in $(seq 1 60); do
  if systemctl is-active --quiet phosh.service && pgrep -f 'libexec/phosh' >/dev/null &&
     test -S "/run/user/$(id -u nixos)/wayland-0"; then
    found_shell=yes
    break
  fi
  sleep 2
done
test "$found_shell" = yes
"""
    return script


def screenshot(socket_path, destination):
    """QMP screenshot is supporting evidence, never the guest-test verdict."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(socket_path))
        stream = client.makefile("rwb", buffering=0)
        json.loads(stream.readline())
        for command in ({"execute": "qmp_capabilities"},
                        {"execute": "screendump", "arguments": {"filename": str(destination)}}):
            stream.write(json.dumps(command).encode() + b"\n")
            while True:
                response = json.loads(stream.readline())
                if "error" in response:
                    raise RuntimeError(str(response["error"]))
                if "return" in response:
                    break


def delivery_command(payload, nonce):
    """Verify transport before running any guest test; always emit a verdict."""
    encoded = base64.b64encode(payload).decode()
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    # The contiguous marker never appears in echoed input, avoiding a false pass.
    # Short heredoc lines also avoid the kernel TTY's canonical line limit.
    # Parse the entire compound command before executing sudo: its PTY must
    # never consume verdict/cleanup lines queued behind the guest tests.
    command = ("{\npayload=$(mktemp /tmp/postern-guest.XXXXXX); setup_rc=$?\n"
               + "base64 -d >\"${payload:-/dev/null}\" <<'POSTERN_PAYLOAD'\n"
               + "\n".join(textwrap.wrap(encoded, 76)) + "\nPOSTERN_PAYLOAD\n"
               + "decode_rc=$?; rc=91\n"
               + "if test \"$setup_rc\" -eq 0 && test \"$decode_rc\" -eq 0; then\n"
               + "  actual=$(sha256sum -- \"$payload\"); hash_rc=$?\n"
               + f"  if test \"$hash_rc\" -eq 0 && test \"${{actual%% *}}\" = '{payload_sha256}'; then\n"
               + "    sudo -n bash \"$payload\" </dev/null; rc=$?\n"
               + "  fi\nfi\n"
               + "if test -n \"$payload\"; then rm -f -- \"$payload\"; fi\n"
               + f"printf '\\n%s%s:%s\\n' 'POSTERN_' 'RESULT_{nonce}' \"$rc\"\n"
               + "}\n")
    return command


def main():
    args = arguments()
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output or args.iso.parent / f"boot-{args.profile}-{stamp}-{os.getpid()}").resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    nonce = secrets.token_hex(12)
    marker = f"POSTERN_RESULT_{nonce}"
    payload = guest_test(args.profile).encode()
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    command = delivery_command(payload, nonce)
    with args.iso.open("rb") as image:
        digest = hashlib.file_digest(image, "sha256").hexdigest()
    result = {"profile": args.profile, "iso": args.iso.name, "iso_sha256": digest,
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "accelerator": "tcg", "network": "none", "vcpus": args.cpus,
              "memory_mib": args.memory_mib, "passed": False}
    result["guest_test_sha256"] = payload_sha256
    (output / "guest-test.sh").write_text(guest_test(args.profile))
    print(f"Boot evidence: {output}", flush=True)
    start = time.monotonic()
    proc = None
    sent = False
    guest_rc = None
    tail = ""
    try:
        with tempfile.TemporaryDirectory(prefix="postern-qmp-") as qmpdir:
            qmp_path = Path(qmpdir) / "qmp.sock"
            qemu = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-machine", "q35",
                    "-cpu", "max", "-smp", str(args.cpus), "-m", str(args.memory_mib),
                    "-cdrom", str(args.iso), "-boot", "d", "-nic", "none",
                    "-display", "none", "-vga", "virtio", "-serial", "stdio",
                    "-monitor", "none", "-qmp", f"unix:{qmp_path},server=on,wait=off",
                    "-no-reboot"]
            result["qemu_command"] = qemu
            proc = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=output)
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            with (output / "serial.log").open("wb") as log:
                while time.monotonic() - start < args.timeout:
                    for key, _ in selector.select(timeout=1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        log.write(chunk)
                        log.flush()
                        tail = (tail + chunk.decode("utf-8", errors="replace"))[-32768:]
                        plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", tail).replace("\r", "")
                        if "Kernel panic - not syncing" in plain:
                            raise RuntimeError("Guest kernel panic; see serial.log")
                        if not sent and re.search(r"\[?nixos@postern-live:[^\n]*\$\s*$", plain):
                            proc.stdin.write(command.encode())
                            proc.stdin.flush()
                            sent = True
                            print("Guest console ready; checking privacy and data processing", flush=True)
                        verdict = re.search(rf"(?m)^{marker}:(\d+)\s*$", plain)
                        if verdict:
                            guest_rc = int(verdict.group(1))
                            break
                    if guest_rc is not None:
                        break
                    if proc.poll() is not None:
                        raise RuntimeError(f"QEMU exited before guest verdict ({proc.returncode})")
                if guest_rc is None:
                    raise RuntimeError(f"Guest test deadline exceeded (console_ready={sent})")
                result["guest_exit_code"] = guest_rc
                try:
                    screenshot(qmp_path, output / "screen.ppm")
                    result["screenshot"] = "screen.ppm"
                except (OSError, ValueError, RuntimeError) as error:
                    result["screenshot_error"] = str(error)
                proc.stdin.write(b"sudo poweroff\n")
                proc.stdin.flush()
                try:
                    remaining, _ = proc.communicate(timeout=90)
                    log.write(remaining)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("Guest did not power off within 90 seconds")
                result["qemu_exit_code"] = proc.returncode
                if guest_rc != 0 or proc.returncode != 0:
                    raise RuntimeError(f"Guest checks failed ({guest_rc}); QEMU exit {proc.returncode}")
                result["passed"] = True
    except (OSError, ValueError, RuntimeError) as error:
        result["error"] = str(error)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        (output / "STATUS").write_text("passed\n" if result["passed"] else "failed\n")
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
