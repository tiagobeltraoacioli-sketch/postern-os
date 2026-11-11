#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Record a scripted walkthrough of a real Postern ISO booted offline in QEMU.

The guest is driven with real keyboard events and its display is captured
through QMP. The captured screen is then placed, unmodified, inside a drawn
device frame with the caption beside it. Playback is faster than real time and
long idle waits are shortened; the boot of the graphical images is not shown.
All of that is stated on the opening card and recorded in result.json.

The video shows one scripted session on one virtual machine; it is a
demonstration, not the boot verification (see postern-verify.py) and not a
test on physical hardware.
"""
import argparse
import datetime
import hashlib
from html import escape
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import threading
import time

VERSION = "0.4.0-dev"
SIZES = {"compute": (1280, 720), "desktop": (1280, 720), "mobile": (720, 1280)}
CANVAS = (1920, 1080)
# Where the captured screen sits on the canvas: x, y, width, height, and the
# corner radius of the opening in the drawn frame.
SCREEN = {"compute": (192, 56, 1536, 864, 14), "desktop": (192, 56, 1536, 864, 14),
          "mobile": (1210, 60, 540, 960, 50)}
TAGLINE = {"compute": "Console image for private, offline data work",
           "desktop": "A private desktop that runs from memory",
           "mobile": "The same private system on a phone-sized screen"}
INTRO_SECONDS, OUTRO_SECONDS = 4.0, 6.0
IDLE_CAP_SECONDS, CAPTION_MIN_SECONDS = 1.6, 3.2
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
PROMPT = re.compile(r"\[?nixos@postern-live:[^\n]*\$\s*$")
PLAIN_KEYS = {
    " ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal",
    "[": "bracket_left", "]": "bracket_right", ";": "semicolon",
    "'": "apostrophe", "`": "grave_accent", "\\": "backslash", ",": "comma",
    ".": "dot", "/": "slash",
}
SHIFT_KEYS = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal",
    "{": "bracket_left", "}": "bracket_right", ":": "semicolon",
    '"': "apostrophe", "~": "grave_accent", "|": "backslash", "<": "comma",
    ">": "dot", "?": "slash",
}


def keys_for(character):
    """QEMU key codes (US layout) that type one character."""
    if character.isascii() and (character.islower() or character.isdigit()):
        return [character]
    if character.isascii() and character.isupper():
        return ["shift", character.lower()]
    if character in PLAIN_KEYS:
        return [PLAIN_KEYS[character]]
    if character in SHIFT_KEYS:
        return ["shift", SHIFT_KEYS[character]]
    raise ValueError(f"No key mapping for {character!r}")


def srt_time(seconds):
    millis = int(round(max(seconds, 0) * 1000))
    return "%02d:%02d:%02d,%03d" % (millis // 3600000, millis // 60000 % 60,
                                    millis // 1000 % 60, millis % 1000)


class Qmp:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.client.settimeout(30)
        self.client.connect(str(path))
        self.stream = self.client.makefile("rwb", buffering=0)
        json.loads(self.stream.readline())
        self.command("qmp_capabilities")

    def command(self, execute, **arguments):
        message = {"execute": execute}
        if arguments:
            message["arguments"] = arguments
        with self.lock:
            self.stream.write(json.dumps(message).encode() + b"\n")
            while True:
                line = self.stream.readline()
                if not line:
                    raise RuntimeError("QMP connection closed")
                response = json.loads(line)
                if "error" in response:
                    raise RuntimeError(f"{execute}: {response['error'].get('desc')}")
                if "return" in response:
                    return response["return"]


class Serial:
    """The guest's serial console: readiness, checks and state, never the show."""

    def __init__(self, process, log_path):
        self.process = process
        self.buffer = ""
        self.raw = ""
        self.condition = threading.Condition()
        self.counter = 0
        self.log = open(log_path, "wb")
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                break
            self.log.write(chunk)
            self.log.flush()
            with self.condition:
                # Strip escape sequences from the accumulated text: one that is
                # split across two reads must not survive as visible residue.
                self.raw = (self.raw + chunk.decode("utf-8", errors="replace"))[-262144:]
                self.buffer = ANSI.sub("", self.raw).replace("\r", "")
                self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def wait_for(self, pattern, timeout):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if "Kernel panic - not syncing" in self.buffer:
                    raise RuntimeError("Guest kernel panic; see serial.log")
                match = pattern.search(self.buffer)
                if match:
                    return match
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.process.poll() is not None:
                    raise RuntimeError(f"Serial console: no match for {pattern.pattern!r}")
                self.condition.wait(min(remaining, 1))

    def run(self, command, timeout=120):
        """Run one shell line on the serial console; return (status, output)."""
        self.counter += 1
        tag = f"{os.getpid()}x{self.counter}"
        # The markers are split in the typed line, so the echo never matches.
        line = (f"printf '\\n%s%s\\n' PD_ S{tag}; {{ {command} ; }}; "
                f"printf '\\n%s%s:%s\\n' PD_ R{tag} \"$?\"\n")
        self.process.stdin.write(line.encode())
        self.process.stdin.flush()
        match = self.wait_for(
            re.compile(rf"(?s)\nPD_S{tag}\n(.*?)\nPD_R{tag}:(\d+)\n"), timeout)
        return int(match.group(2)), match.group(1).strip()

    def close(self):
        self.log.close()


class Session:
    def __init__(self, args, workdir):
        self.args = args
        self.workdir = workdir
        self.frames_dir = workdir / "frames"
        self.frames_dir.mkdir()
        self.frames = []
        self.captions = []
        self.checks = []
        self.origin = None
        self.launches = []
        self.home_open = True
        self.keyboard_launch = True
        self.stop = threading.Event()
        self.started = None
        self.qmp = None
        self.capture_qmp = None
        self.serial = None
        self.scale = 1.0 if args.accelerator == "kvm" else args.slow_factor

    def now(self):
        return time.monotonic() - self.started

    def pause(self, seconds):
        time.sleep(seconds * self.scale)

    def mark_start(self):
        """The video begins here; what was captured earlier (boot) is left out."""
        self.origin = self.now()
        self.captions.clear()

    def park_pointer(self):
        """Move the pointer to the bottom-right corner, out of the picture."""
        for _ in range(4):
            self.qmp.command("input-send-event", events=[
                {"type": "rel", "data": {"axis": "x", "value": 1500}},
                {"type": "rel", "data": {"axis": "y", "value": 1500}}])
            time.sleep(0.2)

    def caption(self, text):
        self.captions.append((self.now(), text))
        print(f"[{self.now():7.1f}s] {text}", flush=True)

    def check(self, name, command, timeout=120):
        status, output = self.serial.run(command, timeout * self.scale)
        self.checks.append({"name": name, "command": command, "passed": status == 0,
                            "output": output[-400:], "at_seconds": round(self.now(), 1)})
        print(f"           check {name}: {'ok' if status == 0 else 'FAILED'}", flush=True)
        return status == 0

    def capture(self):
        index = 0
        interval = 1.0 / self.args.fps
        while not self.stop.is_set():
            begin = time.monotonic()
            target = self.frames_dir / f"{index:06d}.png"
            try:
                self.capture_qmp.command("screendump", filename=str(target), format="png")
                if target.stat().st_size > 0:
                    digest = hashlib.md5(target.read_bytes()).hexdigest()
                    self.frames.append((begin - self.started, target.name, digest))
                    index += 1
            except (OSError, RuntimeError, ValueError):
                pass
            self.stop.wait(max(0.0, interval - (time.monotonic() - begin)))

    def wait_until(self, command, seconds):
        """Poll a guest command until it succeeds; False if it never does."""
        deadline = time.monotonic() + seconds * self.scale
        while True:
            if self.serial.run(command, 60 * self.scale)[0] == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(2)

    def shell_tty(self):
        """Terminal of the newest interactive shell in a window, once it exists."""
        find = "ps -eo tty=,comm= | awk '$2==\"bash\" && $1 ~ /^pts/ {print $1}' | tail -n 1"
        if not self.wait_until(f"test -n \"$({find})\"", 120):
            raise RuntimeError("The terminal window did not open a shell")
        return self.serial.run(find, 60 * self.scale)[1]

    def key(self, *codes, settle=0.3):
        self.qmp.command("send-key", **{
            "keys": [{"type": "qcode", "data": code} for code in codes], "hold-time": 60})
        time.sleep(0.12 + settle * self.scale)

    def type(self, text):
        gap = 0.05 if self.scale == 1.0 else 0.12
        for character in text:
            self.qmp.command("send-key", **{
                "keys": [{"type": "qcode", "data": code} for code in keys_for(character)],
                "hold-time": 40})
            time.sleep(0.05 + gap)

    def wait_idle(self, tty, timeout=180):
        """Wait until only the shell remains on a terminal (a typed command ended)."""
        time.sleep(0.6)
        deadline = time.monotonic() + timeout * self.scale
        probe = f"test \"$(ps -o comm= -t {tty} | grep -cvx -e bash -e login)\" = 0"
        while time.monotonic() < deadline:
            if self.serial.run(probe, 60 * self.scale)[0] == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(f"A command on {tty} did not finish in time")

    def shell(self, tty, command, linger=2.5):
        self.type(command)
        self.pause(0.4)
        self.key("ret")
        self.wait_idle(tty)
        self.pause(linger)


DATA_STEPS = (
    ("Create sample files to process (64 MiB of random data)",
     "mkdir -p demo/in && for i in 1 2 3 4; do head -c 16M /dev/urandom > demo/in/file$i.bin; done; ls -lh demo/in"),
    ("postern-data: hash every file in parallel into a private manifest",
     "postern-data scan demo/in --output demo/manifest.jsonl --workers 4 && ls -l demo/manifest.jsonl"),
    ("Verify the files against the saved manifest",
     "postern-data verify demo/in demo/manifest.jsonl"),
    ("Change one file: verification detects the modification",
     "echo tampered >> demo/in/file1.bin; postern-data verify demo/in demo/manifest.jsonl; echo exit status $?"),
)
VAULT_STEPS = (
    ("postern-vault: create an encrypted container file (LUKS2), here with a key file",
     "head -c 64 /dev/urandom > demo/key && postern-vault create demo/private.vault 64M --key-file demo/key"),
    ("Open the vault and write a note inside it",
     "postern-vault open demo/private.vault --key-file demo/key && echo 'a private note' > /run/postern-vault/private/note.txt && ls -l /run/postern-vault/private"),
    ("Close it: the note cannot be found in the closed file",
     "postern-vault close private; grep -a -c 'a private note' demo/private.vault"),
)
STATE_STEPS = (
    ("No SSH, discovery or remote-desktop service; firewall and AppArmor active",
     "systemctl is-active sshd avahi-daemon firewall apparmor"),
    ("Swap is compressed memory only; nothing listens for remote login",
     "swapon --show; ss -ltn"),
)


def terminal_work(s, tty):
    """The command-line part shared by the compute and desktop walkthroughs."""
    for caption, command in DATA_STEPS:
        s.caption(caption)
        s.shell(tty, command, 4)
    s.check("modified file is detected",
            "postern-data verify ~/demo/in ~/demo/manifest.jsonl; test $? -eq 1")
    s.shell(tty, "clear", 0.5)
    for caption, command in VAULT_STEPS:
        s.caption(caption)
        s.shell(tty, command, 5)
    s.check("closed vault hides the note",
            "test -s ~/demo/private.vault && ! grep -a -q 'a private note' ~/demo/private.vault "
            "&& ! test -e /dev/mapper/postern-vault-private")
    s.shell(tty, "clear", 0.5)
    for caption, command in STATE_STEPS:
        s.caption(caption)
        s.shell(tty, command, 5)
    s.check("no SSH daemon", "! systemctl is-active --quiet sshd.service")
    s.check("firewall active", "systemctl is-active --quiet firewall.service")
    s.check("kernel hardening is in effect",
            "sudo postern-status --json | jq -e '[.checks[] | select(.id == \"hardening\")][0].state == \"ok\"'")
    s.check("status report has no failed check",
            "sudo postern-status --json | jq -e '.summary.fail == 0'")


def compute_scenes(s):
    tty = "tty1"
    s.mark_start()
    s.caption("The compute image boots to a local console: automatic login, locked passwords")
    s.pause(6)
    s.caption("postern-status: the privacy and hardening baseline observed on this system")
    s.shell(tty, "clear; postern-status", 6)
    s.caption("With root it also confirms that every account password is locked")
    s.shell(tty, "clear; sudo postern-status", 7)
    s.caption("Release record and the written privacy baseline shipped in the image")
    s.shell(tty, "clear; jq . /etc/postern/release.json; head -n 12 /etc/postern/privacy.txt", 8)
    s.shell(tty, "clear", 0.5)
    terminal_work(s, tty)
    s.caption("Measured benchmark: sequential and parallel hashing of the same data")
    s.shell(tty, "clear; postern-data-benchmark --files 8 --size-mib 8 --repeats 2 --output demo/bench.json"
                 " && jq -c '.comparison[]' demo/bench.json", 7)
    s.caption("Diagnostics tools are included: htop")
    s.type("htop")
    s.key("ret")
    s.pause(6)
    s.key("q")
    s.pause(1)
    s.caption("Power off: the live session leaves nothing on the machine's disks")
    s.pause(3)


def launch(s, query, process, wait=8):
    """Open an application the way a user does: Activities search, then Enter."""
    s.key("esc")
    s.key("esc")
    s.key("meta_l", settle=1.5)
    s.pause(1.5)
    s.type(query)
    s.pause(2.5)
    s.key("ret")
    # Wait for the process, then for its window to draw.
    s.wait_until(f"pgrep -f {process} >/dev/null", 150)
    s.pause(wait)
    s.check(f"{process} is running", f"pgrep -f {process} >/dev/null", 60)
    s.launches.append({"application": process, "method": "keyboard"})


def desktop_scenes(s):
    session = ("export XDG_RUNTIME_DIR=/run/user/$(id -u) "
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus; ")
    wayland = ("ok=1; for attempt in $(seq 1 150); do for id in $(loginctl list-sessions --no-legend | awk '{print $1}'); do "
               "if test \"$(loginctl show-session $id -p Name --value)\" = nixos && "
               "test \"$(loginctl show-session $id -p Type --value)\" = wayland; then ok=0; fi; done; "
               "test $ok = 0 && break; sleep 2; done; test $ok = 0")
    if not s.check("GNOME Wayland session is active", wayland, 400):
        raise RuntimeError("The desktop session did not start")
    s.serial.run(session + "gsettings set org.gnome.desktop.session idle-delay 0", 60 * s.scale)
    s.pause(20)
    s.check("dock and blur extensions are enabled",
            session + "for attempt in $(seq 1 20); do gnome-extensions list --enabled | grep -c -e dash-to-dock -e blur-my-shell | grep -qx 2 && break; sleep 3; done; "
            "gnome-extensions list --enabled | grep -c -e dash-to-dock -e blur-my-shell | grep -qx 2", 120)
    s.mark_start()
    s.caption("The desktop: GNOME on Wayland with a dock that is always at hand")
    s.pause(8)
    s.caption("Activities overview and search")
    s.key("meta_l", settle=1.5)
    s.pause(6)
    s.caption("Every application in one grid")
    s.key("meta_l", "a", settle=1.5)
    s.pause(6)

    s.caption("Postern Status: privacy and kernel hardening in one window")
    launch(s, "postern status", "postern-status-gui", 12)
    s.pause(7)
    s.key("alt", "f4")
    s.pause(2)

    s.caption("Terminal: release record of the running image")
    launch(s, "terminal", "gnome-terminal-server", 8)
    tty = s.shell_tty()
    s.shell(tty, "jq . /etc/postern/release.json", 5)
    s.shell(tty, "clear", 0.5)
    terminal_work(s, tty)

    s.caption("Firefox opens on a quiet page: no onboarding, no promotions")
    launch(s, "firefox", "firefox", 25)
    s.pause(4)
    s.caption("Firefox: telemetry, studies and saved logins are disabled by locked policy")
    s.key("ctrl", "l")
    s.type("about:policies")
    s.key("ret")
    s.pause(9)

    s.caption("Tor Browser is included; it starts only when you open it")
    launch(s, "tor browser", "tor-browser", 30)
    s.pause(5)
    s.check("no system-wide Tor daemon", "! systemctl is-active --quiet tor.service")

    s.caption("Metadata Cleaner removes author, location and device data from files")
    launch(s, "metadata cleaner", "metadata-cleaner", 14)
    s.pause(4)

    s.caption("KeePassXC: an offline password manager")
    launch(s, "keepassxc", "keepassxc", 12)
    s.pause(4)

    s.caption("Files: removable media is never mounted or opened automatically")
    launch(s, "files", "nautilus", 10)
    s.pause(4)

    s.caption("Settings: location services and usage reporting are off by default")
    launch(s, "settings", "gnome-control-center", 12)
    s.pause(5)
    s.check("location services disabled",
            session + "test \"$(gsettings get org.gnome.system.location enabled)\" = false", 60)
    s.check("no remote-desktop or SSH service",
            "! systemctl is-active --quiet sshd.service && ! systemctl is-active --quiet gnome-remote-desktop.service")

    s.caption("All windows in the Activities overview")
    s.key("esc")
    s.key("meta_l", settle=1.5)
    s.pause(7)
    s.caption("Power off: the live session leaves nothing on the machine's disks")
    s.pause(3)


def mobile_scenes(s):
    """Applications are opened from the phone shell's search with real keyboard
    events. If that does not start one, it is started from the serial console
    instead, and result.json records which way each application was opened."""
    session = ("export XDG_RUNTIME_DIR=/run/user/$(id -u) WAYLAND_DISPLAY=wayland-0 "
               "XDG_CURRENT_DESKTOP=Phosh:GNOME XDG_SESSION_TYPE=wayland "
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus; ")

    def start(query, command, process, wait):
        running = f"pgrep -f {process} >/dev/null"
        method = "serial console"
        if s.keyboard_launch:
            if not s.home_open:
                s.key("meta_l", settle=1.5)
                s.pause(2.5)
            s.type(query)
            s.pause(3)
            s.key("ret")
            if s.wait_until(running, 60):
                s.pause(wait)
                method = "keyboard"
            else:
                # Do not type into an unknown state again.
                s.keyboard_launch = False
        if method != "keyboard":
            s.serial.run(session + f"(setsid {command} >/dev/null 2>&1 &)", 60 * s.scale)
            s.pause(wait)
        s.home_open = False
        s.launches.append({"application": process, "method": method})
        s.check(f"{process} is running", running, 60)

    shell = ("ok=1; for attempt in $(seq 1 150); do if systemctl is-active --quiet phosh.service && "
             "pgrep -f libexec/phosh >/dev/null && test -S /run/user/$(id -u)/wayland-0; "
             "then ok=0; break; fi; sleep 2; done; test $ok = 0")
    if not s.check("Phosh shell is running", shell, 400):
        raise RuntimeError("The phone shell did not start")
    s.park_pointer()
    s.pause(22)
    s.mark_start()
    s.caption("Home: favourites, the app grid and search")
    s.pause(9)

    s.caption("Postern Status: privacy and hardening at a glance")
    start("postern", "postern-status-gui", "postern-status-gui", 14)
    s.pause(8)

    s.caption("Console: the release record of this image")
    start("console", "kgx", "kgx", 12)
    tty = s.shell_tty()
    s.shell(tty, "jq -r '.name, .version, .type' /etc/postern/release.json", 5)
    s.caption("postern-data: hash files into a manifest")
    s.shell(tty, "clear; mkdir -p d && head -c 8M /dev/urandom > d/a.bin", 1)
    s.shell(tty, "postern-data scan d --output m.jsonl", 4)
    s.caption("Verify, then detect a modified file")
    s.shell(tty, "clear; postern-data verify d m.jsonl", 4)
    s.shell(tty, "echo x >> d/a.bin; postern-data verify d m.jsonl", 5)
    s.check("modified file is detected", "postern-data verify ~/d ~/m.jsonl; test $? -eq 1")
    s.check("kernel hardening is in effect",
            "sudo postern-status --json | jq -e '[.checks[] | select(.id == \"hardening\")][0].state == \"ok\"'")
    s.check("status report has no failed check",
            "sudo postern-status --json | jq -e '.summary.fail == 0'")

    s.caption("Firefox with the same locked privacy policy")
    start("firefox", "firefox", "firefox", 30)
    s.key("ctrl", "l")
    s.type("about:policies")
    s.key("ret")
    s.pause(9)

    s.caption("Secrets: a password manager with a phone layout")
    start("secrets", "secrets", "secrets", 16)
    s.pause(4)

    s.caption("Calendar")
    start("calendar", "gnome-calendar", "gnome-calendar", 14)
    s.pause(4)

    s.caption("Files")
    start("files", "nautilus", "nautilus", 12)
    s.pause(4)

    s.caption("Settings")
    start("settings", "gnome-control-center", "gnome-control-center", 14)
    s.pause(5)
    s.check("no remote-desktop or SSH service",
            "! systemctl is-active --quiet sshd.service && ! systemctl is-active --quiet gnome-remote-desktop.service")

    s.caption("Overview: running apps as cards above the app grid")
    s.key("meta_l", settle=1.5)
    s.pause(8)
    s.caption("Power off: nothing is left on the device")
    s.pause(3)


SVG_HEAD = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{CANVAS[0]}" height="{CANVAS[1]}" viewBox="0 0 {CANVAS[0]} {CANVAS[1]}">
<defs>
  <linearGradient id="base" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#070a18"/><stop offset="0.6" stop-color="#0c1130"/><stop offset="1" stop-color="#06131b"/>
  </linearGradient>
  <radialGradient id="indigo" cx="0.5" cy="0.5" r="0.5">
    <stop offset="0" stop-color="#5b5bf0" stop-opacity="0.55"/><stop offset="1" stop-color="#5b5bf0" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="teal" cx="0.5" cy="0.5" r="0.5">
    <stop offset="0" stop-color="#19c6b4" stop-opacity="0.42"/><stop offset="1" stop-color="#19c6b4" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="rose" cx="0.5" cy="0.5" r="0.5">
    <stop offset="0" stop-color="#d9499a" stop-opacity="0.30"/><stop offset="1" stop-color="#d9499a" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="mark" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#6a6cf6"/><stop offset="0.55" stop-color="#3a4fd8"/><stop offset="1" stop-color="#17b8a6"/>
  </linearGradient>
  <linearGradient id="edge" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#3a4060"/><stop offset="1" stop-color="#14172a"/>
  </linearGradient>
  <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="28"/></filter>
</defs>
'''
BACKDROP = f'''<rect width="{CANVAS[0]}" height="{CANVAS[1]}" fill="url(#base)"/>
<ellipse cx="330" cy="240" rx="760" ry="520" fill="url(#indigo)"/>
<ellipse cx="1640" cy="930" rx="820" ry="540" fill="url(#teal)"/>
<ellipse cx="1500" cy="120" rx="560" ry="340" fill="url(#rose)"/>
'''
FONT = 'font-family="Inter, sans-serif"'


def logo(x, y, size):
    """The Postern mark: a small arched gate in a rounded tile."""
    unit = size / 100.0
    return (f'<g transform="translate({x},{y}) scale({unit})">'
            '<rect width="100" height="100" rx="24" fill="url(#mark)"/>'
            '<path d="M32 78 V46 A18 18 0 0 1 68 46 V78 Z" fill="#ffffff"/>'
            '<path d="M43 78 V50 A7 7 0 0 1 57 50 V78 Z" fill="#2f44c9"/></g>')


def frame_svg(profile):
    """Backdrop and device frame, transparent where the captured screen shows."""
    x, y, width, height, radius = SCREEN[profile]
    phone = profile == "mobile"
    pad = 16 if phone else 12
    outer = radius + pad
    body = (f'<rect x="{x - pad}" y="{y - pad}" width="{width + 2 * pad}" height="{height + 2 * pad}" '
            f'rx="{outer}"')
    buttons = ""
    if phone:
        right = x + width + pad
        buttons = (f'<rect x="{right - 2}" y="{y + 190}" width="7" height="96" rx="3.5" fill="#1b1f33"/>'
                   f'<rect x="{x - pad - 5}" y="{y + 150}" width="7" height="58" rx="3.5" fill="#1b1f33"/>'
                   f'<rect x="{x - pad - 5}" y="{y + 226}" width="7" height="58" rx="3.5" fill="#1b1f33"/>')
    return (SVG_HEAD
            + f'<mask id="window"><rect width="{CANVAS[0]}" height="{CANVAS[1]}" fill="#fff"/>'
              f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" fill="#000"/></mask>'
            + '<g mask="url(#window)">' + BACKDROP
            + f'<rect x="{x - pad + 6}" y="{y - pad + 26}" width="{width + 2 * pad - 12}" '
              f'height="{height + 2 * pad}" rx="{outer}" fill="#000" opacity="0.55" filter="url(#shadow)"/>'
            + buttons + body + ' fill="#0b0d18"/>'
            + body + ' fill="none" stroke="url(#edge)" stroke-width="2"/>'
            + '</g></svg>')


def caption_svg(profile, text, step, steps):
    """One caption, on a transparent canvas, set beside or below the screen."""
    counter = f"{step:02d} / {steps:02d}"
    footer = (f"Postern OS {VERSION}  ·  {profile} live image  ·  "
              "offline in a virtual machine, shown faster than real time")
    if profile == "mobile":
        lines = textwrap.wrap(text, 25) or [""]
        size = 58 if len(lines) <= 4 else 46
        top = 500 - (len(lines) - 1) * size * 0.6
        spans = "".join(f'<tspan x="150" dy="{0 if index == 0 else size * 1.2:.0f}">{escape(line)}</tspan>'
                        for index, line in enumerate(lines))
        body = (logo(150, 150, 72)
                + f'<text x="246" y="182" {FONT} font-size="30" font-weight="700" fill="#f2f4fb">Postern OS</text>'
                + f'<text x="246" y="216" {FONT} font-size="22" font-weight="500" fill="#8b93b8">Mobile  ·  {VERSION}</text>'
                + f'<text x="150" y="{top - size * 1.5:.0f}" {FONT} font-size="24" font-weight="600" '
                  f'letter-spacing="3" fill="#35d0bd">{counter}</text>'
                + f'<text y="{top:.0f}" {FONT} font-size="{size}" font-weight="650" fill="#f4f6fd">{spans}</text>'
                + f'<text x="150" y="1000" {FONT} font-size="19" fill="#7a82a8">'
                  f'<tspan x="150">Real capture, offline in a virtual machine.</tspan>'
                  f'<tspan x="150" dy="26">Shown faster than real time; idle waits shortened.</tspan></text>')
    else:
        size = 36 if len(text) <= 78 else 30
        body = (f'<text x="192" y="1000" {FONT} font-size="22" font-weight="600" letter-spacing="3" '
                f'fill="#35d0bd">{counter}</text>'
                + f'<text x="960" y="1002" text-anchor="middle" {FONT} font-size="{size}" font-weight="600" '
                  f'fill="#f4f6fd">{escape(text)}</text>'
                + f'<text x="960" y="1052" text-anchor="middle" {FONT} font-size="19" fill="#7a82a8">'
                  f'{escape(footer)}</text>')
    return SVG_HEAD + body + '</svg>'


def intro_svg(profile, speed):
    note = ("Real capture of the ISO running offline in a virtual machine (software emulation)."
            if speed != 1 else "Real capture of the ISO running offline in a virtual machine.")
    detail = f"Shown at {speed:g}× with idle waits shortened; the boot sequence is not shown."
    return (SVG_HEAD + BACKDROP + logo(900, 250, 120)
            + f'<text x="960" y="510" text-anchor="middle" {FONT} font-size="112" font-weight="750" '
              'letter-spacing="-2" fill="#f6f7fd">Postern OS</text>'
            + f'<text x="960" y="584" text-anchor="middle" {FONT} font-size="38" font-weight="600" '
              f'fill="#35d0bd">{profile.capitalize()}  ·  {VERSION}</text>'
            + f'<text x="960" y="668" text-anchor="middle" {FONT} font-size="34" font-weight="400" '
              f'fill="#c9cfe8">{escape(TAGLINE[profile])}</text>'
            + f'<text x="960" y="930" text-anchor="middle" {FONT} font-size="22" fill="#7a82a8">{escape(note)}</text>'
            + f'<text x="960" y="962" text-anchor="middle" {FONT} font-size="22" fill="#7a82a8">{escape(detail)}</text>'
            + '</svg>')


def outro_svg(profile, checks, iso_name, iso_digest, stopped):
    passed = sum(1 for item in checks if item["passed"])
    colour = "#35d0bd" if passed == len(checks) and not stopped else "#f06278"
    headline = (f"{passed} of {len(checks)} recorded checks passed" if not stopped
                else f"Recording stopped early ({passed} of {len(checks)} checks passed)")
    rows = ""
    half = (len(checks) + 1) // 2
    for index, item in enumerate(checks[:20]):
        column, row = divmod(index, max(half, 1))
        x, y = 330 + column * 660, 470 + row * 44
        dot = "#35d0bd" if item["passed"] else "#f06278"
        rows += (f'<circle cx="{x}" cy="{y - 8}" r="8" fill="{dot}"/>'
                 f'<text x="{x + 26}" y="{y}" {FONT} font-size="25" fill="#dfe3f4">'
                 f'{escape(item["name"][:46])}</text>')
    return (SVG_HEAD + BACKDROP + logo(330, 150, 84)
            + f'<text x="440" y="190" {FONT} font-size="30" font-weight="700" fill="#f2f4fb">Postern OS</text>'
            + f'<text x="440" y="226" {FONT} font-size="22" font-weight="500" fill="#8b93b8">'
              f'{profile.capitalize()}  ·  {VERSION}</text>'
            + f'<text x="330" y="372" {FONT} font-size="{56 if stopped else 72}" font-weight="750" letter-spacing="-1" fill="{colour}">'
              f'{escape(headline)}</text>'
            + rows
            + f'<text x="330" y="960" {FONT} font-size="21" fill="#7a82a8">{escape(iso_name)}  ·  '
              f'sha256 {iso_digest[:16]}…  ·  checked inside the running system during this recording</text>'
            + f'<text x="330" y="992" {FONT} font-size="21" fill="#7a82a8">Development image. One scripted '
              'session in a virtual machine; not an audit, a release or a hardware test.</text>'
            + '</svg>')


def timeline(session, speed):
    """Video duration of every kept frame, and the captions on that clock.

    Playback is `speed` times faster than recorded. A run of identical frames
    (the guest is waiting) is shortened to IDLE_CAP_SECONDS, and each caption
    stays on screen for at least CAPTION_MIN_SECONDS.
    """
    end = session.now()
    start = session.origin if session.origin is not None else session.frames[0][0]
    frames = [frame for frame in session.frames if frame[0] >= start]
    if len(frames) < 2:
        raise RuntimeError("No frames were captured after the start of the walkthrough")
    durations = []
    for index, (moment, _, _) in enumerate(frames):
        following = frames[index + 1][0] if index + 1 < len(frames) else end
        durations.append(max(following - moment, 0.02) / speed)
    index = 0
    while index < len(frames):
        last = index
        while last + 1 < len(frames) and frames[last + 1][2] == frames[index][2]:
            last += 1
        total = sum(durations[index:last + 1])
        if total > IDLE_CAP_SECONDS:
            for position in range(index, last + 1):
                durations[position] *= IDLE_CAP_SECONDS / total
        index = last + 1
    # First frame shown for each caption; captions that share a frame collapse
    # to the later one.
    marks = []
    for moment, text in session.captions:
        position = next((i for i, frame in enumerate(frames) if frame[0] >= moment), len(frames) - 1)
        if marks and marks[-1][0] == position:
            marks[-1] = (position, text)
        else:
            marks.append((position, text))
    if not marks:
        raise RuntimeError("No caption was recorded")
    marks[0] = (0, marks[0][1])
    for number, (position, _) in enumerate(marks):
        until = marks[number + 1][0] if number + 1 < len(marks) else len(frames)
        shown = sum(durations[position:until])
        if shown < CAPTION_MIN_SECONDS:
            durations[until - 1] += CAPTION_MIN_SECONDS - shown
    clock = [0.0]
    for value in durations:
        clock.append(clock[-1] + value)
    captions = []
    for number, (position, text) in enumerate(marks):
        until = marks[number + 1][0] if number + 1 < len(marks) else len(frames)
        captions.append((clock[position], clock[until], text))
    return frames, durations, captions, clock[-1], start


def render(svg, target, workdir):
    source = target.with_suffix(".svg")
    source.write_text(svg)
    done = subprocess.run(["rsvg-convert", "--width", str(CANVAS[0]), "--height", str(CANVAS[1]),
                           str(source), "--output", str(target)],
                          cwd=workdir, capture_output=True, text=True, check=False)
    if done.returncode != 0 or not target.is_file():
        raise RuntimeError("rsvg-convert failed: " + done.stderr[-400:])


def encode(session, output, speed, iso_digest, stopped=False):
    if len(session.frames) < 2:
        raise RuntimeError("No frames were captured")
    profile = session.args.profile
    frames, durations, captions, length, start = timeline(session, speed)
    listing = []
    for (_, name, _), duration in zip(frames, durations):
        listing += [f"file 'frames/{name}'", f"duration {duration:.4f}"]
    listing.append(f"file 'frames/{frames[-1][1]}'")
    (session.workdir / "frames.txt").write_text("\n".join(listing) + "\n")

    subtitles = []
    for index, (begin, finish, text) in enumerate(captions, 1):
        subtitles += [str(index), f"{srt_time(begin + INTRO_SECONDS)} --> {srt_time(finish + INTRO_SECONDS)}",
                      text, ""]
    (output / f"{session.args.name}.srt").write_text("\n".join(subtitles))

    art = session.workdir / "art"
    art.mkdir()
    render(frame_svg(profile), art / "frame.png", session.workdir)
    render(intro_svg(profile, speed), art / "intro.png", session.workdir)
    render(outro_svg(profile, session.checks, session.args.iso.name, iso_digest, stopped),
           art / "outro.png",
           session.workdir)
    for index, (_, _, text) in enumerate(captions):
        render(caption_svg(profile, text, index + 1, len(captions)), art / f"caption{index:02d}.png",
               session.workdir)

    x, y, width, height, _ = SCREEN[profile]
    total = INTRO_SECONDS + length + OUTRO_SECONDS
    inputs = ["-f", "concat", "-safe", "0", "-i", "frames.txt", "-i", "art/frame.png"]
    graph = (f"[0:v]fps=15,scale={width}:{height}:flags=lanczos,setsar=1,"
             f"pad={CANVAS[0]}:{CANVAS[1]}:{x}:{y}:color=black,"
             f"tpad=start_duration={INTRO_SECONDS}:stop_mode=clone:stop_duration={OUTRO_SECONDS}[screen];"
             "[screen][1:v]overlay[v0]")
    stage = 0
    for index, (begin, finish, _) in enumerate(captions):
        inputs += ["-i", f"art/caption{index:02d}.png"]
        graph += (f";[v{stage}][{index + 2}:v]overlay=enable='between(t,{begin + INTRO_SECONDS:.3f},"
                  f"{finish + INTRO_SECONDS - 0.001:.3f})'[v{stage + 1}]")
        stage += 1
    cards = len(captions) + 2
    inputs += ["-i", "art/intro.png", "-i", "art/outro.png"]
    graph += (f";[v{stage}][{cards}:v]overlay=enable='lt(t,{INTRO_SECONDS})'[v{stage + 1}]"
              f";[v{stage + 1}][{cards + 1}:v]overlay=enable='gte(t,{INTRO_SECONDS + length:.3f})',"
              f"fade=t=in:st=0:d=0.6,fade=t=out:st={total - 0.6:.3f}:d=0.6[v]")
    video = output / f"{session.args.name}.mp4"
    command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", *inputs,
               "-filter_complex", graph, "-map", "[v]", "-t", f"{total:.3f}", "-r", "15",
               "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
               "-movflags", "+faststart", str(video)]
    done = subprocess.run(command, cwd=session.workdir, capture_output=True, text=True, check=False)
    if done.returncode != 0 or not video.is_file():
        raise RuntimeError("ffmpeg failed: " + done.stderr[-800:])

    # Raw captured frames and the composed picture, one of each per caption.
    stills = output / "stills"
    preview = output / "preview"
    stills.mkdir()
    preview.mkdir()
    for index, (begin, finish, _) in enumerate(captions):
        at = INTRO_SECONDS + begin + min(2.0, (finish - begin) * 0.8)
        subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                        "-ss", f"{at:.3f}", "-i", str(video), "-frames:v", "1",
                        "-vf", "scale=1280:-2", str(preview / f"{index:02d}.jpg")],
                       cwd=session.workdir, capture_output=True, check=False)
    for index, (moment, _) in enumerate(session.captions):
        later = [name for at, name, _ in session.frames if at >= moment + 2.0 * session.scale]
        if later and moment >= start:
            shutil.copyfile(session.frames_dir / later[0], stills / f"{index:02d}.png")
    for name, at in (("intro", 1.0), ("outro", total - 2.0)):
        subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                        "-ss", f"{at:.3f}", "-i", str(video), "-frames:v", "1",
                        "-vf", "scale=1280:-2", str(preview / f"{name}.jpg")],
                       cwd=session.workdir, capture_output=True, check=False)
    timing = {"video_seconds": round(total, 1), "walkthrough_seconds": round(length, 1),
              "boot_seconds_not_shown": round(start, 1), "idle_cap_seconds": IDLE_CAP_SECONDS,
              "caption_minimum_seconds": CAPTION_MIN_SECONDS,
              "recorded_walkthrough_seconds": round(session.now() - start, 1)}
    return video, [list(item) for item in captions], timing


def arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("iso", type=Path)
    parser.add_argument("--profile", choices=("compute", "desktop", "mobile"), required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory; must not exist")
    parser.add_argument("--accelerator", choices=("auto", "kvm", "tcg"), default="auto")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--fps", type=float, default=4.0, help="Captured frames per second")
    parser.add_argument("--slow-factor", type=float, default=4.0,
                        help="Multiplier for scripted pauses under software emulation")
    parser.add_argument("--speed", type=float,
                        help="Playback speed of the video (default 1 with KVM, 3 without)")
    parser.add_argument("--boot-timeout", type=int, default=1500)
    args = parser.parse_args()
    if not 1 <= args.cpus <= 8 or not 1024 <= args.memory_mib <= 8192:
        parser.error("Use 1-8 vCPUs and 1024-8192 MiB RAM")
    if not 0.5 <= args.fps <= 5 or not 1 <= args.slow_factor <= 20:
        parser.error("Use 0.5-5 frames per second and a slow factor of 1-20")
    args.iso = args.iso.resolve(strict=True)
    if not args.iso.is_file() or args.iso.suffix != ".iso":
        parser.error("Input must be an existing .iso file")
    for tool in ("qemu-system-x86_64", "ffmpeg", "rsvg-convert"):
        if not shutil.which(tool):
            parser.error(f"{tool} is required (use nix develop)")
    if args.accelerator == "auto":
        args.accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    if args.speed is None:
        args.speed = 1.0 if args.accelerator == "kvm" else 3.0
    if not 0.5 <= args.speed <= 10:
        parser.error("Playback speed must be between 0.5 and 10")
    args.name = f"postern-{args.profile}-walkthrough"
    return args


def main():
    args = arguments()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with args.iso.open("rb") as image:
        digest = hashlib.sha256()
        for block in iter(lambda: image.read(1 << 20), b""):
            digest.update(block)
    result = {"format": "postern-demo/v1", "profile": args.profile, "iso": args.iso.name,
              "iso_sha256": digest.hexdigest(), "accelerator": args.accelerator,
              "network": "none", "vcpus": args.cpus, "memory_mib": args.memory_mib,
              "playback_speed": args.speed, "captured_fps": args.fps,
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "One scripted session in a virtual machine; a demonstration, "
                       "not boot verification and not a physical-hardware test.",
              "presentation": "The captured screen is shown unmodified inside a drawn frame. "
                              "Playback is faster than recorded, idle waits are shortened and "
                              "the boot before the walkthrough is not shown.",
              "completed": False}
    process = None
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix="postern-demo-", dir=output.parent) as scratch:
            workdir = Path(scratch)
            qmp_path = workdir / "qmp.sock"
            capture_path = workdir / "capture.sock"
            accelerator = ["-accel", "kvm", "-cpu", "host"] if args.accelerator == "kvm" \
                else ["-accel", "tcg,thread=multi", "-cpu", "max"]
            qemu = ["qemu-system-x86_64", *accelerator, "-machine", "q35",
                    "-smp", str(args.cpus), "-m", str(args.memory_mib),
                    "-cdrom", str(args.iso), "-boot", "d", "-nic", "none",
                    "-display", "none", "-vga", "none",
                    "-device", "virtio-vga,xres=%d,yres=%d" % SIZES[args.profile],
                    "-serial", "stdio", "-monitor", "none",
                    "-qmp", f"unix:{qmp_path},server=on,wait=off",
                    "-qmp", f"unix:{capture_path},server=on,wait=off", "-no-reboot"]
            result["qemu_command"] = [part.replace(str(workdir), "<scratch>") for part in qemu]
            process = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, cwd=workdir)
            session = Session(args, workdir)
            session.started = time.monotonic()
            for _ in range(100):
                if qmp_path.exists() and capture_path.exists():
                    break
                time.sleep(0.1)
            session.qmp = Qmp(qmp_path)
            session.capture_qmp = Qmp(capture_path)
            session.serial = Serial(process, output / "serial.log")
            recorder = threading.Thread(target=session.capture, daemon=True)
            recorder.start()
            try:
                print(f"[{session.now():7.1f}s] booting Postern OS {VERSION} {args.profile}", flush=True)
                session.serial.wait_for(PROMPT, args.boot_timeout)
                {"compute": compute_scenes, "desktop": desktop_scenes, "mobile": mobile_scenes}[args.profile](session)
                process.stdin.write(b"sudo poweroff\n")
                process.stdin.flush()
                try:
                    process.wait(timeout=180 * session.scale)
                    result["qemu_exit_code"] = process.returncode
                except subprocess.TimeoutExpired:
                    result["poweroff"] = "guest did not power off in time"
            except (OSError, ValueError, RuntimeError) as error:
                result["error"] = str(error)
            finally:
                session.stop.set()
                recorder.join(timeout=30)
            recorded = round(session.now(), 1)
            video, captions, timing = encode(session, output, args.speed, digest.hexdigest(),
                                              stopped="error" in result)
            result.update({"video": video.name, "video_sha256": hashlib.sha256(video.read_bytes()).hexdigest(),
                           "captions": captions, "frames": len(session.frames),
                           "recorded_seconds": recorded, "timing": timing,
                           "application_launches": session.launches})
    except (OSError, ValueError, RuntimeError) as error:
        result.setdefault("error", str(error))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if session is not None:
            result["checks"] = session.checks
            if session.serial is not None:
                session.serial.close()
        result["completed"] = ("error" not in result and "video" in result
                               and result.get("qemu_exit_code") == 0
                               and all(item["passed"] for item in result.get("checks", [])))
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        (output / "STATUS").write_text("completed\n" if result["completed"] else "incomplete\n")
    print(json.dumps({key: value for key, value in result.items() if key != "captions"}, indent=2), flush=True)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
