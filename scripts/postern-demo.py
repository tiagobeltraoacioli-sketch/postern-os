#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Record a scripted walkthrough of a real Postern ISO booted offline in QEMU.

The guest is driven with real keyboard events and its display is captured
through QMP. The video shows one scripted session on one virtual machine; it is
a demonstration, not the boot verification (see postern-verify.py) and not a
test on physical hardware.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

SIZES = {"compute": (1280, 720), "desktop": (1280, 720), "mobile": (720, 1280)}
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
                    self.frames.append((begin - self.started, target.name))
                    index += 1
            except (OSError, RuntimeError, ValueError):
                pass
            self.stop.wait(max(0.0, interval - (time.monotonic() - begin)))

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
STATE_STEPS = (
    ("No SSH, discovery or remote-desktop service; firewall and AppArmor active",
     "systemctl is-active sshd avahi-daemon firewall apparmor"),
    ("Swap is compressed memory only; nothing listens for remote login",
     "swapon --show; ss -ltn"),
)


def compute_scenes(s):
    tty = "tty1"
    s.caption("The compute image boots to a local console: automatic login, locked passwords")
    s.pause(6)
    s.caption("postern-status: the observable privacy baseline of this system")
    s.shell(tty, "postern-status", 6)
    s.caption("With root it also confirms that every account password is locked")
    s.shell(tty, "clear; sudo postern-status", 7)
    s.check("status report has no failed check",
            "sudo postern-status --json | jq -e '.summary.fail == 0'")
    s.caption("Release record and the written privacy baseline shipped in the image")
    s.shell(tty, "clear; jq . /etc/postern/release.json; head -n 14 /etc/postern/privacy.txt", 8)
    s.shell(tty, "clear", 0.5)
    for caption, command in DATA_STEPS:
        s.caption(caption)
        s.shell(tty, command, 4)
    s.check("manifest is private (mode 600)", "test \"$(stat -c %a ~/demo/manifest.jsonl)\" = 600")
    s.check("modified file is detected",
            "postern-data verify ~/demo/in ~/demo/manifest.jsonl; test $? -eq 1")
    s.caption("Measured benchmark: sequential and parallel hashing of the same data")
    s.shell(tty, "clear; postern-data-benchmark --files 8 --size-mib 8 --repeats 2 --output demo/bench.json"
                 " && jq -c '.comparison[]' demo/bench.json", 7)
    s.shell(tty, "clear", 0.5)
    for caption, command in STATE_STEPS:
        s.caption(caption)
        s.shell(tty, command, 5)
    s.check("no SSH daemon", "! systemctl is-active --quiet sshd.service")
    s.check("firewall active", "systemctl is-active --quiet firewall.service")
    s.caption("Diagnostics tools are included: htop")
    s.type("htop")
    s.key("ret")
    s.pause(6)
    s.key("q")
    s.pause(1)
    s.caption("Power off: the live session leaves nothing on the machine's disks")


def launch(s, query, process, wait=8):
    """Open an application the way a user does: Activities search, then Enter."""
    s.key("esc")
    s.key("esc")
    s.key("meta_l", settle=1.5)
    s.pause(1.5)
    s.type(query)
    s.pause(2.5)
    s.key("ret")
    s.pause(wait)
    s.check(f"{process} is running", f"pgrep -f {process} >/dev/null", 60)


def desktop_scenes(s):
    session = ("export XDG_RUNTIME_DIR=/run/user/$(id -u) "
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus; ")
    s.caption("The desktop image starts GNOME on Wayland with automatic local login")
    wayland = ("ok=1; for attempt in $(seq 1 150); do for id in $(loginctl list-sessions --no-legend | awk '{print $1}'); do "
               "if test \"$(loginctl show-session $id -p Name --value)\" = nixos && "
               "test \"$(loginctl show-session $id -p Type --value)\" = wayland; then ok=0; fi; done; "
               "test $ok = 0 && break; sleep 2; done; test $ok = 0")
    if not s.check("GNOME Wayland session is active", wayland, 400):
        raise RuntimeError("The desktop session did not start")
    s.serial.run(session + "gsettings set org.gnome.desktop.session idle-delay 0", 60 * s.scale)
    s.pause(15)
    s.caption("Desktop: Postern wallpaper, top bar and a dock that is always at hand")
    s.pause(8)
    s.check("dock and blur extensions are enabled",
            session + "for attempt in $(seq 1 20); do gnome-extensions list --enabled | grep -c -e dash-to-dock -e blur-my-shell | grep -qx 2 && break; sleep 3; done; "
            "gnome-extensions list --enabled | grep -c -e dash-to-dock -e blur-my-shell | grep -qx 2", 120)
    s.caption("Activities overview")
    s.key("meta_l", settle=1.5)
    s.pause(6)
    s.caption("Application grid")
    s.key("meta_l", "a", settle=1.5)
    s.pause(6)

    s.caption("Postern Status: the privacy baseline in one window")
    launch(s, "postern status", "postern-status-gui", 12)
    s.pause(7)
    s.key("alt", "f4")
    s.pause(2)

    s.caption("Terminal: release record of the running image")
    launch(s, "terminal", "gnome-terminal-server", 8)
    _, tty = s.serial.run("ps -eo tty=,comm= | awk '$2==\"bash\" && $1 ~ /^pts/ {print $1}' | tail -n 1",
                          60 * s.scale)
    if not tty.startswith("pts/"):
        raise RuntimeError("The terminal window did not open a shell")
    s.shell(tty, "jq . /etc/postern/release.json", 5)
    s.shell(tty, "clear", 0.5)
    for caption, command in DATA_STEPS:
        s.caption(caption)
        s.shell(tty, command, 4)
    s.check("modified file is detected",
            "postern-data verify ~/demo/in ~/demo/manifest.jsonl; test $? -eq 1")
    s.shell(tty, "clear", 0.5)
    for caption, command in STATE_STEPS:
        s.caption(caption)
        s.shell(tty, command, 5)
    s.check("status report has no failed check",
            "sudo postern-status --json | jq -e '.summary.fail == 0'")

    s.caption("Firefox opens on a quiet page: no onboarding, no promotions")
    launch(s, "firefox", "firefox", 25)
    s.pause(4)
    s.caption("Firefox: telemetry, studies and saved logins are disabled by locked policy")
    s.key("ctrl", "l")
    s.type("about:policies")
    s.key("ret")
    s.pause(9)
    s.caption("Firefox privacy settings: strict tracking protection, HTTPS-only mode")
    s.key("ctrl", "l")
    s.type("about:preferences#privacy")
    s.key("ret")
    s.pause(9)

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


def mobile_scenes(s):
    """The phone shell is touch-driven, so applications are started from the
    serial console; what is typed inside them uses real keyboard events."""
    session = ("export XDG_RUNTIME_DIR=/run/user/$(id -u) WAYLAND_DISPLAY=wayland-0 "
               "XDG_CURRENT_DESKTOP=Phosh:GNOME XDG_SESSION_TYPE=wayland "
               "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus; ")

    def start(command, process, wait):
        s.serial.run(session + f"(setsid {command} >/dev/null 2>&1 &)", 60 * s.scale)
        s.pause(wait)
        s.check(f"{process} is running", f"pgrep -f {process} >/dev/null", 60)

    s.caption("The mobile image starts the Phosh phone shell")
    shell = ("ok=1; for attempt in $(seq 1 150); do if systemctl is-active --quiet phosh.service && "
             "pgrep -f libexec/phosh >/dev/null && test -S /run/user/$(id -u)/wayland-0; "
             "then ok=0; break; fi; sleep 2; done; test $ok = 0")
    if not s.check("Phosh shell is running", shell, 400):
        raise RuntimeError("The phone shell did not start")
    s.pause(15)
    s.caption("Home: favourites, app grid and search")
    s.pause(9)

    s.caption("Postern Status fits the phone screen")
    start("postern-status-gui", "postern-status-gui", 12)
    s.pause(8)

    s.caption("Console: release record of this image")
    start("kgx", "kgx", 10)
    _, tty = s.serial.run("ps -eo tty=,comm= | awk '$2==\"bash\" && $1 ~ /^pts/ {print $1}' | tail -n 1",
                          60 * s.scale)
    if not tty.startswith("pts/"):
        raise RuntimeError("The console did not open a shell")
    s.shell(tty, "jq -r '.name, .version, .type' /etc/postern/release.json", 5)
    s.caption("postern-data: hash files into a manifest")
    s.shell(tty, "clear; mkdir -p d && head -c 8M /dev/urandom > d/a.bin", 1)
    s.shell(tty, "postern-data scan d --output m.jsonl", 4)
    s.caption("Verify, then detect a modified file")
    s.shell(tty, "clear; postern-data verify d m.jsonl", 4)
    s.shell(tty, "echo x >> d/a.bin; postern-data verify d m.jsonl", 5)
    s.check("modified file is detected", "postern-data verify ~/d ~/m.jsonl; test $? -eq 1")
    s.check("status report has no failed check",
            "sudo postern-status --json | jq -e '.summary.fail == 0'")

    s.caption("Firefox with the same locked privacy policy")
    start("firefox", "firefox", 28)
    s.key("ctrl", "l")
    s.type("about:policies")
    s.key("ret")
    s.pause(9)

    s.caption("Files")
    start("nautilus", "nautilus", 12)
    s.pause(4)

    s.caption("Settings")
    start("gnome-control-center", "gnome-control-center", 14)
    s.pause(5)
    s.check("no remote-desktop or SSH service",
            "! systemctl is-active --quiet sshd.service && ! systemctl is-active --quiet gnome-remote-desktop.service")

    s.caption("Overview: running apps as cards")
    s.key("meta_l", settle=1.5)
    s.pause(8)
    s.caption("Power off: nothing is left on the device")


def encode(session, output, speed, font):
    frames = session.frames
    if len(frames) < 2:
        raise RuntimeError("No frames were captured")
    end = session.now()
    listing = []
    for index, (moment, name) in enumerate(frames):
        following = frames[index + 1][0] if index + 1 < len(frames) else end
        listing += [f"file 'frames/{name}'", f"duration {max(following - moment, 0.02) / speed:.4f}"]
    listing.append(f"file 'frames/{frames[-1][1]}'")
    (session.workdir / "frames.txt").write_text("\n".join(listing) + "\n")

    origin = frames[0][0]
    captions = []
    for index, (moment, text) in enumerate(session.captions):
        following = session.captions[index + 1][0] if index + 1 < len(session.captions) else end
        captions.append(((max(moment - origin, 0)) / speed, (following - origin) / speed, text))
    subtitles = []
    for index, (begin, finish, text) in enumerate(captions, 1):
        subtitles += [str(index), f"{srt_time(begin)} --> {srt_time(finish)}", text, ""]
    (output / f"{session.args.name}.srt").write_text("\n".join(subtitles))

    width, height = SIZES[session.args.profile]
    size = 22 if width >= 1280 else 17
    graph = (f"[0:v]scale={width}:{height}:force_original_aspect_ratio=decrease,"
             f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:black,setsar=1")
    burned = bool(font and Path(font).is_file())
    if burned:
        for index, (begin, finish, text) in enumerate(captions):
            (session.workdir / f"caption{index}.txt").write_text(text)
            graph += (f",drawtext=fontfile={font}:textfile=caption{index}.txt:fontsize={size}:"
                      f"fontcolor=white:box=1:boxcolor=black@0.72:boxborderw=12:"
                      f"x=(w-text_w)/2:y=h-text_h-28:enable='between(t,{begin:.3f},{finish:.3f})'")
    graph += "[v]"
    video = output / f"{session.args.name}.mp4"
    command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
               "-f", "concat", "-safe", "0", "-i", "frames.txt",
               "-filter_complex", graph, "-map", "[v]", "-r", "15",
               "-c:v", "libx264", "-preset", "medium", "-crf", "23", "-pix_fmt", "yuv420p",
               "-movflags", "+faststart", str(video)]
    done = subprocess.run(command, cwd=session.workdir, capture_output=True, text=True, check=False)
    if done.returncode != 0 or not video.is_file():
        raise RuntimeError("ffmpeg failed: " + done.stderr[-800:])
    stills = output / "stills"
    stills.mkdir()
    for index, (moment, _) in enumerate(session.captions):
        later = [name for at, name in frames if at >= moment + 2.0 * session.scale]
        if later:
            shutil.copyfile(session.frames_dir / later[0], stills / f"{index:02d}.png")
    return video, burned, [list(item) for item in captions]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("iso", type=Path)
    parser.add_argument("--profile", choices=("compute", "desktop", "mobile"), required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory; must not exist")
    parser.add_argument("--accelerator", choices=("auto", "kvm", "tcg"), default="auto")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--memory-mib", type=int, default=4096)
    parser.add_argument("--fps", type=float, default=2.0, help="Captured frames per second")
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
    for tool in ("qemu-system-x86_64", "ffmpeg"):
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
                note = "" if args.speed == 1 else f" (software emulation; shown at {args.speed:g}x speed)"
                session.caption(f"Postern OS 0.3.1-dev {args.profile} live image booting offline in a virtual machine{note}")
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
            video, burned, captions = encode(session, output, args.speed,
                                             os.environ.get("POSTERN_DEMO_FONT"))
            result.update({"video": video.name, "video_sha256": hashlib.sha256(video.read_bytes()).hexdigest(),
                           "captions_burned_in": burned, "captions": captions,
                           "frames": len(session.frames),
                           "recorded_seconds": round(session.now(), 1)})
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
