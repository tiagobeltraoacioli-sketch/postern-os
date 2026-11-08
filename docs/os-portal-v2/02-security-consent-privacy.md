<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# The OS Portal v2 (Terem) — security, consent & privacy (the trust boundary)

**Status: DESIGN CONCEPT ONLY. Nothing in this document is built, deployed, or
audited.** **Primary owner: Architect 2** (consent/bridge/sandbox security).
This document red-teams and deepens `01-architecture.md` (the lead
architect's / Architect 1's guest-runtime design) the same way v1's PMO 2
document red-teamed PMO 1's — it does not re-derive the architecture, it
answers "what crosses the sandbox boundary, under what consent, and what is
honestly claimed about it." Sections marked `[ARCHITECT-2 STUB]` are this
document's own open work items — filled in by the dispatched security
architect, not left for someone else. Same discipline as every doc in this
tree: `written ≠ built`, `built ≠ booted`, `designed ≠ audited`,
`verifiable ≠ verified` (v1 §6's fourth inequality, inherited here).

> **Merge note.** Architect 2's full pass is preserved verbatim in
> `B-sandbox-consent.md` (this directory) — read it for depth this merged
> version compresses. Two of its refinements are load-bearing enough to fold
> in explicitly rather than leave in the sibling file: **(1)** the VM-vs-
> container isolation asymmetry deserves its own sharp statement, not just a
> table row (§1.1 below); **(2)** GPU/USB passthrough is not a "bridge" like
> clipboard/files/network — it **widens the boundary itself** (hands the
> guest direct, IOMMU-mediated hardware access) rather than moving data
> across a boundary that stays closed otherwise, and the `terem-gate` schema
> (§3) is corrected below to model it as its own `widen` rail, not one more
> `crossings` entry.

> **Update (2026-07-16) — "nothing built" is now imprecise; here is the exact
> state.** The first Terem code exists in-tree and is committed:
> `desktop/src-tauri/src/terem.rs` (the Tauri backend / QMP spawn path) and the
> `apps/terem-gate` crate (this document's `terem-gate` consent spine)
> **compile and pass their unit tests (terem-gate 32/32 + terem.rs 16) — but
> only under QEMU/TCG on the macOS workstation, never under Linux/KVM and never
> on hardware.** `os/terem-compat.nix` (the OS module) exists and is committed
> but is a Nix module not evaluated on this non-Nix host. Everything else this
> document designs remains
> **unbuilt, unbooted, and unaudited** — `written ≠ built`, `built ≠ booted`,
> `TCG ≠ KVM ≠ hardware`.

---

## 0 · The one-sentence claim, and why it needs to be structural

**The claim:** *"The Terem guest is a sealed box. Nothing on your real disk,
your firmware, or your host filesystem is reachable from inside it unless
you explicitly opened a specific bridge — and you can check that, not just
take our word for it."*

Same standard v1 §0 set for the (now-retired) bare-metal portal, carried
forward: the claim is honest only if it is **architectural** (no code path
carries data/access across the boundary) rather than **operational** ("we
promise the guest is isolated"). Every decision below exists to make the
claim checkable, not merely comfortable.

---

## 1 · Threat model — adversaries, capabilities, and boundaries

| Adversary | What a naive design would leak/allow | What it CAN do here | What it CANNOT do here | Primary mitigation |
|---|---|---|---|---|
| **Malicious/compromised software running inside the guest** (a Windows guest with malware, a hostile app under Wine) | Read/write the host's real files, see other guests, reach the host's firmware, pivot to the LAN | In Guest Mode: fully compromise the guest's own virtual disk and virtual devices; attempt to escape the hypervisor (a real but rare class of bug, §1.1). In App Mode: run with the **launching user's own OS privileges** (§9) — this is the sharpest asymmetry in this document | In Guest Mode (KVM/QEMU): touch the host's real disk, firmware, or other guests without an unpatched hypervisor-escape bug — there is no code path, only a bug class. In App Mode: **nothing extra is prevented by construction** unless the sandboxing wrapper (§9) is active | KVM's hardware-enforced ring separation (Guest Mode); Bubblewrap/namespace jail around the `WINEPREFIX` (App Mode, `[ARCHITECT-2 STUB]` §9.1) |
| **A malicious or tampered OS installer image** (fake Windows ISO, backdoored Ubuntu mirror) | Get written into the guest as if genuine, then behave as adversary #1 | Exist, be downloaded, be booted into a guest | Reach the host directly — it only ever reaches the guest's own virtual disk, so the blast radius of a bad image is "this one guest is compromised," not "the host is compromised," **provided** the guest stays inside its KVM boundary | Same isolation as above; optionally a digest-pinned image allowlist for operator-fetched ISOs, reusing v1's signed image-manifest pattern (v1 §1, "Signed image-manifest allowlist") — `[ARCHITECT-2 STUB]` §2.1: decide whether this is worth carrying forward for Terem or whether "the operator brought their own vendor ISO, that's on them" is the honester default |
| **Postern-the-company** | See guest contents, credentials typed inside the guest, host files shared across an open bridge | Publish the Terem/Tauri code, the Nix modules, `os_roothash` of the host (not the guest) | See anything inside a guest or Wine prefix by default — **structurally absent**: Terem's Tauri commands (`01` §2.6) are lifecycle verbs (start/stop/snapshot/destroy), none of which read guest disk contents or guest network traffic. There is no telemetry path from guest to Postern, matching `LICENSING-MODEL.md` principle 2 verbatim | Data-never-in-the-path by construction — no "Tier B/C Planner" exists in this design at all (v2 has no AI agent reading plan state off the guest; that was v1's Planner concern, retired per `01` §6) |
| **A network attacker** (hostile Wi-Fi, on-path) | Read/tamper guest network traffic, substitute a downloaded OS image in transit | Observe the guest's NAT'd egress traffic like any host process's traffic | Reach the guest's virtual disk or the host directly — network isolation (§7) and TLS on the vendor's own download endpoints are the guest's own business, the same as on real hardware | Guest NAT isolation (§7); this is an **honest non-improvement** over real hardware — a Terem guest has exactly the network-attacker exposure a real machine running that OS would have, no more, no less |
| **A compromised host** (the Postern OS machine itself already owned — malware, evil-maid, rooted) | Defeat the guest boundary entirely, since the hypervisor itself is untrusted | Everything — read/write every guest disk, keylog every guest session, disable the bridge consent gate | Nothing is claimed to survive this, same as every other Postern boundary (`docs/design/bridge-trust-boundaries.md`'s discipline, inherited verbatim). Terem's isolation protects the host **from** the guest; it cannot protect the guest **from** an already-compromised host | **Honest limit, not solved** — see §8 |

### 1.1 The core asymmetry — VM vs. shared-kernel container, stated once, sharply

Per Architect 2's pass (`B-sandbox-consent.md` §1): **a VM's isolation is
enforced by hardware and a narrow hypervisor interface below the guest's own
kernel. A container's (`systemd-nspawn`/Podman, `01` §2.1) isolation is
enforced by the SAME kernel the guest's processes run on top of.** This is
not a difference of degree, it is a difference of *what the boundary is
made of*:

| | **VM (KVM)** | **Container (`nspawn`)** |
|---|---|---|
| Guest memory | Hardware-enforced (EPT/NPT second-level page tables) — a guest process cannot address host memory at all | Namespace-isolated *view*, not memory-address isolation — a container process is a real process on the host |
| Guest kernel | Its own (Windows NT, or a different Linux build) — a guest-kernel bug stays inside the guest | **Is** the host kernel — there is no second kernel to contain a bug in |
| Privilege-escalation blast radius | Guest-root compromise stays guest-root; reaching the host needs a hypervisor **escape** (rare, but total when it happens) | Guest-root compromise is a short step from **host-root** — any namespace/cgroup/`unshare`/overlayfs escape CVE turns container-root into host-root, because there was only ever one kernel |
| Attack surface | The virtio/emulated-device surface (network, block, GPU, USB) — bounded | The entire host kernel syscall surface reachable from the namespace — historically the source of most container-escape CVEs |

KVM/QEMU is mature, widely deployed, hardware-assisted virtualization — a
materially stronger boundary than App Mode's "no boundary at all" or v1's
"the executor IS the host" bare-metal case. It is **not** a zero-risk
boundary: guest-to-host escapes are a real, if rare, vulnerability class,
historically concentrated in emulated-device code (the VENOM
floppy-controller CVE and several other QEMU device-emulation bugs are the
canonical examples) — patched as found, like any hypervisor, never claimed
closed by this design. **The honest framing for the container backend is
not "containers leak sometimes" — it is "a container is a resource-isolation
and packaging boundary, not a security boundary against a
kernel-privilege-escalation-capable adversary, full stop."** Design
guidance this asymmetry drives: default the backend picker toward the VM
for any guest the operator does not already fully trust (an unverified
Windows ISO, a RHEL image not built by the operator); position the
container backend honestly as "lightweight, for OSes you already trust — a
shared-kernel boundary, not a hardened one," never as an equally-strong
lighter-footprint alternative to the VM path.

---

## 2 · The sandbox trust boundary — what's structurally contained

### 2.1 Guest Mode (KVM/QEMU)

| Guest can reach | Guest CANNOT reach (by construction, not policy) |
|---|---|
| Its own virtual disk (a qcow2 file) | The host's real disk, partitions, or any other guest's disk |
| Its own virtual firmware (OVMF/`swtpm`) | The host's real firmware, Secure Boot state, or TPM |
| Its own virtual NIC (NAT'd by default, §7) | The host's LAN, unless a bridge is explicitly opened (§3) |
| Its own virtual GPU (software-rendered by default, `01` §2.5) | The host's GPU exclusively, unless VFIO passthrough was explicitly configured (an advanced, hardware-gated opt-in — `01` §2.5) |
| Nothing on the host filesystem | The host filesystem, clipboard, or any host process — unless a bridge is explicitly opened (§3) |

This table **is** the honest version of the v1 one-sentence claim (§0),
made checkable: every "cannot reach" cell holds because there is no QEMU
device, no shared filesystem tag, no virtio-vsock channel wired up by
default — not because a policy promises not to use one that exists.

`[ARCHITECT-2 STUB]` §2.1 — decide and document whether an image-manifest
digest allowlist (mirroring v1's "Signed image-manifest allowlist … checked
by the deterministic Executor, never the Planner") is worth carrying
forward for Terem's operator-fetched vendor ISOs, or whether that
machinery was only load-bearing for v1's AI-agent-driven fetch path (which
v2 does not have by default, `01` §6) and is unnecessary complexity here.

### 2.2 App Mode (Wine/Proton) — the honest asymmetry

Unlike Guest Mode, App Mode has **no hardware isolation boundary at all**.
This must be stated as plainly here as `01` §3.2 states it in the
architecture doc, because it is the single fact most likely to get
flattened into "Terem sandboxes foreign software" marketing copy that would
be false for this path. A Wine process:

- reads/writes anything the launching Postern OS user account can — the
  `WINEPREFIX` directory convention is a **namespace convention**, not an
  access-control boundary, absent the sandboxing wrapper of §9.1;
- can reach the host network exactly like any other user process, unless
  the sandbox wrapper's network policy blocks it;
- is **not** isolated from other Wine prefixes' processes by anything
  Wine itself provides — cross-prefix interference is a user-account-level
  concern, again absent §9.1's wrapper.

**The mitigation is opt-in sandboxing (§9.1), not virtualization** — a
Bubblewrap/Flatpak-style namespace jail, the same posture the Wine/Proton
ecosystem itself has converged on (Steam ships Proton this way). This
document takes the position that App Mode's sandbox wrapper should default
**on**, with the operator able to grant a specific app broader filesystem
access as an explicit, disclosed exception — never the reverse (default-open
with an opt-in jail would repeat the exact "convenient but not honest"
mistake v1 §0 rejected). `[ARCHITECT-2 STUB]` §9.1 owns finalizing this.

---

## 3 · Bridge inventory & consent-gating — the `terem-gate` tier

Every guest↔host or app↔host crossing is modeled as a **new, fifth
consent-gate tier**, following the identical spine
`apps/consent-contract/CONTRACT.md` already formalizes for Sloboda/NoporIS/
Porog and the retired v1 `portal-gate` sketch:

```jsonc
{
  "schema":  "postern.terem-gate.state",   // alias: Architect 2's contribution
                                             // used "postern.sandbox-gate.state"
                                             // as a placeholder name — same
                                             // shape, renamed to match Terem's
                                             // branding (`01` §0.3)
  "version": 1,
  "tier":    "non-attestable",        // pinned; see §6 — the guest is NEVER
                                        // attested, regardless of the HOST's
                                        // own attestation status
  "consent":    { "accepted": false, "scope": "session" },
  "killSwitch": { "engaged": false },

  "backend": "vm" | "container",       // which boundary is actually in force —
                                        // READ-ONLY to the UI; never a capability
                                        // a crossing or the guest can change
                                        // (Architect 2's addition — §1.1's VM/
                                        // container asymmetry must be visible
                                        // in the state itself, not just docs)

  // Bridges: move DATA across an otherwise-closed boundary. Each is
  // deny-by-default, per-direction, individually revocable — the boundary
  // itself is unaffected either way.
  "crossings": {
    "clipboard":    { "hostToGuest": false, "guestToHost": false, "scope": "session" },
    "sharedFolder":  { "hostToGuest": false, "guestToHost": false, "scope": "session", "hostPath": null },
    "audio":         { "hostToGuest": false, "guestToHost": false, "scope": "session" },
    "usbDevice":     { "devices": [], "scope": "session" },        // per-device allowlist: vendor:product + serial, never "all USB"
    "network":       { "mode": "nat-only", "scope": "session" }     // nat-only | bridged-lan — bridged is the escalation
  },

  // Widen: hands the guest direct, IOMMU-mediated hardware access — this is
  // NOT a data crossing and does not fit the bridge shape at all (§2.4,
  // Architect 2's correction to this document's first draft, which had
  // wrongly modeled gpuPassthrough as one more crossing above).
  "widen": {
    "gpuPassthrough": { "open": false, "scope": "persistent" }      // rarely toggled; still its own explicit, loudly-labeled rail
  }
}
```

`direction` ∈ `host→guest` \| `guest→host` \| `both` \| `none` — a crossing
open with `direction: "none"` installs no grant, fail-closed, identical to
Porog's rule in `apps/consent-contract/CONTRACT.md`. Default state for
**every** crossing is closed — the guest boots with clipboard, shared
folders, bridged LAN, USB, and GPU passthrough all off; only the isolated
NAT network is on by default (a guest needs *some* network to reach the OS
vendor's own install/activation/update servers, mirroring why Sloboda's
`waydroid init` needs egress — but NAT-isolated egress is a materially
smaller grant than a bridged LAN or a shared folder, so it is the one
crossing this design proposes leaving default-**on** rather than
default-closed like every other one; `[ARCHITECT-2 STUB]` §3.1 — confirm or
overturn this one exception, since it is the one place this schema departs
from "every capability is closed unless consented").

**One crossing set per guest instance, `WINEPREFIX`-scoped for App Mode** —
the schema above is Guest Mode-shaped; App Mode's equivalent is narrower
(`filesystemScope`, `network`, no `sharedFolder`/`usbDevice`/`widen.*`
concepts at all, since there's no guest to pass a device into) —
`[ARCHITECT-2 STUB]` §3.2: draft the App Mode variant schema explicitly
rather than overloading the Guest Mode one.

### 3.0 Bridges vs. widening — why `gpuPassthrough` moved out of `crossings`

Architect 2's correction to this document's first draft (`B-sandbox-consent.md`
§1.3, §2.4): a **bridge** (`clipboard`, `sharedFolder`, `audio`, `usbDevice`,
`network`) moves *data* across a boundary that otherwise stays fully closed —
the boundary itself is unaffected either way. **GPU passthrough is not
that** — it hands the guest direct, DMA-capable access to a physical device,
mediated only by the platform's IOMMU grouping, not by hypervisor logic.
That is a *widening of the boundary itself*, categorically different from a
data crossing, so it lives in its own `widen` rail (§2's schema), consented
at a *higher* bar than an ordinary bridge, and named honestly in UI copy as
what it is: *"this does not share data with the guest — it gives the guest
direct access to a physical device, subject only to your motherboard's IOMMU
grouping."* USB passthrough sits closer to this same category (a passed-
through device's own firmware/command surface is reachable by the guest,
not merely a data channel) — this document keeps it under `crossings` per
its per-device allowlist model but flags the classification as worth
Architect 2's final call, not settled here.

### 3.1 What "opening a bridge" concretely does

Mechanisms corrected below to match `01`'s license-driven pivot away from
SPICE (§2.1 there — SPICE clipboard/USB-redirection agents are LGPL, ruled
out): every mechanism here uses QEMU's own virtio devices and QMP, or the
wayvnc/FreeRDP,xrdp display session, never a SPICE agent.

| Crossing | Mechanism when open | Mechanism when closed |
|---|---|---|
| `clipboard` | A host-side clipboard-sync helper relays content across the boundary in the consented direction, over a `virtio-vsock`/QMP-mediated channel (not SPICE's `spice-vdagent`) — `[ARCHITECT-1/2 STUB]`: pick and vet the concrete permissively-licensed mechanism; QEMU has no first-class non-SPICE clipboard agent today, so this may need to ship as Terem's own small helper rather than reusing an existing one | No agent wired up; the guest's clipboard and the host's clipboard are two unrelated pieces of state |
| `sharedFolder` | `virtiofs`/9p filesystem passthrough (native QEMU device, no SPICE dependency) of exactly one operator-chosen host directory into the guest | No filesystem tag exists; nothing in the guest can enumerate, let alone read, the host filesystem |
| `network: bridged-lan` | The guest's virtual NIC attaches to a bridged interface reaching the client's real LAN, instead of NAT | Guest traffic stays behind QEMU's NAT; the client's LAN (printers, NAS, other machines) is unreachable from the guest |
| `usbDevice` | One named USB device (by vendor:product ID + serial, not "all USB") passed through via QEMU's own `-device usb-host,vendorid=…,productid=…` hostdev (not SPICE USB-redirection) | No USB passthrough; the guest sees no host USB devices |
| `audio` | Guest audio routed to/from the host's audio server (PipeWire) via QEMU's native audio backend, in the consented direction | No audio device wired, or a null/silent virtual audio device |

A separate table for the `widen` rail, deliberately not merged into the one
above (§3.0):

| Widen | Mechanism when open | Mechanism when closed |
|---|---|---|
| `widen.gpuPassthrough` | VFIO PCI passthrough of a dedicated GPU (`01` §2.5's advanced, hardware-gated opt-in) | Software-rendered `virtio-gpu`, or `virtio-gpu`+Venus where available (`01` §2.5) — never a data crossing, so "closed" here just means the guest has no physical device, not that a channel is unavailable |

### 3.2 Signed `ConsentRecord`, not a boolean toggle

Upgrading the boolean sketch above to the same **signed, time-boxed
`ConsentRecord`** model v1 §3.1 already specified and
`apps/noporis-bridge-glue/src/consent_record.rs` already implements and
tests: a boolean state file can be flipped by anything that can write it; a
signed record can only be produced by whoever holds the operator's local,
session-only `ConsentAuthority` key (generated fresh per Terem session,
destroyed at session end, never seen by Postern). The **5-step fail-closed
check** (`consent_record.rs`) — signature → session binding → **target
binding** (which guest/prefix, by its own generated instance id, not a
reorderable path) → capability → time-box — applies verbatim, with
`capability` drawn from the crossing set in §3 instead of NoporIS's
`clipboard/files/mic/camera/location` set.

`widen.gpuPassthrough`, being `persistent`-scoped and rarely toggled, is the
one grant in this design that is **not** required to have a live re-tap every
session (unlike `01`'s retired v1 disk-verbs, which required a live tap for
every irreversible action) — because opening it is not irreversible or
destructive, only a hardware-resource grant that is trivially revocable
(close it, the next guest boot has no passthrough device). `[ARCHITECT-2
STUB]` §3.3 — confirm this scope choice against the actual risk (a
passed-through GPU does hand the guest a real PCI device with real driver
attack surface against host firmware/IOMMU groups — is `persistent` scope
still the right call, or should this be `session`-scoped like the others
out of caution?).

---

## 4 · The kill-switch and reversibility — the actual improvement over v1

v1 §3.5/§5.2 could not solve "the kill-switch halts the next step but
cannot un-write bytes already committed to disk" because the object being
written was the client's **real** disk. Terem's kill-switch does not have
that problem, because nothing it touches is the client's real disk:

- **Guest Mode kill-switch**: stops the guest's virtual CPU (QMP `quit` for
  a graceful stop, or SIGTERM/SIGKILL the QEMU child process — no `virsh`,
  per `01` §2.1/§2.6's no-libvirt correction — equivalent to pulling the
  virtual power cord) and, on an
  explicit separate confirmation, deletes the guest's disk file entirely
  (`01` §2.3's `terem_destroy`). A kill mid-install can leave a **corrupted
  guest disk image** — annoying, but recoverable by deleting that one file
  and starting over, never a host-disk emergency. This is stated as
  plainly as v1 stated its own limit: **the kill-switch can leave a broken
  guest. It cannot, and structurally could not, ever leave a broken host.**
- **App Mode kill-switch**: kills the Wine process (`SIGTERM`/`SIGKILL`,
  same as terminating any other app) and, on explicit confirmation, deletes
  the `WINEPREFIX` directory. Identical reasoning.

This is the single most important honest upgrade this document can make
over v1's unresolved §5.2 — not because the mechanism is more clever, but
because the **object being protected changed**: v1 protected a live,
in-place write to irreplaceable host state; Terem protects a disposable
file the client can always recreate.

---

## 5 · Network isolation of the guest

Default: **NAT-only egress** (§3), no inbound listener from the host's real
LAN, no bridged-LAN attachment. This gives the guest internet access (for
OS vendor download/activation/update traffic — necessary, since the whole
point is running the vendor's real, updatable OS) while keeping the guest
off the client's home/office LAN by default. Bridged-LAN is available as an
explicit, consented crossing (§3.1) for operators who genuinely need the
guest to appear as a first-class LAN citizen (e.g., testing a
network-service the guest hosts). `[ARCHITECT-2 STUB]` §5.1 — should Terem
offer routing guest egress over `crates/postern-tor` the way v1 §5 flagged
for its Planner traffic? Unlike v1's Planner-privacy question, this is
about **guest OS vendor telemetry** (Windows/RHEL update and activation
traffic), which is the vendor's own business, not Postern's to intercept or
promise privacy for — the honest answer may be "Terem does not, and should
not, try to anonymize the guest OS's own vendor traffic; that is outside
this product's trust boundary" (§8), but this needs an explicit decision
rather than silent omission.

---

## 6 · Attestation — the guest is honestly non-attestable, always

Mirroring Sloboda's honesty header (`apps/sloboda/README.md`) verbatim in
spirit:

> **A Terem guest is the NON-ATTESTABLE tier, by construction, for every
> guest OS Terem can run.** Windows, Ubuntu, RHEL, or any other guest's disk
> image is mutable state the operator installs or downloads — it is never
> part of any measured, reproducible Nix closure, `os_roothash` says
> **nothing** about what runs inside a guest, and no Postern Seal ever
> covers guest contents. This is not a limitation to be fixed later; it is
> structurally permanent for as long as the guest OS is Windows/Ubuntu/RHEL/
> anything not Postern OS itself — the same wall v1 §3.5/§6 already named
> for its (retired) bare-metal target, unchanged by the pivot to a sandbox.

What **is** true and attestable: the **host** — Postern OS Desktop
(`os/desktop.nix`, optionally paired with `os/attested.nix`'s dm-verity/UKI
chain) — retains its own, unrelated attestation story exactly as before.
Enabling Terem (`os/terem-compat.nix`, `01` §2.7) does not unseal the host;
it adds a capability to run non-attestable guests *beside* a still-sealed
base, the identical posture `os/sloboda-compat.nix` already establishes for
the Waydroid tier. **The forbidden overclaim, named explicitly per
`docs/design/bridge-trust-boundaries.md`'s discipline: never imply "your
Windows guest is Seal-covered" or "Terem attests what runs inside the
guest."** `scripts/check-trust-labels.sh`'s `NONATTEST_PATHS` list should
gain the Terem surfaces (`apps/terem*`, `os/terem-compat.nix`) once code
exists, exactly as `apps/sloboda`/`apps/sloboda-gate`/
`os/sloboda-compat.nix` are listed today.

App Mode inherits the identical posture a fortiori: there isn't even a
guest disk image to *not* attest — a `WINEPREFIX` is ordinary host
filesystem state, further from anything attestation-shaped than a VM.

---

## 7 · Data handling — what exists, where, and what (if anything) leaves

| Data | Lives where | Lifetime | Ever leaves the device? |
|---|---|---|---|
| Guest disk contents (files, installed apps, registry, activation state) | The guest's qcow2 file, on the host's (LUKS-encrypted, per `os/desktop.nix`) real filesystem | Until the operator destroys the guest | Only over the guest's own NAT'd network egress, to wherever the operator's software inside the guest chooses to send it — Postern never reads this file's contents and has no code path that does |
| Wine prefix contents (App Mode) | The `WINEPREFIX` directory, same host filesystem | Until the operator destroys the prefix | Same as above — only via the app's own network activity |
| Bridge crossing state (`terem-gate` state file) | `/var/lib/postern/terem-gate/state.json`, same layout as every other consent-gate tier | Persistent (if `scope: persistent`) or session | Never — local only, matches the consent-spine's "no telemetry" rail #7 (`apps/consent-contract/CONTRACT.md`) |
| `ConsentAuthority` signing key (§3.2) | Operator's device only | Generated fresh per session, destroyed at session end | Never — Postern never holds or sees it |
| Local audit trail of grants/denials/lifecycle events | Client's own disk, hash-chained, `fsync`'d, same idiom as `crates/postern-trail`/`crates/yagabona/src/trail.rs`/`apps/noporis-bridge-glue/src/audit.rs` | Client-owned; persists until deleted | Never auto-transmitted; exportable by the client on their own terms only |
| Terem's own license/grant tokens (`03-license-honesty.md` §3) | Local device (verification) + Postern's license service (issuance/CRL) | Per `enterprise/licensing`'s existing model | Only `jti`/status CRL check — reveals grant-revocation status, never guest contents |

**Metadata minimization, honestly bounded:** even NAT-isolated guest egress
carries the guest OS vendor's own telemetry/update traffic, timing, and
source IP visible to that vendor and any network observer — this is
identical to what a real machine running that OS would expose, and Terem
does not claim to reduce it (§5's open question notwithstanding).

---

## 8 · Honest limits — where the client must extend trust, plainly stated

- **A compromised or rooted host defeats every boundary in this document.**
  Terem protects the host from a hostile guest; it cannot protect a guest
  (or App Mode's launched app) from an already-hostile host. Same wall
  every other Postern bridge product bottoms out at
  (`docs/design/bridge-trust-boundaries.md`).
- **KVM/QEMU isolation is strong, not absolute** (§1.1) — hypervisor-escape
  bugs are a real, patched-as-found class, not a theoretical zero.
- **App Mode has no hardware isolation boundary at all** (§2.2) — its
  safety rests entirely on the optional namespace-jail wrapper (§9.1),
  which is new, unbuilt code as of this document.
- **GPU passthrough, when enabled, hands the guest a real PCI device** —
  narrows the isolation boundary for that specific hardware resource; this
  is disclosed as an advanced, explicit opt-in (§3.1), never a default.
- **The guest OS vendor's own binaries, telemetry, and update behavior are
  outside this trust boundary entirely** — Windows/RHEL/Ubuntu's own
  conduct is Microsoft's/Red Hat's/Canonical's to answer for, not
  Postern's, the same wall v1 §6 already drew and this document does not
  weaken.
- **"Verifiable" is not "verified"** (v1's fourth inequality, inherited
  verbatim) — every isolation claim in this document depends on the actual
  KVM/QEMU build being unpatched-vulnerability-free at time of use, and on
  the operator's Nix config genuinely matching `os/terem-compat.nix` as
  written, not a promise nobody checked.
- **Nothing described here has been built, let alone security-reviewed.**
  This inherits verbatim from every other honesty ledger in this tree.

---

## 9 · Least privilege for App Mode — Architect 2's primary open item

### 9.1 `[ARCHITECT-2 STUB]` — the sandbox wrapper default

This is the single largest unresolved item this document hands to
Architect 2, larger than any individual crossing schema question above:
**decide and specify the concrete default sandboxing mechanism for App
Mode** (§2.2, §3.2). At minimum, resolve:

- Bubblewrap direct invocation vs. a Flatpak-portal-based approach vs. a
  `firejail` profile — pick one as the shipped default and state why.
- The default filesystem allowlist (the `WINEPREFIX` itself; does it also
  need read access to a font cache, a Documents folder the operator
  explicitly shared — mirroring the `sharedFolder` crossing's consent
  model from §3 rather than inventing a separate App Mode-only concept).
- Default network policy (off unless the app's manifest/operator consent
  says otherwise) and whether that consent uses the same `terem-gate`
  schema (§3, extended per the App Mode variant flagged in §3's
  `[ARCHITECT-2 STUB]` §3.2) or a separate one.
- Whether the wrapper is mandatory (no way to launch a Wine app without it)
  or operator-disable-able, and if disable-able, what honest warning
  accompanies that choice (mirroring Sloboda's default-safe posture: never
  silently weaken, always disclose).

### 9.2 `[ARCHITECT-2 STUB]` — audit trail schema for guest lifecycle events

Specify the concrete hash-chained trail entry shape for Terem lifecycle
events (guest create/install/snapshot/restore/destroy, crossing
open/close/revoke), reusing `crates/postern-trail`'s existing primitive —
analogous to v1 §3.6's intent/commit pattern but simpler, since Terem's
"destructive" actions (§4) no longer need the journaled pre-image/commit
transactional design v1 flagged as its own unsolved problem (v1 §3.5) —
confirm that simplification holds or name any residual case where it
doesn't (e.g., is a *snapshot restore* mid-flight ever itself
non-atomically dangerous in a way worth journaling?).

---

## 10 · Cross-reference — where this document answers `01`'s open items

| `01-architecture.md` item | Where answered here |
|---|---|
| §2.4 "no shared folders/clipboard by default" | §2.1, §3 — the full crossing inventory and default-closed schema |
| §7 item 5 (Architect 2 owns this document) | This entire document |
| §6 table row "Kill-switch cannot undo an in-flight disk write" → "weakened to a real, solvable problem" | §4 — the concrete reason it's solvable (disposable file vs. real disk) |

---

## 11 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| The Guest Mode "cannot reach" table (§2.1) | **Real for KVM/QEMU's design**, honestly bounded by §1.1's hypervisor-escape caveat — not yet built or tested in this repo |
| App Mode's "no isolation boundary by default" claim (§2.2) | **Real, and the single most safety-relevant fact in this document** — explicitly not softened |
| The `terem-gate` consent schema (§3) | **[SPECULATIVE / NEW]** — pattern directly reuses the real, tested consent-spine kernel (`apps/consent-contract/consent-spine.mjs`); the specific crossing set is new and unbuilt |
| Signed `ConsentRecord` for guest/prefix crossings (§3.2) | **Directly reuses** `apps/noporis-bridge-glue/src/consent_record.rs`'s real, tested 5-step check — the `capability` enum is new |
| The kill-switch reversibility improvement over v1 (§4) | **Real architectural claim** (the object protected changed from "live host disk" to "disposable guest file") — the concrete QMP-`quit`/process-kill + prefix-deletion mechanism is unbuilt |
| The non-attestable posture for every Terem guest (§6) | **Real and structurally permanent**, mirrors Sloboda's honesty header; the host's own separate attestation story is unaffected |
| Data handling table (§7) | Grounded in the architecture's own claims (`01`); no code exists to verify against yet |
| §9's sandbox wrapper decision | **Open — Architect 2's primary deliverable**, not yet decided in this document |

*Design and scaffold only. UNAUDITED. Do not treat any schema, crossing, or
claim in this document as a security control. `signed ≠ attested`,
`built ≠ booted`, `verifiable ≠ verified`. Product name "Terem" is proposed
only, pending trademark clearance. Never "Postern Windows," "Postern
Ubuntu," or "Postern RedHat." BLCH is worthless and is not a security. Not
legal advice.*
