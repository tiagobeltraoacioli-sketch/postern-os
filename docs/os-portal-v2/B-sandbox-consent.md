<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Architect B — the sandbox trust boundary + consent/bridge security

**Role:** Architect B, OS Portal v2 ("run another OS in a sandbox" — Windows /
Ubuntu / RedHat in a container or VM on the Postern desktop; user brings their
own license; Wine/Proton covers the single-app case separately). **Status:
design / reference-prototype. UNAUDITED — certifies nothing.** This document
is my contribution to the lead's `docs/os-portal-v2/02-security-consent-privacy.md`;
it does not re-derive the product architecture (deployment shapes, UX, license
flow) — that is the lead's and other architects' job. It answers three
questions honestly: **what does the sandbox boundary actually guarantee, what
does every guest↔host bridge cost in consent, and what can this design
truthfully claim about attestation and guest privacy.**

Same discipline as every other design doc in this tree: `designed ≠ built`,
`written ≠ audited`, `verifiable ≠ verified`. Nothing here is a security
control until it is code, reviewed, and run.

> ## ⚠ HONESTY HEADER — read before trusting anything in this document
>
> - **The guest is the NON-ATTESTABLE tier, by construction, forever.** It runs
>   arbitrary user-supplied OS media (a Windows ISO, an Ubuntu/RedHat image the
>   user brings) inside a container or VM. `os_roothash` — Postern OS's own
>   measured-boot chain, if the host happens to be Postern OS — says **nothing**
>   about what runs inside the guest. **Not covered by the Postern Seal.** Never
>   will be, for any guest image a user supplies themselves.
> - **A Windows guest phones home to Microsoft. That is the guest's own
>   behavior, not Postern's.** Postern does not, and cannot, make a Windows or
>   RHEL guest private. Same posture as NoporIS's Google-Play persona:
>   **separation, not privacy**, extended to a new host shape.
> - **DRM and anti-cheat will detect the sandbox and may refuse to run** —
>   Widevine L1, Windows Defender System Guard, kernel-level anti-cheat
>   (Vanguard/EAC/BattlEye-class) all fingerprint the hypervisor (CPUID
>   hypervisor bit, MSR probes, timing side-channels) or a shared-kernel
>   container. **Not a bug we can fix** — the same honest limit Sloboda already
>   states for Waydroid/Play Integrity STRONG.
> - **Every guest↔host bridge is CLOSED by default and stays closed until an
>   explicit, disclosed, individually-revocable consent opens it.** No bridge
>   is ever silently on. "Every bridge is a hole you open on purpose."
> - **A container (shared-kernel) sandbox is a materially weaker boundary than
>   a VM (hypervisor-mediated) sandbox against a hostile guest**, and this
>   document says so plainly rather than letting "sandboxed" imply one uniform
>   guarantee — see §1.
> - **The coin is worthless. Personal use is free. This is not legal advice.**

---

## 0 · What "the sandbox" is, precisely (scope of this document)

Two backend shapes are in scope, and they are **not equivalent security
boundaries** — conflating them is the single biggest honesty risk in this
product, so this document treats them as two rows in every table below, never
as one undifferentiated "sandbox":

| Backend | What it is | Isolation primitive |
|---|---|---|
| **VM** | KVM-backed virtual machine (QEMU/KVM, driven directly over QMP — ~~or a libvirt-managed equivalent~~ **libvirt is out, full stop**, `LICENSE-DECISION.md` §1); the guest runs its own kernel | Hardware virtualization (VT-x/AMD-V), a hypervisor mediating all guest memory/device access |
| **Container** | `systemd-nspawn`-class OS container; the guest shares the **host's** kernel | Linux namespaces + cgroups (process/mount/network/PID isolation), no separate kernel |

Both are in scope for "run Windows/Ubuntu/RedHat in a sandbox," but only the
VM backend can run a **foreign kernel** (Windows, a different Linux build than
the host) — a container necessarily runs Linux under the host's own kernel, so
it is realistically the RedHat/Ubuntu path, never the Windows path. This split
is load-bearing for §1 and should be surfaced in the product's own UI/docs,
not just this design doc: **the backend picker is a security decision, not a
performance one.**

---

## 1 · The sandbox boundary — what KVM/VM and container isolation actually guarantee, and where each leaks

### 1.1 The core asymmetry (the honest headline)

> **A VM's isolation is enforced by hardware and a narrow hypervisor
> interface below the guest's own kernel. A container's isolation is enforced
> by the SAME kernel the guest's processes run on top of.** A VM escape
> requires exploiting the hypervisor or an emulated/virtio device — a
> deliberately narrow, audited surface. A container escape requires exploiting
> **any** namespace/cgroup/syscall bug in the host kernel the guest can reach
> — a surface orders of magnitude larger, because the guest's own untrusted
> code runs directly on that kernel. This is not a detail; it is the reason
> the two backends cannot share one "sandboxed" claim without a qualifier.

### 1.2 What each backend actually protects against

| | **VM (KVM)** | **Container (nspawn)** |
|---|---|---|
| **Guest memory** | Hardware-enforced (EPT/NPT second-level page tables); a guest process cannot address host memory at all, only what the hypervisor maps into the guest's own address space | Namespace-isolated view of `/proc`, PIDs, mounts — **not** memory-address isolation; a container process is a real process on the host, subject to the host kernel's own memory management |
| **Guest kernel** | The guest runs **its own kernel** (Windows NT kernel, a different Linux kernel) — a kernel bug in the guest OS stays inside the guest | The guest **is** the host kernel — there is no second kernel to contain a guest-kernel-class bug; the "guest kernel" and "host kernel" are literally the same binary |
| **Device access** | Only the (small, chosen) set of virtio/emulated devices the VMM exposes; everything else is simply absent from the guest's view | Everything the host kernel exposes through the namespace is reachable unless explicitly denied (seccomp/AppArmor/cgroup device allowlist do real work here, but they are a denylist/allowlist layered on top of a shared kernel, not an absence) |
| **Privilege-escalation blast radius** | A guest-root compromise stays guest-root; reaching the host requires a **hypervisor** escape (rare, but total when it happens — full host compromise) | A guest-root compromise is a short step from **host-root**: any of the many historical namespace/cgroup/`unshare`/overlayfs escape CVEs turns "root in the container" into "root on the host," because there was only ever one kernel |
| **Attack surface size** | The virtio/QEMU device-emulation surface (network, block, GPU if passed through, USB if passed through) — bounded, and this is exactly the surface SEV-SNP/TDX-class confidential-VM hardening exists to shrink further | The entire host kernel syscall surface reachable from an unprivileged (or, worse, misconfigured-privileged) namespace — historically the source of most container-escape CVEs |

### 1.3 Where each boundary leaks — stated plainly, not softened

- **VM leak #1 — the virtio/emulated device surface.** Every device the VMM
  exposes to the guest (virtio-net, virtio-blk, virtio-gpu, the emulated
  chipset) is code running with host privileges that parses guest-controlled
  input. Historical VM-escape CVEs (the VENOM floppy-controller bug, several
  virtio/QEMU device-emulation bugs) all live here. **Fewer, simpler devices
  exposed to the guest is strictly safer** — this is a design lever (§2), not
  just an implementation detail.
- **VM leak #2 — GPU passthrough widens the boundary categorically, not
  incrementally.** Passing a physical GPU through to the guest (for gaming,
  CAD, ML workloads) hands the guest **direct DMA-capable hardware access**,
  mediated only by the IOMMU (VT-d/AMD-Vi) grouping the platform firmware
  defines — not by the hypervisor's own logic. This is qualitatively
  different from a virtio device: the guest is no longer talking to
  hypervisor-mediated software, it is talking to real silicon that can issue
  DMA. An IOMMU group that is too coarse (a known firmware/motherboard
  problem, sometimes "solved" by risky ACS-override patches), a GPU firmware
  bug, or a malicious/compromised GPU driver inside the guest are all
  potential paths back to host memory. **GPU passthrough must be modeled as
  its own explicit, separately-consented, loudly-labeled escalation — never
  bundled into "enable sandbox."**
- **VM leak #3 — side-channels are not closed by virtualization at all.**
  Speculative-execution and cache-timing classes (Spectre/Meltdown-family)
  cross the VM boundary on shared physical cores; this document does not
  claim KVM isolation closes them, and neither should any product copy.
- **Container leak — the whole premise.** There is no "leak" distinct from
  the boundary itself: a container's isolation is namespace/cgroup policy
  enforced by the shared kernel, so **any kernel bug reachable from inside
  the container is, by definition, already inside the host's trust domain.**
  The honest framing is not "containers leak sometimes" — it is "a container
  is a resource-isolation and packaging boundary, not a security boundary
  against a kernel-privilege-escalation-capable adversary, full stop."

### 1.4 The recommendation this leads to (design guidance, not a promise)

- **Default the backend picker toward VM (KVM) for anything the user does not
  already fully trust** — a Windows ISO from an unverified source, a RedHat
  image the user did not build themselves. Position the container backend
  honestly as **"lightweight, for OSes you already trust; a shared-kernel
  boundary, not a hardened one"** — never as an equally-strong alternative to
  the VM path with a lighter footprint.
- **GPU passthrough and USB passthrough are the two levers that most widen
  the VM boundary** (§1.3, §2.4) — surface them as their own consent-gated,
  separately-labeled toggles, never folded into the base "start sandbox" flow.
- **Neither backend is claimed to survive a compromised host.** Exactly the
  same honest ceiling `docs/design/bridge-trust-boundaries.md` states for
  Porog/NoporIS/Waydroid: **a rooted or firmware-compromised host defeats
  every boundary in this document.** This design adds a boundary *around* the
  guest; it does not, and cannot, harden the host underneath it.

---

## 2 · The consent-gated bridge model — reusing the NoporIS crossing pattern

### 2.1 Why the NoporIS pattern is the right one to reuse, almost unchanged

`apps/noporis-bridge-glue` already solved the exact shape of problem this
sandbox has: **two personas of unequal trust, joined by named, individually-
revocable, fail-closed "crossings," where only the more-trusted side can mint
authorization.** The host desktop and the guest OS map onto that pattern
directly:

| NoporIS concept | Sandbox mapping |
|---|---|
| `Persona::Clean` (near, mints) | **The host** — the desktop shell / sandbox-gate daemon that owns the consent-authority key |
| `Persona::GooglePlay` (far, requests only) | **The guest** — Windows/Ubuntu/RedHat, or anything else the user boots |
| `ConsentRecord` / `ConsentAuthority` (`apps/noporis-bridge-glue/src/consent_record.rs`) | A **host-only-minted**, signed, time-boxed authorization for one bridge to cross in one direction |
| `ConsentRequest` (no signature, no way to add one) | What the guest side can produce: an *ask*, never a yes — e.g. "guest wants to read the host clipboard now" |
| `Capability` (`clipboard, files, mic, camera, location`) | Sandbox `Capability`: **`clipboard, files, network, usb, audio`** (§2.3) |
| `Direction` (`from → to`, cryptographically pinned) | **`host → guest`** vs **`guest → host`**, pinned per record — a clipboard grant `host→guest` (paste into the guest) never authorizes `guest→host` (the guest reading the host clipboard) |
| `ConsentLedger` + four revocation paths | Reused verbatim: explicit per-record revoke, close-a-capability-lane, kill-switch (`revoke_all`), passive time-box expiry |
| `GateConsent` deny-by-default seam (`apps/noporis-bridge-glue/src/consent.rs`) | The sandbox-gate's own decision authority — reusing the seam, never the `ReferenceGate` stand-in, on a real build |
| `AuditTrail` (`apps/noporis-bridge-glue/src/audit.rs`) | Same idiom: **size + SHA-256 digest, never the bytes**, hash-chained, `fsync`'d, local-only, never telemetry |

One structural simplification versus NoporIS: NoporIS's two personas live on
**one physical device joined by a network pairing channel** (ML-KEM-1024‖X25519,
SAS-anchored), so it needs a `Channel`/`Transport` to carry a sealed crossing
between them. The sandbox's host and guest are **co-resident on one machine**
— the consent authority and its signing key live entirely on the host side
(inside the sandbox-gate daemon or the hypervisor's own host-side agent
process), and the guest never holds, and never can reach, that key. This
removes the need for a pairing/transport layer but keeps every other rail:
**only the host mints; the guest only ever asks.**

### 2.2 The state-file contract — reusing the consent spine, adding a fourth tier

`apps/consent-contract/CONTRACT.md` already formalizes ONE spine shared by
Waydroid/NoporIS/Porog (`schema`, `version`, `tier`, `consent`, `killSwitch`,
one capability object, one pinned tier rail). This sandbox is a **fourth
tier** on the same spine, not a new contract:

```jsonc
{
  "schema":  "postern.sandbox-gate.state",
  "version": 1,
  "tier":    "non-attestable",              // pinned, never from input
  "lang":    "pt-BR" | "en",
  "consent":    { "accepted": false, "scope": "session"|"persistent", "acceptedAtIso": null },
  "killSwitch": { "engaged": false, "engagedAtIso": null },

  "backend": "vm" | "container",            // which boundary is actually in force —
                                             // read-only to the UI, never a capability
                                             // the guest or a crossing can change

  "bridges": {
    "clipboard":   { "hostToGuest": false, "guestToHost": false },
    "files":       { "hostToGuest": false, "guestToHost": false },   // one host-side shared folder, path-scoped
    "audio":       { "hostToGuest": false, "guestToHost": false },   // playback vs mic, independently gated
    "usb":         { "devices": [] },                                // per-device allowlist: vendor:product + serial, never "all USB"
    "network":     { "mode": "isolated" }                             // "isolated" (NAT, no LAN reachability) | "bridged" (host LAN) — bridged is the consent-gated escalation
  },

  "widen": {
    "gpuPassthrough": false                  // its own top-level rail, never folded into "bridges" —
                                              // see §1.3/§2.4: this widens the BOUNDARY, it does not
                                              // cross DATA across it, so it does not fit the
                                              // crossing/bridge shape at all
  }
}
```

Rails carried over unchanged from the contract (`CONTRACT.md` §"Seven rails"):
schema discriminator, pinned `tier`/`version`, deny-by-default capabilities
(`asBool`: anything not exactly `true`/an explicit open object is closed),
`normalize()` as the trust boundary (malformed/partial/hostile input collapses
to full-deny, never throws), non-destructive kill-switch, fail-closed
decisions, zero telemetry.

### 2.3 The five bridges — each modeled as its own crossing

Each bridge is **deny-by-default, per-direction, individually revocable**,
exactly like NoporIS's five capabilities. None is a blanket "give the guest
access to the host":

- **Clipboard** — `hostToGuest` (paste something typed on the host into the
  guest) and `guestToHost` (copy something from the guest back to the host)
  are independent grants. A grant for one direction never authorizes the
  other — this is the same cryptographic pinning `ConsentRecord::Direction`
  already enforces, and it matters here specifically because **shared-
  clipboard features have a real CVE history** in other hypervisor products
  (VMware/VirtualBox drag-and-drop and clipboard-sync features have shipped
  guest-to-host escape bugs). Default: both directions closed.
- **Files** — a single host-side folder, explicitly path-scoped (never the
  whole host filesystem), shared read-only or read-write per direction.
  Mirrors Sloboda/NoporIS's `files` capability one-for-one. A file crossing
  is the most dangerous ingest direction (`guestToHost`, i.e. a guest binary
  landing on host storage) — treat it at the higher `ExplicitReview`
  consequence tier NoporIS already reserves for its ambient-sensor
  capabilities (`Capability::tier()` in `apps/noporis-bridge-glue/src/capability.rs`),
  never the low-friction `SingleTap` tier clipboard gets.
- **Audio** — playback (`hostToGuest`, the guest's sound reaches host
  speakers) and capture (`guestToHost`, the guest reads a host microphone)
  are independent grants, same asymmetry as NoporIS's `mic`/`camera` sitting
  at the highest consequence tier: **microphone capture into an
  arbitrary user-supplied guest OS is exactly the "continuous, ambient sensor
  stream" case that must never be a silent default.**
- **USB / devices** — modeled on Porog's `connectedApp` shape
  (`crossingDirectional` with a `package` allowlist, `apps/consent-contract/consent-spine.schema.json`
  §`porogState`), adapted to hardware: **one device at a time, named by
  vendor:product ID + serial, never "pass through all USB."** Passing a USB
  device into a VM hands the guest that device's full command surface
  (firmware update paths on some devices, DMA on Thunderbolt-class
  peripherals) — treat each grant as its own record, individually revocable,
  never a wildcard.
- **Network** — not a per-event crossing like the other four; it is a
  **standing rail**, closer to Sloboda's `egress.torOnly` tier rail than to a
  capability toggle. Default `isolated` (NAT-only; the guest can reach the
  internet like any VM, but cannot see or be seen by the host's LAN). The
  consent-gated escalation is **`bridged`** — putting the guest directly on
  the host's network, discoverable and reachable by other LAN hosts. This
  needs a single explicit, disclosed toggle of its own, labeled honestly:
  bridged networking is not a "guest↔host" bridge in the clipboard/files
  sense, it is a "guest↔the user's whole LAN" widening, and the consent
  copy must say that, not just "allow networking."

### 2.4 The one thing that is NOT a bridge: GPU (and other) passthrough

§1.3 already establishes why GPU passthrough is categorically different from
the five bridges above: **a bridge moves data across an otherwise-closed
boundary; passthrough widens the boundary itself**, handing the guest direct,
DMA-capable hardware access mediated only by IOMMU grouping. It still needs
consent — arguably stronger consent, at NoporIS's `ExplicitReview` tier or
above — but it must be modeled and labeled as its own `widen.*` rail, never
listed alongside "clipboard" and "files" as if it were one more bridge of the
same kind. The honest copy: **"this does not share data with the guest — it
gives the guest direct access to a physical device, subject only to your
motherboard's IOMMU grouping."**

### 2.5 What "only the host mints" buys, concretely

Because the guest never holds signing key material (it has no path to the
host's consent-authority key — the guest is, by construction, just a VM/
container with no privileged access to the host process holding that key),
a compromised or malicious guest **cannot forge its own bridge grants**. It
can *request* loudly (spam the consent UI, attempt social-engineering copy
inside itself), exactly like NoporIS's `ConsentRequest` — "an ask, never a
yes" — but every actual crossing still runs the same 5-step fail-closed check
(`ConsentRecord::check`: signature → session/instance binding → direction →
capability → time-box) before anything moves. **This is the load-bearing
honesty claim of this whole section: the guest asks, only the host can ever
say yes, and yes is cryptographically pinned to one direction, one capability,
one instance, one expiry.**

---

## 3 · Honest attestation posture — mirroring Sloboda exactly

This section exists because §1 and §2 could be read as implying the sandbox
is "secure" in some absolute sense. It is not, and this section is where that
gets said plainly, in the same words the rest of the fleet already commits to.

- **The guest is NON-ATTESTABLE. Full stop, no path to change it.** Unlike
  Porog (which legitimately says "key-attested device") or Postern OS
  (measured-boot, `os_roothash`), the sandbox's guest is **arbitrary
  user-supplied media** — a Windows ISO, a RedHat image, whatever the user
  points the installer at. There is no manifest Postern controls, no digest
  Postern pins, no boot chain Postern measures **inside the guest**. Even if
  the host itself is Postern OS with a valid `os_roothash`, that hash
  attests the host's own measured-boot chain — it says **nothing** about
  what the guest, once booted inside the sandbox, is actually running. This
  is the direct analogue of Sloboda's own honesty header ("the Android image
  is mutable state pulled at `waydroid init`; `os_roothash` says nothing
  about what runs inside Waydroid") — restated here for a VM/container guest
  instead of an LXC Android userland. **"Entering the sandbox" is this
  product's version of "entering Android = data leaves the sealed base."**
- **`tier` is pinned `"non-attestable"` in the state schema (§2.2), exactly
  like Sloboda's and NoporIS's `tier` field** — never read from input, never
  relabeled by any code path, checked by the same class of tripwire
  `docs/design/bridge-trust-boundaries.md §5` already runs
  (`scripts/check-trust-labels.sh`) against Waydroid/NoporIS surfaces. This
  document's own recommendation to the lead: extend that script's
  `NONATTEST_PATHS` to whatever directory ships this sandbox's gate/wrapper
  code, the same way Waydroid is covered today.
- **DRM and anti-cheat detecting the sandbox is not a bug, it is the guest's
  own vendor doing exactly what it is designed to do.** Widevine L1, Windows
  Defender System Guard, and kernel-level anti-cheat all actively fingerprint
  virtualization (the CPUID hypervisor-present bit, timing side-channels,
  MSR probes) or a shared-kernel container's cgroup/namespace fingerprint,
  and are entitled to refuse to run. **Not a bug we can fix** — verbatim the
  same honest sentence Sloboda's README already uses for Play Integrity
  STRONG, extended here to the desktop DRM/anti-cheat case. Product copy
  must say this plainly rather than imply the sandbox is "invisible" to the
  guest.
- **A Windows guest phones home to Microsoft. A RedHat guest phones home to
  Red Hat's entitlement servers. This is the guest's own networking, its own
  vendor relationship, entirely outside Postern's control** — see §4.
- **No claim of "attested," "hardware-backed," "tamper-proof," or
  "Seal-covered" may ever attach to the guest**, on any surface: UI copy,
  marketing, this doc's own future revisions. Where attestation is named at
  all on a sandbox surface, it must be to **deny** it, adjacent in the same
  sentence — the exact NEGATION/CONTRAST discipline
  `docs/design/bridge-trust-boundaries.md §2.1` already specifies for
  Waydroid and NoporIS.
- **Contrast anchor, stated once more for clarity:** if the *host* happens to
  be Postern OS, the host's own `os_roothash`/measured-boot chain is a real,
  separate claim about the host's own boot integrity — and it still says
  nothing about the guest. The sandbox does not inherit the host's
  attestation, and the host's attestation does not extend into the sandbox.
  These are two separate stories that must never be allowed to blur into one
  another in any copy this product ships.

---

## 4 · Guest privacy — what the guest leaks is the guest's own behavior, stated plainly

This section deliberately does not soften anything, because "sandboxed"
invites exactly the misreading this section exists to prevent: **a sandbox
boundary controls what crosses between host and guest (§2); it does not, and
cannot, control what the guest itself does on its own network connection.**

- **Windows telemetry is Microsoft's, not Postern's, to disable, redact, or
  attest.** Whatever a stock Windows install phones home about — hardware
  inventory, usage telemetry, Defender cloud lookups, activation checks — it
  does exactly that from inside the sandbox, over whatever network path the
  guest has (§2.3's `network` rail controls LAN *reachability*, not whether
  the guest can reach the internet at all — a VM with `isolated`/NAT
  networking still reaches the open internet by default, same as any
  ordinary VM). Postern is not in that data path, has no visibility into it,
  and makes no claim to reduce it. This mirrors, word for word, the standing
  posture already committed to for NoporIS's Google-Play persona: **the
  guest is the less-private side, by construction**, and running it in a
  sandbox does not change that — it only changes what the *host* is exposed
  to (§1), never what the *guest's own vendor* sees.
- **Vendor activation is the same story.** A Windows product key or a RHEL
  subscription entitlement crosses from the user, through whatever install
  flow the lead's architecture defines, to Microsoft's/Red Hat's own
  activation service — outside Postern's trust boundary entirely, the same
  posture `docs/os-portal/02-security-privacy.md §6` already states for v1's
  install-agent product ("activation/entitlement servers are entirely
  outside Postern's trust boundary … Postern cannot grant, audit, or see
  what \[the vendor's] activation service does with it").
- **What Postern's design *does* legitimately claim, and only this:** the
  bridges in §2 are closed by default, individually consented, and audited
  (size+digest, never content) on the host side. That is a real, checkable
  claim about the **host↔guest boundary**. It is not, and must never be
  marketed as, a claim about what the guest does on its own with its own
  network connection, its own OS vendor relationship, or its own telemetry
  stack. **Do not let "your sandbox is consent-gated" imply "your Windows
  guest is private." It is not, and cannot be made so by this design.**
- **The one thing this design *can* honestly reduce:** with `network.mode =
  "isolated"` (§2.3 default) the guest cannot passively enumerate or be
  reached by other devices on the user's LAN, and with every bridge closed,
  nothing the guest observes (clipboard, files, audio, USB) reaches the
  host. That is real containment of **host-ward** leakage. It says nothing
  about the guest's own outbound telemetry to its own vendor, and this
  document refuses to let that distinction blur.

---

## 5 · Threat model — guest-escape, a malicious guest image, and the bridges as attack surface

| Adversary / scenario | What it can do | What it cannot do (given the design in §1–§2) | Primary mitigation |
|---|---|---|---|
| **A malicious or compromised guest OS image** (pirated/tampered Windows ISO, a backdoored community Linux build the user installed) | Run arbitrary code as guest-root/Administrator; attempt every bridge request it can construct (`ConsentRequest`-shaped asks, §2.5); attempt to fingerprint or evade the sandbox; attempt to exploit any exposed virtio/emulated device or, on a container, any host-kernel syscall reachable from its namespace | **Cannot forge a bridge grant** — no signing key, only asks (§2.5); cannot reach a bridge that was never opened (default-closed, §2); cannot cross the VM boundary without a hypervisor/device-emulation bug (§1.3) — a materially higher bar than crossing the container boundary, which has none of its own | Deny-by-default bridges (§2), the host-only mint rule (§2.1/§2.5), defaulting risky guests to the VM backend (§1.4) |
| **VM escape** (a bug in QEMU/KVM's device emulation, virtio surface, or a GPU-passthrough path) | If successful: **full host compromise** — this is not softened; a real hypervisor escape is total, the same honesty NoporIS/Porog already apply to "a rooted host defeats everything" | Cannot be prevented by this design; can only be made **less likely** by minimizing the exposed device surface (fewer virtio devices, no passthrough unless explicitly widened per §2.4) and **less silent** (the audit trail, §2.1, records every crossing decision even though it cannot detect a hypervisor-level escape by itself) | Minimal device surface by default; GPU/USB passthrough gated as an explicit widening, never default-on; keeping the host patched is outside this document's scope but is the actual first line of defense |
| **Container escape** (any of the historical namespace/cgroup/overlayfs-class host-kernel CVEs) | Same end state as a VM escape — full host compromise — but reachable through a **much larger** surface (§1.2–§1.3): the entire host kernel syscall surface, not a narrow device-emulation layer | Cannot be prevented by this design at all; the container backend structurally has no hypervisor layer to contain the bug in the first place | Recommend the VM backend for any guest the user does not already fully trust (§1.4); the container backend must never be marketed with the same isolation strength as the VM backend |
| **The bridges themselves, as an attack surface** (a malicious guest abusing an *open* clipboard/file/audio/USB bridge the user did consent to) | Once a bridge is legitimately open, use it for its intended purpose in a hostile way — e.g., a guest-to-host file share the user opened for convenience becomes the guest's exfiltration/drop path for a malicious binary; a `guestToHost` clipboard grant becomes a vector for a crafted clipboard payload targeting a host application's clipboard-parsing bug | Cannot exceed the **specific direction and capability** it was granted (Direction is cryptographically pinned, §2.1); cannot make the grant persistent beyond its scope/expiry (time-boxed, §2.1); cannot silently re-open a bridge the user revoked (monotonic revocation, four independent paths, §2.1) | Per-direction, per-capability, time-boxed grants; the `files`/`audio`-capture bridges pinned at the higher `ExplicitReview` consequence tier (§2.3) so they are never a muscle-memory tap |
| **GPU/USB passthrough specifically** (§1.3, §2.4) | A malicious guest driver or compromised device firmware attempts DMA against host memory outside its IOMMU group, or a passed-through USB device's own firmware update path is abused | Cannot be prevented by this design — the boundary here is the platform's IOMMU grouping, a hardware/firmware property this design does not control and does not claim to harden | Model passthrough as its own loudly-labeled `widen.*` rail (§2.4), never bundled with the ordinary bridges; document that IOMMU grouping quality varies by motherboard and is the user's own hardware's problem, not something Postern's consent gate can strengthen |
| **A compromised host** (the machine running the sandbox is itself already rooted/firmware-compromised) | Everything — read/write guest memory directly, forge its own "host-side" consent records since it *is* the host, defeat every boundary in this document | Nothing is claimed to survive this — **the same honest ceiling every other Postern bridge product states**: a rooted or firmware-compromised host defeats the boundary. This design protects the host from a hostile *guest*; it says nothing about protecting a user from their own already-compromised host | Not solved here; out of scope by design, same as `docs/os-portal/02-security-privacy.md §1.6` and `docs/design/bridge-trust-boundaries.md` |

---

## 6 · Cross-reference — what this document reuses, verbatim vs. adapted

| Reused from | Verbatim | Adapted |
|---|---|---|
| `apps/noporis-bridge-glue/src/consent_record.rs` | The 5-step fail-closed check (signature → session/instance → direction → capability → time-box); the 4 revocation paths; "only the near side mints, the far side only asks" | `SessionId`/pairing-channel binding is unneeded (host+guest are co-resident, no network pairing) — replaced by a host-local instance binding |
| `apps/noporis-bridge-glue/src/capability.rs` | The deny-by-default `Capability` enum shape + derived (never requester-set) consequence tier | Five capabilities renamed for the desktop case: `clipboard, files, network, usb, audio` (vs. NoporIS's `clipboard, files, mic, camera, location`) |
| `apps/noporis-bridge-glue/src/audit.rs` | Hash-chained, `fsync`'d, append-only trail; size+SHA-256 digest, never payload bytes; local-only, never telemetry | Event/record field names adapted to bridge crossings instead of NoporIS crossings |
| `apps/consent-contract/CONTRACT.md` + `consent-spine.schema.json` | The shared spine (`schema`/`version`/`tier`/`consent`/`killSwitch`), the seven enforced rails, the canonical-file + projection-file split | A fourth tier (`postern.sandbox-gate.state`) added to the `oneOf`; a new `backend` field (read-only) and `widen.*` rail (GPU passthrough) with no NoporIS/Porog/Waydroid analogue |
| `apps/sloboda/README.md` honesty header | The exact phrasing pattern: non-attestable / not covered by the Seal / "not a bug we can fix" / default-safe / UNTESTED-where-applicable | Applied to a VM/container guest instead of a Waydroid LXC Android userland |
| `docs/design/bridge-trust-boundaries.md` | The NEGATION/CONTRAST labeling discipline; "a rooted host defeats every boundary here"; the qualifier-companion rule shape | Recommends extending `NONATTEST_PATHS` / a future `QUALIFIED_PATHS`-style check to cover this sandbox's shipped surfaces once they exist |
| `docs/os-portal/02-security-privacy.md` | The "verify before you consent," least-privilege consent-record pattern, and the honesty-ledger closing-table format this document mirrors | Applied to guest↔host bridges instead of install-agent privileged verbs; this product has no equivalent to that document's Planner/Executor split |

---

## 7 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| VM isolation is hardware-mediated and structurally stronger than a shared-kernel container against a hostile guest (§1) | **Real, well-established property** of KVM/hypervisor vs. namespace isolation; not new engineering, just stated plainly instead of glossed over |
| GPU/USB passthrough categorically widens the boundary rather than crossing data across it (§1.3, §2.4) | **Real property** of IOMMU-mediated device passthrough; the `widen.*` schema shape modeling it separately from `bridges.*` is **[SPECULATIVE / NEW]** |
| The sandbox `Capability`/`Direction`/`ConsentRecord`/`ConsentLedger` reuse (§2.1–2.2) | **Directly reuses** `apps/noporis-bridge-glue`'s real, tested consent-record and ledger code/pattern; the host-co-resident simplification (no pairing channel) and the five-bridge capability set are **[SPECULATIVE / NEW]** |
| The `postern.sandbox-gate.state` schema (§2.2) | **[SPECULATIVE / NEW]** — follows the real, tested `consent-spine` contract pattern (`apps/consent-contract`) byte-for-byte in spine shape; the sandbox-specific fields (`backend`, `bridges.*.hostToGuest/guestToHost`, `widen.gpuPassthrough`) are new and unbuilt |
| "Only the host mints, the guest only asks" (§2.5) | **Directly reuses** the real, tested `ConsentAuthority`/`ConsentRequest` type-level guarantee (`consent_record.rs`'s own canary test: `ConsentRequest` carries no signature field by construction) |
| The non-attestable posture and its phrasing (§3) | **Directly mirrors** Sloboda's and NoporIS's real, shipped honesty headers and the `tier` pinning already enforced in code (`gate-store.mjs`'s `defaultState()`, `consent-spine.mjs`'s `normalize()`) |
| The guest-privacy honesty claims (§4) | **Directly mirrors** NoporIS's real, shipped "separation, not privacy" posture and `docs/os-portal/02-security-privacy.md`'s real "activation servers are outside the trust boundary" claim, applied to a new host shape |
| The threat-model table (§5) | Grounded in real, cited primitives for the mitigation column (consent-record pinning, IOMMU grouping, namespace/cgroup mechanics); the adversary-capability analysis is this document's own |
| Any claim that this design has been built, tested, or run | **None made.** Nothing in this document exists as code. `designed ≠ built`, `written ≠ audited`, `verifiable ≠ verified` apply in full |

---

## 8 · Open questions for the lead / other architects

- **Where does the host-side consent-authority key actually live?** (the
  sandbox-gate daemon's own process, a per-user keyring, something tied to
  the host's own attested identity if the host is Postern OS) — this
  document assumes "somewhere the guest cannot reach," which is necessary
  but not sufficient; the exact custody model is the lead's call.
- **Does the license-gating flow (user brings own Windows/RHEL license) ever
  need to see anything from inside the guest**, and if so, does that path
  reuse this document's bridge model or bypass it entirely (e.g., activation
  happening natively inside the guest over its own network, per §4, with no
  Postern-mediated crossing at all)? This document assumes the latter and
  states it as the honest default (§4) — worth the lead confirming it stays
  that way.
- **Does Wine/Proton (the single-app path, no full guest OS) need its own,
  lighter consent model**, or does it sit entirely outside this document's
  scope because there is no separate kernel/namespace boundary to consent
  across in the first place? This document has treated Wine/Proton as
  out-of-scope (it is host-process-level compatibility, not a sandboxed
  guest OS) — flagging that assumption explicitly for the lead to confirm or
  correct.
- **Should `check-trust-labels.sh`-class tripwire coverage (§3, §6) be
  extended before or after the first line of sandbox-gate code ships?** This
  document recommends before, mirroring how Waydroid's coverage predates any
  real on-device boot.

---

*Design and scaffold only. UNAUDITED. Do not treat any schema, state shape, or
claim in this document as a security control. `signed ≠ attested`, `built ≠
booted`, `designed ≠ built`, `verifiable ≠ verified`. Product name(s) pending
trademark clearance where applicable. Never "Postern Windows," "Postern
Ubuntu," or "Postern RedHat" — the guest OS is the vendor's, always. BLCH is
worthless and is not a security. Personal use is free. Not legal advice.*
