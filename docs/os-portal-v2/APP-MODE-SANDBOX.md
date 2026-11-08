<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Copyright (c) Postern Labs and Postern community contributors -->

# Terem App Mode — the sandbox wrapper decision, resolved

**Status: DESIGN DECISION + reference POC. UNAUDITED — certifies nothing.**
This closes `02-security-consent-privacy.md` §9.1 — Architect 2's own
"largest unresolved item," larger than any individual crossing schema
question in that document — and the identical open item restated in
`01-architecture.md` §3.2's `[ARCHITECT-1 STUB]` and `01` §7 item 3
("App Mode sandboxing default … Partially answered … leaves the final pick
**open**"). It does not re-derive App Mode's architecture (`01` §3) or the
`terem-gate` consent spine (`02` §3) — it picks the concrete wrapper, states
the mandatory-default call, specifies the exact confinement, and ships a
runnable proof-of-concept. Same discipline as every document in this tree:
`written ≠ built`, `built ≠ booted`, `designed ≠ audited`,
`verifiable ≠ verified`.

> **The one sentence this document exists to keep honest, restated from
> `02` §2.2 and `01` §3.2 and never softened below:** *App Mode has no
> hardware isolation boundary. Guest Mode's KVM guest and App Mode's
> sandboxed Wine process are not the same strength of "isolated," and no
> copy on any surface may imply otherwise.* Everything in this document
> narrows that gap with a namespace jail; nothing in it closes it.

---

## 0 · What this document decides, in one table

| Question (`02` §9.1) | Decision |
|---|---|
| Bubblewrap vs. Flatpak-portal vs. `firejail`? | **Bubblewrap (`bwrap`), invoked directly by Terem's own Tauri backend.** §1. |
| Mandatory or operator-disable-able? | **Mandatory.** No code path in Terem ever spawns `wine`/`wine64` outside `bwrap`. §2. |
| Default filesystem allowlist? | Empty-by-construction mount namespace; only the `WINEPREFIX` (read-write) plus a minimal read-only system base (`/usr`, `/bin`, `/lib`, `/lib64`, `/sbin` where present) are visible. No `$HOME`, no other user data. §3.1. |
| Default network policy? | **Off** (`--unshare-net` — a real emptied network namespace, not a firewall rule). Same-shape, per-app consent exception as the `sharedFolder`/`network` crossings `02` §3 already specifies. §3.2. |
| Same `terem-gate` schema, or a separate one? | The App Mode variant `02` §3's own `[ARCHITECT-2 STUB]` §3.2 asked for — sketched in §5 below, not a new contract. |

---

## 1 · Wrapper choice — Bubblewrap, and why not the alternatives

### 1.1 The three candidates `02` §9.1 named, compared honestly

| Candidate | What it is | Isolation primitive | Why it's in/out |
|---|---|---|---|
| **Bubblewrap (`bwrap`)** | A small, purpose-built CLI for constructing a Linux namespace sandbox (mount, user, pid, ipc, uts, net, cgroup namespaces) around one child process | Kernel namespaces, unprivileged by default on kernels with unprivileged user namespaces enabled (falls back to a setuid-root helper path where they're disabled — §1.4) | **CHOSEN.** It is the actual mechanism Flatpak uses under the hood, and this document's own `01`/`02` already cite "Valve ships Proton apps inside a Flatpak/Steam sandbox" as the ecosystem precedent — `bwrap` is that mechanism's load-bearing primitive, at the Steam-Deck-scale-proven layer, without the packaging format on top (§1.2). |
| **`firejail`** | A SUID-root(-by-default) sandboxing tool with its own profile-language ecosystem (per-app `.profile` files, e.g. `firefox.profile`) | Kernel namespaces + seccomp-bpf, applied by a setuid-root binary that parses a large, historically security-relevant profile-parsing surface | **Rejected as the default.** Structurally the wrong shape for this repo's own stated design lever (`B-sandbox-consent.md` §1.3: "fewer, simpler devices exposed … is strictly safer" — the same reasoning extends to fewer, simpler privileged code paths). `firejail`'s default install is a **setuid-root binary with a large, historically leaky profile-parsing attack surface** (its own project history includes multiple real sandbox-escape and privilege-escalation reports tied to profile handling and to the SUID design itself) — a materially bigger, more historically troubled trusted-code surface than `bwrap`'s single-purpose namespace-construction tool. `firejail`'s own upstream has moved toward recommending the non-SUID (`no-root`) build precisely because of this history, which quietly concedes the point. Not rejected because it "doesn't work" — real products ship it — rejected because Postern's own discipline elsewhere in this document family (no libvirt, no Distrobox, no SPICE — "skip the bigger/leakier abstraction, drive the narrow primitive directly," `01` §2.1) applies here identically. |
| **Flatpak-portal (`xdg-desktop-portal` + `flatpak-portal` D-Bus service)** | The full Flatpak sandboxing stack: apps are packaged as Flatpaks, sandboxed via `bwrap` internally, and mediated at runtime by a **system D-Bus portal service** for file access, printing, etc. | `bwrap` (same primitive as above) plus a portal/broker layer | **Rejected as unnecessary layering, not as unsafe.** Terem does not distribute App Mode apps as Flatpaks — there is no `.flatpakref`, no OSTree repo, no reason to adopt Flatpak's packaging format just to reach its sandboxing primitive. Terem's own Tauri backend, talking to the `terem-gate` consent spine (`02` §3), already plays the exact role `xdg-desktop-portal` plays for a real Flatpak app: the trusted broker that decides what crosses the boundary. Standing up a second broker (a D-Bus system service, `flatpak-portal`, `xdg-desktop-portal` and its per-desktop-environment backend) to mediate grants Terem's own consent-spine already mediates would duplicate a trust boundary this repo has already built (`apps/consent-contract`), not add one. Drive `bwrap` directly, the same "no extra daemon in the loop" call already made for QEMU-over-QMP instead of libvirt (`01` §2.1). |
| **Landlock LSM (kernel ≥5.13, unprivileged filesystem-scoping syscalls)** | A kernel API for a process to restrict its **own** filesystem access, no namespaces, no privilege needed at all | In-kernel LSM ruleset, applied via `landlock_create_ruleset`/`landlock_add_rule`/`landlock_restrict_self` | **Not the primary mechanism — noted as defense-in-depth, §1.5.** Landlock alone gives filesystem scoping but no network isolation, no PID/IPC/UTS isolation, and no equivalent of `--unshare-net`'s network-namespace containment — it answers a narrower question than App Mode's threat model needs answered (`02` §2.2: filesystem **and** network, not filesystem alone). Genuinely useful layered under `bwrap` (§1.5), not a substitute for it. |

### 1.2 Bubblewrap's license, and why it gets the same treatment as Wine/QEMU

Bubblewrap is licensed **LGPL-2.1-or-later** (per its upstream `COPYING`,
`containers/bubblewrap`) — the identical license class already navigated in
this document family for Wine and QEMU. `LICENSE-DECISION.md` §1/§2 already
resolved the general shape of this question: **QEMU (GPL-2.0) and Wine
(LGPL-2.1) are not bundled into Postern's default, attested closure; they
are opt-in, operator-toggled Nix modules that pull the binary from nixpkgs
under the operator's own explicit action, invoked by Terem's Tauri backend
as an external, unforked process — never linked, never a `libwine`/`libvirt`-
class dependency.** `bwrap` is the same shape exactly: a standalone CLI
binary, invoked by `exec`, its own process, its exit status read the same
way `resolve_node_binary`'s callers already read `bloch`'s. It joins the
same `postern.terem.enableAppMode` opt-in toggle already proposed for Wine
(`LICENSE-DECISION.md` §2) — flipping that toggle pulls **both** `wine` and
`bwrap` into the operator's own rebuilt closure, never into the default
image. `os_roothash` for a machine that never enabled App Mode says nothing
about either binary, exactly as `LICENSE-DECISION.md` §2 already commits to
for Wine alone. **This is this document's own honest, non-legal-advice
application of the existing rule, flagged for the same license-counsel pass
`LICENSE-DECISION.md`'s own footer already asks for before anything ships** —
not a new legal opinion, the same one extended one component further.

### 1.3 Why `bwrap` over `firejail`, stated as a design lever, not a vibe

Both tools are real, both are used in production by serious projects. The
reason to pick one as *this repo's* default is the same lever
`B-sandbox-consent.md` §1.3 already names for VM device surfaces, restated
for App Mode's namespace surface: **a narrower, single-purpose, already-
massively-production-proven trusted binary is a smaller attack surface than
a broader one with a history of exactly the class of bug this document is
trying to prevent (sandbox escape via the wrapper's own privileged code, not
via the sandboxed app).** `bwrap`'s job is one thing — construct a namespace
sandbox from an explicit argument list and `exec` into it — with no profile
language to parse, no separate configuration format, no persistent daemon.
Every confinement decision in this document is visible in the argument list
in §4's script; nothing is hidden in a profile file `bwrap` interprets on
its own.

### 1.4 The unprivileged-user-namespace caveat, stated honestly

`bwrap` needs **either** unprivileged user namespaces enabled on the kernel
(`kernel.unprivileged_userns_clone=1` on Debian-family kernels; on by
default on most current distributions, including NixOS) **or** a
setuid-root `bwrap` binary as a fallback (the historical default on some
distributions before unprivileged user namespaces were widely enabled).
**This is a real, host-dependent variance this document does not paper
over:** on a hardened kernel with unprivileged user namespaces disabled and
no setuid `bwrap` installed, App Mode simply cannot launch — which, given
§2's mandatory-default decision, is the **correct, honest failure mode**
(no wrapper, no launch — never "no wrapper, launch anyway"). `os/terem-
compat.nix`'s eventual App Mode module (unbuilt — `01` §2.7, `[ARCHITECT-1
STUB]`) should assert unprivileged user namespaces are enabled (or provision
the setuid fallback deliberately) as part of enabling
`postern.terem.enableAppMode`, not leave it to chance. `--cap-drop ALL` in
§4's script matters specifically in the setuid-fallback case — under the
unprivileged-userns path there are no host capabilities to drop in the new
user namespace in the first place, so the flag is a no-op there and
load-bearing in the fallback path; included unconditionally because it is
correct and harmless in both.

### 1.5 Follow-on hardening this POC does not build — named, not hidden

- **Seccomp-BPF filtering** (`bwrap --seccomp FD`, passing a pre-compiled
  BPF program over a file descriptor). Real, supported by `bwrap`, **not
  built in this POC.** Generating a correct seccomp allowlist for Wine's own
  syscall footprint (which is large and version-dependent — Wine emulates a
  full Win32 kernel surface in userspace) is a nontrivial follow-on project
  in its own right, the same honest "flagged, not built" treatment this
  document family gives every other deferred hardening layer (`01` §2.5's
  VFIO gating, `02` §9.2's audit-trail schema). Flatpak itself layers
  seccomp on top of `bwrap` via a separate helper for exactly this reason —
  the two are complementary, not the same step.
- **Landlock, layered under `bwrap`** (§1.1) as defense-in-depth against a
  future namespace-escape-class bug in `bwrap`/the kernel's own namespace
  code — genuinely valuable, genuinely not required to ship a first working
  App Mode sandbox, noted here as a real open item rather than invented as
  already-decided.
- **A per-app manifest / capability declaration** (what a given `.exe`
  is allowed to ask for — network, a specific shared folder) is sketched in
  §5 as a schema shape, not implemented as code here.

---

## 2 · Mandatory default-on — the decision, and why

**Decision: mandatory.** There is no Terem code path, in this design, that
ever spawns `wine`/`wine64` without `bwrap` wrapping it. This resolves `02`
§9.1's explicit open question ("mandatory … or operator-disable-able") in
the direction `02` §2.2 already leaned but left unresolved: *"this document
takes the position that App Mode's sandbox wrapper should default **on**,
with the operator able to grant a specific app broader filesystem access as
an explicit, disclosed exception — never the reverse."* This document goes
one step further than "default on": **on, with no off switch**, for these
reasons:

1. **`02` §2.2 already names the exact failure mode a disable-able wrapper
   invites**: "default-open with an opt-in jail would repeat the exact
   'convenient but not honest' mistake v1 §0 rejected." An operator-visible
   *toggle* that can be switched off is functionally default-open the
   moment any operator (or any install script, or any future engineer
   under deadline pressure) flips it "just this once" — the entire honesty
   ledger discipline this repo runs on exists because "just this once"
   toggles are exactly how a fleet-wide invariant quietly stops being true.
2. **App Mode is `01` §4's *recommended-first* path** ("run this one
   Windows program" → App Mode, fall back to Guest Mode only if Wine
   fails). A recommended-first, no-guest-kernel, no-hypervisor path that
   ships with *optional* isolation is the single likeliest surface in this
   whole product family to get flattened into "Terem sandboxes foreign
   software" marketing copy that is false for the disabled case — the exact
   risk `02` §2.2 names by name. Making it mandatory removes the disabled
   case from existing at all, which is a stronger honesty guarantee than
   any amount of careful copywriting around an optional toggle.
3. **The cost is real and is disclosed, not hidden.** A mandatory wrapper
   means some Wine-compatible apps that need broader filesystem access
   (e.g. an app that expects to see a real `~/Documents`) need an explicit,
   named, consent-gated exception (§5's `filesystemScope`) rather than
   working by default — the same honest friction
   `LICENSE-DECISION.md` §5 already accepts for the opt-in-module cost and
   `03-license-honesty.md` §1.2 already accepts for "type your own Windows
   key." This is a real UX cost, stated plainly, not softened into
   "advanced settings" language that hides why the requirement exists —
   `02` §9.1's own instruction for whatever this decision turned out to be.
4. **What "mandatory" does NOT mean**: it does not mean the *confinement
   strength* is fixed. An operator can still consent, per app, to a wider
   `filesystemScope` (a specific shared folder, `02`'s existing
   `sharedFolder` crossing model reused per §5) or to `network: allowed`.
   What cannot happen is an app running with **zero** wrapper — the floor
   (§3) is always in force; only named, audited, individually-revocable
   exceptions widen it.

---

## 3 · The exact confinement

### 3.1 Filesystem — allowlist, not denylist

`bwrap`'s own mount namespace starts **empty** — there is no host filesystem
visible until something is explicitly bound in. This is the same structural
guarantee `02` §2.1's Guest Mode table already claims for KVM ("no QEMU
device, no shared filesystem tag … wired up by default — not because a
policy promises not to use one that exists"), applied here to a namespace
jail instead of a hypervisor boundary:

| Bound into the sandbox | Mode | Why |
|---|---|---|
| The app's own `WINEPREFIX` directory | **read-write** | The one directory a Wine app is expected to read and write — its fake `C:\`, its registry hive, its own installed files. |
| `/usr`, `/bin`, `/lib`, `/lib64`, `/sbin` (whichever exist on the host) | **read-only** | The minimal system base needed to `exec` anything (the dynamic linker, Wine's own shared libraries, libc) at all. Nothing here is writable by the sandboxed process. |
| `/proc` (fresh mount), `/dev` (fresh, minimal device nodes) | as `bwrap --proc`/`--dev` provide | Needed for a normal userspace process to function at all (`/proc/self`, `/dev/null`, etc.) — not the host's real `/proc`/`/dev` state, a fresh, namespace-scoped one. |
| `/tmp` | **private tmpfs**, not the host's `/tmp` | Prevents using the host's shared `/tmp` as an incidental cross-sandbox or host-reachable IPC/leak channel. |

**Bound into the sandbox: nothing else, ever, by default.** Concretely and
by name: **no `$HOME` bind** (the sandbox's own `HOME` environment variable
points inside the prefix, never at the operator's real home directory), no
`/etc` beyond what a consented `network: allowed` exception explicitly adds
(`/etc/resolv.conf`, `/etc/ssl`, `/etc/hosts`, `/etc/nsswitch.conf` — only
present when network is on, §3.2), no `/media`/`/mnt`/other-user-data mount
points, no other app's `WINEPREFIX`. An operator-consented `sharedFolder`-
style exception (mirroring `02` §3's existing crossing) is the **only** way
anything beyond this table becomes visible, and it is one named, path-
scoped, individually-revocable bind — never a wildcard, never "give this app
the whole home directory."

### 3.2 Network — off by construction, not a firewall rule

Default: `bwrap --unshare-net` — a genuinely new, empty network namespace,
not an iptables/nftables rule that could be misconfigured or bypassed by a
process with enough privilege. There is no interface for the sandboxed
process to route traffic through at all; DNS resolution is additionally
impossible because `/etc/resolv.conf` is not bound in (§3.1). This mirrors
`02` §3's `network` crossing default (`"mode": "nat-only"` for Guest Mode;
the App Mode equivalent per `02` §3.2's own flagged-but-undrafted variant
schema, sketched here in §5, is simply `"mode": "off"` by default, with an
explicit `"allowed"` exception). **The one exception `02` §3 itself already
carves out for Guest Mode — leaving NAT egress default-on because a guest
needs to reach the OS vendor's own install/update servers — does not apply
to App Mode by the same logic that created it**: a Wine app is not an OS
needing vendor update traffic to function at all; many Wine-compatible
productivity apps need zero network access, and the ones that do (an
installer fetching a redistributable, a game checking a license server)
should ask for it as a named, disclosed, per-app exception, not inherit a
default-on grant designed for a different product shape.

### 3.3 No host-home access — stated once more, unambiguously

This is explicitly named in the task this document answers, so it gets its
own line rather than being implied by §3.1's table: **the operator's real
`$HOME` (SSH keys, browser profiles, personal documents, the Postern
wallet/vault state, any other application's data) is never bound into an
App Mode sandbox, under any default configuration.** The sandboxed
process's own `HOME` environment variable is set to a path **inside its own
`WINEPREFIX`**, so any code that looks up `$HOME` finds a directory that is
part of its own confined prefix, not the operator's real profile. The only
way host data becomes reachable is the same named, consent-gated,
individually-revocable `sharedFolder`-style exception as §3.1 — never a
default, never implicit, never "well it's the same user account so it's
fine" (the exact reasoning `02` §2.2 already names as the thing App Mode
does *not* get for free, unlike Guest Mode's hardware boundary).

### 3.4 Other namespaces, briefly

`--unshare-pid` (the sandboxed process cannot see or signal any host
process, including other App Mode sandboxes' processes — each app's
processes are invisible to each other, not just filesystem-isolated),
`--unshare-ipc` (no shared System V IPC / POSIX shared memory with the
host or other sandboxes), `--unshare-uts` (its own hostname namespace),
`--unshare-cgroup-try` (its own cgroup namespace where the kernel supports
it), `--die-with-parent` (a crashed or killed Terem backend process takes
its sandboxes down with it — no orphaned Wine processes surviving outside
Terem's own lifecycle control), `--new-session` (blocks a known TTY-
injection class of escape — `TIOCSTI`-style terminal-injection attacks
against whatever terminal launched the sandbox).

---

## 4 · The POC script

`scripts/terem-app-mode-sandbox-poc.sh` (this repo, alongside it) is a
runnable, `bwrap`-style reference wrapper implementing exactly §3's policy.
It is **not** wired into any Tauri command, Rust module, or product surface
— it is a standalone proof that the confinement policy described above is
expressible and enforceable with `bwrap`, and a self-test that actually
exercises it rather than merely asserting it.

### 4.1 What it does

- **Self-check mode (default, no arguments)**: builds the exact `bwrap`
  argument list from §3, drops a canary file in the *real* invoking user's
  `$HOME`, then runs a small confinement self-test **inside** the sandbox
  that asserts, from the inside: the host-`$HOME` canary is unreachable;
  writing outside the bound prefix (into the read-only `/usr`) fails;
  writing/reading inside the prefix works; no `/etc/resolv.conf` exists
  (DNS is structurally impossible); and, best-effort when `python3` happens
  to be present inside the sandbox's own minimal base, an outbound TCP
  connect attempt fails. Each check prints an explicit `PASS`/`FAIL`/`SKIP`
  line — nothing is asserted silently.
- **`--with-net`**: reruns the same self-check with the network exception
  applied (mirrors a consented `network: allowed` exception per §5) —
  demonstrates the policy is a real toggle, not hardcoded.
- **`-- <command>`** (with `TEREM_PREFIX` optionally pointing at a real
  `WINEPREFIX`): confines an arbitrary caller-supplied command in the same
  jail — e.g. `TEREM_PREFIX=/path/to/prefix scripts/terem-app-mode-sandbox-poc.sh -- wine app.exe`
  runs **real** Wine under the **real** confinement policy, if Wine happens
  to be installed on the test host. This is the literal "confines a sample
  process" deliverable, generalized past the self-test so it can also
  confine a real Wine invocation without any code change.

### 4.2 Linux-runnable vs. box-gated — the honest split

Matching `POC-SCOPE.md` §4's own table discipline (that document's "host-
testable vs. KVM-gated" split, applied here to "Linux vs. everything else"):

| What | Runnable on this repo's actual dev machine (macOS, this session)? | Runnable on any Linux host with `bwrap` installed? |
|---|---|---|
| Script syntax (`sh -n`) | **Yes — done, passes.** | Yes |
| `shellcheck -s sh` | **Yes — done, zero errors** (three `SC2016` info-level notes are the intentional single-quote variable-splice technique used to inject outer-shell values into the sandboxed inner script; one `SC2329` info-level note is an intentional trap-only helper). | Yes |
| The honest platform/tool gate (SKIP on non-Linux or missing `bwrap`) | **Yes — done, verified live**: this session ran the script on this macOS host and it printed `SKIP (box-gated): this host is 'Darwin', not Linux …` and exited **77**, exactly as designed. Nothing past the gate executed — no fake pass. | N/A — the gate passes through on Linux with `bwrap` present |
| The actual `bwrap` sandbox construction + self-check (§4.1) | **No.** `bwrap` requires Linux kernel namespaces; this macOS host cannot run it, full stop, and this document does not claim otherwise. A local Docker daemon was checked as a possible Linux substrate for this session and was not usably available (`docker info` did not return a running daemon) — **this was not worked around by faking a result**; the execution path is honestly unverified in this session. | **Yes — this is the intended, real test target.** Run `scripts/terem-app-mode-sandbox-poc.sh` on any Linux box (bare metal, VM, or container) with `bubblewrap` installed (`apt install bubblewrap` / `dnf install bubblewrap` / `pacman -S bubblewrap` / NixOS `pkgs.bubblewrap`). |
| `-- wine app.exe` mode against a real Wine install | No (no Wine on this host either, and no Linux to run it under regardless) | Yes, given `wine` on `PATH` inside the sandbox's bound `/usr` (or wherever the host's package manager puts it) |

**The headline honesty statement this table exists to make plain:** this
document's confinement *design* (§3) and its *mechanical correctness*
(syntax, argument construction, the honest failure gate) are verified in
this session. Its *actual enforcement behavior under a real Linux kernel* —
whether the canary is truly unreachable, whether the write into `/usr`
truly fails, whether the network truly does not route — is **designed to
standard, well-established `bwrap` semantics** (the same primitive
Flatpak/Steam already run at scale) but **is not independently verified
by this session**, because no Linux execution environment was available.
`verifiable ≠ verified` (this repo's own fourth inequality) applies here
exactly as written — run it on a real Linux box before trusting the
`PASS` lines.

### 4.3 Relationship to `02`'s `terem-gate` audit trail (§9.2)

Every check the self-test prints is the same shape of event
`02` §9.2's `[ARCHITECT-2 STUB]` asks for a hash-chained audit-trail entry
for (crossing/exception open, in this case "network exception granted for
this run") — this POC does not implement that trail (out of scope, no code
exists to hash-chain into yet), but its `PASS`/`FAIL` line format is a
direct, intentional preview of what a real `terem_app_run` Tauri command's
`app.emit("terem-log", …)` stream (mirroring `node_start`'s existing
pattern, `01` §2.6) should surface to the operator.

---

## 5 · `terem-gate` App Mode variant — sketched, not built

`02` §3's `[ARCHITECT-2 STUB]` §3.2 asks for an explicit App Mode variant of
the `terem-gate` schema rather than overloading Guest Mode's. A minimal
sketch, following that document's own spine (`schema`/`version`/`tier`/
`consent`/`killSwitch`, deny-by-default, `normalize()`-to-full-deny) with
App Mode's narrower crossing set:

```jsonc
{
  "schema":  "postern.terem-gate.app-mode.state",
  "version": 1,
  "tier":    "non-attestable",          // pinned; a WINEPREFIX is ordinary host
                                          // filesystem state, further from
                                          // attestation-shaped than a VM (01 §6)
  "consent":    { "accepted": false, "scope": "session" },
  "killSwitch": { "engaged": false },

  "wrapper": "bwrap",                    // read-only to the UI; §1's decision,
                                          // never a capability a crossing can change
  "wrapperMandatory": true,               // read-only; §2's decision — there is no
                                          // "false" this field is ever allowed to hold

  // App Mode's crossing set is narrower than Guest Mode's terem-gate (02 §3):
  // no sharedFolder/usbDevice/audio/widen.* concepts at all in this POC — only
  // the two exceptions this document's confinement model actually needs.
  "exceptions": {
    "filesystemScope": {                  // one additional named path, beyond the
      "paths": [],                         // prefix itself — vendor:product-style
      "mode":  "none"                      // allowlist, never "share $HOME"
    },
    "network": { "mode": "off" }           // "off" (default) | "allowed" — no
                                            // "bridged-lan" concept; App Mode has
                                            // no guest NIC to bridge at all
  }
}
```

`direction`/per-crossing revocation, the signed `ConsentRecord` upgrade
(`02` §3.2), and the audit-trail entry shape (`02` §9.2) all carry over
unmodified from the Guest Mode spine — this is a narrower **capability
set**, not a different **contract**. Not implemented as code in this pass;
left as the concrete next step for whoever picks up `02` §3.2's stub.

---

## 6 · Tauri integration — the shape, not the code

Following `01` §2.6's and `01` §3.5's own pattern (`resolve_node_binary`,
one `Mutex<HashMap<…>>` per running process class), the eventual
`desktop/src-tauri/src/terem.rs` App Mode surface should add:

```rust
fn resolve_bwrap_binary(binary: &str) -> Result<PathBuf, String>   // pins "bwrap",
                                                                     // same name+location+
                                                                     // canonicalize+exec-bit
                                                                     // check as resolve_node_binary

// terem_app_run is the ONLY entry point that ever launches a Wine app.
// There is no terem_app_run_unsandboxed, no debug flag that skips bwrap,
// no code path at all that execs wine/wine64 directly — this IS §2's
// "mandatory" decision, expressed as "the unsandboxed verb does not exist,"
// not as "the unsandboxed verb exists but defaults to off."
terem_app_run(prefix: String, exe: String, args: Vec<String>) -> Result<u32, String>
    // resolves bwrap + wine/wine64, builds the §3 argument list (+ any
    // consented §5 exceptions), spawns bwrap as a plain Command (no shell
    // interpolation, same discipline as every other Terem/node verb),
    // returns the child PID
```

No new Tauri **capability** entries are needed
(`desktop/src-tauri/capabilities/default.json` stays default-deny for
plugin permissions, per that file's own documented rationale, already
reused unmodified for every other Terem verb in `01` §2.6) — `terem_app_run`
is an application command, gated by the `terem-gate` consent check (§5)
inside its own implementation, the same shape as every existing wallet/vault
command.

---

## 7 · Honest limits — App Mode is still weaker than Guest Mode, stated once more, plainly

This document narrows App Mode's isolation gap; it does not close it, and
repeating that plainly here (once more, not softened) is the entire point
of writing it down rather than letting a POC quietly read as "solved":

- **A namespace jail is enforced by the same kernel the sandboxed process
  runs on** — the identical asymmetry `B-sandbox-consent.md` §1.1 already
  states for containers vs. VMs, applied here: a namespace/cgroup/overlayfs-
  class kernel bug that lets a sandboxed process escape its mount namespace
  reaches the **host** directly, because there is no second kernel, no
  hypervisor, nothing between the sandboxed Wine process and the host
  kernel except the namespace boundary itself. Guest Mode's KVM boundary
  does not have this shape (`01` §1.1's asymmetry table) — App Mode never
  will, by construction, because Wine's entire value proposition is running
  as an ordinary host process (`01` §3.1: "no VM overhead").
- **No seccomp filter ships with this POC** (§1.5) — the syscall surface a
  sandboxed Wine process can reach is whatever the namespace boundary
  alone allows, which is still a large kernel surface (every syscall not
  gated by a namespace at all). This is a real, named gap, not implied to
  be closed.
- **DRM/anti-cheat that fingerprints Wine itself (not just virtualization)
  is untouched by any of this** — `01` §3.4 and `03-license-honesty.md` §4
  already state this plainly for the unsandboxed case; wrapping Wine in
  `bwrap` does not change what Wine's own API surface looks like to a
  fingerprinting check running inside the guest process.
- **A compromised host defeats this exactly as it defeats every other
  Postern boundary** (`02` §8, `B-sandbox-consent.md` §1.4) — this document
  adds a boundary *around* a Wine process; it does not, and cannot, harden
  the host underneath the boundary.
- **Side-channels are not addressed** — the same honest non-claim
  `B-sandbox-consent.md` §1.3 already makes for VM boundaries applies at
  least as strongly here, where there is not even a hypervisor-level
  mitigation surface to discuss.
- **This whole document is unaudited, unreviewed, and the POC script has
  never executed under a real Linux kernel in this session (§4.2).** Treat
  every `PASS` this document or its script prints as *designed to pass*,
  not as *proven to hold*, until it has actually run on Linux.

---

## 8 · Honesty ledger — real vs. speculative, at a glance

| Claim in this document | Status |
|---|---|
| `bwrap` is the right default wrapper, over `firejail`/Flatpak-portal/Landlock-alone (§1) | **This document's own judgment call**, grounded in real, citable properties of each tool (Flatpak's own use of `bwrap`, `firejail`'s SUID+profile-parsing history, Landlock's narrower scope) — not a fabricated comparison, but a reasoned pick among real alternatives, same posture as `A-virtualization.md`'s VMM comparisons |
| Bubblewrap's LGPL-2.1-or-later license and its "opt-in, external-process, never-linked" treatment (§1.2) | **Directly extends** `LICENSE-DECISION.md`'s own already-adjudicated rule for Wine/QEMU one component further — same non-legal-advice posture, same "needs a real counsel pass before shipping" caveat |
| Mandatory default-on, no disable path (§2) | **This document's own decision**, explicitly resolving `02` §9.1's open question in the direction `02` §2.2 already leaned but did not commit to — the reasoning is this document's synthesis of that document's own stated risk, not a new invented risk |
| The exact confinement policy (§3: filesystem allowlist, network off, no host-home) | **Real, standard, well-established `bwrap` semantics** (empty-by-default mount namespace, `--unshare-net` as a genuine namespace, not a firewall rule) — the *policy* is real and correct; its *enforcement on this specific script* is unverified this session (§4.2) |
| The POC script's syntax validity and honest box-gating | **Verified live in this session** — `sh -n` passed, `shellcheck -s sh` reported zero errors (info-level notes only, explained), and running the script on this session's actual macOS host produced the exact documented `SKIP`/exit-77 behavior, observed directly, not assumed |
| The POC script's actual `bwrap` confinement behavior (canary unreachable, `/usr` write refused, network absent) | **Unverified this session.** Designed to standard `bwrap` idioms; no Linux execution environment (bare host or working container runtime) was available in this session to run it for real. Must be run on Linux before any `PASS` line is trusted — stated here, not hidden. |
| The `terem-gate` App Mode schema sketch (§5) | **[SPECULATIVE / NEW]** — follows the real, tested consent-spine contract shape byte-for-byte in structure; the specific fields are new and unbuilt, directly answering `02` §3's own flagged-open `[ARCHITECT-2 STUB]` §3.2 |
| The Tauri integration shape (§6) | **Directly reuses** `resolve_node_binary`'s real, tested pattern; `terem_app_run` itself is new and unbuilt, same maturity level as every other Terem verb in `01` §2.6 |
| App Mode remains weaker than Guest Mode after this document (§7) | **Real, and deliberately restated rather than left implicit** — the single most safety-relevant claim in this document, per the same standard `02` §2.2 already set for the underlying architecture docs |

---

*Design decision + reference POC only. UNAUDITED. Do not treat any argument
list, schema, or `PASS` line in this document or its accompanying script as
a security control until it has been run, reviewed, and audited on a real
Linux host. `written ≠ built`, `built ≠ booted`, `designed ≠ audited`,
`verifiable ≠ verified`. Product name "Terem" is proposed only, pending
trademark clearance. Never "Postern Windows," "Postern Ubuntu," or "Postern
RedHat." BLCH is worthless and is not a security. Not legal advice.*
