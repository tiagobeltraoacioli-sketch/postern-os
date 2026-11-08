<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Sloboda Gate — the consent gate for the escape hatch

**Status: reference-prototype. UNAUDITED — certifies nothing about security.**

The deny-by-default consent kernel **and its on-device writer** for **Sloboda**, the
Waydroid tier — "Postern for postmarketOS — community edition". This directory owns the
question *"may the Android container run, and which host↔Android bridges are open?"*:
a rich canonical JSON state (`gate-store.mjs`), the daemon/CLI that mutates it and
compiles it into the minimal line-file the wrapper reads (`sloboda-gated`), and the
honest UI (`index.html`).

> ## ⚠ HONESTY HEADER — read before trusting anything here
>
> - **Sloboda is NEVER attested and NEVER Postern-Seal-covered BY DESIGN.** This is the
>   deliberate escape hatch: the tier where **data leaves the sealed base**. Entering
>   Android is a one-way door out of anything the sealed tiers can vouch for —
>   `os_roothash` cannot measure a mutable Android userland pulled over the network at
>   `waydroid init`, and no code path here may relabel the tier (`tier` is pinned
>   `"non-attestable"`, never read from input).
> - **Play Integrity STRONG is EXPECTED to FAIL** in this tier (uncertified container,
>   no hardware TEE keymaster). Disclosed, never spoofed. Banking / Wallet / DRM apps
>   will refuse to run — that is the tier working as described, not a defect.
> - **This gate is a consent recorder, not a security boundary.** It never claims to
>   contain a hostile app: a rooted host or a leak below the wrapper defeats it. Tor
>   egress here is metadata reduction, NOT anonymity.
> - **NAMING.** Sloboda is NOT **"Porog"** (the stock-Android managed-profile container
>   — a different product) and NEVER **"Postern OS"** (the sealed Nix tier). It is
>   "Postern for postmarketOS — community edition". Different host, different tier — do
>   not conflate them.
> - **UNAUDITED reference-prototype.** On-device behaviour (boot ordering, a real
>   waydroid, dir modes on a live host) is deferred-to-VM — see the validation matrix
>   at the bottom for exactly what has and has not run. The coin is worthless and is
>   **not a security**. Personal use is free. **This is not legal advice.**

## What this is (and is not)

- **The whole gate, both halves.** `gate-store.mjs` is the canonical, node-tested
  consent kernel (the state shape + decision helpers). `sloboda-gated` /
  `sloboda-gated.mjs` is the on-device WRITER: it applies operator intents as pure
  transforms over the kernel's `normalize()` trust boundary, atomically writes the
  canonical JSON, and compiles the projection the wrapper reads. The writer adds **no
  new decision logic** — the projection serializes the kernel's shipped
  `containerAllowed()` / `activeBridges()` / `egressAllowed()` helpers, never invents.
- **The wrapper is elsewhere and only READS.** `apps/sloboda` (the Waydroid wrapper)
  consumes the projection and never writes it. The NixOS install wiring is
  `os/sloboda-compat.nix` (`postern.slobodaCompat.consentGate`), imported ONLY by the
  non-attested DEV/VM host `os/sloboda-vm.nix` — never by a sealed profile.
- **Sibling gates.** Same deny-by-default / fail-closed / pinned-rail house pattern as
  `apps/noporis-gate` (the guarded bridge) and `apps/porog-crossprofile` (the guarded
  door's decision core). Those directories are **not** modified here; Sloboda's extra
  rail is Tor-only egress, which the siblings do not carry.

## Files

| File | Role |
|---|---|
| `gate-store.mjs` | Canonical DOM-free, dependency-free consent kernel: `normalize()` trust boundary + decision helpers (`containerAllowed`, `activeBridges`, `egressAllowed`). No network, no telemetry, no imports. |
| `sloboda-gated` | POSIX-sh shim: stable CLI entrypoint, execs `node sloboda-gated.mjs`. |
| `sloboda-gated.mjs` | The writer/daemon: operator intents → atomic canonical write → projection compile. Also emits the boot-ordering systemd unit text (`systemd-unit`). |
| `gate-state.schema.json` | JSON Schema (draft-07) for the canonical state file (constants re-checked against `gate-store.mjs` exports — see validation). |
| `state.example.json` | A fresh, fully-safe state (not consented, every bridge denied, kill-switch clear, egress held). |
| `index.html` | Self-contained honest UI (inlines a behavior-equivalent copy of the kernel; parity is pinned by `test-ui-parity.mjs`). |
| `test-store.mjs` | `node test-store.mjs` — kernel honesty rails (31 checks). |
| `test-gated.mjs` | `node test-gated.mjs` — writer: atomicity, discriminator, projection, intents, boot re-ask (173 checks). |
| `test-ui-parity.mjs` | `node test-ui-parity.mjs` — UI copy ≡ canonical kernel (420 checks). |

Install/read side, outside this directory: `os/sloboda-compat.nix` (NixOS wiring),
`os/sloboda-gate-boot.service.in` (the boot unit template, byte-pinned to
`systemdUnit()` by `os/test-sloboda-gate-boot-unit.mjs`), `apps/sloboda/bin/paw-lib.sh`
(the reader).

## The two-file model: canonical vs projection

| | Canonical | Projection |
|---|---|---|
| Path | `/var/lib/postern/sloboda-gate/state.json` | `/run/postern/consent/sloboda-bridge.state` |
| Format | rich JSON (`gate-state.schema.json`) | flat line-file (contract below) |
| Modes | file `0600`, dir `0700` (root-only) | file `0644`, dir `0755` (world-readable) |
| Written by | `sloboda-gated` only | `sloboda-gated` only (derived) |
| Read by | `sloboda-gated` (strict discriminator) | the wrapper (`paw-lib.sh`), fail-safe |
| Survives reboot | yes (persistent) | **no** — `/run` is tmpfs |

Every mutation writes **canonical first, projection derived LAST** (each write is
atomic: temp-in-same-dir → fsync → chmod → rename, so a reader never observes a partial
file, and a failed write leaves either the prior file or nothing — and "nothing" reads
as OFF at the wrapper). Projection-last is the skew rationale: if the process dies
between the two writes, the wrapper keeps reading the *previous* projection while the
canonical is already newer — an over-restrictive stale read for a grant in flight,
never a projection that got ahead of recorded state; the next `sloboda-gated` run (or
the boot oneshot) re-derives it. Because the projection evaporates on reboot,
`sloboda-gated boot` must run before anything reads it: it re-derives the projection
from canonical, clears `scope:"session"` consent (the re-ask; `"persistent"` survives)
and clears `torBootstrapped` (Tor is definitionally down at boot). The NixOS module
installs exactly the unit `sloboda-gated systemd-unit` emits, ordered
`Before=waydroid-container.service` and `RequiredBy` it — a failed gate keeps the
container down, fail-closed.

## The projection line-file contract (what a wrapper implementer ports)

The projection is newline-terminated `key=value` lines after a bare posture line 1.
Order: line 1, then `container=`, then `egress=`, then optional `kill=engaged`, then
zero or more `<cap>=on`.

```
line 1     enabled | disabled      BRIDGE posture. "enabled" iff the container is
                                   allowed AND ≥1 bridge is open. This keeps the
                                   shipped wrapper's `first line == "enabled"`
                                   contract byte-for-byte.
container= allowed | blocked       CONTAINER-ENTRY posture (consent + kill-switch),
                                   independent of bridges — a consented user with NO
                                   bridges may still enter: accept is permission to
                                   RUN, not permission to share.
egress=    tor | held | blocked    Tor-only network egress, fail-closed:
                                     blocked  container may not run → no egress;
                                     held     container allowed but Tor NOT yet
                                              bootstrapped → traffic is HELD;
                                     tor      container allowed AND Tor live.
                                   Never the value `on`, so it can never be mistaken
                                   for a `<cap>=on` bridge line.
kill=engaged                       present ONLY while the kill-switch is engaged.
<cap>=on                           one line per open bridge, ONLY when line 1 is
                                   "enabled". cap ∈ clipboard | files | mic |
                                   camera | location.
```

Reader rules (mirror `paw-lib.sh`): a missing/unreadable file, an empty file, or
anything but a literal `enabled` line 1 reads as bridge-OFF; any BLOCK marker
(`kill=engaged`, `container=blocked`) wins over any ALLOW marker; unknown additive
lines are ignored, so old readers stay safe as lines are added. Fail-safe: every doubt
resolves to OFF/blocked.

## The honesty rails, enforced in code (not just prose)

1. **`tier` pinned `"non-attestable"`**, `egress.torOnly` pinned `true` — both set by
   `defaultState()`, never taken from input. No state file can relabel the tier or
   widen egress to clearnet.
2. **Every bridge DEFAULTS TO DENY**; anything not exactly `true` is deny. The writer
   never opens a bridge on its own — every grant is one explicit operator intent
   (`bridge <cap> on`), one lever at a time; nothing bundles.
3. **Strict on-disk trust boundary.** The writer refuses (full-deny `defaultState()`)
   any blob that fails the discriminator: foreign `schema`, wrong `version` (even
   `"1"` vs `1`), or a relabelled `tier`. Corrupt JSON or an absent file read the
   same. `gate-store.loadState()` is the matching strict reader.
4. **Fail-closed egress.** Egress needs container-allowed AND pinned Tor-only AND a
   live `torBootstrapped` signal; a half-open or dropped circuit is treated as no Tor
   (`held`). The tor-glue's `tor up|down` flips ONLY `torBootstrapped`.
5. **Kill projects `disabled` BEFORE teardown.** `kill on` persists + projects the
   refusal first, then hands off to the wrapper's runtime actuator (`sloboda kill`) —
   re-entry is refused even if teardown fails midway.
6. **Boot re-ask.** `scope:"session"` consent does not survive a reboot; the boot
   oneshot clears it so the user is re-asked. `"persistent"` survives until withdrawn.
7. **No network, no telemetry.** Neither file ever leaves the device.

## CLI / API surface

```
sloboda-gated accept [--scope session|persistent]   record informed consent
sloboda-gated withdraw                              revoke consent
sloboda-gated bridge <cap> on|off                   toggle ONE bridge
sloboda-gated tor up|down                           record the tor-glue's live signal
sloboda-gated kill on|off                           engage/disengage the kill-switch
sloboda-gated boot                                  re-derive projection + session re-ask
sloboda-gated project                               re-derive projection (no state change)
sloboda-gated systemd-unit                          print the boot-ordering unit text
sloboda-gated status                                current posture (no side effects)
```

Module exports (`sloboda-gated.mjs`): `loadCanonical`, `persist`, `project`,
`egressPosture`, `discriminatorOk`, `atomicWrite`, `applyAccept/Withdraw/Bridge/Kill/
Egress/Boot`, `systemdUnit`, `execWrapperKill`. Kernel exports (`gate-store.mjs`):
`defaultState`, `normalize`, `parse`, `loadState`, `serialize`, `containerAllowed`,
`activeBridges`, `egressAllowed` + the pinned constants (`SCHEMA_ID`,
`SCHEMA_VERSION`, `TIER`, `BRIDGE_KEYS`, `CONSENT_SCOPES`, `LANGS`,
`EGRESS_TOR_ONLY`, `STATE_PATH`). All transforms are pure; timestamps are
caller-suppliable.

## Validation — what actually ran vs what is VM/device-blocked

Commands actually executed on the authoring host (macOS, node, no nix, no Android
SDK), all green:

```
node apps/sloboda-gate/test-store.mjs          # gate-store: 31 passed, 0 failed
node apps/sloboda-gate/test-gated.mjs          # gated: 173 passed, 0 failed
node apps/sloboda-gate/test-ui-parity.mjs      # test-ui-parity: 420 passed, 0 failed
node os/test-sloboda-gate-boot-unit.mjs        # boot-unit template ≡ systemdUnit(): 7 passed, 0 failed
sh apps/sloboda/test/dry-run.sh                # wrapper harness: passed: 25   failed: 0
bash scripts/check-trust-labels.sh             # RESULT: pass (exit 0)
```

`gate-state.schema.json` constants were re-checked against the `gate-store.mjs`
exports during this change (schema id, version, tier pin, `BRIDGE_KEYS` order +
required set, `CONSENT_SCOPES`, `LANGS`, egress field names + `torOnly` pin): all
match.

**Pending — VM/device-required, listed, NOT claimed** (nothing below has run
anywhere yet):

| # | Proof | Why it cannot run here |
|---|---|---|
| 1 | `nix build .#nixosConfigurations.sloboda-vm.config.system.build.vm` evaluates + the VM boots | no nix on the authoring host; the nix wiring is compile-correct by inspection only |
| 2 | Boot-ordering race: the `/run` projection exists BEFORE the first wrapper read (`Before=`/`RequiredBy=` edges honoured by `waydroid-container.service`) | needs the booted VM; byte-parity of the unit text is proven, its runtime effect is not |
| 3 | `waydroid-container` interaction + stop privileges for the kill path (`sloboda-gated kill on` → real teardown) | needs a real waydroid + systemd; only the mock/dry-run halves ran here |
| 4 | tmpfiles dir modes on a real boot (`/var/lib/postern/sloboda-gate` `0700`, `/run/postern/consent` `0755`) | needs the booted VM; the writer's own mkdir/chmod of the same modes is node-tested |
| 5 | `sloboda-gate-smoke` (accept → start → kill through the gate) against a REAL container | boots Android; its gate logic ran here in dry-run only (start-refuse / allow / kill-refuse held; wait-for-RUNNING needs the VM) |

---

*Reference-prototype; UNAUDITED. Do not treat any file here as a security control.*
