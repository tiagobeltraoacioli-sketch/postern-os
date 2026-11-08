<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# The Postern Consent Contract — ONE state-file spine, three tiers

**Reference-prototype / DESIGN. UNAUDITED — certifies nothing.** This is the
canonical formalization of the consent state-file contract that architects A8
(Waydroid), A3 (Porog) and A5 (NoporIS) converged on. It is the foundation the
per-tier gate stores (`apps/sloboda-gate`, `apps/noporis-gate`, the
proposed `apps/porog-*`) implement. It ships a single validator
(`consent-spine.mjs`), a single JSON Schema (`consent-spine.schema.json`), and a
node proof (`test-spine.mjs`, **117 assertions green**).

> **Default-SAFE.** Every capability is CLOSED unless an explicit, disclosed,
> consented toggle opened it. A missing / unparseable / foreign / wrong-version /
> partial file is treated as **full-deny + not-consented**. The Google side
> (NoporIS/Porog far persona) is the **less-private, non-attestable** side. No
> tier here implies the Postern Seal or measured boot. USERLAND, not a kernel
> boundary — a rooted host defeats it. The coin is not a security; personal use
> is free; not legal advice.

## Two files per product

| | Canonical | Projection |
|---|---|---|
| Path | `/var/lib/postern/<product>-gate/state.json` | `/run/postern/consent/<product>-bridge.state` |
| Owner / mode | `root:root` `0600` (dir `0700`) | `root:root` `0644` (dir `0755`, `/run` tmpfs) |
| Format | rich JSON (this contract) | line 1 = `enabled`\|`disabled`; optional `KEY=on` lines |
| Lifetime | persistent (if `scope=persistent`) | ephemeral; re-derived from canonical |
| Role | source of truth | the dumb, read-only bool the wrappers already consume |

`<product>` ∈ `sloboda` (Waydroid tier), `noporis`, `porog`. The projection is a
**pure function** of the canonical state — the daemon compiles it, never invents
it. Line 1 is the ONLY field the shipped wrappers read (`== "enabled"`); the
`KEY=on` extras are additive and safely ignored by an old reader.

## The identical spine (all three tiers)

```jsonc
{
  "schema":  "postern.<product>-gate.state",   // discriminator; foreign => full-deny
  "version": 1,                                 // unknown version => full-deny
  "tier":    "<pinned>",                        // never from input
  "lang":    "pt-BR" | "en",                    // cosmetic
  "consent":    { "accepted": false, "scope": "session"|"persistent", "acceptedAtIso": null },
  "killSwitch": { "engaged": false, "engagedAtIso": null }
  // + exactly one capability object + exactly one tier rail (below)
}
```

Pinned `tier` per product (a code-set honesty rail, never read from input):

| Product | `schema` | `tier` (pinned) | Honest meaning |
|---|---|---|---|
| Waydroid | `postern.sloboda-gate.state` | `non-attestable` | community edition; not Sealed |
| NoporIS | `postern.noporis-gate.state` | `non-attestable` | Google side; less-private, phones home |
| Porog | `postern.porog-gate.state` | `key-attested-device` | attests the **phone**, NOT the workspace (never measured-boot) |

## The ONLY per-tier variation

| | Capability object | Tier rail (pinned) |
|---|---|---|
| **Waydroid** | `bridges: { clipboard, files, mic, camera, location }` — flat bool | `egress: { torOnly:true, torBootstrapped }` — Tor-only egress, fail-closed until Tor up |
| **NoporIS** | `crossings: { …: { open, scope, openedAtIso } }` | `sealedWallet: { preserved:true }` |
| **Porog** | `crossings: { intents, clipboard, files, contacts, calendar, connectedApp }` each `{ open, direction, scope, openedAtIso[, package] }` | `sealedWallet: { preserved:true }` |

`direction` ∈ `p2w` \| `w2p` \| `both` \| `none` (Porog). A crossing open with
`direction:"none"` installs **no** grant — fail-closed. `package` (Porog
`calendar`/`connectedApp` only) names the single allowlisted package.

## The projection rule (pure, identical across tiers)

```
line1 = (consent.accepted && !killSwitch.engaged && activeCaps(state).length > 0)
          ? "enabled" : "disabled"
extras = activeCaps(state).map(k => `${k}=on`)   // only when line1 == "enabled"
```

`activeCaps` returns a capability only when the container/bridge is allowed
(consented + kill clear) AND the capability is open (for Porog, open **and** a
real direction). This is `projectionLine1()` / `projectionFile()` in the spine.

## Seven rails, enforced in code (proven by `test-spine.mjs`)

1. **Schema discriminator** — `loadState()` refuses a foreign `schema` => full-deny.
2. **Pinned tier + version** — `tier`/`schema`/`version` come from the descriptor,
   never input; an unknown `version` => full-deny.
3. **Deny-by-default caps** — a capability is open only on exactly `true`; anything
   else (missing, `1`, `"true"`, garbage) is closed.
4. **`normalize()` is the trust boundary** — any input (missing/partial/garbage/
   hostile) collapses to a well-formed full-deny state; it never throws.
5. **Non-destructive kill** — engaging the kill-switch never clears the pinned
   rail (`egress.torOnly` / `sealedWallet.preserved`); caps are masked, not wiped.
6. **Fail-closed decisions** — unknown/malformed/not-consented/killed => full-deny;
   the projection is a pure, deterministic, non-mutating function of state.
7. **No telemetry** — zero network I/O; the file never leaves the device.

## Using it

```js
import S from "./consent-spine.mjs";
const state = S.loadState(fs.readFileSync(S.PRODUCTS.noporis.statePath, "utf8"), "noporis");
const line  = S.projectionFile(state, "noporis");   // write to the projection path, atomic rename
```

The spine is **byte-compatible** (deep-equal `normalize()` and `defaultState()`)
with the shipped `apps/sloboda-gate/gate-store.mjs` and
`apps/noporis-gate/gate-store.mjs` — verified in the test — so the per-tier
stores keep their rich transforms (`openCrossing`, etc.) and delegate the shared
spine + projection here. Porog has no shipped store yet; its shape here follows
`docs/design/porog-03-crossprofile-bridge.md` §3.2.

*Design/scaffold only. Do not treat any file here as a security control.
Porog / NoporIS names pending trademark clearance. Never "Postern OS".*
