<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs -->

# noporis-signer-glue — the guarded bridge, made honest in code

**Status: SCAFFOLD / reference-prototype. UNAUDITED — certifies nothing about
security.**

> **Porog is the guarded *door*; NoporIS is the guarded *bridge*.** This crate is
> the narrow, net-new **signer** glue for the crossing: **ONE phone holding TWO
> INDEPENDENT pairings** — one per world — **never one signer that spans the
> bridge.** A grant to the Google-Play peer can never auto-approve the Porog peer.

It invents no crypto, no pairing, no consent kernel. It **composes** the frozen
crates the other devs shipped, through their **public APIs only** — it adds a
two-world *lane*, never an approval *shortcut*.

## The one design rule (verbatim from `src/lib.rs :: DESIGN_RULE`)

> One keyring, two doors; presented at one door at a time, each presentation
> named and consented. No master approval opens both.

The signer core has **no notion of a persona, world, or profile.** A signature is
bound to *a session*, *a named peer*, and *the exact bytes*. There is no
"cross-world approval" primitive, so the honest model is two independent pairings
on one handset — and unpairing or revoking one world can never touch the other.

## Honesty rails (verbatim from `src/lib.rs :: RAILS`)

These are carried as a `pub const` next to the code so they cannot drift from what
the code does; a surface can print the string as-is:

> reference-prototype / UNAUDITED. ScaffoldSigner is NOT real cryptography. Not a
> hardware wallet — the PQ key is in RAM at sign time. Grant enforcement and the
> bridge kill-switch are userland, in-process checks (ByConstruction), not an
> OS/kernel boundary; a rooted host defeats them. The NoporIS/Google-Play side is
> non-attestable by construction and phones home to Google — it does not make you
> private. An app on stock Android, NEVER 'Postern OS'.

Unpacked, none of these rounds up:

- **SCAFFOLD / UNAUDITED.** The default build signs with `ScaffoldSigner`, a
  deterministic SHA3 stand-in — **NOT real cryptography**. Internal review is not
  an audit.
- **The real signer is still not a hardware wallet.** The `wallet-core` feature
  (OFF by default) wires the WalletCore-backed PQ signer, but the private key is
  in **RAM at sign time**; this is not a secure element.
- **Userland, not a kernel boundary.** Grant enforcement and the bridge
  kill-switch are in-process `EnforcementMode::ByConstruction` checks. A
  rooted/malware host reads keys from RAM and can forge the approval UI; nothing
  here fixes that.
- **The Google-Play side does not make you private.** Its persona is
  `non-attestable` by construction and phones home to Google; it shows no Seal and
  no padlock it hasn't earned.
- **An app on stock Android — NEVER "Postern OS."** The measured-boot,
  self-sovereign path is Postern OS Mobile; NoporIS and Porog are not it.
- **One keyring, no master approval.** See `DESIGN_RULE` above: one keyring
  presented at one door at a time; **no master approval opens both**, and a grant
  to the Google-Play peer never auto-approves the Porog peer.

## What it composes (owned by others — never edited here)

| Consumed | From | Used for |
|---|---|---|
| `PhoneApprover`, byte-derived WYSIWYS, revocable `ApprovalGrant`, fail-closed `ReplayGuard` session binding, the `ScaffoldSigner` test stand-in | `integration/signer-protocol` | the frozen phone↔desktop signer protocol |
| the pairing ceremony + the sealed `PairedTerminals` collection (monotonic per-record revoke, panic-revoke-all) | `integration/pairing` | the per-world hard-unpair |
| fail-closed `Decision`, the honest `EnforcementMode` label | `crates/postern-policy` | the one shared consent kernel behind the kill-switch |
| the REAL WalletCore-backed `WalletCoreSigner` (hybrid Falcon-ML-DSA) | `mobile/signer` | only under the `wallet-core` feature (OFF by default; pulls heavyweight PQ crypto) |

The world **badge rides the EXISTING WYSIWYS `peer_device`**, derived from *which
pairing the frame arrived on* — never from requester-controlled text. No new wire
data is added.

## Build / test / run

This is a **standalone crate** — it deliberately carries its own empty
`[workspace]` and does **not** join the root `members` list (owned by other
devs). Build and test it in place:

```sh
cd apps/noporis-signer-glue
cargo test                 # 23 tests: the no-master-approval invariant + every
                           # fail-closed branch (wrong-world session, kill-switch
                           # spares the door, per-world unpair isolation, …)
```

`#![forbid(unsafe_code)]`. The default check proves every honesty rail on the
lightweight `ScaffoldSigner` and needs **no PQ toolchain**. The `wallet-core`
feature pulls `bloch-crypto` (heavy, PQ) and only builds when compiled as part of
the bloch-protocol root workspace (its seeded-RNG `pqcrypto-internals` patch
applies from a workspace ROOT).

## Marks & coin

"NoporIS/Nopor" is a **coined, proposed** name pending formal trademark clearance
(a bare "NOPOR" filing is on record); the authentic myth is the *crossing between
two worlds* (the Kalinov Bridge), not the word "Nopor". The guardian is
**Yagabona**, never the registered "Baba Yaga". **BLCH is not a security**, is not
involved in licensing, and buys no software; personal use is free.

Licensed `MIT OR Apache-2.0`.
