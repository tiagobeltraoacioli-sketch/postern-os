# Postern Deadbolt — duress & anti-forensics (design spec)

> ## Status: two mechanisms, split by the founder's ethics call
> - ✅ **Panic Lock — APPROVED, being built** (`crates/postern-panic`). A panic
>   button that **instantly re-locks** everything: keys evicted from RAM, the
>   vault/container sealed, so all data becomes **at-rest ciphertext — unreadable
>   but NOT destroyed.** The legitimate owner reopens later with their key. This
>   protects the theft/coercion/kidnap victim by **denial of access**, and —
>   because nothing is destroyed — it **cannot be misused to destroy evidence.**
>   This is the founder-chosen "best format." **Honest scope:** the re-lock is
>   denial of access ONLY — the locked state is observable and there is no decoy,
>   so it must never be marketed as "duress" or "deniable" on its own.
> - ✅ **Deniable container (decoy vault) — CRATE PRIMITIVE BUILT**
>   (`crates/postern-panic::deniable`): a hidden-volume-style dual-slot container
>   where a decoy passphrase opens a decoy vault and the hidden vault's existence
>   is computationally indistinguishable from random filler (single-snapshot
>   guarantee; multi-snapshot diffing, storage metadata, and UI leaks are
>   documented limits in the module docs). The platform pieces — duress-PIN UX,
>   informed-consent warning, TEE wiring — remain TODO before any product
>   surfaces a "duress" claim.
> - ⏸️ **Active erase / wipe — DEFERRED** (founder decision, recorded). The
>   destructive variant (crypto-erase the TEE key / `wipeData`) is **held for a
>   later moment out of concern it could be misused.** The reasoning stands (dual-
>   use like all crypto; misuse without cause is the user's own crime), but the
>   call is to not ship active destruction now. Kept below as the design of record.

Protection for the high-threat user against **kidnapping, coercion, robbery, and
device seizure**. The crypto-erase primitive it relies on is already proven by
`crates/postern-vault` (delete the key → the data is unrecoverable); Deadbolt adds
the **triggers** and the **platform wipe**, which are OS-native.

## The mechanism

- **Crypto-erase (instant, no slow wipe).** All Postern data (vault, wallet keys,
  messenger sessions) is wrapped by a **non-exportable TEE master key** (StrongBox /
  Secure Enclave). Deleting that one key (`KeyStore.deleteEntry`) makes **everything
  it wrapped unrecoverable in milliseconds** — there is no multi-GB overwrite to
  interrupt. This is *denial of access made permanent*, not a file-by-file shred.
- **Container-only wipe (the default, least-drastic).** `DevicePolicyManager.
  wipeData()` on the Postern **managed profile** nukes only the Postern space and
  leaves the personal phone untouched — the highest-value, lowest-blast-radius form.
- **Lockout + eviction policies.** Failed-attempt lockout; auto-reboot-to-locked
  after N minutes idle (evicts keys from RAM → data is at-rest-encrypted again);
  optional dead-man's-switch timer.
- **Desktop.** A LUKS key-slot nuke (`cryptsetup luksKillSlot`) + `landlock`/USB
  lockdown; same crypto-erase idea at the disk layer.

## Triggers

- A **duress PIN/passphrase** distinct from the real one — entering it unlocks a
  decoy/empty state *and* fires the erase. (Or a hidden gesture / hardware combo.)
- All triggers are **explicitly opt-in** and off by default.

## Ethics & law — stated in the product, not hidden

Deadbolt is a **victim-protection** tool. Like all cryptography it is dual-use: the
same erase that protects a kidnapped person or a robbed traveller could be misused.
Postern's position, and the rule this design encodes:

- **Postern protects by DENIAL of access (encryption), and offers destruction only
  as an opt-in the informed user chooses** — the tool is neutral; **triggering it
  without legitimate cause (to destroy evidence of one's own crime) is that user's
  own offence (obstruction), not Postern's.** This is the same logic that justifies
  encryption existing at all.
- **Informed-consent warning, shown before enabling:** in some jurisdictions
  wiping a device during or after a lawful seizure can itself be a crime
  (evidence destruction / obstruction). The user is told plainly and decides.
- Passive strong encryption (LUKS + TEE + the container's FBE) is **always on** and
  already protects a theft/coercion victim by making data unreadable — **Deadbolt's
  active erase is an addition for the high-threat user, never the baseline.**

## Honest limits

- **Not against an image already taken** — Deadbolt defends a *coerced unlock
  attempt*, not a forensic copy made before the trigger.
- **Traces outside the profile** — in the container, Android may retain
  notifications/logs in the personal profile or OS layer.
- **Crypto-erase soundness assumes** the TEE key was truly non-exportable (true on
  modern StrongBox / Secure Enclave; weaker on TEE-only fallback devices).
- **Legal risk is real and jurisdiction-dependent** — see the informed-consent note.

## Scope / build path

1. Prove nothing new cryptographically — reuse `postern-vault`'s key-wrapping (the
   crypto-erase = drop the master key, already tested).
2. Android (container): the `DeviceAdminReceiver` duress logic + `KeyStore.
   deleteEntry` + `wipeData()` + lockout policy.
3. Desktop: `landlock` + `luksKillSlot` + USB lockdown.
4. The informed-consent + duress-PIN UX, with the legal warning verbatim.
