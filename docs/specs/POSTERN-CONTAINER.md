# Postern Container (Android) — design spec

**Product (Postern Labs). Status: design.** The low-friction *entry* product: a
hardened, isolated, **attestable** privacy workspace on the Android a person
**already owns** — no OS replacement, no root. Sensitive apps, data, keys and
comms live sealed off in a Postern-managed space; the rest of the phone is
untouched.

> Meets the user where they are (see `docs/POSTERN-LABS.md`): container first,
> full **Postern OS Mobile** later for those who want to go all the way.

## Isolation model — Android managed profile (work profile)

The container is an Android **managed profile** (the "work profile" mechanism),
created by a lightweight self-enrolled **Device Policy Controller (DPC)** — the
same no-root approach Shelter/Island use via `DevicePolicyManager`. Why this over
a single sandboxed app:

- **Cryptographic storage separation** — the managed profile has its own
  file-based-encryption (FBE) keys, unlocked by a **separate work challenge**;
  the personal profile cannot read container data.
- **App + process isolation** — container apps run as a separate Android user;
  cross-profile visibility is off by default (no shared clipboard/contacts/
  notifications unless the user allows it).
- **Per-profile controls** — the DPC can disable screenshots, block unknown
  sources, force a VPN, and wipe *only* the container.

```
┌──────────────── the phone (unchanged) ───────────────┐
│  Personal profile            Postern Container        │
│  (their normal apps)         = managed profile        │
│                              ┌──────────────────────┐ │
│                              │ separate FBE storage  │ │
│                              │ Postern Wallet        │ │
│                              │ sensitive apps/comms  │ │
│                              │ StrongBox keys        │ │
│                              │ Tor-only networking   │ │
│                              └──────────────────────┘ │
│         ── cryptographic profile boundary ──          │
└───────────────────────────────────────────────────────┘
```

## Key protection + attestation — the Postern Seal on mobile

- Sensitive keys (the **Postern Wallet**'s wrapping key) are generated in the
  **Android Keystore StrongBox** (a discrete hardware security module) —
  non-exportable, use-authenticated.
- **Key Attestation**: the Keystore emits an X.509 chain rooted in Google's
  attestation CA that proves the key lives in genuine hardware **and** binds the
  device state — **verified-boot state, OS patch level, the app that owns the
  key**. The container echoes a verifier **nonce** in the attestation challenge.
- This is the mobile form of **Postern Seal**: a verifier runs
  `bloch::attestation::verify` with the `mobile` backend (already scaffolded — see
  `mobile/README.md` + `docs/specs/BLOCH-SIS-ATTESTATION.md §4`) against the
  Key-Attestation chain. Optionally **Play Integrity** adds a device/app integrity
  verdict.

## Private-by-default networking

The DPC sets an **always-on, lockdown per-profile VPN** routed through **Tor**
(Orbot's `VpnService`), so container traffic is Tor-only and cannot leak outside
the tunnel — while the personal profile keeps normal networking.

## The wallet inside

The container embeds the **Postern Wallet** engine (`bloch-mobile`, pure Rust)
via **UniFFI** (Kotlin bindings). The PQ signing key material is wrapped by the
StrongBox key; the wallet is byte-compatible with the node (golden test). Requires
the lean `bloch-core` extraction first (see `mobile/README.md` — the full `bloch`
crate is too heavy to cross-compile).

## Critical pieces (sketch)

Provision the managed profile (self-enrolled DPC):
```kotlin
// The user taps "Create Postern Container"; we request profile provisioning.
val intent = Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE).apply {
    putExtra(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
             ComponentName(context, PosternDeviceAdminReceiver::class.java))
    putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, false) // keep FBE
}
startActivityForResult(intent, REQ_PROVISION)
```

StrongBox-backed key + attestation challenge:
```kotlin
val spec = KeyGenParameterSpec.Builder("postern-wallet-wrap",
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)                 // discrete HSM
    .setUserAuthenticationRequired(true)
    .setAttestationChallenge(verifierNonce)     // echoes the node/verifier nonce
    .build()
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
kpg.initialize(spec); kpg.generateKeyPair()
// -> the cert chain (getCertificateChain) is the Key-Attestation proof to verify.
```

Lock the container down (in the DPC, once profile owner):
```kotlin
dpm.setScreenCaptureDisabled(admin, true)
dpm.setPermittedInputMethods(admin, permittedSecureImes)   // no keylogger IMEs
dpm.setAlwaysOnVpnPackage(admin, "org.torproject.android", /*lockdown=*/ true)
```

## Honesty — the real limits (no overclaim)

- **Not a separate OS.** A managed profile is isolation *within* Android's security
  model — a kernel/hypervisor compromise or a malicious vendor image can cross it.
  Postern OS Mobile is the answer for those who want the whole OS.
- **Mobile TEE is classical.** StrongBox is P-256 hardware — it protects the PQ
  key **at rest** and attests the device; it does **not** hold the post-quantum key
  *in* hardware (same honest limit as `mobile/README.md`).
- **Attestation trusts Google + the vendor.** Key Attestation chains to Google's
  CA and Play Integrity to Google's service — a real trust dependency, and an
  ironic one for an ownerless ethos. We state it plainly; a self-sovereign path is
  Postern OS Mobile with its own measured boot.
- **Not every device qualifies.** StrongBox needs a hardware security module;
  older/cheaper phones lack it (fall back to TEE-backed keys, weaker guarantee).
- **Nothing here is audited.** Design only; no security claim until a gate.

## Build path

1. Extract lean **`bloch-core`** (crypto + address + tx types, no rocksdb/libp2p)
   → cross-compiles for `aarch64-linux-android`.
2. UniFFI-export `bloch-mobile`'s `WalletCore` → Kotlin.
3. Android app: the **DPC** (`DeviceAdminReceiver` + profile provisioning +
   lockdown policy), StrongBox key + Key-Attestation plumbing, Orbot always-on
   VPN, and the wallet UI (Jetpack Compose) — inside the managed profile.
4. Wire the Key-Attestation verify into the `mobile` attestation backend.
