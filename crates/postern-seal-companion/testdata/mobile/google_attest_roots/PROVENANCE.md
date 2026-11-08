# Google Android hardware-attestation root certificates — vendored offline collateral

**Status: REAL vendored roots.** These `.der` files are Google's *current*
Android Key-Attestation root certificates, fetched from Google's authoritative
attestation-root endpoint and embedded verbatim (DER). They are the trust
anchors an operator pins into `mobile::MobileExpected::roots` (see
`crates/postern-seal-companion/src/mobile.rs`, `GoogleRootPinProvenance`).

Verified **offline** at test time by
`crates/postern-seal-companion/tests/mobile_google_roots.rs` (no verify-time
network I/O): each root parses as a well-formed self-signed X.509v3 CA whose own
signature verifies under its own key, and whose SHA-256 DER fingerprint equals
the pinned value recorded below.

## Fetch provenance

- **Source URL (authoritative):** `https://android.googleapis.com/attestation/root`
  — Google's own published Android Key Attestation endpoint. It returns a
  JSON-formatted array of PEM (base64 DER) X.509 root certificates. This is the
  URL documented in `mobile.rs` as `GoogleRootPinProvenance::ROOT_LIST_URL`.
- **Fetched:** 2026-07-18 (UTC) from a developer workstation with `curl`.
- **HTTP response metadata (recorded for audit):**
  - `HTTP/2 200`, `content-type: application/json`, `content-length: 2690`
  - `cache-control: public, max-age=86400` (Google's stated trust window: 24h)
  - `last-modified: Tue, 29 Jul 2025 17:38:00 GMT`
  - `date: Sat, 18 Jul 2026 13:34:57 GMT`
- **Fetch note:** the array contained **2** roots at fetch time. Both are
  pinned here — the array legitimately carries more than one root across a
  rotation window, and pinning only one risks rejecting a genuine device still
  presenting the other (see `mobile.rs` fetch-procedure step 4). Conversion
  PEM->DER was done with `openssl x509 -outform DER`; the DER bytes are embedded
  unmodified.

## Pinned roots

### `google_hw_attestation_root_rsa4096.der`
- The long-lived Google Hardware Attestation Root (the classic root documented
  in Android's Key Attestation developer docs).
- Self-signed X.509v3, subject == issuer `serialNumber=f92009e853b6b045`.
- Key: RSA 4096-bit; signature: `sha256WithRSAEncryption`. `CA:TRUE`.
- Serial: `F1C172A699EAF51D`.
- Validity: `notBefore=2022-03-20 18:07:48 UTC`, `notAfter=2042-03-15 18:07:48 UTC`.
- Length: 1312 bytes.
- **SHA-256 (DER):** `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc`

### `google_key_attestation_ca1_ecdsa_p384.der`
- The newer RKP-era root `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US`
  (the ECDSA root that appears in the array alongside the classic RSA root
  during the current rotation window; cf. the RKP root rotation noted in
  `mobile.rs`).
- Self-signed X.509v3, subject == issuer
  `C=US, O=Google LLC, OU=Android, CN=Key Attestation CA1`.
- Key: ECDSA P-384 (`secp384r1`); signature: `ecdsa-with-SHA384`. `CA:TRUE`.
- Serial: `84A9D0297B0EB58AE7FF0E80DE760605`.
- Validity: `notBefore=2025-07-17 22:32:18 UTC`, `notAfter=2035-07-15 22:32:18 UTC`.
- Length: 550 bytes.
- **SHA-256 (DER):** `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`

## Honesty / scope

Pinning these roots makes an Android Key-Attestation chain *authenticatable*
against Google's genuine trust anchor. It does **NOT** by itself mean any real
StrongBox/TEE attestation has been verified: reaching a `Verdict::Genuine`
requires a real Key-Attestation leaf chain minted by a genuine device and signed
by Google's private key (hardware-gated — no such chain exists in this repo).
The offline test therefore proves (a) the roots are genuine self-signed X.509
CAs with the pinned fingerprints, (b) `mobile.rs` verify **fails closed** with no
root pinned, and (c) the pinned real roots are actually consulted as the trust
anchor. `vendored real root != attested device`. UNAUDITED.

Do not replace these bytes with anything but Google's genuine roots re-fetched
from the URL above — the anchor is the whole trust decision. Re-fetch and update
the fingerprints on the next RKP rotation.
