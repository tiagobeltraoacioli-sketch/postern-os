# Welcome to Postern for postmarketOS — community edition

This is the short note shown right after install (shipped by `postern-apps` to
`/usr/share/doc/postern-apps/first-run.md`; `../postern/postern.post-install`
points at it). The long-form version is the "about this tier" screen at
`/usr/share/postern/first-run/about-tier.txt`, and the same rails ride the
login MOTD (`../overlay/etc/motd`).

We would rather tell you than have you find out.

## The one thing to understand: which tier this is

**You are on the lower-trust, NON-attestable tier.** This is Postern
*software* on postmarketOS — it is **not "Postern OS"**, and it is **not
covered by the Postern Seal**.

> Postern software on postmarketOS. No reproducibility or attestation
> guarantee. The attestable images are "Postern OS" (Mobile NixOS) only.

- Packages are **signed** — you can verify *who* published them and that they
  were not tampered with in transit.
- They are **not reproducible** — nobody, including us, can rebuild a
  bit-identical file (postmarketOS/Alpine is not bit-reproducible), and this
  repo attests nothing about the rest of your system.
- The Seal covers only the reproducible, verity-sealed Postern OS (Nix)
  images, on a shorter list of devices.

## Your wallet keys are in software

The wallet is the centerpiece here, and its keys are stored **in software**,
encrypted at rest. There is **no hardware-backed keystore** on this platform
(no TEE, no StrongBox). Fine for daily use; not for keys you cannot afford to
lose.

## Privacy is on, and it is transparent

- Traffic routes through **Tor via Arti** (the Rust Tor stack): the node
  embeds it in-process, and an on-device SOCKS proxy on `127.0.0.1:9150`
  serves the app suite. Config: `/etc/postern/arti.toml`.
- A **default-deny firewall** blocks unsolicited inbound traffic.
  Config: `/etc/nftables.d/postern.nft`.
- **No covert telemetry.** Nothing here phones home. Any future analytics will
  be **opt-in and disclosed** before a single byte leaves the device.

## The rest, plainly

- The **Postern coin has no monetary value**, and no value is claimed for it.
  Postern's revenue never touches the coin. **Personal use is free.**
- Nothing in Postern is **legal or financial advice**.
- Want the attestable tier? That is exactly what **Postern OS** (the Nix
  images) provides, on a shorter list of devices — on the site, honestly
  labeled.

What works — once you have booted it on a real device — is the portable heart
of Postern: the wallet, the app suite, Tor routing. Those parts were portable
all along. As of writing, **nothing in this overlay has been built or booted on
any device** (`../HONESTY.md`); treat every "works" here as pending that boot.
