# Postern OS

Private source repository for the Postern OS Linux distribution and its supporting
desktop, mobile, wallet and attestation components.

Imported from the original [Postern product repository on GitLab](https://gitlab.com/bloch-sis-group/bloch-sis-project)
at commit [`257ab0703ffc63a7faddb5bf646791e52b3dee3f`](https://gitlab.com/bloch-sis-group/bloch-sis-project/-/tree/257ab0703ffc63a7faddb5bf646791e52b3dee3f).
The upstream product workspace is retained because the OS, desktop and mobile
components reference its shared crates and integration modules.

This import preserves the historical source. It does **not** migrate the OS to
the current Bloch network, produce a new ISO, or deploy a validator.

## Source layout

| Path | Contents |
| --- | --- |
| `os/`, `flake.nix`, `flake.lock` | NixOS profiles, desktop/mobile/cloud images, packaging and boot harnesses |
| `crates/` | Shared privacy, wallet, policy, cryptography and attestation components |
| `desktop/`, `mobile/`, `apps/` | Product interfaces and platform applications |
| `integration/`, `android-*`, `os-portal-v2/` | Pairing, signing and platform integration |
| `docs/`, `scripts/` | Upstream specifications, checks and build procedures |
| `UPSTREAM.json`, `SOURCE-MANIFEST.json` | Source revision, archive digest and per-file import hashes |

`data/` contains upstream Rust source packages; it is not an operator database.
The original product overview is preserved in [UPSTREAM-README.md](UPSTREAM-README.md).
The original GitLab CI configuration is retained as source; it is not a GitHub
Actions workflow and does not deploy this repository.

## Integration with the current Bloch node

The imported configuration belongs to the PoW era: `os/configuration.nix`
enables `services.bloch` with mining, `os/bloch-node.nix` starts the legacy
`bloch` executable, and protocol dependencies are pinned to historical GitLab
revisions. These settings must be adapted before use with the current
`bloch-pos` node.

The recommended first integration keeps the operating system separate from
consensus: package an explicitly approved Bloch release for the target Linux
architecture, configure its genesis/data directory/keystore and network options,
then adapt the applications to its supported RPC interface. Reuse the current
node's NixOS service module where compatible, supplying a real package containing
`bin/bloch-pos`.

| Change | Required artifact |
| --- | --- |
| OS packaging, services and an external RPC client | New OS image/package; no protocol change inherently required |
| Architecture or runtime compatibility | Possibly a rebuild of the same node revision, without changing consensus |
| New functionality inside the node executable | New node build for the nodes using that functionality |
| New block-validation, validator-admission or reward rules | Coordinated protocol change and validator upgrade |

Hardware attestation must be evaluated separately from software build metadata.
This import makes no new claim that an image boots, that a hardware attestation
chain is verified, or that the historical build is compatible with production.
Nix evaluation, image builds and boot/hardware tests were not run as part of the
repository import. Existing evidence and its limitations remain in `os/`.

## Licenses and credentials

Preserve [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE),
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) and the component-specific notices.
Their terms continue to apply to the imported code and third-party assets.

Do not commit access tokens, validator keys, wallet seeds or operator credentials.
Public certificate chains and explicitly documented development/test fixtures
remain part of the upstream source.
