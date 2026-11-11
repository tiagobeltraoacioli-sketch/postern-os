# postern-vault

Encrypted container files for private data. A vault is one ordinary file that
holds an encrypted ext4 file system (LUKS2, AES-256-XTS, Argon2id key
derivation). Because it is a file, it can live on removable media: a live
session can keep documents across restarts without writing anything readable
to a disk.

```sh
postern-vault create /run/media/nixos/USB/notes.vault 2G   # asks for a passphrase twice
postern-vault open   /run/media/nixos/USB/notes.vault      # mounts /run/postern-vault/notes
postern-vault list
postern-vault close notes                                   # or: postern-vault close --all
```

`--key-file KEY` uses the contents of a file instead of a passphrase, for
`create` and `open`. `--read-only` opens a vault without allowing writes. When
standard input is not a terminal, the passphrase is its first line.

Opening, formatting and mounting need root; the tool calls `sudo` for exactly
those steps. The file system inside belongs to the user who created the vault
and is mounted `nosuid,nodev`.

## Limits

- **No recovery.** A lost passphrase or key file means lost data. There is no
  second key slot, backup header or escrow unless you add one with `cryptsetup`.
- The vault protects data **at rest**, while it is closed. While it is open,
  every program running as that user (and root) can read it.
- It hides the contents, not the existence or size of the file, and not what
  programs copied elsewhere (caches, thumbnails, temporary files).
- A passphrase is only checked for a minimum length of 8 characters; its
  strength is the user's responsibility. A key file is as private as the place
  it is stored.
- Powering off without `close` can lose recent writes, like any file system.
- It is not a disk-encryption installer and does not encrypt the system itself.

## Tests

`bash -n` in `scripts/postern-test-core.sh`; the booted test in
`os/tests/privacy.nix` creates a vault, writes to it, checks that the marker is
not readable in the closed file, rejects a wrong passphrase and reopens it.
