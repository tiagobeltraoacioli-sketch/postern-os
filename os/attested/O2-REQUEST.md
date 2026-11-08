<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Request to OS Dev O2 (sole owner of `flake.nix`)

O5 requests one **optional** additive attribute. O5 does not edit `flake.nix`.
Drop this next to the existing `apps.aarch64-linux.boot-qemu` block (same style,
`writeShellApplication`). It is x86_64 because `attested-image` is x86_64-only.

```nix
      # `nix run .#attested-roothash` — PRODUCE the real dm-verity roothash of
      # the attested image (backlog #4). Builds `.#attested-image`, reads the
      # roothash systemd-repart emits into repart-output.json, prints it. With
      # `-- --bind` it runs pass 2 (rebind roothash= into the measured UKI
      # cmdline). VM-gated: needs a Nix host — NOT built/run on the mac.
      apps.x86_64-linux.attested-roothash =
        let pkgs = import nixpkgs { system = "x86_64-linux"; };
        in {
          type = "app";
          program = "${pkgs.writeShellApplication {
            name = "postern-attested-roothash";
            runtimeInputs = [ pkgs.nix pkgs.jq pkgs.coreutils pkgs.gnugrep ];
            text = builtins.readFile ./os/attested/extract-roothash.sh;
          }}/bin/postern-attested-roothash";
        };
```

Notes for O2:
- `extract-roothash.sh` takes args (`-f/-a/-o/--bind`), so invoke as
  `nix run .#attested-roothash -- -f . -a attested-image --bind`.
- `--bind`'s inline `--expr` override needs `--impure` and a **local** flake path
  (it resolves `-f .` to an absolute path and calls `builtins.getFlake` +
  `extendModules` to set `bloch.attested.osRoothash`). No `flake.nix` change is
  needed for that override to work; the app is purely a convenience wrapper.
- Optional `checks` entry: a `nix flake check` derivation could assert
  `postern-attested.config.bloch.attested.osRoothash == null` (the honest
  placeholder default), so CI fails if anyone hardcodes a fabricated roothash.
  O5 can supply that snippet on request if O2 wants it.
