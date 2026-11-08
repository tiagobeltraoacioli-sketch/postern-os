# SPDX-License-Identifier: MIT OR Apache-2.0
# cloud-image.nix — OPTIONAL Nix image profile for the Postern Cloud (hosted)
# edition. Builds a deterministic OCI/container image with dockerTools instead of
# a Containerfile, for operators who want Nix's content-addressed, pinned build
# graph.
#
# REPRODUCIBLE-BY-DESIGN, NOT REPRODUCED. dockerTools.buildLayeredImage pins
# every input and sets a fixed image creation time, so the image is deterministic
# by construction — but no independent bit-for-bit reproduction is claimed or
# attested here. Verify it yourself: `nix build --rebuild` then compare, or load
# the tarball twice and diff the digests.
#
# HOSTED = LESS PRIVATE (DISCLOSED). This produces the *hosted* edition image;
# running it as a managed service exposes traffic/metadata to the operator that
# self-hosting or on-device would not. Disclosed here and in BUILD-AND-DEPLOY.md.
#
# Written on a non-Nix host — NOT built here. Mirrors the style of the repo's
# os/*.nix modules (see ../../../os/cloud.nix) and the packaging skeleton in
# ../../deployment/packaging/enterprise-profile.nix. Iterate on a real Nix host.
# Not hardened, not audited, not production-ready.
#
# Build (operator-run, on a Nix host):
#   nix-build cloud-image.nix -A image
#   # -> ./result is an OCI tarball; load with: podman load < result
# Reproducibility check:
#   nix-build cloud-image.nix -A image --rebuild
{
  pkgs ? import <nixpkgs> { },

  # Provide the verified cloud artifact. No default: this is a skeleton. Supply a
  # package you built from source (strongest) or verified via
  # ../../deployment/signing/verify-build.sh.
  posternCloud ? null,

  # Fixed image creation time keeps the output deterministic. Override with your
  # release's SOURCE_DATE_EPOCH. "1" (not "now") so the build never embeds a
  # wall-clock timestamp.
  creationTime ? "@1",

  tag ? "local",
}:

let
  lib = pkgs.lib;

  # A non-root passwd/group baked deterministically into the image so the service
  # runs as uid/gid 10001, matching the Containerfile.
  nonRootEtc = pkgs.runCommand "postern-cloud-etc" { } ''
    mkdir -p $out/etc $out/var/lib/postern $out/etc/postern $out/tmp
    printf 'root:x:0:0:root:/root:/sbin/nologin\n' > $out/etc/passwd
    printf 'postern:x:10001:10001:postern:/var/lib/postern:/sbin/nologin\n' >> $out/etc/passwd
    printf 'root:x:0:\npostern:x:10001:\n' > $out/etc/group
    printf 'postern:!:1::::::\n' > $out/etc/shadow
  '';
in
{
  # The deployable image. Layered for cache-friendly, deterministic assembly.
  image = pkgs.dockerTools.buildLayeredImage {
    name = "postern-cloud";
    inherit tag;

    # Deterministic: fixed creation time, no impure "now".
    created = creationTime;

    contents =
      [ nonRootEtc ]
      ++ lib.optional (posternCloud != null) posternCloud;

    config = {
      # Replace with the real entrypoint from posternCloud once supplied.
      Entrypoint =
        if posternCloud != null
        then [ "${posternCloud}/bin/postern-cloud" ]
        else [ "/bin/sh" "-c" "echo 'postern-cloud: supply posternCloud (see cloud-image.nix)'; exit 1" ];

      User = "10001:10001";
      WorkingDir = "/var/lib/postern";
      ExposedPorts = { "8080/tcp" = { }; };
      Volumes = { "/var/lib/postern" = { }; };

      Env = [
        # Privacy posture, by construction. No telemetry; egress controlled.
        "POSTERN_TELEMETRY=off"
        "POSTERN_EGRESS=controlled"
        "POSTERN_EDITION=cloud"
        "TZ=UTC"
        "LANG=C.UTF-8"
        "LC_ALL=C.UTF-8"
      ];

      Labels = {
        "org.opencontainers.image.title" = "Postern Cloud";
        "org.opencontainers.image.description" =
          "Postern Cloud (hosted) edition — reference deployable image. Reproducible-by-design, not reproduced. Not audited.";
        "org.opencontainers.image.licenses" = "MIT OR Apache-2.0";
        "com.postern.edition" = "cloud";
        "com.postern.telemetry" = "off";
        "com.postern.privacy-note" =
          "hosted deployment is less private than self-hosting; disclosed.";
      };
    };
  };
}
