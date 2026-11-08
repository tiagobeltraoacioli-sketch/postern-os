#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# EC2 USER-DATA — headless Postern OS Mobile build on a native aarch64 Graviton.
# Paste this whole file into the EC2 launch "User data" box. On first boot it:
#   1. verifies it is on aarch64 (refuses otherwise — the whole point is NO
#      emulation; the aarch64 Rust build crashes under qemu-user),
#   2. installs Nix (flakes on),
#   3. clones the repo (branch roadmap/consolidate-all),
#   4. builds .#packages.aarch64-linux.mobile-image against nixos-unstable
#      (the channel mobile-nixos tracks — eval already verified: 777 derivations),
#   5. uploads the .img + build log + sha256 to your S3 bucket,
#   6. optionally QEMU-boots it, optionally powers off to stop billing.
# Everything is echoed to the EC2 SYSTEM LOG too, so you can watch via
#   aws ec2 get-console-output --instance-id <id> --latest
# without ever SSH-ing in.
#
# ── LAUNCH SETTINGS (do these in the console) ────────────────────────────────
#   AMI            : Amazon Linux 2023, ARM64   (has aws-cli + SSM preinstalled)
#   Instance type  : c7g.4xlarge  (16 vCPU / 32 GB — fast; ~1 GB disk needs 40+ GB)
#   Storage        : 60 GB gp3
#   IAM role       : an instance profile allowing s3:PutObject on your bucket
#                    (so the upload in step 5 works with NO keys in this file)
#   Security group : none needed (no inbound; it phones nothing but S3/github)
#
# ── FILL THESE IN ────────────────────────────────────────────────────────────
# The token lives in its OWN variable and the clone URL stays token-free: the
# clone below feeds it to git through a credential helper, so the secret can
# never appear in the `set -x` trace that ships to S3 as build.log (a
# tokenized URL in the traced `git clone` line was exactly that leak).
GITLAB_TOKEN="REPLACE_WITH_A_SHORTLIVED_GITLAB_TOKEN"
GITLAB_REPO_URL="https://gitlab.com/bloch-sis-group/bloch-sis-project.git"
BRANCH="roadmap/consolidate-all"
S3_BUCKET="REPLACE_WITH_YOUR_BUCKET_NAME"          # e.g. postern-mobile-out (must already exist, same or any region)
S3_PREFIX="mobile-build"
DO_BOOT="0"        # "1" = also QEMU-boot the image and capture a graded log
DO_SHUTDOWN="1"    # "1" = poweroff after a SUCCESSFUL upload (stops billing; STOP the instance, don't forget to terminate)
UNSTABLE_REV="18b9261cb3294b6d2a06d03f96872827b8fe2698"   # the nixos-unstable rev the eval was verified against
#
# ⚠️  SECURITY: user-data is readable by anything on the instance via
#     http://169.254.169.254/latest/user-data — so the GitLab token above is
#     EXPOSED there. Use a SHORT-LIVED, read-only deploy token, and REVOKE it
#     right after the build. Prefer an IAM ROLE (above) over pasting AWS keys —
#     never put AWS secret keys in user-data.
#     (What IS fixed here: the token no longer reaches the xtrace/build.log
#     that gets uploaded to S3 — but the user-data exposure above remains,
#     so the short-lived + revoke discipline is still mandatory.)
# ─────────────────────────────────────────────────────────────────────────────
set -x
exec > >(tee -a /var/log/postern-mobile.log) 2>&1
say(){ echo; echo "═══ [postern-mobile] $* ═══"; }
fail(){ echo "═══ [postern-mobile] FAILED: $* ═══"; exit 1; }

say "start $(date -u) on $(uname -m)"
case "$(uname -m)" in aarch64|arm64) : ;; *) fail "not aarch64 ($(uname -m)) — this must run on a Graviton or the Rust build emulates and crashes";; esac

# 1) deps + Nix
if command -v dnf >/dev/null 2>&1; then dnf install -y git tar xz qemu-img 2>/dev/null || dnf install -y git tar xz; fi
if ! command -v nix >/dev/null 2>&1; then
  say "installing Nix"
  curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm || fail "nix install"
fi
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh 2>/dev/null || true
export NIX_CONFIG="experimental-features = nix-command flakes"

# 2) source
cd /root || cd /home/ec2-user || cd /tmp
rm -rf repo
say "cloning $BRANCH"
# TOKEN HYGIENE — the token must NEVER hit the S3-shipped log:
#   * xtrace is suspended around the clone ({ set +x; } 2>/dev/null keeps even
#     the toggle line out of the trace);
#   * the token goes to git via an inline credential helper whose body is
#     SINGLE-QUOTED — the shell never expands ${GITLAB_TOKEN} on the command
#     line, git expands it in a subprocess — so neither xtrace nor a failed
#     `git clone` error message can ever print the secret (the printed URL is
#     token-free);
#   * no other line in this script echoes $GITLAB_TOKEN.
{ set +x; } 2>/dev/null
export GITLAB_TOKEN
git -c credential.helper= \
    -c credential.helper='!f(){ echo "username=oauth2"; echo "password=${GITLAB_TOKEN}"; }; f' \
    clone --depth 1 -b "$BRANCH" "$GITLAB_REPO_URL" repo || fail "git clone (check the token)"
unset GITLAB_TOKEN
set -x
cd repo || fail "cd repo"
say "HEAD $(git log -1 --oneline)"

# 3) native build (aarch64 host → aarch64 target, no emulation)
say "building .#packages.aarch64-linux.mobile-image (native; ~20-90 min, mostly cache.nixos.org substitutes)"
if nix build ".#packages.aarch64-linux.mobile-image" \
      --override-input nixpkgs-mobile "github:NixOS/nixpkgs/${UNSTABLE_REV}" \
      -o /root/mobile-result --print-build-logs ; then
  BUILD_OK=1
else
  BUILD_OK=0
  say "BUILD FAILED — see the log above / in S3. This is honest evidence; record it in os/boot-harness/evidence/."
fi

# 4) locate artifact + hash
IMG=""
if [ "$BUILD_OK" = "1" ]; then
  IMG="$(find "$(readlink -f /root/mobile-result)" -maxdepth 3 -type f \( -name '*.img' -o -name '*.img.*' -o -name '*.raw' \) 2>/dev/null | head -1)"
  [ -n "$IMG" ] && { SHA="$(sha256sum "$IMG" | cut -d' ' -f1)"; say "ARTIFACT $IMG  sha256=$SHA"; } || say "built, but no .img file located under the result — inspect /root/mobile-result"
fi

# 5) upload log + artifact to S3 (uses the instance IAM role — no keys here)
UP_OK=0
if [ -n "$S3_BUCKET" ] && [ "$S3_BUCKET" != "REPLACE_WITH_YOUR_BUCKET_NAME" ]; then
  say "uploading to s3://$S3_BUCKET/$S3_PREFIX/"
  aws s3 cp /var/log/postern-mobile.log "s3://$S3_BUCKET/$S3_PREFIX/build.log" && UP_OK=1
  if [ -n "$IMG" ]; then
    aws s3 cp "$IMG" "s3://$S3_BUCKET/$S3_PREFIX/$(basename "$IMG")" && \
    printf '%s  %s\n' "$SHA" "$(basename "$IMG")" | aws s3 cp - "s3://$S3_BUCKET/$S3_PREFIX/SHA256SUMS" || UP_OK=0
  fi
  say "S3 upload done (ok=$UP_OK)"
else
  say "S3_BUCKET not set — artifact stays at $IMG on the instance (retrieve via SSM/scp)."
fi

# 6) optional QEMU boot (software boot chain only — not hardware, not attestation)
if [ "$DO_BOOT" = "1" ] && [ -n "$IMG" ]; then
  say "attempting QEMU-aarch64 boot (graded harness)"
  dnf install -y qemu-system-aarch64 2>/dev/null || true
  [ -x os/boot-harness/boot-qemu-aarch64.sh ] && IMG_PATH="$IMG" bash os/boot-harness/boot-qemu-aarch64.sh || say "boot harness not run/failed — read os/boot-harness/evidence/ (an honest FAIL is still evidence)"
  [ "$UP_OK" = "1" ] && aws s3 cp os/boot-harness/evidence/aarch64-mobile-boot.evidence "s3://$S3_BUCKET/$S3_PREFIX/boot.evidence" 2>/dev/null || true
fi

say "DONE  build_ok=$BUILD_OK  upload_ok=$UP_OK  $(date -u)"
say "REMINDER: revoke the GitLab deploy token now; UNAUDITED; built≠booted; QEMU≠hardware."
# 7) stop billing (only after a good upload so you don't lose the artifact)
if [ "$DO_SHUTDOWN" = "1" ] && [ "$UP_OK" = "1" ]; then say "powering off (artifact safe in S3)"; sleep 5; poweroff; fi
