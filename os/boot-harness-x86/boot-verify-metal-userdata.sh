#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# boot-verify-metal-userdata.sh — EC2 user-data for a *.metal instance that
# self-provisions Nix + QEMU/KVM, pulls a Postern OS ISO, runs boot-verify.sh
# under REAL KVM, ships the evidence to S3, and (by default) self-terminates
# so the metal instance is never left running/billing after the check.
#
# STATUS: STAGED, NOT RUN. No instance has been launched with this. Written so
# the launch is a single `aws ec2 run-instances --user-data file://...` once a
# `.#iso` actually exists. Fill in the placeholders marked TODO before use.
#
# Target instance: c5.metal (96 vCPU / 192 GiB, us-west-2) — see the sizing
# note in boot-verify.sh's README companion. m5.metal (96 vCPU / 384 GiB) or
# m5zn.metal (48 vCPU / 192 GiB, smallest metal footprint available in
# us-west-2) are drop-in alternatives; nothing here is instance-type-specific
# beyond needing /dev/kvm, which every *.metal type exposes.
#
# QUOTA BLOCKER (checked 2026-07-13, account 184353710627, us-west-2):
#   Running On-Demand Standard (A,C,D,H,I,M,R,T,Z) instances (L-1216C47A) = 16
#   vCPUs. EVERY metal type in this family needs more (m5zn.metal=48,
#   c5n.metal=72, c5.metal/m5.metal=96). A quota increase to >=96 (or >=48 if
#   defaulting to m5zn.metal) MUST be requested and approved before
#   run-instances will succeed — it will otherwise fail with
#   VcpuLimitExceeded. Request it with:
#     aws service-quotas request-service-quota-increase \
#       --service-code ec2 --quota-code L-1216C47A --desired-value 96 \
#       --region us-west-2
#   (Not run by this task — quota changes are a separate, explicit step; this
#   file only documents the blocker so it isn't rediscovered at launch time.)
#
# Base AMI assumption: Ubuntu 22.04/24.04 LTS in us-west-2 (apt-based). Swap
# the package-manager block near the top if using Amazon Linux 2023 instead.
#
# What it does, in order:
#   1. Installs qemu-kvm, xorriso, jq, awscli, git, curl.
#   2. Confirms /dev/kvm (kvm_intel/kvm_amd already loaded on bare metal;
#      chmods it into the default user's reach).
#   3. Installs Nix (Determinate installer; unattended, multi-user).
#   4. Clones the repo (TODO: set REPO_URL/REPO_REF) to /opt/postern.
#   5. Fetches the built ISO from S3 (TODO: set ISO_S3_URI) — the metal
#      instance does NOT build the ISO itself; a separate Nix builder produces
#      it and stages it to S3, this instance only boots+grades it.
#   6. Runs os/boot-harness-x86/boot-verify.sh under KVM, both variants
#      (node, desktop) if both ISOs are present.
#   7. Uploads logs/evidence/summary to S3 (TODO: set RESULTS_S3_PREFIX).
#   8. Self-terminates (TODO: set SELF_TERMINATE=0 to disable, e.g. while
#      debugging interactively over SSM).
#
# Launch (once quota is approved and TODOs below are filled in — NOT run here):
#   aws ec2 run-instances \
#     --region us-west-2 \
#     --instance-type c5.metal \
#     --image-id ami-XXXXXXXX \
#     --key-name YOUR_KEY \
#     --iam-instance-profile Name=YOUR_S3_ACCESS_ROLE \
#     --instance-market-options '{"MarketType":"spot"}' \
#     --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=64,VolumeType=gp3}' \
#     --user-data file://os/boot-harness-x86/boot-verify-metal-userdata.sh \
#     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=postern-boot-verify},{Key=purpose,Value=iso-boot-verify},{Key=ephemeral,Value=true}]'
#
# (--instance-market-options spot is a cost control, not a requirement — metal
# spot capacity/pricing varies; drop it for on-demand if spot is unavailable.
# The IAM instance profile needs s3:GetObject on the ISO bucket and
# s3:PutObject on the results prefix; scope it tightly, not to all of S3.)

set -euo pipefail
exec > >(tee -a /var/log/postern-boot-verify-userdata.log) 2>&1

echo "=== Postern OS boot-verify metal bootstrap: $(date -u +%FT%TZ) ==="

# ---- TODO: fill these in before launch --------------------------------------
REPO_URL="TODO-git-remote-for-bp-wt-buckets"
REPO_REF="main"
ISO_S3_URI_NODE="s3://TODO-bucket/TODO-prefix/postern-os-node.iso"
ISO_S3_URI_DESKTOP="s3://TODO-bucket/TODO-prefix/postern-os-desktop.iso"
RESULTS_S3_PREFIX="s3://TODO-bucket/boot-verify-results/$(date -u +%Y%m%dT%H%M%SZ)"
SELF_TERMINATE=1
# -------------------------------------------------------------------------------

WORKDIR=/opt/postern
LOGDIR=/var/log/postern-boot-verify
mkdir -p "$LOGDIR"

echo "--- 1. packages ---"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  qemu-system-x86 qemu-utils xorriso libarchive-tools p7zip-full \
  jq awscli git curl ca-certificates

echo "--- 2. /dev/kvm sanity ---"
if [ ! -e /dev/kvm ]; then
  echo "FATAL: /dev/kvm absent on this instance. Wrong instance type (not" >&2
  echo "       *.metal) or nested-virt not exposed. Aborting." >&2
  exit 1
fi
chgrp kvm /dev/kvm || true
chmod 660 /dev/kvm || true
usermod -aG kvm ubuntu || true
echo "kvm ok: $(ls -l /dev/kvm)"

echo "--- 3. Nix (Determinate installer, unattended multi-user) ---"
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm
# shellcheck disable=SC1091
. /etc/profile.d/nix.sh 2>/dev/null || . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh

echo "--- 4. repo checkout ---"
if [ "$REPO_URL" = "TODO-git-remote-for-bp-wt-buckets" ]; then
  echo "FATAL: REPO_URL placeholder not filled in — edit this user-data before launch." >&2
  exit 1
fi
rm -rf "$WORKDIR"
git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$WORKDIR"

echo "--- 5. fetch ISOs from S3 ---"
ISO_NODE=""
ISO_DESKTOP=""
if aws s3 ls "$ISO_S3_URI_NODE" >/dev/null 2>&1; then
  ISO_NODE=/tmp/postern-node.iso
  aws s3 cp "$ISO_S3_URI_NODE" "$ISO_NODE"
else
  echo "WARN: node ISO not found at $ISO_S3_URI_NODE — skipping node variant." >&2
fi
if aws s3 ls "$ISO_S3_URI_DESKTOP" >/dev/null 2>&1; then
  ISO_DESKTOP=/tmp/postern-desktop.iso
  aws s3 cp "$ISO_S3_URI_DESKTOP" "$ISO_DESKTOP"
else
  echo "WARN: desktop ISO not found at $ISO_S3_URI_DESKTOP — skipping desktop variant." >&2
fi

echo "--- 6. boot-verify under KVM ---"
OVERALL_RC=0
BOOT_VERIFY="$WORKDIR/os/boot-harness-x86/boot-verify.sh"
chmod +x "$BOOT_VERIFY"

if [ -n "$ISO_NODE" ]; then
  echo "=== node variant ==="
  sh "$BOOT_VERIFY" --variant node --iso "$ISO_NODE" \
    --flake "$WORKDIR" \
    --log "$LOGDIR/node-kvm-boot.log" \
    --s3-results "$RESULTS_S3_PREFIX/node" \
    || OVERALL_RC=$?
fi

if [ -n "$ISO_DESKTOP" ]; then
  echo "=== desktop variant ==="
  sh "$BOOT_VERIFY" --variant desktop --iso "$ISO_DESKTOP" \
    --flake "$WORKDIR" \
    --log "$LOGDIR/desktop-kvm-boot.log" \
    --s3-results "$RESULTS_S3_PREFIX/desktop" \
    || { rc=$?; [ "$OVERALL_RC" -eq 0 ] && OVERALL_RC=$rc; }
fi

echo "--- 7. ship the userdata log itself too ---"
aws s3 cp /var/log/postern-boot-verify-userdata.log "$RESULTS_S3_PREFIX/userdata.log" || true

echo "=== overall rc=$OVERALL_RC ==="

echo "--- 8. self-terminate ---"
if [ "$SELF_TERMINATE" -eq 1 ]; then
  IID=$(curl -fsS -H "X-aws-ec2-metadata-token: $(curl -fsS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/meta-data/instance-id || true)
  REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $(curl -fsS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" http://169.254.169.254/latest/meta-data/placement/region || true)
  if [ -n "$IID" ] && [ -n "$REGION" ]; then
    echo "terminating self: $IID in $REGION (ephemeral by design — do not touch other instances)"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$IID" || true
  else
    echo "WARN: could not resolve instance-id/region via IMDSv2 — not self-terminating. Terminate manually." >&2
  fi
else
  echo "SELF_TERMINATE=0 — leaving instance running for interactive debugging (e.g. over SSM). Remember to terminate it manually."
fi

exit "$OVERALL_RC"
