#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# repro-verify-iso-builder-userdata.sh — EC2 user-data for an INDEPENDENT
# ISO-repro builder. Self-provisions Nix, checks out the EXACT pinned
# <LOCK_COMMIT> (see repro-verify-iso.sh's header for why "exact" matters —
# both builders MUST share a byte-identical flake.lock, not just "run
# flake-lock.sh on the same day"), builds `.#iso` (or whatever --attr this
# is parameterized for), and ships the JSON manifest to S3 so it can be
# diffed against the other builder's manifest with:
#   repro-verify-iso.sh compare --a s3://.../builder-a-iso.json \
#                                --b s3://.../builder-b-iso.json
#
# STATUS: STAGED, NOT RUN. No instance has been launched with this. Written
# so the launch is a single `aws ec2 run-instances --user-data file://...`
# once <LOCK_COMMIT> exists (see the FILL-IN-FIRST section below). Mirrors
# os/boot-harness-x86/boot-verify-metal-userdata.sh's conventions (self-
# terminating, IMDSv2, TODO placeholders that fail loudly if left unfilled)
# but is DELIBERATELY NOT a *.metal instance — building `.#iso` needs no
# /dev/kvm (nothing is booted here), so a plain on-demand instance works and
# stays under the account's default vCPU quota (see the QUOTA note below,
# the opposite situation from the metal-only boot-verify path).
#
# This ONE script provisions EITHER builder — set BUILDER_ROLE to "builder-a"
# or "builder-b" per launch (different instance type / AZ / region recommended
# for the two, so the "independent" in "two independent builders" means
# something beyond "two processes on the same underlying host"; see the
# launch examples below).
#
# What it does, in order:
#   1. Installs jq, awscli, git, curl (small footprint — no qemu needed).
#   2. Installs Nix (Determinate installer; unattended, multi-user).
#   3. Clones the repo (TODO: set REPO_URL) at EXPECT_COMMIT (TODO) and
#      REFUSES to continue if the checked-out commit doesn't match exactly
#      (fail-closed — a silent branch-HEAD drift would invalidate the whole
#      proof, see repro-verify-iso.sh's header).
#   4. Runs repro-verify-iso.sh build --attr "$ATTR" --role "$BUILDER_ROLE"
#      --commit "$EXPECT_COMMIT" --s3 "$RESULTS_S3_PREFIX".
#   5. Uploads this userdata's own log to S3 too.
#   6. Self-terminates (TODO: set SELF_TERMINATE=0 to disable, e.g. while
#      debugging interactively over SSM).
#
# ---------------------------------------------------------------------------
# FILL IN FIRST (both TODOs are fail-closed — the script refuses to proceed
# on the placeholder values rather than silently doing the wrong thing)
# ---------------------------------------------------------------------------
#   REPO_URL       git remote for bp-wt-buckets (TODO)
#   EXPECT_COMMIT  the EXACT git sha of <LOCK_COMMIT> — the commit where
#                  flake.lock is FILLED (non-empty-seed), per
#                  docs/plan/FLAKE-REPRO.md §3. As of this writing, the
#                  integration HEAD (0ee1af648c698babf866e770f7b326ad6b10d0f8)
#                  still carries the EMPTY-SEED flake.lock — scripts/flake-
#                  lock.sh has NOT yet been run on any Nix host. <LOCK_COMMIT>
#                  is therefore a CHILD of 0ee1af6 that does not exist yet.
#                  Do not point EXPECT_COMMIT at 0ee1af6 itself; that commit
#                  will fail this script's own fail-closed lock check in
#                  step 3/4 (repro-verify-iso.sh refuses the empty seed) —
#                  it is listed here only as the KNOWN-GOOD ancestor to branch
#                  <LOCK_COMMIT> from once §3 has run.
#
# ---------------------------------------------------------------------------
# QUOTA (checked 2026-07-13, account 184353710627, us-west-2, read-only
# `aws service-quotas get-service-quota` — no instances launched):
#   L-1216C47A "Running On-Demand Standard (A,C,D,H,I,M,R,T,Z) instances" = 16
#   vCPUs, unchanged from the metal-boot-verify blocker. UNLIKE that path,
#   this script does NOT need *.metal (no /dev/kvm requirement — building is
#   not booting), so a modest instance fits comfortably: the default ATTR
#   (c6i.2xlarge = 8 vCPU) lets BOTH builder-a and builder-b run
#   SIMULTANEOUSLY within the existing 16-vCPU quota, no increase request
#   needed. (c6i.4xlarge = 16 vCPU also works but would consume the entire
#   quota for one instance at a time — fine for a sequential A-then-B run,
#   not for a concurrent one.)
#
# Base AMI assumption: Ubuntu 22.04/24.04 LTS (apt-based). Swap the
# package-manager block near the top if using Amazon Linux 2023 instead.
#
# Launch (once <LOCK_COMMIT> exists and the TODOs below are filled in — NOT
# run here):
#   # Builder A — Intel, us-west-2a:
#   aws ec2 run-instances \
#     --region us-west-2 --availability-zone us-west-2a \
#     --instance-type c6i.2xlarge \
#     --image-id ami-XXXXXXXX \
#     --key-name YOUR_KEY \
#     --iam-instance-profile Name=YOUR_S3_ACCESS_ROLE \
#     --instance-market-options '{"MarketType":"spot"}' \
#     --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=64,VolumeType=gp3}' \
#     --user-data file://os/repro/repro-verify-iso-builder-userdata.sh \
#     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=postern-repro-builder-a},{Key=purpose,Value=iso-repro-verify},{Key=role,Value=builder-a},{Key=ephemeral,Value=true}]'
#
#   # Builder B — AMD, us-west-2b (different family + AZ: strengthens the
#   # "independent" claim beyond "same AMI, same rack"):
#   aws ec2 run-instances \
#     --region us-west-2 --availability-zone us-west-2b \
#     --instance-type c6a.2xlarge \
#     --image-id ami-XXXXXXXX \
#     --key-name YOUR_KEY \
#     --iam-instance-profile Name=YOUR_S3_ACCESS_ROLE \
#     --instance-market-options '{"MarketType":"spot"}' \
#     --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=64,VolumeType=gp3}' \
#     --user-data file://os/repro/repro-verify-iso-builder-userdata.sh \
#     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=postern-repro-builder-b},{Key=purpose,Value=iso-repro-verify},{Key=role,Value=builder-b},{Key=ephemeral,Value=true}]'
#
# (--user-data is IDENTICAL for both — BUILDER_ROLE below is read from EC2
# instance tags at boot via IMDSv2, falling back to a TODO default if tag
# lookup fails, so you don't have to hand-edit two copies of this file. Set
# --iam-instance-profile to a role scoped to s3:GetObject on the repo-clone
# needs (none, if REPO_URL is public) and s3:PutObject on the results prefix
# only — not broad S3 access.)

set -euo pipefail
exec > >(tee -a /var/log/postern-repro-verify-userdata.log) 2>&1

echo "=== Postern OS repro-verify-iso builder bootstrap: $(date -u +%FT%TZ) ==="

# ---- TODO: fill these in before launch --------------------------------------
REPO_URL="TODO-git-remote-for-bp-wt-buckets"
EXPECT_COMMIT="TODO-lock-commit-child-of-0ee1af648c698babf866e770f7b326ad6b10d0f8"
ATTR="iso"
RESULTS_S3_PREFIX="s3://TODO-bucket/repro-verify-iso/TODO-lock-commit"
SELF_TERMINATE=1
# -------------------------------------------------------------------------------

WORKDIR=/opt/postern
LOGDIR=/var/log/postern-repro-verify
mkdir -p "$LOGDIR"

echo "--- 0. resolve BUILDER_ROLE (EC2 tag 'role' via IMDSv2, else TODO default) ---"
IMDS_TOKEN=$(curl -fsS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' || true)
INSTANCE_ID=$(curl -fsS -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id || true)
REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/region || true)
BUILDER_ROLE="TODO-builder-role"
if [ -n "$INSTANCE_ID" ] && [ -n "$REGION" ]; then
  TAG_ROLE=$(aws ec2 describe-tags --region "$REGION" \
    --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=role" \
    --query 'Tags[0].Value' --output text 2>/dev/null || true)
  [ -n "$TAG_ROLE" ] && [ "$TAG_ROLE" != "None" ] && BUILDER_ROLE="$TAG_ROLE"
fi
echo "builder role: $BUILDER_ROLE  (instance=$INSTANCE_ID region=$REGION)"

echo "--- 1. packages (no qemu — this script only BUILDS, it never boots) ---"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends jq awscli git curl ca-certificates

echo "--- 2. Nix (Determinate installer, unattended multi-user) ---"
curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm
# shellcheck disable=SC1091
. /etc/profile.d/nix.sh 2>/dev/null || . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh

echo "--- 3. repo checkout, PINNED to the exact lock commit ---"
if [ "$REPO_URL" = "TODO-git-remote-for-bp-wt-buckets" ]; then
  echo "FATAL: REPO_URL placeholder not filled in — edit this user-data before launch." >&2
  exit 1
fi
case "$EXPECT_COMMIT" in
  TODO-*)
    echo "FATAL: EXPECT_COMMIT placeholder not filled in. This is fail-closed on" >&2
    echo "       purpose: launching against an unpinned/floating ref would let the" >&2
    echo "       two builders silently diverge on SOURCE, which makes any store-" >&2
    echo "       path comparison meaningless (see repro-verify-iso.sh's header," >&2
    echo "       'WHY THIS CANNOT JUST BE each builder runs flake-lock.sh')." >&2
    exit 1
    ;;
esac
rm -rf "$WORKDIR"
git clone "$REPO_URL" "$WORKDIR"
cd "$WORKDIR"
git checkout --detach "$EXPECT_COMMIT"
ACTUAL_COMMIT=$(git rev-parse HEAD)
if [ "$ACTUAL_COMMIT" != "$EXPECT_COMMIT" ]; then
  echo "FATAL: checked out commit ($ACTUAL_COMMIT) != EXPECT_COMMIT ($EXPECT_COMMIT)." >&2
  exit 1
fi
echo "checked out exactly $ACTUAL_COMMIT"

echo "--- 4. build + manifest (repro-verify-iso.sh does its own fail-closed lock check) ---"
REPRO_SCRIPT="$WORKDIR/os/repro/repro-verify-iso.sh"
chmod +x "$REPRO_SCRIPT"
OVERALL_RC=0
"$REPRO_SCRIPT" build \
  --attr "$ATTR" \
  --role "$BUILDER_ROLE" \
  --commit "$EXPECT_COMMIT" \
  --flake "$WORKDIR" \
  --out "$LOGDIR/${BUILDER_ROLE}-${ATTR}.json" \
  --s3 "$RESULTS_S3_PREFIX" \
  || OVERALL_RC=$?

echo "--- 5. ship the userdata log itself too ---"
if [ -n "${REGION:-}" ]; then :; fi  # region already resolved above for tag lookup
aws s3 cp /var/log/postern-repro-verify-userdata.log "$RESULTS_S3_PREFIX/${BUILDER_ROLE}-userdata.log" || true

echo "=== overall rc=$OVERALL_RC (role=$BUILDER_ROLE attr=$ATTR commit=$EXPECT_COMMIT) ==="

echo "--- 6. self-terminate ---"
if [ "$SELF_TERMINATE" -eq 1 ]; then
  if [ -n "$INSTANCE_ID" ] && [ -n "$REGION" ]; then
    echo "terminating self: $INSTANCE_ID in $REGION (ephemeral by design — do not touch other instances)"
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID" || true
  else
    echo "WARN: could not resolve instance-id/region via IMDSv2 — not self-terminating. Terminate manually." >&2
  fi
else
  echo "SELF_TERMINATE=0 — leaving instance running for interactive debugging (e.g. over SSM). Remember to terminate it manually."
fi

exit "$OVERALL_RC"
