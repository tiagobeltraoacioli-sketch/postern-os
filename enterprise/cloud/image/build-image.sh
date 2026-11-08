#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# build-image.sh — build the Postern Cloud (hosted) edition image LOCALLY.
#
# This script BUILDS ONLY. It does NOT push to a registry and does NOT deploy.
# Pushing and deploying are separate, explicit operator steps documented in
# BUILD-AND-DEPLOY.md — kept apart on purpose so a build can never accidentally
# ship or go live.
#
# It sets the reproducibility knobs the Containerfile expects (base pinned by
# DIGEST, SOURCE_DATE_EPOCH, deterministic locale/timezone) and prints the image
# digest so you can compare rebuilds. REPRODUCIBLE-BY-DESIGN is NOT REPRODUCED:
# verify parity yourself (rebuild + compare digests, or diffoscope).
#
# HOSTED = LESS PRIVATE (DISCLOSED): this builds the hosted edition; running it
# as a managed service is a disclosed privacy trade-off (see BUILD-AND-DEPLOY.md).
#
# No secrets are baked in — the image takes config/secrets only at runtime.
#
# Usage:
#   ./build-image.sh -d <base-digest> [-t <tag>] [-e <epoch>] [-r <engine>] [-n]
#
#   -d  base image digest, e.g. sha256:abc...  (required; vet it yourself)
#   -t  image tag                (default: postern-cloud:local)
#   -e  SOURCE_DATE_EPOCH        (default: git commit time, else 0)
#   -r  container engine         (podman|docker; default: autodetect)
#   -n  dry-run: print the build command, do not run it
#   -h  help
#
# Exit status: 0 = image built locally; non-zero = build failed / bad input.
set -eu

prog="build-image"
die() { printf '%s: %s\n' "$prog" "$*" >&2; exit 1; }
log() { printf '%s: %s\n' "$prog" "$*" >&2; }

# Directory this script lives in, so it works from any CWD.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

BASE_DIGEST=""
TAG="postern-cloud:local"
EPOCH=""
ENGINE=""
DRYRUN=0

while getopts ':d:t:e:r:nh' opt; do
	case "$opt" in
		d) BASE_DIGEST="$OPTARG" ;;
		t) TAG="$OPTARG" ;;
		e) EPOCH="$OPTARG" ;;
		r) ENGINE="$OPTARG" ;;
		n) DRYRUN=1 ;;
		h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		:) die "option -$OPTARG needs a value (try -h)" ;;
		\?) die "unknown option -$OPTARG (try -h)" ;;
	esac
done

# ── Base digest: required and must be a real, pinned sha256 digest ──────────
[ -n "$BASE_DIGEST" ] || die "missing -d <base-digest> (pin the base by digest; try -h)"
case "$BASE_DIGEST" in
	sha256:*) : ;;
	*) die "base digest must look like sha256:<64 hex chars>" ;;
esac
placeholder="sha256:0000000000000000000000000000000000000000000000000000000000000000"
[ "$BASE_DIGEST" != "$placeholder" ] || die "refusing the placeholder digest — pin a base you vetted"

# ── SOURCE_DATE_EPOCH: reproducibility knob ────────────────────────────────
if [ -z "$EPOCH" ]; then
	if command -v git >/dev/null 2>&1 && git -C "$here" rev-parse --git-dir >/dev/null 2>&1; then
		EPOCH=$(git -C "$here" log -1 --format=%ct 2>/dev/null || echo 0)
	else
		EPOCH=0
	fi
fi
case "$EPOCH" in
	''|*[!0-9]*) die "SOURCE_DATE_EPOCH must be an integer, got: $EPOCH" ;;
esac

# ── Provenance labels (best-effort; do not fail the build if git is absent) ─
VCS_REF="unknown"
if command -v git >/dev/null 2>&1 && git -C "$here" rev-parse --git-dir >/dev/null 2>&1; then
	VCS_REF=$(git -C "$here" rev-parse --short HEAD 2>/dev/null || echo unknown)
fi

# ── Pick a container engine ────────────────────────────────────────────────
if [ -z "$ENGINE" ]; then
	if command -v podman >/dev/null 2>&1; then
		ENGINE=podman
	elif command -v docker >/dev/null 2>&1; then
		ENGINE=docker
	else
		die "no container engine found (install podman or docker)"
	fi
fi
command -v "$ENGINE" >/dev/null 2>&1 || die "container engine not found: $ENGINE"

log "engine=$ENGINE  tag=$TAG  epoch=$EPOCH  base=$BASE_DIGEST  vcs=$VCS_REF"

# ── Re-vendor the service source from the single source of truth ────────────
# The Containerfile COPYs ./vendor/services into the image. To make sure the
# image can never ship a STALE copy of the code (the exact drift that made the
# deployed /v1/crl 404 while the source served it), re-stage vendor/services from
# ../services on every build and refresh the integrity manifest. Local file copy
# only — no network, so the build stays deterministic. If ../services is absent
# (e.g. building from an already-vendored context), keep the committed copy.
SERVICES_SRC="$here/../services"
if [ -d "$SERVICES_SRC/src" ]; then
	log "re-vendoring service source from $SERVICES_SRC -> vendor/services"
	mkdir -p "$here/vendor/services/src"
	cp "$SERVICES_SRC"/src/*.mjs        "$here/vendor/services/src/"
	cp "$SERVICES_SRC/self-check.mjs"   "$here/vendor/services/"
	cp "$SERVICES_SRC/package.json"     "$here/vendor/services/"
	# Refresh the integrity manifest so it always matches what ships.
	if command -v shasum >/dev/null 2>&1; then
		( cd "$here/vendor/services" && shasum -a 256 \
			src/common.mjs src/console-service.mjs src/license-service.mjs \
			src/relay-service.mjs package.json > VENDOR-SHA256SUMS.txt )
	elif command -v sha256sum >/dev/null 2>&1; then
		( cd "$here/vendor/services" && sha256sum \
			src/common.mjs src/console-service.mjs src/license-service.mjs \
			src/relay-service.mjs package.json > VENDOR-SHA256SUMS.txt )
	fi
else
	log "no ../services source found; building from the committed vendor/services copy"
fi
[ -f "$here/vendor/services/entrypoint.mjs" ] || die "vendor/services/entrypoint.mjs missing — cannot launch the service"

# ── Assemble the build command (build ONLY; never push, never deploy) ──────
set -- "$ENGINE" build \
	--build-arg "BASE_DIGEST=$BASE_DIGEST" \
	--build-arg "SOURCE_DATE_EPOCH=$EPOCH" \
	--build-arg "POSTERN_EDITION=cloud" \
	--build-arg "VCS_REF=$VCS_REF" \
	-t "$TAG" \
	-f "$here/Containerfile" \
	"$here"

# podman/buildah honor SOURCE_DATE_EPOCH and can rewrite layer timestamps for a
# more deterministic result; add the flag when the engine is podman.
if [ "$ENGINE" = "podman" ]; then
	set -- "$@" --timestamp "$EPOCH"
fi

if [ "$DRYRUN" -eq 1 ]; then
	log "dry-run; would execute:"
	printf '  '; for a in "$@"; do printf '%s ' "$a"; done; printf '\n'
	exit 0
fi

# Export for any engine that reads it from the environment as well.
SOURCE_DATE_EPOCH="$EPOCH"
export SOURCE_DATE_EPOCH

log "building (this does NOT push or deploy) ..."
"$@" || die "build failed"

# ── Report the image digest so rebuilds can be compared ────────────────────
log "built: $TAG"
if digest=$("$ENGINE" inspect --format '{{index .RepoDigests 0}}' "$TAG" 2>/dev/null); then
	[ -n "$digest" ] && log "repo digest: $digest"
fi
if id=$("$ENGINE" inspect --format '{{.Id}}' "$TAG" 2>/dev/null); then
	[ -n "$id" ] && log "image id:    $id"
fi

log "DONE (build only). To push + deploy, follow BUILD-AND-DEPLOY.md."
log "Reminder: reproducible-by-design is NOT reproduced — verify parity yourself."
