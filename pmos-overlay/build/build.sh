#!/bin/sh
# build/build.sh -- assemble an installable "Postern for postmarketOS" disk
# image (.img) for one aarch64 device by INSTALLING the already-PUBLISHED
# `postern` meta package (+ wallet + apps) from the LIVE, signed R2 apk repo --
# it does NOT rebuild the apks. Every version we can pin is recorded into a
# build-manifest, and the .img + a checksum are emitted.
#
#   Product: "Postern for postmarketOS -- community edition"   (NEVER "Postern OS")
#   This is repeatable-ish + publisher-authenticated. It is NOT reproducible and
#   NOT attestable (Alpine/pmOS are not bit-for-bit reproducible; there is no Nix
#   closure and no hardware anchor). See ../HONESTY.md. The wallet uses a
#   SOFTWARE keystore -- never described as hardware-backed. The token is
#   worthless and this carries no security/legal/financial claim.
#
# WHAT IS LIVE (../PUBLISHED.md):
#   repo base : https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/postern
#   key       : https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/pmos/keys/builder-6a52d247.rsa.pub
#   packages  : postern-0.1.0-r0 (meta), postern-wallet-0.1.0_alpha1-r0, postern-apps-0.1.0_alpha1-r0
#   index     : pmos/postern/aarch64/APKINDEX.tar.gz (abuild-signed with the key above)
#   NOTE: signed with an ALPHA BUILD key (builder-6a52d247), not a stable release
#   key. Treat the signature as "this build, this key", not a long-lived anchor.
#
# HOST: this MUST run on a Linux aarch64 host (or a Linux x86_64 cross host with
# binfmt_misc + qemu-user; see ../aarch64-build.md). It CANNOT run on macOS.
# pmbootstrap builds in chroots and needs a real Linux kernel + user namespaces
# / loop devices. On a Mac this script only reaches the preflight guard and stops.
#
# Ordered recipe (install-from-published, NOT rebuild):
#   0. preflight  host + tool checks; refuse non-Linux / missing pmbootstrap
#   1. init       non-interactive `pmbootstrap init` + pin channel/device/ui
#   2. repo       wget the builder-6a52d247 key into pmbootstrap's cross-chroot
#                 apk key dir (copied into every chroot incl. the rootfs), and
#                 record the LIVE R2 repo URL to append at install time
#   3. image      `pmbootstrap install` a Phosh base, then inside the rootfs
#                 chroot add the R2 repo line + `apk add postern` (pulls the
#                 published meta -> wallet+apps, and phosh/tor from pmOS/Alpine),
#                 then re-create the .img from that rootfs
#   4. export     locate the .img, copy to OUT with a versioned name + sha256
#   5. manifest   full pin set + resolved postern versions + honest status
#
# Usage (on the build host):
#   DEVICE=pine64-pinephone ./build/build.sh all
#   ./build/build.sh preflight | init | repo | image | export | manifest
#
# `pmbootstrap init` here is driven non-interactively (accept defaults, then
# override channel/device/ui via `pmbootstrap config`). Set the pins below for a
# release build.
set -eu

# ---- config (all overridable from the environment) --------------------------
OVERLAY_DIR="${OVERLAY_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"  # pmos-overlay/
BUILD_DIR="${BUILD_DIR:-$OVERLAY_DIR/build}"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/out}"

# Target device. Default is a well-documented, widely-tested aarch64 pmOS phone.
# Documented ALTERNATIVES (any aarch64 pmOS codename with a mainline/community
# port + Phosh works): oneplus-enchilada (OnePlus 6), fairphone-fp4,
# xiaomi-scorpio, pine64-pinetab2. Override with DEVICE=<codename>.
DEVICE="${DEVICE:-pine64-pinephone}"
UI="${UI:-phosh}"                          # postern meta hard-deps postmarketos-ui-phosh
ARCH="${ARCH:-aarch64}"
FILESYSTEM="${FILESYSTEM:-ext4}"
PMOS_RELEASE="${PMOS_RELEASE:-v26.06}"     # the pmOS release these pkgs target (= one Alpine ABI)
IMG_VERSION="${IMG_VERSION:-v0.1}"         # matches the R2 os/<IMG_VERSION>/ prefix
BUILD_USER="${BUILD_USER:-build}"          # pmbootstrap runs as this non-root user (see setup-aarch64.sh)

# The channel must match the pmOS release (NOT edge) for a release image.
# pmbootstrap channel names track pmOS releases; default to the release codename.
PMB_CHANNEL="${PMB_CHANNEL:-$PMOS_RELEASE}"

# Pins you SHOULD set for a release build (empty = "record whatever is present",
# repeatable-ish but not enforced; set them to enforce):
PMBOOTSTRAP_VERSION="${PMBOOTSTRAP_VERSION:-}"   # e.g. 3.9.0 ; enforced if set
PMAPORTS_COMMIT="${PMAPORTS_COMMIT:-}"           # git sha ; checked out + enforced if set

# ---- LIVE published apk repo (../PUBLISHED.md) ------------------------------
R2_BASE="${R2_BASE:-https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev}"
REPO_URL="${REPO_URL:-$R2_BASE/pmos/postern}"          # append to /etc/apk/repositories
KEY_NAME="${KEY_NAME:-builder-6a52d247.rsa.pub}"
KEY_URL="${KEY_URL:-$R2_BASE/pmos/keys/$KEY_NAME}"
META_PKG="${META_PKG:-postern}"
# The three packages we expect the meta to pull from the R2 repo (for the
# manifest's resolved-version pin). phosh + tor resolve from pmOS/Alpine.
POSTERN_PKGS="postern postern-wallet postern-apps"

msg()  { printf '\033[1;32m>>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

# run a pmbootstrap command as the unprivileged build user if we are root
pmb() {
    if [ "$(id -u)" = 0 ] && id "$BUILD_USER" >/dev/null 2>&1; then
        su "$BUILD_USER" -c "pmbootstrap $*"
    else
        pmbootstrap "$@"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---- 0. preflight -----------------------------------------------------------
preflight() {
    [ "$(uname -s)" = Linux ] || die "host is $(uname -s); pmbootstrap image builds require Linux (a Mac cannot do this). See aarch64-build.md."
    command -v pmbootstrap >/dev/null 2>&1 || die "pmbootstrap not found -- run ../setup-aarch64.sh pmbootstrap first (or apk add pmbootstrap)"
    command -v wget >/dev/null 2>&1 || command -v curl >/dev/null 2>&1 || die "need wget or curl to fetch the signing key"
    [ -n "$DEVICE" ] || die "set DEVICE=<pmos-device-codename> (default pine64-pinephone)"
    mkdir -p "$OUT_DIR"
    msg "preflight OK -- device=$DEVICE ui=$UI arch=$ARCH fs=$FILESYSTEM release=$PMOS_RELEASE channel=$PMB_CHANNEL"
    msg "install source: LIVE published repo $REPO_URL (apks are NOT rebuilt)"
}

# fetch a URL to a file with whichever of wget/curl is present
fetch() {
    _url=$1; _dst=$2
    if command -v wget >/dev/null 2>&1; then wget -q -O "$_dst" "$_url"
    else curl -fsSL -o "$_dst" "$_url"; fi
}

# ---- 1. init: non-interactive pmbootstrap init + pin selection --------------
init() {
    preflight
    # If pmbootstrap has never been initialised, do it non-interactively by
    # accepting the prompts' defaults, then override the selection via config.
    # (`pmbootstrap init` is interactive by design; `yes '' | ... init` feeds it
    # empty lines = defaults. We then pin channel/device/ui deterministically.)
    if ! pmb config work >/dev/null 2>&1; then
        msg "no pmbootstrap config found -- running non-interactive init (defaults, then override)"
        if [ "$(id -u)" = 0 ] && id "$BUILD_USER" >/dev/null 2>&1; then
            su "$BUILD_USER" -c "yes '' | pmbootstrap init" || die "pmbootstrap init failed"
        else
            yes '' | pmbootstrap init || die "pmbootstrap init failed"
        fi
    else
        msg "pmbootstrap already initialised -- reusing config, overriding selection"
    fi

    # Enforce pmbootstrap version pin if requested.
    PMB_VER=$(pmbootstrap --version 2>/dev/null | head -n1 | tr -d '[:space:]')
    if [ -n "$PMBOOTSTRAP_VERSION" ] && [ "$PMB_VER" != "$PMBOOTSTRAP_VERSION" ]; then
        die "pmbootstrap version pin mismatch: want $PMBOOTSTRAP_VERSION, have $PMB_VER (apk add pmbootstrap=$PMBOOTSTRAP_VERSION or pip install pmbootstrap==$PMBOOTSTRAP_VERSION)"
    fi

    # Pin the target selection so the build is deterministic regardless of what
    # the non-interactive init chose.
    WORK=$(pmb config work | tr -d '[:space:]')
    APORTS=$(pmb config aports | tr -d '[:space:]')
    [ -n "$WORK" ]   || die "pmbootstrap config work is empty after init"
    [ -n "$APORTS" ] || die "pmbootstrap config aports is empty after init"

    # Channel. pmbootstrap 2.x exposed `config channel`; 3.x REMOVED it and derives
    # the channel from the checked-out pmaports branch. Try the 2.x config first;
    # on failure (3.x) switch the pmaports branch to the channel and re-sync.
    if pmb config channel "$PMB_CHANNEL" 2>/dev/null; then
        msg "channel set via pmbootstrap config (2.x): $PMB_CHANNEL"
    elif [ -d "$APORTS/.git" ]; then
        msg "pmbootstrap 3.x: switching pmaports branch to channel $PMB_CHANNEL"
        git -C "$APORTS" fetch --quiet origin || warn "pmaports fetch failed; using local objects"
        git -C "$APORTS" checkout --quiet "$PMB_CHANNEL" 2>/dev/null \
            || git -C "$APORTS" checkout --quiet -b "$PMB_CHANNEL" "origin/$PMB_CHANNEL" 2>/dev/null \
            || die "cannot switch pmaports to channel branch '$PMB_CHANNEL' (does it exist on the pmaports remote?)"
        pmb pull >/dev/null 2>&1 || warn "pmbootstrap pull after channel switch failed; continuing"
    else
        die "cannot set channel '$PMB_CHANNEL': pmbootstrap 3.x has no 'config channel' and aports is not a git checkout"
    fi

    pmb config device "$DEVICE"
    pmb config ui "$UI"
    # Switching channels (edge <-> v26.06) leaves chroots pinned to the old
    # channel; pmbootstrap 3.x then errors "Chroot is for the 'systemd-edge'
    # channel, but you are on 'systemd-v26.06'". Auto-zap stale chroots so a
    # channel change rebuilds them cleanly instead of dying.
    pmb config auto_zap_misconfigured_chroots yes 2>/dev/null || true

    # Enforce/record the pmaports commit pin.
    if [ -d "$APORTS/.git" ]; then
        if [ -n "$PMAPORTS_COMMIT" ]; then
            msg "pinning pmaports to $PMAPORTS_COMMIT"
            git -C "$APORTS" fetch --quiet origin || warn "pmaports fetch failed; using local objects"
            git -C "$APORTS" checkout --quiet "$PMAPORTS_COMMIT" || die "cannot checkout pmaports commit $PMAPORTS_COMMIT"
        fi
        PMAPORTS_SHA=$(git -C "$APORTS" rev-parse HEAD)
        PMAPORTS_REMOTE=$(git -C "$APORTS" config --get remote.origin.url 2>/dev/null || echo unknown)
    else
        PMAPORTS_SHA="unknown (aports is not a git checkout)"
        PMAPORTS_REMOTE="unknown"
    fi

    msg "pins recorded:"
    msg "  pmbootstrap : $PMB_VER"
    msg "  channel     : $PMB_CHANNEL"
    msg "  device      : $DEVICE"
    msg "  pmaports    : $PMAPORTS_SHA"
    cat > "$OUT_DIR/.pins.env" <<EOF
WORK=$WORK
APORTS=$APORTS
PMB_VER=$PMB_VER
PMB_CHANNEL=$PMB_CHANNEL
PMAPORTS_SHA=$PMAPORTS_SHA
PMAPORTS_REMOTE=$PMAPORTS_REMOTE
EOF
}

_load_pins() {
    [ -f "$OUT_DIR/.pins.env" ] || die "no pins recorded -- run './build/build.sh init' (or 'all') first"
    # shellcheck disable=SC1091
    . "$OUT_DIR/.pins.env"
}

# ---- 2. repo: trust the LIVE published signing key --------------------------
# pmbootstrap copies every key under $WORK/config_apk_keys/ into EVERY chroot it
# creates (build + rootfs). Dropping the R2 key there makes the published repo's
# signature trusted in the installed rootfs -- exactly the "wget the
# builder-6a52d247 key into the rootfs apk keys" step, done the pmbootstrap way.
# We do NOT rebuild any apk; we only teach apk to trust the publisher's key.
repo() {
    _load_pins
    KEYDIR="$WORK/config_apk_keys"
    mkdir -p "$KEYDIR"
    msg "fetching signing key: $KEY_URL"
    fetch "$KEY_URL" "$KEYDIR/$KEY_NAME" || die "could not fetch signing key $KEY_URL"
    # Sanity: it must look like a key, not an R2 error/HTML page.
    head -n1 "$KEYDIR/$KEY_NAME" | grep -q -- '-----BEGIN' \
        || die "fetched key does not look like a PEM public key -- refusing ($KEYDIR/$KEY_NAME)"
    KEY_SHA=$(sha256_of "$KEYDIR/$KEY_NAME")
    msg "key trusted in pmbootstrap chroots: $KEYDIR/$KEY_NAME (sha256 $KEY_SHA)"
    echo "KEY_SHA=$KEY_SHA" >> "$OUT_DIR/.pins.env"
    msg "repo URL to be added into the rootfs at install time: $REPO_URL"
}

# ---- 3. image: base install, add the published `postern`, then assemble -----
# NOTE ON THE FIX (2026-07): the old phase-3 re-ran `pmbootstrap install` to
# regenerate the .img. That FAILS on this build host: pmbootstrap's image
# assembly runs the final `dd if=<u-boot> of=/dev/install bs=1024 seek=8`
# (the deviceinfo_sd_embed_firmware embed) as the unprivileged 'pmos' user, which
# cannot open the /dev/install loop device -> "Command failed (exit code 1)".
# We now assemble the disk image OURSELVES with privileges (_assemble_image),
# matching byte-for-byte-equivalent layout to what pmbootstrap would emit. This
# is still signed & publisher-authenticated only -- NOT reproducible, NOT
# attested (../HONESTY.md); a rebuild is functionally equivalent, not identical.
image() {
    _load_pins
    [ -f "$WORK/config_apk_keys/$KEY_NAME" ] || die "signing key not trusted yet -- run './build/build.sh repo' first"

    ROOTFS_CHROOT="$WORK/chroot_rootfs_$DEVICE"

    msg "phase 1/3: pmbootstrap install -> build the Phosh base rootfs chroot"
    pmb config device "$DEVICE"
    pmb config ui "$UI"
    # `pmbootstrap install` builds the rootfs chroot AND then tries to assemble a
    # disk image; the image-assembly tail fails here (unprivileged /dev/install
    # firmware embed, see the note above). We only need the ROOTFS from this
    # step -- phase 3 builds the real image -- so tolerate that known post-rootfs
    # failure and then hard-assert the rootfs chroot was actually produced.
    pmb install --filesystem "$FILESYSTEM" --no-split --password "${IMG_PASSWORD:-147147}" \
        || warn "pmbootstrap install returned non-zero (expected: the unprivileged /dev/install u-boot embed cannot run on this host); verifying the rootfs still built"
    [ -d "$ROOTFS_CHROOT" ] || die "rootfs chroot not found at $ROOTFS_CHROOT -- pmbootstrap install failed BEFORE building the rootfs (not the known embed failure); see $WORK/log.txt"
    [ -f "$ROOTFS_CHROOT/lib/apk/db/installed" ] || die "rootfs chroot $ROOTFS_CHROOT has no apk db -- rootfs build incomplete"

    msg "phase 2/3: trust the published key + install '$META_PKG' into the rootfs"
    # Make the rootfs self-consistent with the trusted publisher key.
    pmb chroot --rootfs -- /bin/sh -c "mkdir -p /etc/apk/keys"
    cp -f "$WORK/config_apk_keys/$KEY_NAME" "$ROOTFS_CHROOT/etc/apk/keys/$KEY_NAME"
    # Install the published meta straight from the LIVE R2 repo. On pmbootstrap
    # 3.10 a repo line appended to the chroot's /etc/apk/repositories does NOT
    # persist across `pmb chroot` calls (it is regenerated), so we pass the repo
    # inline with `apk add --repository <R2>` instead of editing that file. This
    # pulls postern -> postern-wallet + postern-apps (phosh already present, tor
    # resolves on-device). We do NOT rebuild any apk.
    pmb chroot --rootfs -- apk add --repository "$REPO_URL" "$META_PKG" \
        || die "apk add $META_PKG --repository $REPO_URL failed inside the rootfs"
    for _p in $POSTERN_PKGS; do
        grep -qx "P:$_p" "$ROOTFS_CHROOT/lib/apk/db/installed" \
            || die "$_p not present in rootfs apk db after install (meta did not pull it?)"
    done

    msg "phase 3/3: PRIVILEGED manual disk-image assembly (replaces the failing 'pmb install' re-image)"
    _assemble_image
}

# ---- 3b. privileged manual image assembly -----------------------------------
# Assemble the disk image ourselves, with sudo, reproducing the layout
# pmbootstrap would have emitted for this device: an MBR (msdos) disk with a
# 256 MiB *bootable* ext2 boot partition (label pmOS_boot) + an ext4 root filling
# the rest (label pmOS_root), using the SAME filesystem UUIDs the rootfs
# /etc/fstab already references, and the deviceinfo_sd_embed_firmware u-boot blob
# dd'd in at the 8 KiB offset. This is the step the team proved works when
# pmbootstrap's own (unprivileged) assembly cannot run on this host.
_assemble_image() {
    command -v sudo >/dev/null 2>&1 || die "sudo required for privileged image assembly"
    for _t in sfdisk mkfs.ext2 mkfs.ext4 rsync losetup truncate dd; do
        command -v "$_t" >/dev/null 2>&1 || die "missing tool for image assembly: $_t (apt-get install util-linux e2fsprogs rsync coreutils)"
    done

    ROOTFS_CHROOT="$WORK/chroot_rootfs_$DEVICE"
    OUT_IMG="$OUT_DIR/postern-pmos-${DEVICE}-${PMOS_RELEASE}-${IMG_VERSION}.img"

    # Geometry (matches pmbootstrap's pine64-pinephone layout). GNU truncate/dd
    # 'M' == MiB (1024*1024): 3000M == 3145728000 bytes. 1 MiB alignment; sfdisk
    # units are 512-byte sectors (1 MiB == 2048 sectors).
    IMG_MIB="${IMG_MIB:-3000}"        # total image size (MiB)
    BOOT_MIB="${BOOT_MIB:-256}"       # boot partition size (MiB)
    ALIGN_MIB=1                        # first partition starts at 1 MiB
    UBOOT_BLOB="$ROOTFS_CHROOT/usr/share/u-boot/${DEVICE}/u-boot-sunxi-with-spl-528.bin"
    UBOOT_SEEK_KIB=8                   # deviceinfo_sd_embed_firmware "...:8"
    [ -f "$UBOOT_BLOB" ] || die "u-boot firmware blob not found: $UBOOT_BLOB (deviceinfo_sd_embed_firmware)"

    # Reuse the SAME fs UUIDs the rootfs /etc/fstab already points at, so the
    # installed fstab keeps resolving (pmbootstrap wrote that fstab by UUID).
    FSTAB="$ROOTFS_CHROOT/etc/fstab"
    [ -f "$FSTAB" ] || die "rootfs fstab not found: $FSTAB"
    BOOT_UUID=$(awk '$2=="/boot"{u=$1; sub(/^UUID=/,"",u); print u}' "$FSTAB")
    ROOT_UUID=$(awk '$2=="/"    {u=$1; sub(/^UUID=/,"",u); print u}' "$FSTAB")
    [ -n "$BOOT_UUID" ] || die "could not read /boot UUID from $FSTAB"
    [ -n "$ROOT_UUID" ] || die "could not read / UUID from $FSTAB"
    msg "  fstab UUIDs: boot=$BOOT_UUID root=$ROOT_UUID"

    # 1. raw image file
    msg "  creating raw image $OUT_IMG (${IMG_MIB} MiB)"
    rm -f "$OUT_IMG"
    truncate -s "${IMG_MIB}M" "$OUT_IMG" || die "could not allocate $OUT_IMG"

    # 2. MBR (msdos) table: p1 ext boot 256 MiB *bootable*, p2 root = remainder.
    msg "  partitioning (msdos): p1 boot ${BOOT_MIB}MiB bootable + p2 root remainder"
    sudo sfdisk "$OUT_IMG" <<EOF || die "sfdisk failed"
label: dos
unit: sectors
start=$((ALIGN_MIB*2048)), size=$((BOOT_MIB*2048)), type=83, bootable
start=$(((ALIGN_MIB+BOOT_MIB)*2048)), type=83
EOF

    # 3. attach a partition-scanned loop device
    LOOP=$(sudo losetup --find --show --partscan "$OUT_IMG") || die "losetup failed"
    MNT=$(mktemp -d); MNT_ROOT="$MNT/root"; MNT_BOOT="$MNT/boot"
    # always clean up mounts + loop, even on failure
    trap 'sudo umount "$MNT_BOOT" 2>/dev/null || true; sudo umount "$MNT_ROOT" 2>/dev/null || true; [ -n "${LOOP:-}" ] && sudo losetup -d "$LOOP" 2>/dev/null || true; rm -rf "$MNT" 2>/dev/null || true' EXIT INT TERM
    BOOT_DEV="${LOOP}p1"; ROOT_DEV="${LOOP}p2"
    [ -b "$BOOT_DEV" ] && [ -b "$ROOT_DEV" ] || die "loop partitions absent ($BOOT_DEV/$ROOT_DEV) -- kernel partscan?"

    # 4. filesystems with the fstab UUIDs + pmOS labels
    msg "  mkfs.ext2 $BOOT_DEV (label pmOS_boot, uuid $BOOT_UUID)"
    sudo mkfs.ext2 -q -F -L pmOS_boot -U "$BOOT_UUID" "$BOOT_DEV" || die "mkfs.ext2 (boot) failed"
    msg "  mkfs.ext4 $ROOT_DEV (label pmOS_root, uuid $ROOT_UUID)"
    sudo mkfs.ext4 -q -F -L pmOS_root -U "$ROOT_UUID" "$ROOT_DEV" || die "mkfs.ext4 (root) failed"

    # 5. mount + copy rootfs (numeric ids; drop virtual fs, /boot, apk cache)
    mkdir -p "$MNT_ROOT" "$MNT_BOOT"
    sudo mount "$ROOT_DEV" "$MNT_ROOT" || die "mount root failed"
    sudo mount "$BOOT_DEV" "$MNT_BOOT" || die "mount boot failed"

    msg "  rsync rootfs -> root partition"
    sudo rsync -aHAXx --numeric-ids \
        --exclude=/boot --exclude=/proc --exclude=/sys --exclude=/dev \
        --exclude=/run --exclude=/tmp --exclude=/var/cache/apk \
        "$ROOTFS_CHROOT"/ "$MNT_ROOT"/ || die "rsync rootfs->root failed"
    # recreate the excluded mount-point dirs so they exist at boot
    sudo mkdir -p "$MNT_ROOT"/boot "$MNT_ROOT"/proc "$MNT_ROOT"/sys "$MNT_ROOT"/dev \
        "$MNT_ROOT"/run "$MNT_ROOT"/tmp "$MNT_ROOT"/var/cache/apk
    sudo chmod 1777 "$MNT_ROOT"/tmp

    msg "  rsync /boot -> boot partition"
    sudo rsync -aHAXx --numeric-ids "$ROOTFS_CHROOT"/boot/ "$MNT_BOOT"/ || die "rsync /boot->boot failed"

    # 6. flush, unmount, detach loop BEFORE touching the raw device again
    sync
    sudo umount "$MNT_BOOT" || die "umount boot failed"
    sudo umount "$MNT_ROOT" || die "umount root failed"
    sudo losetup -d "$LOOP"; LOOP=''
    trap - EXIT INT TERM
    rm -rf "$MNT"

    # 7. embed the u-boot SPL at the deviceinfo 8 KiB offset (pre-partition gap;
    #    the first partition starts at 1 MiB, so this never touches a filesystem).
    msg "  embedding u-boot ($(basename "$UBOOT_BLOB")) at ${UBOOT_SEEK_KIB} KiB (bs=1024 seek=$UBOOT_SEEK_KIB conv=notrunc)"
    dd if="$UBOOT_BLOB" of="$OUT_IMG" bs=1024 seek="$UBOOT_SEEK_KIB" conv=notrunc status=none \
        || die "u-boot embed dd failed"

    echo "$OUT_IMG" > "$OUT_DIR/.image.path"
    msg "image ready: $OUT_IMG ($(wc -c < "$OUT_IMG") bytes)"
    msg "HONEST STATUS: signed & publisher-authenticated only -- NOT reproducible"
    msg "(this manual assembly is functionally equivalent, not byte-identical, run"
    msg "to run) and boot_tested stays UNBOOTED until a real device boot."
}

export_img() {
    _load_pins
    [ -f "$OUT_DIR/.image.path" ] || die "no image built -- run './build/build.sh image' first"
    OUT_IMG=$(cat "$OUT_DIR/.image.path")
    [ -f "$OUT_IMG" ] || die "recorded image missing: $OUT_IMG"
    IMG_SHA=$(sha256_of "$OUT_IMG")
    printf '%s  %s\n' "$IMG_SHA" "$(basename "$OUT_IMG")" > "$OUT_IMG.sha256"
    msg "checksum sidecar: $OUT_IMG.sha256"
}

# ---- 5. manifest: full pin set + resolved postern versions + honest status --
manifest() {
    _load_pins
    [ -f "$OUT_DIR/.image.path" ] || die "no image built -- run './build/build.sh image' first"
    OUT_IMG=$(cat "$OUT_DIR/.image.path")
    [ -f "$OUT_IMG" ] || die "recorded image missing: $OUT_IMG"

    msg "computing sha256 (the checksum the .img ships with)"
    IMG_SHA=$(sha256_of "$OUT_IMG")
    IMG_BYTES=$(wc -c < "$OUT_IMG" | tr -d '[:space:]')
    IMG_BASE=$(basename "$OUT_IMG")
    printf '%s  %s\n' "$IMG_SHA" "$IMG_BASE" > "$OUT_IMG.sha256"

    # apk "world" pin: exact installed package set from the built rootfs db.
    PKGS_FILE="$OUT_DIR/installed-packages.txt"
    ROOTFS_DB="$WORK/chroot_rootfs_$DEVICE/lib/apk/db/installed"
    if [ -f "$ROOTFS_DB" ]; then
        awk '/^P:/{p=substr($0,3)} /^V:/{print p "=" substr($0,3)}' "$ROOTFS_DB" | sort > "$PKGS_FILE"
    else
        warn "rootfs apk db not found at $ROOTFS_DB -- installed-packages pin will be empty"
        : > "$PKGS_FILE"
    fi
    APK_WORLD_SHA=$(sha256_of "$PKGS_FILE")

    # Resolved versions of the Postern packages actually installed FROM the R2
    # repo, read out of the rootfs apk db (this is the "repo commit" analogue:
    # the content-addressed identity of the published apks that landed).
    OV_JSON_FILE="$OUT_DIR/.postern-pkgs.json"
    : > "$OV_JSON_FILE"
    _first=1
    for p in $POSTERN_PKGS; do
        if [ -f "$PKGS_FILE" ]; then
            _v=$(awk -F= -v k="$p" '$1==k{print $2; exit}' "$PKGS_FILE")
        fi
        [ "$_first" -eq 1 ] || printf ',\n' >> "$OV_JSON_FILE"
        _first=0
        printf '      "%s": "%s"' "$p" "${_v:-not-installed}" >> "$OV_JSON_FILE"
    done
    printf '\n' >> "$OV_JSON_FILE"

    KEY_SHA_VAL="${KEY_SHA:-unknown}"

    MANIFEST="$OUT_DIR/build-manifest.json"
    msg "writing manifest -> $MANIFEST (status=BUILT)"
    {
        printf '{\n'
        printf '  "schema": "postern-pmos-build-manifest/v1",\n'
        printf '  "product": "Postern for postmarketOS — community edition",\n'
        printf '  "not_product": "Postern OS",\n'
        printf '  "status": "BUILT",\n'
        printf '  "boot_tested": "UNBOOTED",\n'
        printf '  "install_source": "published apk repo — packages installed, NOT rebuilt",\n'
        printf '  "attestation": "none — signed & publisher-authenticated only; NOT reproducible, NOT attested",\n'
        printf '  "reproducible": false,\n'
        printf '  "attestable": false,\n'
        printf '  "keystore": "software (never hardware-backed on pmOS)",\n'
        printf '  "image": {\n'
        printf '    "file": "%s",\n' "$IMG_BASE"
        printf '    "sha256": "%s",\n' "$IMG_SHA"
        printf '    "bytes": %s\n' "$IMG_BYTES"
        printf '  },\n'
        printf '  "target": {\n'
        printf '    "device": "%s",\n' "$DEVICE"
        printf '    "ui": "%s",\n' "$UI"
        printf '    "arch": "%s",\n' "$ARCH"
        printf '    "pmos_release": "%s",\n' "$PMOS_RELEASE"
        printf '    "image_version": "%s",\n' "$IMG_VERSION"
        printf '    "filesystem": "%s"\n' "$FILESYSTEM"
        printf '  },\n'
        printf '  "published_repo": {\n'
        printf '    "base": "%s",\n' "$REPO_URL"
        printf '    "signing_key": "%s",\n' "$KEY_NAME"
        printf '    "signing_key_sha256": "%s",\n' "$KEY_SHA_VAL"
        printf '    "key_note": "alpha BUILD key, not a stable release key (../PUBLISHED.md)"\n'
        printf '  },\n'
        printf '  "pins": {\n'
        printf '    "pmbootstrap_version": "%s",\n' "$PMB_VER"
        printf '    "pmbootstrap_channel": "%s",\n' "$PMB_CHANNEL"
        printf '    "pmaports_commit": "%s",\n' "$PMAPORTS_SHA"
        printf '    "pmaports_remote": "%s",\n' "$PMAPORTS_REMOTE"
        printf '    "apk_world_sha256": "%s",\n' "$APK_WORLD_SHA"
        printf '    "installed_packages_file": "installed-packages.txt",\n'
        printf '    "postern_packages": {\n'
        cat "$OV_JSON_FILE"
        printf '    }\n'
        printf '  },\n'
        printf '  "build": {\n'
        printf '    "built_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '    "built_by_host": "%s",\n' "$(uname -srm | sed 's/"/\\"/g')"
        printf '    "build_script": "build/build.sh"\n'
        printf '  }\n'
        printf '}\n'
    } > "$MANIFEST"

    msg "manifest written. checksum sidecar: $OUT_IMG.sha256"
    msg ""
    msg "NEXT (on a host with R2 creds): publish with"
    msg "  ./publish-to-r2.sh -i \"$OUT_IMG\" -m \"$MANIFEST\" -s <minisign.key>"
    msg ""
    msg "HONEST STATUS: status=BUILT means the .img exists; boot_tested=UNBOOTED"
    msg "means it has NOT been smoke-tested on hardware. Flip boot_tested by hand"
    msg "only after a real device boot. Packages were INSTALLED from the live"
    msg "signed repo (not rebuilt); this is repeatable-ish + publisher-"
    msg "authenticated, NOT reproducible and NOT attested (../HONESTY.md)."
}

all() { preflight; init; repo; image; export_img; manifest; }

case "${1:-}" in
    preflight) preflight ;;
    init)      init ;;
    repo)      repo ;;
    image)     image ;;
    export)    export_img ;;
    manifest)  manifest ;;
    all)       all ;;
    *)
        sed -n '2,55p' "$0"
        exit 1
        ;;
esac
