#!/bin/sh
# setup-aarch64.sh — build aarch64 Alpine apks (postern-wallet) on an x86_64
# Alpine Fly Machine (Firecracker microVM, NO nested KVM).
#
# Two paths (see aarch64-build.md for the full evaluation):
#   pmbootstrap (RECOMMENDED)  chroots + crossdirect: rustc runs natively,
#                              qemu-user only for linking/scripts. ~10-30 min.
#   chroot (FALLBACK)          full aarch64 userspace under qemu-user TCG,
#                              plain abuild. Faithful but 10-20x slower (1-3 h).
#
# Neither path uses KVM. Both need kernel binfmt_misc (present in the
# Firecracker recommended config Fly uses; `preflight` verifies).
#
# Usage (run as root on the Fly machine):
#   ./setup-aarch64.sh preflight       # kernel + arch checks
#   ./setup-aarch64.sh pmbootstrap     # install + set up pmbootstrap (interactive init)
#   ./setup-aarch64.sh build           # pmbootstrap checksum + build --arch aarch64
#   ./setup-aarch64.sh chroot          # fallback: binfmt + bootstrap aarch64 chroot
#   ./setup-aarch64.sh chroot-build    # fallback: abuild -r inside the chroot
#
# NOTE: postern-apps and the postern meta package are arch="noarch" — they
# need NO aarch64 build. Build them once on x86_64 (plain `abuild -r`) and
# index the same .apk into both arch dirs. Only postern-wallet is native.
set -eu

# ---- config ----------------------------------------------------------------
OVERLAY_DIR="${OVERLAY_DIR:-$(cd "$(dirname "$0")" && pwd)}"   # this repo's pmos-overlay/
PKG="${PKG:-postern-wallet}"
BUILD_USER="${BUILD_USER:-build}"
# fallback-path knobs:
ALPINE_BRANCH="${ALPINE_BRANCH:-v3.22}"   # match the Alpine base of the pmOS release you target
MIRROR="${MIRROR:-http://dl-cdn.alpinelinux.org/alpine}"
CHROOT="${CHROOT:-/srv/aarch64-chroot}"   # put this on a Fly volume (needs 5-10 GB)

msg()  { printf '\033[1;32m>>>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- preflight ---------------------------------------------------------------
preflight() {
    [ "$(id -u)" = 0 ] || die "run as root"
    [ "$(uname -m)" = x86_64 ] || msg "warning: host is $(uname -m), recipe assumes x86_64"
    grep -q '^ID=alpine' /etc/os-release || die "this recipe targets an Alpine host"

    if [ -e /proc/config.gz ]; then
        if zcat /proc/config.gz | grep -q '^CONFIG_BINFMT_MISC=[ym]'; then
            msg "kernel: CONFIG_BINFMT_MISC=$(zcat /proc/config.gz | sed -n 's/^CONFIG_BINFMT_MISC=//p')"
        else
            die "kernel lacks CONFIG_BINFMT_MISC — no qemu-user path possible on this machine"
        fi
    else
        msg "no /proc/config.gz; probing binfmt_misc directly"
    fi
    grep -q binfmt_misc /proc/filesystems 2>/dev/null || modprobe binfmt_misc 2>/dev/null || true
    grep -q binfmt_misc /proc/filesystems || die "binfmt_misc unavailable (not builtin, modprobe failed)"
    msg "binfmt_misc available"

    avail_gb=$(df -Pk / | awk 'NR==2{print int($4/1048576)}')
    [ "$avail_gb" -ge 8 ] || msg "warning: only ${avail_gb}G free on / — mount a Fly volume for the work dir"
    msg "preflight OK"
}

# ---- shared: register qemu-aarch64 binfmt handler ---------------------------
# Same registration the Alpine qemu-openrc initd (jirutka/qemu-openrc) writes,
# incl. the F (fix-binary) flag so the handler works inside chroots without
# copying qemu-aarch64 in. Manual because OpenRC is not PID 1 on Fly.
register_binfmt() {
    apk add --no-cache qemu-aarch64
    if ! [ -f /proc/sys/fs/binfmt_misc/register ]; then
        mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
    fi
    if [ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
        msg "binfmt: qemu-aarch64 already registered"
        return 0
    fi
    # magic/mask: standard qemu aarch64 ELF match (EM_AARCH64=0xb7, ET_EXEC|ET_DYN)
    printf '%s' ':qemu-aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-aarch64:POCF' \
        > /proc/sys/fs/binfmt_misc/register
    grep -q enabled /proc/sys/fs/binfmt_misc/qemu-aarch64 || die "binfmt registration failed"
    msg "binfmt: qemu-aarch64 registered (flags POCF)"
}

# ---- path B (RECOMMENDED): pmbootstrap --------------------------------------
setup_pmbootstrap() {
    preflight
    msg "installing pmbootstrap + doas + git (Alpine ${ALPINE_BRANCH} community)"
    apk add --no-cache pmbootstrap doas git
    # pmbootstrap wants a normal user escalating via doas, not raw root:
    if ! id "$BUILD_USER" >/dev/null 2>&1; then
        adduser -D "$BUILD_USER"
    fi
    adduser "$BUILD_USER" wheel 2>/dev/null || true
    mkdir -p /etc/doas.d
    echo 'permit nopass :wheel' > /etc/doas.d/wheel.conf

    msg "running interactive 'pmbootstrap init' as ${BUILD_USER}"
    msg "  - channel: pick the one matching pmOS v26.06 (NOT edge) for release builds"
    msg "  - work path: put it on your Fly volume (needs 5-10 GB)"
    msg "  - device: irrelevant for package builds (e.g. qemu-amd64); UI: none"
    msg "  (CI: 'yes \"\" | pmbootstrap init' accepts defaults = edge channel)"
    su "$BUILD_USER" -c 'pmbootstrap init'

    APORTS=$(su "$BUILD_USER" -c 'pmbootstrap config aports')
    msg "installing overlay packages into pmaports checkout: ${APORTS}/temp/"
    mkdir -p "$APORTS/temp"
    for p in postern postern-wallet postern-apps; do
        [ -d "$OVERLAY_DIR/$p" ] && cp -r "$OVERLAY_DIR/$p" "$APORTS/temp/"
    done
    chown -R "$BUILD_USER" "$APORTS/temp"
    msg "setup done. Next: ./setup-aarch64.sh build"
}

build_pmbootstrap() {
    id "$BUILD_USER" >/dev/null 2>&1 || die "run './setup-aarch64.sh pmbootstrap' first"
    msg "checksum + build (crossdirect: native rustc, qemu-user for link only)"
    su "$BUILD_USER" -c "pmbootstrap checksum $PKG"
    time su "$BUILD_USER" -c "pmbootstrap build --arch aarch64 $PKG"
    WORK=$(su "$BUILD_USER" -c 'pmbootstrap config work')
    msg "aarch64 apks:"
    find "$WORK/packages" -name "${PKG}-*.apk" -path '*aarch64*'
    msg "sideload to a device:  doas -u $BUILD_USER pmbootstrap sideload $PKG"
    msg "if the Rust build fails under crossdirect, add options=\"!pmb:crossdirect\""
    msg "to the APKBUILD to force the qemu-only method (reliable, 10-20x slower)."
}

# ---- path A (FALLBACK): full qemu-user chroot + plain abuild -----------------
setup_chroot() {
    preflight
    register_binfmt
    apk add --no-cache alpine-keys  # provides /usr/share/apk/keys/aarch64/

    msg "bootstrapping aarch64 rootfs at $CHROOT (Alpine $ALPINE_BRANCH)"
    mkdir -p "$CHROOT/etc/apk/keys"
    cp /usr/share/apk/keys/aarch64/* "$CHROOT/etc/apk/keys/"
    apk --arch aarch64 --root "$CHROOT" --initdb -U \
        -X "$MIRROR/$ALPINE_BRANCH/main" -X "$MIRROR/$ALPINE_BRANCH/community" \
        add alpine-base alpine-sdk cargo rust doas
    printf '%s\n%s\n' "$MIRROR/$ALPINE_BRANCH/main" "$MIRROR/$ALPINE_BRANCH/community" \
        > "$CHROOT/etc/apk/repositories"
    cp /etc/resolv.conf "$CHROOT/etc/resolv.conf"

    mountpoint -q "$CHROOT/proc" || mount -t proc proc "$CHROOT/proc"
    mountpoint -q "$CHROOT/sys"  || mount -o bind /sys "$CHROOT/sys"
    mountpoint -q "$CHROOT/dev"  || mount -o bind /dev "$CHROOT/dev"

    # sanity: transparent emulation works (F flag => no qemu binary in chroot)
    chroot "$CHROOT" /bin/busybox uname -m | grep -q aarch64 \
        || die "emulated exec failed — check binfmt registration"
    msg "emulated aarch64 userspace OK"

    msg "creating builder user + abuild key inside chroot"
    chroot "$CHROOT" /bin/sh -c '
        set -eu
        id builder >/dev/null 2>&1 || adduser -D builder
        addgroup builder abuild 2>/dev/null || true
        echo "permit nopass :abuild" > /etc/doas.d/abuild.conf
        su builder -c "abuild-keygen -a -i -n"
    '
    msg "copying $PKG APKBUILD into chroot"
    cp -r "$OVERLAY_DIR/$PKG" "$CHROOT/home/builder/"
    chroot "$CHROOT" chown -R builder /home/builder
    msg "setup done. Next: ./setup-aarch64.sh chroot-build   (expect 1-3 h)"
}

build_chroot() {
    [ -d "$CHROOT/home/builder/$PKG" ] || die "run './setup-aarch64.sh chroot' first"
    msg "building $PKG under full qemu-user emulation — this is the SLOW path"
    # Cap parallelism: each emulated rustc costs guest RAM + qemu overhead.
    time chroot "$CHROOT" su builder -c "
        set -eu
        export CARGO_BUILD_JOBS=\${CARGO_BUILD_JOBS:-2}
        cd /home/builder/$PKG
        abuild checksum
        abuild -r
    "
    msg "aarch64 apks:"
    find "$CHROOT/home/builder/packages" -name "${PKG}-*.apk"
}

teardown_chroot() {
    for m in dev sys proc; do
        mountpoint -q "$CHROOT/$m" && umount "$CHROOT/$m"
    done
    msg "chroot mounts released (rootfs kept at $CHROOT; rm -rf to delete)"
}

# ---- dispatch ----------------------------------------------------------------
case "${1:-}" in
    preflight)      preflight ;;
    pmbootstrap)    setup_pmbootstrap ;;
    build)          build_pmbootstrap ;;
    chroot)         setup_chroot ;;
    chroot-build)   build_chroot ;;
    chroot-teardown) teardown_chroot ;;
    *)
        sed -n '2,22p' "$0"
        exit 1
        ;;
esac
