#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# install.sh — put the Postern Hygiene "Scrub metadata" right-click action into
# the current user's file manager. Per-user, no root; uninstall with --uninstall.
#
#   ./install.sh                 auto-detect OS/desktop and install
#   ./install.sh --uninstall     remove what we installed
#
# What it installs:
#   * the shared core postern-scrub.sh -> ~/.local/share/postern/file-manager/
#   * Linux: the Nautilus script AND the KDE/nautilus-actions .desktop action
#   * macOS: the "Postern Scrub Metadata.workflow" Quick Action -> ~/Library/Services/
#
# It does NOT install the `postern-hygiene` binary — build/install that
# separately (cargo build -p postern-hygiene) and put it on PATH, or export
# POSTERN_HYGIENE_BIN. The core script resolves it at run time.

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SHARE="$HOME/.local/share/postern/file-manager"
UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

os=$(uname -s)

install_core() {
    mkdir -p "$SHARE"
    cp "$SELF_DIR/postern-scrub.sh" "$SHARE/postern-scrub.sh"
    chmod +x "$SHARE/postern-scrub.sh"
    echo "installed core -> $SHARE/postern-scrub.sh"
}

case "$os" in
    Linux)
        NAUT="$HOME/.local/share/nautilus/scripts"
        KDE="$HOME/.local/share/kio/servicemenus"
        if [ "$UNINSTALL" -eq 1 ]; then
            rm -f "$NAUT/Scrub metadata (Postern Hygiene)" \
                  "$NAUT/postern-scrub.sh" \
                  "$KDE/postern-hygiene-scrub.desktop"
            rm -rf "$SHARE"
            echo "uninstalled Linux file-manager action"
            exit 0
        fi
        install_core
        mkdir -p "$NAUT" "$KDE"
        cp "$SELF_DIR/linux/nautilus-scripts/Scrub metadata (Postern Hygiene)" \
           "$NAUT/Scrub metadata (Postern Hygiene)"
        cp "$SHARE/postern-scrub.sh" "$NAUT/postern-scrub.sh"
        chmod +x "$NAUT/Scrub metadata (Postern Hygiene)" "$NAUT/postern-scrub.sh"
        cp "$SELF_DIR/linux/postern-hygiene-scrub.desktop" \
           "$KDE/postern-hygiene-scrub.desktop"
        echo "installed Nautilus script -> $NAUT"
        echo "installed .desktop action -> $KDE"
        echo "note: ensure 'postern-scrub.sh' (in $SHARE) is reachable, or that"
        echo "      postern-hygiene is on PATH, for the KDE .desktop Exec to resolve."
        ;;
    Darwin)
        SERVICES="$HOME/Library/Services"
        WF="Postern Scrub Metadata.workflow"
        if [ "$UNINSTALL" -eq 1 ]; then
            rm -rf "$SERVICES/$WF"
            rm -rf "$SHARE"
            echo "uninstalled macOS Quick Action"
            exit 0
        fi
        install_core
        mkdir -p "$SERVICES"
        rm -rf "$SERVICES/$WF"
        cp -R "$SELF_DIR/macos/$WF" "$SERVICES/$WF"
        echo "installed Quick Action -> $SERVICES/$WF"
        echo "note: the workflow calls $SHARE/postern-scrub.sh; keep it in place."
        echo "      It appears under Finder > right-click > Quick Actions."
        # Nudge the Services cache (best-effort).
        /System/Library/CoreServices/pbs -flush 2>/dev/null || true
        ;;
    *)
        echo "unsupported OS: $os (Linux and macOS only)" >&2
        exit 1
        ;;
esac
