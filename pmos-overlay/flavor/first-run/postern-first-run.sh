#!/bin/sh
# SPDX-License-Identifier: MIT
# postern-first-run.sh -- show the "About this tier" honesty notice ONCE, per
# user, on first graphical login. Wired by the XDG autostart entry
# postern-first-run.desktop (installed to /etc/xdg/autostart/).
#
#   License: MIT.
#
# Design (flavor/first-run.md): "build a pointer, never a nag." This shows the
# notice a single time and then stamps a marker so it never shows again -- even
# if the display step could not run. It is a POINTER to the full text, not a
# modal gate.
#
# HONESTY / UNBOOTED: community, NON-attestable tier. Syntax-checked (sh -n)
# only; never run under a real phosh session. This is "Postern for postmarketOS",
# never "Postern OS".
set -eu

ABOUT="/usr/share/postern/first-run/about-tier.txt"
MARKER="${XDG_STATE_HOME:-$HOME/.local/state}/postern/first-run-done"

# Already shown for this user -> nothing to do (never nag).
[ -e "$MARKER" ] && exit 0
mkdir -p "$(dirname "$MARKER")" 2>/dev/null || true

# A short desktop notification pointing at the full notice, if a notifier
# exists. Purely a pointer; the authoritative text is the about-tier screen.
if command -v notify-send >/dev/null 2>&1; then
	notify-send -u normal "Postern for postmarketOS -- community edition" \
		"Non-attestable tier: software wallet keys, signed (not reproducible) packages, coin worthless. Tap to read the full notice." \
		2>/dev/null || true
fi

# Open the full "About this tier" text in the default viewer, once.
if [ -r "$ABOUT" ] && command -v xdg-open >/dev/null 2>&1; then
	xdg-open "$ABOUT" >/dev/null 2>&1 || true
fi

# Stamp the marker even if display failed: a pointer shown at most once, never a
# recurring prompt.
: > "$MARKER" 2>/dev/null || true
exit 0
