#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# test-scrub-action.sh — acceptance test for the file-manager "scrub" action.
#
# Scripts a real invocation of the right-click action (postern-scrub.sh, the
# exact glue the Nautilus/.desktop/Quick-Action integrations all call) on:
#   * a real EXIF-tagged JPEG (APP1 "Exif\0\0" segment carrying author/GPS text)
#   * an OOXML .docx carrying docProps author metadata (dc:creator, lastModifiedBy)
# and asserts that:
#   1. the ORIGINALS report NOT clean   (postern-hygiene check --json -> clean:false)
#   2. the action produced a scrubbed sibling for each
#   3. each SCRUBBED sibling reports CLEAN (check --json -> clean:true, exit 0)
#
# This proves the embed hook is wired end-to-end (roadmap gap
# "OS/file-manager embed not wired yet" filled), not just that the core works.
#
# Requires: python3 (to synthesize the fixtures) and a built postern-hygiene
# binary. The binary is taken from $POSTERN_HYGIENE_BIN, else PATH, else the
# repo's target/{debug,release}. Run from anywhere.

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- resolve the binary (same order the action uses) ------------------------
BIN="${POSTERN_HYGIENE_BIN:-}"
if [ -z "$BIN" ]; then
    if command -v postern-hygiene >/dev/null 2>&1; then
        BIN=$(command -v postern-hygiene)
    else
        for c in "$SELF_DIR/../../target/debug/postern-hygiene" \
                 "$SELF_DIR/../../target/release/postern-hygiene"; do
            [ -x "$c" ] && BIN="$c" && break
        done
    fi
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "TEST ERROR: no postern-hygiene binary. Build it:" >&2
    echo "  cargo build -p postern-hygiene --bin postern-hygiene" >&2
    exit 3
fi
export POSTERN_HYGIENE_BIN="$BIN"
echo "using binary: $BIN"

command -v python3 >/dev/null 2>&1 || { echo "TEST ERROR: python3 required for fixtures" >&2; exit 3; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/postern-scrub-action.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- synthesize the two fixtures --------------------------------------------
python3 - "$WORK" <<'PY'
import sys, struct, zipfile, os
work = sys.argv[1]

# 1) EXIF-tagged JPEG: SOI + APP1(Exif) with identifying text + EOI.
#    A real APP1 "Exif\0\0" segment is exactly what carries EXIF; scrub_jpeg
#    drops every APP1..APP15. (Minimal marker stream — enough to carry and
#    then lose real EXIF; not a full raster.)
app1 = b"Exif\x00\x00" + b"MM\x00*" + b"Artist=Alice Secret;GPSLatitude=51.5074;Make=Leica"
seg  = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
jpg  = b"\xff\xd8" + seg + b"\xff\xd9"
with open(os.path.join(work, "vacation photo.jpg"), "wb") as f:
    f.write(jpg)

# 2) OOXML .docx with author metadata in docProps/core.xml.
path = os.path.join(work, "quarterly report.docx")
z = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)
z.writestr("[Content_Types].xml", "<Types/>")
z.writestr("docProps/core.xml",
    '<?xml version="1.0"?>'
    '<cp:coreProperties xmlns:cp="x" xmlns:dc="y" xmlns:dcterms="z">'
    '<dc:creator>Alice Secret</dc:creator>'
    '<cp:lastModifiedBy>Bob Reviewer</cp:lastModifiedBy>'
    '<dcterms:created>2026-01-02T03:04:05Z</dcterms:created>'
    '</cp:coreProperties>')
z.writestr("word/document.xml", "<w:document>the visible body text is preserved</w:document>")
z.close()
print("fixtures:", os.listdir(work))
PY

JPG="$WORK/vacation photo.jpg"
DOCX="$WORK/quarterly report.docx"

fail=0
note() { printf '  %s\n' "$1"; }

assert_dirty() {
    f=$1
    if "$BIN" check --json - <"$f" >"$WORK/chk.json" 2>/dev/null; then
        echo "FAIL: expected '$f' to be reported NOT clean, but check exited 0"
        cat "$WORK/chk.json"; fail=1; return
    fi
    grep -q '"clean":false' "$WORK/chk.json" || { echo "FAIL: '$f' json not clean:false"; cat "$WORK/chk.json"; fail=1; return; }
    note "OK original NOT clean: $(basename "$f")  ->  $(cat "$WORK/chk.json")"
}

assert_clean() {
    f=$1
    if ! "$BIN" check --json - <"$f" >"$WORK/chk.json" 2>/dev/null; then
        echo "FAIL: expected scrubbed '$f' to be CLEAN (exit 0), got exit $?"
        cat "$WORK/chk.json"; fail=1; return
    fi
    grep -q '"clean":true' "$WORK/chk.json" || { echo "FAIL: '$f' json not clean:true"; cat "$WORK/chk.json"; fail=1; return; }
    note "OK scrubbed CLEAN: $(basename "$f")  ->  $(cat "$WORK/chk.json")"
}

echo
echo "[1] originals carry metadata (baseline):"
assert_dirty "$JPG"
assert_dirty "$DOCX"

echo
echo "[2] invoke the right-click action (postern-scrub.sh) on the selection:"
# This is exactly what Nautilus / the .desktop Exec / the Quick Action run.
"$SELF_DIR/postern-scrub.sh" "$JPG" "$DOCX"

echo
echo "[3] scrubbed siblings exist and are clean:"
JPG_OUT="$WORK/vacation photo.scrubbed.jpg"
DOCX_OUT="$WORK/quarterly report.scrubbed.docx"
[ -f "$JPG_OUT" ]  || { echo "FAIL: no scrubbed sibling '$JPG_OUT'"; fail=1; }
[ -f "$DOCX_OUT" ] || { echo "FAIL: no scrubbed sibling '$DOCX_OUT'"; fail=1; }
[ -f "$JPG_OUT" ]  && assert_clean "$JPG_OUT"
[ -f "$DOCX_OUT" ] && assert_clean "$DOCX_OUT"

echo
echo "[4] originals are untouched (read-only guarantee):"
"$BIN" check --json - <"$JPG"  >/dev/null 2>&1 && r1=clean || r1=dirty
"$BIN" check --json - <"$DOCX" >/dev/null 2>&1 && r2=clean || r2=dirty
[ "$r1" = dirty ] && [ "$r2" = dirty ] || { echo "FAIL: an original was modified by the action"; fail=1; }
note "OK originals still report dirty (never rewritten): jpg=$r1 docx=$r2"

echo
if [ "$fail" -eq 0 ]; then
    echo "PASS: file-manager scrub action produces clean scrubbed siblings."
    exit 0
else
    echo "FAILED."
    exit 1
fi
