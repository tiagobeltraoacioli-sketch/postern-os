# desktop/file-manager/ — right-click "Scrub metadata" action

Wires the **already-shipping** stdin/stdout embed mode of the Postern Hygiene
scrubber (`postern-hygiene scrub -` / `check -`, black-box tested in
`crates/postern-hygiene/tests/cli.rs`) into a native file-manager right-click
action. This fills the roadmap gap **"OS/file-manager embed not wired yet"**:
the core pipe has existed for a while; this is the missing GUI glue.

Select a file in your file manager → right-click → **Scrub metadata (Postern
Hygiene)** → a scrubbed copy appears next to it (`photo.jpg` →
`photo.scrubbed.jpg`). The original is opened read-only and never modified.

UNAUDITED, pre-mainnet — like everything in this repo. This adds no crypto and
makes no new claim; it only pipes files through the existing scrubber.

## Layout

| Path | Role |
|------|------|
| `postern-scrub.sh` | The **one** piece of glue every integration calls: pipes each selected file through `postern-hygiene scrub -` into a non-clobbering `.scrubbed` sibling. Fail-closed (a non-zero scrub deletes the partial output). |
| `linux/postern-hygiene-scrub.desktop` | freedesktop Desktop-Entry **+ Desktop-Action** file — KDE Dolphin ServiceMenus, and GNOME Files via `filemanager-actions`/`nautilus-actions`. Passes `%F`. |
| `linux/nautilus-scripts/Scrub metadata (Postern Hygiene)` | GNOME Files / Nautilus **Scripts** drop-in (plain Nautilus has no native `.desktop` service menus). Uses `$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS`. |
| `macos/Postern Scrub Metadata.workflow/` | macOS **Automator Quick Action** (a Finder Service). `Run Shell Script` action → `postern-scrub.sh`. |
| `install.sh` | Per-user installer (no root). Auto-detects Linux vs macOS and drops the right integration + the shared core into the user's config dirs. `--uninstall` reverses it. |
| `test-scrub-action.sh` | Acceptance: synthesizes a real EXIF-tagged JPEG + an OOXML with author metadata, runs the action, asserts each scrubbed sibling is `check --json` **clean**. |

The same acceptance runs hermetically under Cargo (no python needed):
`cargo test -p postern-hygiene --test file_manager_action`.

## Install

```sh
# 1. Build/instal the scrubber binary and put it on PATH (or export POSTERN_HYGIENE_BIN):
cargo build -p postern-hygiene --release --bin postern-hygiene
#   e.g. cp target/release/postern-hygiene ~/.local/bin/   (or /usr/local/bin)

# 2. Install the right-click action for the current user:
desktop/file-manager/install.sh
#   Linux:  Nautilus Scripts + KDE ServiceMenu
#   macOS:  ~/Library/Services Quick Action (appears under Finder > Quick Actions)
```

`postern-scrub.sh` finds the binary via `$POSTERN_HYGIENE_BIN`, then `PATH`,
then a `postern-hygiene` next to itself, then the repo's `target/{debug,release}`.

## Test

```sh
cargo build -p postern-hygiene --bin postern-hygiene
POSTERN_HYGIENE_BIN=target/debug/postern-hygiene \
  desktop/file-manager/test-scrub-action.sh
# ... [3] scrubbed siblings exist and are clean ...
# PASS: file-manager scrub action produces clean scrubbed siblings.
```

## Honest limits

- Scrubs the formats the core supports (OOXML/ODF, PDF, JPEG, PNG — magic-byte
  detection, never by extension). An unrecognized format fails closed: the
  action reports failure and writes **no** sibling.
- A non-empty `passed_through` in the report (e.g. embedded EMF/GIF/TIFF media
  the core cannot scrub) means the copy is **not** fully scrubbed; the report is
  forwarded to stderr / a desktop notification rather than silently blessed.
- The `.workflow` and `.desktop` files are checked in as source. macOS may
  require approving the Quick Action once under System Settings → Extensions,
  and Gatekeeper/quarantine rules apply to anything copied from the internet.
