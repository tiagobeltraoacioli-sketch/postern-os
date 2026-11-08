# App review — Content Safety & Duress

**Reviewer slice:** `postern-hygiene`, `postern-quarantine`, `postern-panic` (+ their `postern-sdk` FFI wrappers and `postern-vault` foundation).
**Status of code under review:** pre-release / **UNAUDITED**. Read-only review — no code was modified.
**Scope of lens:** untrusted-file parsing, decompression bombs, path traversal, metadata-scrub completeness, quarantine isolation, duress/panic zeroization + observability, panic-on-hostile-input.

Findings are ranked most-severe first. Each fix is tagged **SMALL/safe (apply now)** or **LARGE/defer (human)**.

---

## HIGH — 1. "Metadata never rides along" / "revision trails" is an overclaim; OOXML scrub misses the biggest leaks

- **file:** `crates/postern-hygiene/src/lib.rs:82-146` (`scrub_ooxml`), claim sites `crates/postern-courier/src/lib.rs:8`, `apps/postern-store/index.html:1059` ("metadata never rides along") and `:1133` ("revision trails").
- **Failure (inputs → bad outcome):** `scrub_ooxml` only rewrites `docProps/core.xml`, strips `Company`/`Manager` from `docProps/app.xml`, and drops `docProps/custom.xml`. **Every other part is copied byte-for-byte** (`_ => { w.start_file… w.write_all(&data) }`, line 137-140). That leaves the identifying data users most expect to be gone:
  - **Tracked-change and comment authorship** in `word/document.xml`, `word/comments.xml`, `word/people.xml` — `w:author="Alice"` on `<w:ins>/<w:del>`, `w:comment w:author=…`, and `rsid` session IDs. The store literally advertises stripping **"revision trails"** (`:1133`); the code strips none of it. A `.docx` scrubbed here still names every editor.
  - **Embedded thumbnail** `docProps/thumbnail.jpeg`/`.emf` — a preview render of page 1, often carrying its own EXIF. Not dropped.
  - **`customXml/` parts** (Office custom-XML data store, distinct from `docProps/custom.xml`) — SharePoint/DMS metadata, case IDs. Not dropped.
  - **`word/media/*` embedded images** — retain their own EXIF/GPS. Not scrubbed.
  - **`app.xml` residue** beyond Company/Manager: `Template`, `TitlesOfParts`, `TotalTime`, `HyperlinkBase` (can be a local filesystem path). Not touched.
- **Why it's a HIGH:** this is the flagship "anonymize before you share" product. A user who trusts "metadata never rides along" will disclose editor identities and internal paths. A partial scrub that reads as total is worse than none, because it defeats the user's own caution.
- **Fix:** *SMALL/safe (apply now)* for the honesty half — soften the copy: the store card, courier doc, and crate rustdoc must scope the claim to "author/company/timestamps in `docProps`", and explicitly say tracked-change authors, comments, embedded thumbnails and media EXIF are **not yet** stripped. *LARGE/defer (human)* for the real scrub: parse `word/document.xml`/`comments.xml` to drop `w:author`/`rsid`, drop `docProps/thumbnail.*`, drop `customXml/`, and recurse `scrub_jpeg` over `word/media/*`.

---

## HIGH — 2. JPEG scrub only drops APP1; IPTC/Photoshop author + comments survive

- **file:** `crates/postern-hygiene/src/lib.rs:233-275` (`scrub_jpeg`).
- **Failure:** the loop drops only marker `0xE1` (APP1 = EXIF/XMP) and copies every other segment through. Identifying metadata lives in markers this code preserves:
  - **APP13 (`0xED`)** — Photoshop IRB / **IPTC-IIM**: `By-line` (author), `Copyright`, `Credit`, caption, and city/country/GPS fields. Written by Lightroom, Photoshop, most photo pipelines. Survives untouched.
  - **COM (`0xFE`)** — free-text comment; encoders/tools embed usernames, tool banners, paths. Survives.
  - **APP2 (`0xE2`)** — ICC profile / MPF; usually benign but can name the creating device/profile. Survives.
- **Outcome:** a photo "scrubbed" here still carries the photographer's name, copyright line, and sometimes location, contradicting the store's "remove EXIF and GPS from photos" for any IPTC-tagged image. Also note the scrubber is **JPEG-only** — PNG (`eXIf`/`tEXt`/`iTXt`), TIFF, HEIC, WebP get no scrub at all despite the "photos" framing.
- **Fix:** *SMALL/safe (apply now)* — also drop `0xED` (APP13) and `0xFE` (COM); optionally drop all `APPn` except APP0/JFIF. Update the rustdoc/store to say JPEG-only until other formats land.

---

## HIGH — 3. JPEG scrub fails **open** on a malformed segment length (silent EXIF passthrough)

- **file:** `crates/postern-hygiene/src/lib.rs:263-266`.
- **Failure (inputs → bad outcome):**
  ```
  if len < 2 || seg_end > input.len() {
      out.extend_from_slice(&input[i..]); // malformed length — copy rest, don't lose data
      break;
  }
  ```
  If an **APP1** (or APP13) segment declares a length that runs past end-of-buffer — trivially forgeable, and also produced by some real cameras — the scrubber copies the **entire remainder including the un-dropped metadata segment** and returns `Ok`. The caller sees success and a `ScrubReport`, but the EXIF/IPTC block rode along. "Don't lose data" was chosen over "don't leak data" in a privacy tool.
- **Outcome:** an adversary who wants their metadata to survive a Postern scrub only has to overstate one APP-segment length by one byte; the user is told the file is clean.
- **Fix:** *SMALL/safe (apply now)* — on a malformed/oversized segment length, return `Err(HygieneError::…)` (fail closed) instead of copying the tail. A privacy scrubber must never emit "cleaned" bytes it did not fully parse.

---

## HIGH — 4. "Duress lock" is marketed but **no decoy / plausible-deniability exists** — panic is denial-of-access only

- **file:** `crates/postern-panic/src/lib.rs` (whole crate), `crates/postern-sdk/src/panic.rs:1,20,33` ("duress-lockable", "seal under duress"), `apps/postern-store/index.html:1103-1104` (capability "duress lock", tags `duress`,`coercion`).
- **Finding:** `PanicSession` is a single vault + single key with `panic()` (seal + evict) and `unlock(key)` (reopen). There is **no duress passphrase, no decoy vault, no fake-empty state** anywhere in the code — verified: the string "duress"/"decoy"/"deniab" appears only in doc comments, never in logic. The decoy-PIN mechanism is described only in `docs/specs/POSTERN-DEADBOLT.md:40-41` as the **deferred** variant.
- **Why it matters (safety, not just wording):** the crate's own ethos ("denial of access", `lib.rs:11-13`) and the store oneliner ("denial of access that destroys nothing", `:1101`) are honest. But the SDK naming ("duress-lockable session", "seal under duress") and the store **"duress lock"** capability imply coercion-resistance / deniability that is not implemented. Under coercion the panic state is trivially observable — `is_locked()` returns `true`, the app plainly shows a locked vault, and the coercer simply compels the real key. A user who believes "duress" means a decoy will present a *locked* device to an adversary who can then demand it be unlocked, with no fallback. Selling deniability that doesn't exist endangers exactly the theft/coercion/kidnap victim in the threat model.
- **Fix:** *SMALL/safe (apply now)* — drop "duress" from the SDK module/rustdoc and the store capability; describe it as "instant panic re-lock (denial of access)". Reserve "duress"/"decoy" wording for when the deferred decoy-PIN in the Deadbolt spec actually ships. *LARGE/defer (human)* — if deniability is a product goal, build the decoy vault + duress key.

---

## MEDIUM — 5. PDF scrub leaves the `/ID` fingerprint and any per-object/-page XMP

- **file:** `crates/postern-hygiene/src/lib.rs:151-184` (`scrub_pdf`).
- **Failure:** removes the trailer `/Info` object and the **Catalog** `/Metadata` (XMP) stream — good — but:
  - **Trailer `/ID`** (the two-element file-identifier array) is not removed. Many producers seed it from author/path/timestamp; it is a stable correlator across copies. Survives.
  - **XMP attached to non-Catalog objects** — page dictionaries, image XObjects, and embedded files each may carry their own `/Metadata` stream. Only the Catalog's is dropped; per-page/-image XMP survives.
  - **Embedded files** (`/Names /EmbeddedFiles`) keep their own metadata.
- **Outcome:** a PDF "cleaned" for Author/Producer/dates + top-level XMP still carries a durable `/ID` fingerprint and any page-level XMP.
- **Fix:** *SMALL/safe (apply now)* — also `doc.trailer.remove(b"ID")`. *LARGE/defer (human)* — walk all objects for `/Metadata` streams and embedded-file info, not just the Catalog.

---

## MEDIUM — 6. `quarantine_image` runs an untrusted decoder in-process, no sandbox, no dimension cap → decode-bomb DoS and live decoder attack surface

- **file:** `crates/postern-quarantine/src/lib.rs:38-44` (`quarantine_image`); claim `apps/postern-store/index.html:1149` ("exploits… don't survive").
- **Failure (inputs → bad outcome):**
  1. `image::load_from_memory` uses the crate's **default `Limits`** — `max_alloc: Some(512 MiB)` but **`max_image_width/height: None`** (verified in `image-0.25.10/src/io/limits.rs:49-56`). A ~1 KB PNG/JPEG declaring enormous dimensions forces allocation up to the 512 MiB cap, then the mandatory PNG **re-encode** allocates and CPU-crunches the full raster. Single blocking call, no timeout. On the exact threat quarantine exists for — a hostile inbound file — one attachment can pin ~0.5–1 GB + a CPU spike per call.
  2. The image path has **no sandbox** (the module doc reserves Landlock/seccomp for the *unbuilt* PDF/Office path, `lib.rs:12-16`). The store says quarantine makes "exploits… don't survive" — but for images the **decoder itself is the attack surface**, and it runs in-process. A memory-safety bug in an `image` decoder (the class has had RUSTSEC advisories) executes *during decode*, before the "pixel round-trip" neutralizes anything. The round-trip protects the *output*, not the host doing the decoding.
- **Fix:** *SMALL/safe (apply now)* — build with an explicit `image::io::Reader` and set `Limits{ max_image_width/height }` to sane bounds (plus keep/lower `max_alloc`); document that decode is in-process and unsandboxed for images. *LARGE/defer (human)* — run the decode in the same Landlock/seccomp sandbox planned for the PDF path, or a subprocess with a wall-clock timeout, before claiming exploit-neutralization for images.

---

## LOW — 7. Panic key is a `Copy [u8; 32]`; stack/heap residue survives zeroization

- **file:** `crates/postern-panic/src/lib.rs:50-64` (`panic`), `68-85` (`unlock`), `113-118` (`Drop`); `crates/postern-vault/src/lib.rs:89-94` (`seal`).
- **Failure:** the master key is `[u8; 32]`, which is `Copy`. In `panic()` the key is moved out via `mem::replace` and re-bound (`if let State::Unlocked { … mut key } = old`), a bitwise copy; only the final `key` binding is zeroized. Earlier copies (the source enum slot, the `vault.seal(key)` frame) may linger in stack memory unwiped. Likewise `Vault::seal` builds `plain` by `Vec::extend`; reallocation leaves secret bytes in freed heap even though the final buffer is zeroized (`vault/src/lib.rs:90-93`). The functional zeroization is correct; this is defense-in-depth residue.
- **Fix:** *SMALL/safe (apply now)* — hold the key in a non-`Copy` `zeroize::Zeroizing<[u8;32]>` (or a `Secret` wrapper) so every move is tracked and drop-wiped; pre-`reserve` the serialize buffer to avoid reallocation, or serialize into a fixed `Zeroizing<Vec<u8>>`.

---

## LOW — 8. Scrubbed OOXML re-stamps every entry with the scrub-time clock

- **file:** `crates/postern-hygiene/src/lib.rs:102-103` (`SimpleFileOptions::default()`), with `zip` built `time`-enabled (confirmed in `Cargo.lock`).
- **Failure:** `SimpleFileOptions::default()` sets `last_modified_time = DateTime::default_for_write()` = **`OffsetDateTime::now_utc()`** (`zip-2.4.2/src/types.rs:136-141`). Every rewritten/copied entry in the output package is stamped with the moment of scrubbing. This removes the *original* timestamps (good) but writes a fresh, uniform "scrubbed at HH:MM:SS UTC today" fingerprint across all entries — a new, if weak, metadata signal.
- **Fix:** *SMALL/safe (apply now)* — pin a fixed epoch (e.g. `DateTime::default()` = 1980-01-01) via `.last_modified_time(...)` on the write options so scrub output is deterministic and time-neutral.

---

## LOW — 9. SDK `Mutex::lock().unwrap()` panics on poison (availability)

- **file:** `crates/postern-sdk/src/panic.rs:29-52` (every method does `self.inner.lock().unwrap()`).
- **Failure:** if any method panics while holding the lock, the mutex is poisoned and **every subsequent call panics** — including `panic()` and `is_locked()`. In a panic-button product, a poisoned lock means the emergency re-lock and the state check become unreachable. No secret leak, but a denial of the safety function. (Not a duress-distinguisher, since it fails uniformly.)
- **Fix:** *SMALL/safe (apply now)* — recover with `lock().unwrap_or_else(|e| e.into_inner())` for the state-reading/locking paths so panic-lock survives a poisoned mutex.

---

## Informational

- **lopdf / image untrusted-parser panic surface.** `scrub_pdf` (`lib.rs:153`) and `quarantine_image` (`lib.rs:39`) both feed fully untrusted bytes to third-party parsers. Versions are current and patched — `lopdf 0.43.0` (Cargo.toml notes it clears RUSTSEC-2026-0187 fixed in ≥0.42), `image 0.25.10` — and both APIs return `Result`, but library-internal `panic!`/overflow on adversarial input would still abort the process (or poison the SDK mutex, see #9). Keep `cargo-deny`/RUSTSEC watch on both. Note `deny.toml:22` downgrades transitive advisories (incl. via lopdf) to warnings — acceptable but means an advisory here won't fail CI on its own.
- **Zip Slip is N/A here (good).** `scrub_ooxml` never extracts archive entries to the filesystem — it decompresses in memory and re-zips (`lib.rs:104-143`). Malicious `../` entry names are copied as opaque names, not written to disk, so archive path traversal does not apply on this path.
- **No indexing panics found in hand-rolled parsers.** `scrub_jpeg` bounds-checks every slice (`i+1 < len`, the `i+3 >= len` guard, `seg_end <= input.len()`); `postern-vault::deserialize` (`vault/src/lib.rs:132-158`) validates every length against buffer size and returns `Corrupt`; `to_array` (`sdk/src/lib.rs:40-44`) errors instead of panicking on wrong key length. `String::from_utf8_lossy` on `app.xml` (`lib.rs:131`) cannot panic.

## Positives worth keeping

- **Zip-bomb caps in hygiene are genuinely enforced on the one path** (`lib.rs:91-120`): `MAX_ENTRIES` on `zip.len()`, per-entry `take(MAX_ENTRY+1)` that bounds the *actual decompressed read* regardless of a lying header, and a running `MAX_TOTAL` accumulator. This is the correct pattern and closes the 42.zip amplification vector for OOXML.
- **Panic zeroization logic is correct** for the tracked buffers: `panic()` seals before mutating (no data loss on failure), evicts the key and drops the vault; `unlock()` wipes the caller's key copy on the wrong-key path (`lib.rs:75-78`); `Drop` wipes the key on non-panic teardown (`lib.rs:113-118`). Residue caveats in #7 are defense-in-depth, not a functional gap.
- **Quarantine image containment is real:** decode → re-encode → return bytes, in-process, with **no execution, auto-open, or callback** of the input — the isolation claim holds for what the code does; the gap is the unsandboxed decoder itself (#6), not leakage of the neutralized output.

---

### 5-line summary
1. **Hygiene overclaims:** OOXML scrub leaves tracked-change/comment authors, embedded thumbnails, `customXml` and media EXIF, so "metadata never rides along" and "revision trails" (store/courier) are HIGH overclaims (#1).
2. **JPEG scrub is incomplete and fails open:** only APP1 is dropped — IPTC/Photoshop author+GPS (APP13) and COM comments survive — and a malformed segment length silently passes the metadata through as "cleaned" (#2, #3).
3. **"Duress lock" is marketed but not built:** `postern-panic` is denial-of-access only — no decoy, no deniability; panic state is plainly observable, so selling "duress" endangers the coercion victim in the threat model (#4).
4. **Quarantine's image path** runs an untrusted decoder in-process, unsandboxed, with no dimension cap — a decode-bomb DoS and a live parser attack surface that the "pixel round-trip" does not cover (#6); PDF `/ID` fingerprint survives hygiene (#5).
5. **Genuine strengths:** hygiene's zip-bomb caps are correctly enforced, Zip Slip is N/A (in-memory rebuild), and panic key/vault zeroization is functionally correct (Copy-key stack residue is a LOW defense-in-depth item, #7). Pre-release/UNAUDITED; no revenue touches the token.
