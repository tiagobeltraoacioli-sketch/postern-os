#!/usr/bin/env bash
# check-trust-labels.sh — the mechanical half of the "trust-label bleed" guardrail
# (holistic-VISION.md #5 / the existential guardrail).
#
# Honest labeling IS the value proposition: a single leak of an attestation-grade
# word onto an unaudited / non-attestable / preview surface poisons it. This is a
# HEURISTIC tripwire, not a proof — it flags affirmative claims for human review
# and hard-fails on two absolutes. It never "passes" a surface as safe; it only
# catches the obvious bleed. Pair it with the EnforcementMode type (postern-policy)
# so the labels are typed, not just grepped.
#
# Exit non-zero on any CRITICAL finding (for CI). Two checks are BLOCKING: the
# 'Baba Yaga' trademark string (CRITICAL 1) and attestation-grade words bleeding
# onto the non-attestable tiers (CRITICAL 2 — promoted from WARN per R1). The
# remaining WARN pass (bare secure/audited) is printed for review and does not
# fail by default (set STRICT=1 to fail on warnings too).
set -uo pipefail
cd "$(dirname "$0")/.."

crit=0
warn=0

# Never descend into build output / vendored / VCS dirs.
EX="--exclude-dir=target --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist"

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }

# Surfaces that must NEVER claim attestation/audit — the non-attestable tiers and
# unbuilt/preview scaffolds. "Postern OS" (Nix, attestable) is deliberately excluded.
NONATTEST_PATHS=(
  pmos-overlay
  apps/sloboda
  apps/sloboda-gate
  os/sloboda-compat.nix
)

# Qualified tier (A9 bridge-trust-boundaries.md §5A): the Porog/NoporIS glue + UI.
# These MAY legitimately say Porog is "key-attested" (the phone's device key) and
# name "StrongBox", so a blanket ban would wrongly kill a TRUE claim. They are
# scanned with 'key-attest…' STRIPPED and 'strongbox' dropped from the forbidden
# set (see FORBIDDEN_LC_Q + scan_nonattest strip arg), while the workspace-level
# overclaims (attestable/attested/hardware-backed/measured-boot/seal-covered/…)
# still hard-fail. The "key-attested" claim is instead policed by CRITICAL 3's
# qualifier-companion rule (§2.2). Previously these dirs sat outside any scan —
# the coverage gap A9 flagged (an 'attestable-capable' door / 'attested' badge).
QUALIFIED_PATHS=(
  apps/noporis-switcher
  apps/noporis-signer-glue
  apps/noporis-bridge-glue
  apps/noporis-gate
  apps/noporis-tor-glue
  apps/porog-tor-glue
)

# CRITICAL 4 source surfaces (dossier 2026-07-16 §"Riscos", backlog item 10): the
# NoporIS control-plane, the Porog Container source (DPC kernel + Kotlin), and the
# whole Terem (OS Portal v2) tree. Until now NONE of these were scanned, so an
# attestation OVERCLAIM on them passed CI clean — the exact gap the dossier flags
# ("check-trust-labels.sh não cobre noporis/porog/terem — overclaim passa no CI").
# These are NOT the same as QUALIFIED_PATHS: they are richer, honesty-dense
# surfaces (real Key-Attestation code, long compliance docs, hostile-input test
# fixtures) whose device-key claims are TRUE (Porog key-attests the phone on real
# StrongBox/Secure-Enclave hardware — G3-legitimate) and whose "attested" mentions
# are contrast references to the Postern OS host. So CRITICAL 4 (below) scans them
# for the words that are NEVER legitimate as a SELF-claim on a mobile/guest tier
# (the Postern-OS-only Seal/measured-boot family + the marketing absolutes), while
# tolerating the true device-key vocabulary. Terem is deliberately included: its
# own code says it is "the non-attestable tier, by construction, forever".
NEWSURF_PATHS=(
  apps/porog-crossprofile
  android-container
  android-common
  android-bridge
  apps/terem-gate
  os-portal-v2/terem-core
  os/terem-compat.nix
)

# Words that are attestation/audit-grade claims. On a non-attestable surface they
# are bleed UNLESS the line negates them (not/no/never/non-/un-/isn't/cannot).
# The measured-boot / Seal family (§2.3, §5B) belongs to Postern OS ONLY; no tier
# may affirmatively claim it about itself, so it is forbidden on every scanned tier.
FORBIDDEN='attestable|attested|tamper-proof|tamper proof|hardware-backed|hardware backed|secure enclave|strongbox|military-grade|military grade|bit-for-bit reproducible|unhackable|NSA-proof|zero-knowledge-proof-of|measured-boot|measured boot|seal-covered|seal covered|os_roothash|postern seal'
NEGATION='not |no |never|non-|un-|isn.t|are n.t|cannot|can.t|NOT|without|lacks|fails|refus'

# Lowercased variants for the awk pass below (the self-hosted mac runner's BSD awk
# has no IGNORECASE, so we tolower() both text and pattern). '≠' is intentionally
# omitted — an adjacent 'not/never/no' line already negates those idioms and a
# multibyte character class is not portable across awk builds. CONTRAST adds the
# guardrail-meta words ('bleed', 'poison') and the shell metadata-field read
# ('mget attestable') so the honesty docs' own disclaimers do not self-trip.
FORBIDDEN_LC='attestable|attested|tamper-proof|tamper proof|hardware-backed|hardware backed|secure enclave|strongbox|military-grade|military grade|bit-for-bit reproducible|unhackable|nsa-proof|zero-knowledge-proof-of|measured-boot|measured boot|seal-covered|seal covered|os_roothash|postern seal'
# Qualified-path forbidden set: identical to FORBIDDEN_LC but WITHOUT 'strongbox'
# (a legitimate device-keystore name on Porog surfaces). 'key-attest…' is not
# listed either — it is stripped from the line before matching (scan_nonattest's
# strip arg), so Porog's TRUE "key-attested" claim survives while a bare
# "attested/attestable workspace", "hardware-backed", "measured-boot", etc. fail.
FORBIDDEN_LC_Q='attestable|attested|tamper-proof|tamper proof|hardware-backed|hardware backed|secure enclave|military-grade|military grade|bit-for-bit reproducible|unhackable|nsa-proof|zero-knowledge-proof-of|measured-boot|measured boot|seal-covered|seal covered|os_roothash|postern seal'
NEGATION_LC='not |no |never|non-|un-|isn.t|are n.t|cannot|can.t|without|lacks|fails|refus'
CONTRAST_LC='postern os|= ?.?false|"false"|: ?false|only|leave|the attestable|less-|not part|elsewhere|is the requirement|strongbox / keystore|do not|don.t|no .*guarantee|bleed|poison|mget'

# --- CRITICAL 4 (NoporIS/Porog/Terem source surfaces) pattern sets ------------
# A SEPARATE, self-contained set — it does NOT touch the CRITICAL 1-3 sets above,
# so the existing tiers' behaviour is unchanged (no weakening). The forbidden set
# is the subset of attestation vocabulary that can NEVER be a truthful SELF-claim
# on a stock-Android / Linux-guest tier: the Postern-OS-only measured-boot / Seal
# / roothash family, the '-able' capability form ('attestable' = "this workspace
# can be attested"), and the marketing absolutes. The device-key words that ARE
# true here — 'attested'/'hardware-backed'/'strongbox'/'secure enclave' (Porog
# key-attests the phone on real hardware; Terem only ever says 'attested' of the
# Postern OS host) — are deliberately NOT forbidden, so honest code stays green.
FORBIDDEN_NS='attestable|tamper-proof|tamper proof|military-grade|military grade|bit-for-bit reproducible|unhackable|nsa-proof|zero-knowledge-proof-of|measured-boot|measured boot|seal-covered|seal covered|os_roothash|postern seal'
# Negation/contrast for CRITICAL 4. Wider than the CRITICAL 1-3 sets because these
# surfaces disclaim in long prose: negation-list section headers ('what … will NOT
# claim'), 'nothing … is attestable', a 'No "attestable" headline ships' whose 'No'
# ends the PREVIOUS line, an interrogative table header 'Attestable?', and contrast
# to the Postern OS 'attested host/build/image'. A bare affirmative self-claim with
# none of these nearby still fails (proven by the in-repo positive-control test).
NEGATION_NS='not |no |never|non-|un-|isn.t|are n.t|cannot|can.t|without|lacks|fails|refus|nothing|will not|not claim|does not|is the requirement'
CONTRAST_NS='postern os|= ?.?false|"false"|: ?false|only|leave|the attestable|less-|not part|elsewhere|do not|don.t|no .*guarantee|bleed|poison|mget|attested host|attested build|attested image|attested\.nix|attested closure|hostile|relabel|stays pinned|rejected|attestable[?]'
# Hostile-input test fixtures embed the forbidden strings ON PURPOSE (to prove the
# kernel REJECTS/relabels a bogus 'measured-boot-workspace' tier), so they are not
# shipping surfaces and are excluded from the CRITICAL 4 scan.
NS_FIXTURE_EXCLUDE='(golden-vectors|export-vectors|-vectors|/tests?/|test-[a-z-]*\.mjs|\.lock$)'

# Scan one path for attestation-grade bleed. A hit is a FORBIDDEN word on a line
# that is NOT negated by the current OR the immediately-preceding line, and NOT an
# inline contrast/reference to the attestable tier. Prev-line context is what lets
# a multi-line "Never / describe … as hardware-backed" disclaimer read as the
# negation it is; without it the heuristic false-fires on honest disclaimers.
scan_nonattest() {
  local dir="$1"
  local forb="${2:-$FORBIDDEN_LC}"   # forbidden pattern for this pass
  local strip="${3:-0}"              # 1 = strip 'key-attest…' first (qualified tier)
  grep -rilIE $EX "$FORBIDDEN" "$dir" 2>/dev/null | while IFS= read -r f; do
    awk -v FORB="$forb" -v NEG="$NEGATION_LC" -v CON="$CONTRAST_LC" -v STRIP="$strip" '
      {
        lc = tolower($0)
        work = lc
        # Qualified tier: "key-attested" is a TRUE Porog claim (policed by
        # CRITICAL 3, not here), so remove it before testing FORBIDDEN — a bare
        # "attested/attestable" NOT part of "key-attest…" still trips.
        if (STRIP == "1") gsub(/key[ -]?attest[a-z]*/, " ", work)
        if (work ~ FORB) {
          ctx = tolower(prev) "\n" lc
          # Neutralize markdown emphasis and the not-equal sign so a bolded
          # "**not**" or "signed != attested" reads as the negation it is.
          nctx = ctx; gsub(/[*_`]/, " ", nctx); gsub(/\xe2\x89\xa0|!=/, " not ", nctx)
          # Suppress when the current OR the immediately-preceding line carries a
          # NEGATION or CONTRAST token (§2.1: "the same line or the line directly
          # above"). CONTRAST is prev-aware too, so a multi-line "Postern OS is the
          # only … attestable / Seal-covered" contrast stays suppressed.
          if (nctx !~ NEG && nctx !~ CON) printf "%s:%d:%s\n", FILENAME, FNR, $0
        }
        prev = $0
      }' "$f"
  done
}

# Scan a CRITICAL 4 source surface for an attestation SELF-claim overclaim. Unlike
# scan_nonattest (prev-line-only window, tuned to the terse glue-app prose), this
# buffers the whole file and suppresses a hit when a NEGATION_NS/CONTRAST_NS token
# appears within a small window (4 lines back .. 1 line forward) — because these
# surfaces routinely state the claim then disclaim it on the NEXT line ("proves the
# phone … It does NOT measure the workspace") or under a section header a few lines
# up. 'key-attest…' is stripped first (Porog's true phone claim). Test fixtures are
# filtered out by the caller. A real affirmative overclaim with no nearby negation
# still trips (verified by scripts/check-trust-labels.sh's own positive control).
scan_newsurface() {
  local dir="$1"
  grep -rilIE $EX "$FORBIDDEN_NS" "$dir" 2>/dev/null \
    | grep -vE "$NS_FIXTURE_EXCLUDE" \
    | while IFS= read -r f; do
      awk -v FORB="$FORBIDDEN_NS" -v NEG="$NEGATION_NS" -v CON="$CONTRAST_NS" '
        { raw[NR] = $0; L[NR] = tolower($0) }
        END {
          for (i = 1; i <= NR; i++) {
            w = L[i]; gsub(/key[ -]?attest[a-z]*/, " ", w)
            if (w ~ FORB) {
              # Context window: up to 4 preceding lines + 1 following line.
              c = L[i]
              for (j = i-4; j < i; j++) if (j >= 1) c = L[j] "\n" c
              if (i < NR) c = c "\n" L[i+1]
              # Neutralize md emphasis, the not-equal sign, and a line-final "no"
              # (a "…hardware. No\n\"attestable\" headline" spread across two lines).
              n = c; gsub(/[*_`]/, " ", n); gsub(/\xe2\x89\xa0|!=/, " not ", n)
              gsub(/no$|no"|[^a-z]no\n/, " not ", n)
              if (n !~ NEG && n !~ CON) printf "%s:%d:%s\n", FILENAME, i, raw[i]
            }
          }
        }' "$f"
    done
}

# ---------------------------------------------------------------------------
hdr "CRITICAL 1 — 'Baba Yaga' must not appear in shipping surfaces (trademark, Class 9)"
# Ship as Yagabona/Izbushka; never the registered string. Scan code/UI/site.
# Code/UI/config only — a defensive nominative note in a .md ("we ship as
# Yagabona, NOT the registered 'BABA YAGA'") is allowed; the string in shipping
# metadata (Cargo.toml descriptions, .rs/.html/.js) is not.
byhits=$(grep -rniE $EX 'baba[ -]?yaga' apps crates site desktop pmos-overlay 2>/dev/null \
  | grep -viE '\.md:' \
  | grep -viE 'never|not |instead|avoid|registered|class ?9|trademark|word ?mark|reg\.' || true)
if [ -n "$byhits" ]; then
  say "FAIL: 'Baba Yaga' found in a shipping surface:"; say "$byhits"; crit=$((crit+1))
else
  say "ok — no 'Baba Yaga' in apps/crates/site/desktop/pmos-overlay."
fi

# ---------------------------------------------------------------------------
hdr "CRITICAL 2 — attestation-grade words on non-attestable tiers (BLOCKING, R1)"
# Promoted WARN -> FAIL (R1). These surfaces (pmOS overlay, Sloboda) are the
# NON-attestable tiers; an affirmative attestation/audit-grade claim here is a
# trust-label bleed and must hard-fail the pipeline. Honest disclaimers that negate
# the word or point at the attestable Postern OS tier are suppressed by
# scan_nonattest (current + preceding line). A residual hit is a real
# 'this non-attestable tier is attestable' claim and blocks the merge.
na_hits=""
for p in "${NONATTEST_PATHS[@]}"; do
  [ -e "$p" ] || continue
  h=$(scan_nonattest "$p")
  [ -n "$h" ] && na_hits="${na_hits}${h}"$'\n'
done
# Qualified tier (A9 §5A): scan the Porog/NoporIS glue+UI with 'key-attest…'
# stripped and 'strongbox' dropped — so the TRUE "key-attested device" claim
# survives while an "attestable/attested/hardware-backed/measured-boot" WORKSPACE
# overclaim (e.g. an 'attested' badge class) still hard-fails.
for p in "${QUALIFIED_PATHS[@]}"; do
  [ -e "$p" ] || continue
  h=$(scan_nonattest "$p" "$FORBIDDEN_LC_Q" 1)
  [ -n "$h" ] && na_hits="${na_hits}${h}"$'\n'
done
if [ -n "$(printf '%s' "$na_hits" | tr -d '[:space:]')" ]; then
  say "FAIL: attestation-grade claim on a non-attestable / qualified tier (fix before shipping):"
  printf '%s\n' "$na_hits" | sed '/^[[:space:]]*$/d'
  crit=$((crit+1))
else
  say "ok — no attestation-grade bleed on non-attestable tiers (pmOS, Sloboda) or the Porog/NoporIS qualified tier."
fi

# ---------------------------------------------------------------------------
hdr "CRITICAL 3 — 'key-attested' without its 'not measured-boot' qualifier (BLOCKING, §2.2/§5C)"
# Porog legitimately owns "key-attested", but "key-attested" WITHOUT its
# "not a measured-boot workspace" qualifier silently implies workspace/measured-boot
# attestation — the exact overclaim. Positive-companion rule: every 'key-attest…'
# on a Porog/NoporIS surface must have a "not/never … measured(-boot)" within a
# ±3-line window, else FAIL. This is the inverse of CRITICAL 2's ban.
kc_hits=""
for p in "${QUALIFIED_PATHS[@]}"; do
  [ -e "$p" ] || continue
  while IFS= read -r f; do
    h=$(awk '
      { L[NR] = tolower($0) }
      END {
        for (i = 1; i <= NR; i++) if (L[i] ~ /key[ -]?attest/) {
          ok = 0
          for (j = i-3; j <= i+3; j++)
            if (j >= 1 && j <= NR && L[j] ~ /not[^a-z]*measured|not a measured|never[^a-z]*measured|never a measured/) ok = 1
          if (!ok) printf "%s:%d: key-attested without \"not a measured-boot workspace\" qualifier within +/-3 lines\n", FILENAME, i
        }
      }' "$f")
    [ -n "$h" ] && kc_hits="${kc_hits}${h}"$'\n'
  done < <(grep -rilIE $EX 'key[ -]?attest' "$p" 2>/dev/null)
done
if [ -n "$(printf '%s' "$kc_hits" | tr -d '[:space:]')" ]; then
  say "FAIL: 'key-attested' missing its 'not a measured-boot workspace' companion (§2.2):"
  printf '%s\n' "$kc_hits" | sed '/^[[:space:]]*$/d'
  crit=$((crit+1))
else
  say "ok — every 'key-attested' on a Porog/NoporIS surface carries its 'not measured-boot' qualifier."
fi

# ---------------------------------------------------------------------------
hdr "CRITICAL 4 — attestation overclaim on NoporIS/Porog/Terem source (BLOCKING, dossier item 10)"
# Closes the coverage gap the 2026-07-16 dossier flagged: these source trees (the
# NoporIS control-plane, the Porog Container DPC/kernel, and the whole Terem OS
# Portal v2 tree) were scanned by NO prior check, so a workspace/measured-boot/Seal
# overclaim on them merged clean. A residual hit here is a real 'this guest tier is
# measured-boot / Seal-covered / attestable' SELF-claim (the words that can never be
# truthful on a stock-Android or Linux-guest tier) — not the phone's true
# key-attestation, which is tolerated — and blocks the merge.
ns_hits=""
for p in "${NEWSURF_PATHS[@]}"; do
  [ -e "$p" ] || continue
  h=$(scan_newsurface "$p")
  [ -n "$h" ] && ns_hits="${ns_hits}${h}"$'\n'
done
if [ -n "$(printf '%s' "$ns_hits" | tr -d '[:space:]')" ]; then
  say "FAIL: attestation self-claim overclaim on a NoporIS/Porog/Terem source surface (fix before shipping):"
  printf '%s\n' "$ns_hits" | sed '/^[[:space:]]*$/d'
  crit=$((crit+1))
else
  say "ok — no attestation overclaim on the NoporIS/Porog/Terem source surfaces (control-plane, Porog Container, Terem)."
fi

# ---------------------------------------------------------------------------
hdr "WARN — bare 'secure' / 'audited' on product surfaces (review for over-claim)"
# These are legitimate when negated ('unaudited', 'not secure yet'); flag the rest.
sw=$(grep -rniE $EX '\b(audited|secure|hardened|production-ready)\b' apps 2>/dev/null \
  | grep -viE "$NEGATION|unaudited|un-audited|to secure|security\.txt|security policy|secure the|secure boot" || true)
if [ -n "$sw" ]; then
  say "review these product-surface claims:"; say "$sw" | head -40; warn=$((warn+1))
else
  say "ok — no bare secure/audited claims flagged on apps/."
fi

# ---------------------------------------------------------------------------
hdr "SUMMARY"
say "critical: $crit   warn: $warn"
if [ "$crit" -gt 0 ]; then
  say "RESULT: FAIL (critical trust-label findings — fix before shipping)."
  exit 1
fi
if [ "${STRICT:-0}" = "1" ] && [ "$warn" -gt 0 ]; then
  say "RESULT: FAIL (STRICT: warnings present)."
  exit 1
fi
say "RESULT: pass (heuristic — human review still required; this is a tripwire, not a proof)."
exit 0
