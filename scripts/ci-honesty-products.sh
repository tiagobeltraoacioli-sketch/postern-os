#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# ci-honesty-products.sh — BLOCKING honesty gate for the PRODUCT surfaces.
#
# A pure `git grep` tripwire (no toolchain, no build) over the shipping product
# tree (apps/, site/, desktop/, pmos-overlay/, public/). It closes the same class
# of risk as scripts/ci-banned-words.sh (bloch-blockchain) but for THIS repo's
# consumer products: trademark leaks, product-name misuse, coin/investment
# claims, and bare privacy/security over-claims.
#
# It is a HEURISTIC, not a proof: it flags high-signal AFFIRMATIVE constructions
# and post-filters out honest DISCLAIMERS (negated forms) and the honesty RAILS
# themselves (the "never use BABA YAGA" / "no app is 100% private" notes). It
# self-excludes (this script and the sibling gates carry the banned patterns as
# data). A clean run is necessary, not sufficient — human review still applies.
#
# Four checks, all case-insensitive, all over the TRACKED tree (`git grep`, so it
# matches exactly what a CI checkout carries). ERE only (git's -E), no PCRE — so
# it is identical on macOS/BSD and Linux/GNU runners.
#
#   1. TRADEMARK        "BABA YAGA" (federally registered, Class 9) used as a
#                       product name. Ship as Yagabona / Izbushka. The honest
#                       "never the registered 'Baba Yaga' word mark" rail is
#                       exempt; the string as a live product name is not.
#   2. NAME MISUSE      the apk / Waydroid / community (non-attestable) edition
#                       called "Postern OS". "Postern OS" is the attestable Nix
#                       edition ONLY; the escape-hatch tier is "Postern Android".
#   3. COIN CLAIM       any affirmative coin/token value or investment claim.
#                       The rail is: the coin is worthless, not a security,
#                       revenue never touches it. Honest disclaimers are exempt.
#   4. OVER-CLAIM       bare "100% private" / "fully secure|audited|attested|
#                       anonymous" (and kin) NOT inside a negation. "not fully
#                       private", "no app is 100% private" and friends are exempt.
#
# Usage:  scripts/ci-honesty-products.sh     # run from anywhere inside the repo
# Exit:   0 = clean, 1 = at least one violation (prints file:line for each).

set -eu

# Run from the repo root so `git grep` covers the whole tracked product tree.
cd "$(git rev-parse --show-toplevel)"

# Product surfaces to scan. Docs (.md) are IN scope so a README that misuses a
# mark or makes a coin claim is caught; the negation/rails filters below keep the
# honest policy docs green. apps/postern-enterprise/ is scanned read-only like
# any other app — this gate never writes.
PATHS="apps site desktop pmos-overlay public"

# Self-exclude: this gate and its siblings embed the banned patterns as data.
EXCL=":!scripts/ci-honesty-products.sh :!scripts/ci-banned-words.sh :!scripts/check-trust-labels.sh"

# Shared negation post-filter: a line whose banned phrase sits in a negated /
# disclaimer context is an HONEST statement, not a violation.
NEG='\b(not|no|never|without|nothing|isn.?t|aren.?t|cannot|can.?t|won.?t|neither|un-)\b|worthless|no value|no such thing|far from|sem valor|n[aã]o [eé]|n[aã]o h[aá]'

fail=0

# scan PATTERN [EXTRA_EXEMPT]
#   git-greps the product tree for PATTERN, then drops lines matching NEG or the
#   optional EXTRA_EXEMPT. Prints the survivors (file:line:text). Empty = clean.
scan() {
  pat=$1
  extra=${2:-}
  hits=$(git grep -iInE -- "$pat" -- $PATHS $EXCL 2>/dev/null || true)
  [ -n "$hits" ] || { printf '%s' ''; return 0; }
  hits=$(printf '%s\n' "$hits" | grep -viE "$NEG" || true)
  if [ -n "$extra" ] && [ -n "$hits" ]; then
    hits=$(printf '%s\n' "$hits" | grep -viE "$extra" || true)
  fi
  printf '%s' "$hits"
}

report() {
  title=$1
  body=$2
  advice=$3
  if [ -n "$body" ]; then
    printf '\n\342\235\214 %s\n' "$title"
    printf '   %s\n   Offending lines:\n' "$advice"
    printf '%s\n' "$body" | sed 's/^/     /'
    fail=1
  else
    printf '\342\234\223 %s — clean.\n' "$title"
  fi
}

# ── 1. TRADEMARK ─────────────────────────────────────────────────────────────
# Matches baba<sep>yaga with sep = space / _ / - / &nbsp; / &#160; / &#xa0;, plus
# the glued "babayaga". The Alibaba ticker "BABA" / the word "alibaba" have no
# trailing "yaga", so they never match. TM_RAILS exempts the honest nominative
# "never the registered 'Baba Yaga' word mark" note.
TM='baba([[:space:]_-]|&nbsp;|&#160;|&#xa0;)*yaga|babayaga'
TM_RAILS='never|not |instead|avoid|registered|trademark|word ?mark|reg\.|class ?9|ship as|coined mark|do not use|don.?t use|yagabona|nominative'
tm_hits=$(git grep -iInE -- "$TM" -- $PATHS $EXCL 2>/dev/null || true)
[ -n "$tm_hits" ] && tm_hits=$(printf '%s\n' "$tm_hits" | grep -viE "$TM_RAILS" || true)
report "TRADEMARK — 'BABA YAGA' (registered, Class 9) as a product name" \
  "$tm_hits" \
  "Never ship the registered mark. Use Yagabona / Izbushka."

# ── 2. PRODUCT-NAME MISUSE — 'Postern OS' for the non-attestable tier ─────────
# "Postern OS" = the attestable Nix edition ONLY. The Waydroid / apk / community
# escape hatch is "Postern Android" and must never borrow the "Postern OS" name.
# Bounded adjacency (<=10 chars) keeps the legit contrast "on Postern OS the
# daemon reads real .toml" (no android/apk nearby) and the minified catalog line
# from tripping. The exemption also skips explicit contrasts ("not Postern OS").
POS='postern[ ]?os[a-z .]{0,10}(android|apk|waydroid|community)|(android|apk|waydroid)[a-z .-]{0,10}(compat[a-z -]*)?postern[ ]?os'
POS_EXEMPT='is not|isn.?t|unlike|rather than|instead of|vs\.?|escape hatch|contrast|not covered|outside'
pos_hits=$(scan "$POS" "$POS_EXEMPT")
report "NAME MISUSE — non-attestable tier called 'Postern OS' (use 'Postern Android')" \
  "$pos_hits" \
  "'Postern OS' is the attestable Nix edition only; the apk/Waydroid tier is 'Postern Android'."

# ── 3. COIN / INVESTMENT CLAIM ───────────────────────────────────────────────
# Any AFFIRMATIVE value/investment construction. The honest rail ("the coin is
# worthless, isn't a security, revenue never touches it" / "sem valor, não é um
# investimento") is dropped by NEG plus the extra security/worthless exemptions.
COIN='(coin|token)[^.]{0,40}(worth [0-9$]|to the moon|will (rise|pump|surge|moon|appreciate)|[0-9]+x\b|price target|good investment|great investment|sound investment|guaranteed (return|profit)|buy now)|invest(ing|ment)? in (the |a |our |your )?(postern[ -])?(coin|token)|buy (the |our |your )?(postern[ -])?(coin|token)|(coin|token) is (a |an )?(security|good investment|great investment)'
COIN_EXEMPT='not a security|isn.?t a security|is not a security|not an investment|never touches|n[aã]o [eé] (um )?(investimento|t[ií]tulo|valor)'
coin_hits=$(scan "$COIN" "$COIN_EXEMPT")
report "COIN CLAIM — affirmative coin/token value or investment claim" \
  "$coin_hits" \
  "The coin is worthless and not a security; make no value or investment claim."

# ── 4. PRIVACY / SECURITY OVER-CLAIM ─────────────────────────────────────────
# Bare superlatives NOT inside a negation. Honest disclaimers ("Sotto is not
# '100% private'", "speech input is not fully private", "no app is described as
# '100% private'") are dropped by NEG plus the contrast/meta exemptions.
OVER='100 ?% ?(private|secure|anonymous|safe|audited|attested)|fully (private|secure|audited|attested|anonymous)|completely (private|secure|anonymous)|totally (private|secure|anonymous)|perfectly (secure|private|anonymous)|unhackable|nsa-proof'
OVER_EXEMPT='described as|no app|must not|may not|forbid|disallow|do not (claim|describe|market)|won.?t claim|caveat|honest|is the requirement|would be'
over_hits=$(scan "$OVER" "$OVER_EXEMPT")
report "OVER-CLAIM — bare '100% private' / 'fully secure|audited|attested|anonymous'" \
  "$over_hits" \
  "No surface is 100% private/secure. State it as defense-in-depth, honestly."

# ── verdict ──────────────────────────────────────────────────────────────────
printf '\n'
if [ "$fail" -ne 0 ]; then
  printf 'products honesty gate: FAIL\n'
  exit 1
fi
printf 'products honesty gate: OK — no trademark, name-misuse, coin or over-claim violations.\n'
printf '(heuristic tripwire — human review still required.)\n'
