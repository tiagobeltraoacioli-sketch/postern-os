#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# sla-track.sh — lightweight, privacy-preserving SLA response-time tracker.
#
# Reads a support-intake ticket (intake-schema.json shape), looks up the
# response target for its {tier, severity} from an embedded table that MIRRORS
# sla-policy.yaml, and reports whether first-response is MET / AT_RISK /
# BREACHED against the target window.
#
# PRIVACY: this reads ONLY the ticket file you pass. It captures nothing, phones
# nowhere, and needs no customer data beyond what is already in the ticket. It
# is a scaffold, not audited or production-ready.
#
# SIMPLIFICATION (documented, honest): "business hours/days" targets are
# approximated as ELAPSED CALENDAR time here (1 business hour ~= 1h, 1 business
# day ~= 8h). A real deployment should compute against the business calendar in
# sla-policy.yaml (timezone + working days). This scaffold does not implement a
# working-calendar; it gives an order-of-magnitude SLA signal only.
#
# Usage:
#   ./sla-track.sh <ticket.json> [--now <RFC3339>]
#
# Exit status: 0 MET, 1 AT_RISK, 2 BREACHED, 3 usage/error.
set -euo pipefail

die() { printf 'sla-track: %s\n' "$*" >&2; exit 3; }

TICKET="${1:-}"
[ -n "$TICKET" ] || die "usage: sla-track.sh <ticket.json> [--now <RFC3339>]"
[ -f "$TICKET" ] || die "ticket not found: $TICKET"
command -v jq >/dev/null 2>&1 || die "jq not found (needed to read the ticket)"

NOW_OVERRIDE=""
if [ "${2:-}" = "--now" ]; then
	NOW_OVERRIDE="${3:-}"
	[ -n "$NOW_OVERRIDE" ] || die "--now needs an RFC3339 timestamp"
fi

# Parse an RFC3339/ISO-8601 UTC timestamp to epoch seconds (GNU or BSD date).
to_epoch() {
	local ts="$1" e
	if e=$(date -u -d "$ts" +%s 2>/dev/null); then printf '%s' "$e"; return 0; fi   # GNU
	# BSD/macOS: strip fractional seconds, normalise trailing Z.
	ts="${ts%Z}"; ts="${ts%.*}"
	if e=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$ts" +%s 2>/dev/null); then printf '%s' "$e"; return 0; fi
	return 1
}

TIER=$(jq -r '.tier // "eval"' "$TICKET")
SEV=$(jq -r '.severity' "$TICKET")
OPENED=$(jq -r '.opened_at' "$TICKET")
ACKED=$(jq -r '.acknowledged_at // empty' "$TICKET")
TID=$(jq -r '.ticket_id // "?"' "$TICKET")
[ -n "$SEV" ] && [ "$SEV" != "null" ] || die "ticket has no severity"
[ -n "$OPENED" ] && [ "$OPENED" != "null" ] || die "ticket has no opened_at"

# Response targets in HOURS, mirroring sla-policy.yaml (business hr ~=1h, day~=8h).
# Empty string means "no committed target" (best effort).
target_hours() {
	case "$1:$2" in
		enterprise:sev1) echo 1 ;;      # 1 hour, 24x7
		enterprise:sev2) echo 4 ;;      # 4 business hours
		enterprise:sev3) echo 8 ;;      # 1 business day
		enterprise:sev4) echo 24 ;;     # 3 business days
		business:sev1)   echo 4 ;;      # 4 business hours
		business:sev2)   echo 8 ;;      # 8 business hours
		business:sev3)   echo 16 ;;     # 2 business days
		business:sev4)   echo 40 ;;     # 5 business days
		eval:sev1)       echo 8 ;;      # 1 business day
		eval:sev2)       echo 16 ;;     # 2 business days
		eval:sev3)       echo 40 ;;     # 5 business days
		eval:sev4)       echo "" ;;     # best effort
		community:*)     echo "" ;;     # best effort, no SLA
		*)               echo "" ;;
	esac
}

TGT=$(target_hours "$TIER" "$SEV")

OPENED_E=$(to_epoch "$OPENED") || die "cannot parse opened_at: $OPENED"
if [ -n "$NOW_OVERRIDE" ]; then
	NOW_E=$(to_epoch "$NOW_OVERRIDE") || die "cannot parse --now: $NOW_OVERRIDE"
else
	NOW_E=$(date -u +%s)
fi

# Response clock stops at acknowledgement if present, else runs to now.
if [ -n "$ACKED" ]; then
	END_E=$(to_epoch "$ACKED") || die "cannot parse acknowledged_at: $ACKED"
	RESPONDED="yes (at $ACKED)"
else
	END_E="$NOW_E"
	RESPONDED="no (open)"
fi

ELAPSED_H=$(( (END_E - OPENED_E) / 3600 ))
[ "$ELAPSED_H" -lt 0 ] && ELAPSED_H=0

printf 'ticket:     %s\n' "$TID"
printf 'tier/sev:   %s / %s\n' "$TIER" "$SEV"
printf 'opened:     %s\n' "$OPENED"
printf 'responded:  %s\n' "$RESPONDED"
printf 'elapsed:    ~%sh (calendar approx)\n' "$ELAPSED_H"

if [ -z "$TGT" ]; then
	printf 'target:     none (best-effort tier/severity)\n'
	printf 'sla:        N/A (no committed response target)\n'
	exit 0
fi

printf 'target:     ~%sh to first substantive response\n' "$TGT"

# AT_RISK threshold: within the last 25% of the window (and not yet responded).
RISK_H=$(( TGT * 3 / 4 ))

if [ "$ELAPSED_H" -le "$TGT" ]; then
	if [ -z "$ACKED" ] && [ "$ELAPSED_H" -ge "$RISK_H" ]; then
		printf 'sla:        AT_RISK (%sh of ~%sh window used, still open)\n' "$ELAPSED_H" "$TGT"
		exit 1
	fi
	printf 'sla:        MET (%sh <= ~%sh)\n' "$ELAPSED_H" "$TGT"
	exit 0
fi

printf 'sla:        BREACHED (%sh > ~%sh)\n' "$ELAPSED_H" "$TGT"
exit 2
