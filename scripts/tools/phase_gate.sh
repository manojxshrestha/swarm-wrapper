#!/usr/bin/env bash
# =============================================================================
# Phase Gate — Enforce pipeline ordering + Phase 6 coverage threshold
#
# Called by pipeline.sh after each phase.
# For Phase 6 specifically, checks that hunt agents were dispatched.
#
# Usage: ./tools/phase_gate.sh <phase-num> <domain>
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

PHASE_NUM="${1:?Usage: $0 <phase-num> <domain>}"
TARGET="${2:?Usage: $0 <phase-num> <domain>}"

OUT_DIR="${RECON_BASE}/${TARGET}"
GATE_DIR="$OUT_DIR/.gates"
mkdir -p "$GATE_DIR"

# ── Phase 6: Coverage gate ──────────────────────────────────────────────
# NOTE: This gate is called TWICE:
#   1. From pipeline.sh after bash tool execution (dispatch files don't exist yet → soft pass)
#   2. By the autopilot/consult agent AFTER ALL agents dispatched (enforced)
if [ "$PHASE_NUM" = "6" ]; then
  COVERAGE_FILE="$OUT_DIR/hunt/coverage_matrix.csv"
  DISPATCH_FILE="$OUT_DIR/hunt/dispatch_list.json"

  if [ ! -f "$DISPATCH_FILE" ]; then
    # Called from pipeline.sh before AI dispatch — soft pass
    log_info "Phase 6: No dispatch list yet (AI agents not dispatched)"
    log_info "Full gate enforcement runs after agent dispatch completes"
  elif [ ! -f "$COVERAGE_FILE" ]; then
    log_info "Phase 6: No coverage matrix yet (agents dispatched but not tracked)"
  else
    # Full gate enforcement — dispatch files exist
    # FIX #7: Proper error handling instead of 2>/dev/null || echo "0"
    TOTAL=$(python3 -c "
import json, sys
try:
    with open('$DISPATCH_FILE') as f:
        d = json.load(f)
    total = d.get('summary', {}).get('total', 0)
    if not isinstance(total, (int, float)) or total < 0:
        print(f'ERROR: invalid total in dispatch file', file=sys.stderr)
        sys.exit(2)
    print(int(total))
except (FileNotFoundError, json.JSONDecodeError, AttributeError) as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(2)
") || {
    log_err "Phase 6 gate: Failed to read dispatch list (malformed JSON?)"
    log_err "Check: $DISPATCH_FILE"
    TOTAL=0
}
# END FIX #7

    # Count completed agents (using Python csv module — robust against commas in fields)
    read -r COMPLETED PENDING <<< "$(python3 -c "
import csv, sys
completed = 0
pending = 0
status_map = {'complete', 'done', 'finished', 'dispatched'}
with open('$COVERAGE_FILE', newline='') as f:
    reader = csv.reader(f)
    next(reader, None)  # skip header
    for row in reader:
        if not row:
            continue
        raw = row[5].strip().lower().strip(' \"\\r\\n')
        if raw in status_map:
            completed += 1
        elif raw in ('pending', 'skipped', ''):
            pending += 1
        else:
            pending += 1  # unknown → pending
print(f'{completed} {pending}')
")"

    PCT=$(( TOTAL > 0 ? COMPLETED * 100 / TOTAL : 0 ))
    log_info "Phase 6 dispatch coverage: $COMPLETED/$TOTAL agents ($PCT%)"

    if [ "$PCT" -lt 90 ]; then
      log_err "PHASE 6 GATE FAILED: Only $PCT% of agents dispatched ($COMPLETED/$TOTAL)"
      log_err "This means vulnerability categories were skipped."
      log_err "Run dispatch_hunt.sh again and dispatch ALL agents before proceeding."
      log_err "Gate file NOT written — pipeline will not advance past Phase 6."
      exit 1
    fi

    if [ "$PENDING" -gt 0 ]; then
      log_warn "Phase 6: $PENDING agents still pending — but $PCT% threshold met"
      log_warn "For best coverage, dispatch remaining agents"
    fi
  fi
fi

# ── Verify previous phase gate exists (ordering) ────────────────────────
# P-H2: SINGLE_PHASE_MODE (set by pipeline.sh when a single phase is run
#        standalone) suppresses the ordering check — it was previously dead.
# P-H1: when STRICT_GATES=1 an ordering violation is ENFORCED (exit 1);
#        otherwise it is advisory (warn) to allow intentional partial runs.
if [ "${SINGLE_PHASE_MODE:-}" != "1" ] && [ "$PHASE_NUM" -gt 1 ]; then
  PREV=$((PHASE_NUM - 1))
  if [ ! -f "$GATE_DIR/phase${PREV}_done" ]; then
    if [ "${STRICT_GATES:-}" = "1" ]; then
      log_err "Phase $PREV gate not found — ordering violation (STRICT_GATES=1)."
      log_err "Run phase $PREV first, or unset STRICT_GATES for advisory mode."
      exit 1
    fi
    log_warn "Phase $PREV gate not found! Did you skip a phase?"
    log_warn "Ordering violation (advisory — set STRICT_GATES=1 to enforce)"
  fi
fi

# ── Mark this phase as completed ────────────────────────────────────────
date -Iseconds > "$GATE_DIR/phase${PHASE_NUM}_done"

log_ok "Gate passed for Phase $PHASE_NUM"
