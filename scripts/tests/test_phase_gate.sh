#!/usr/bin/env bash
# =============================================================================
# Regression test: phase_gate.sh ordering enforcement (P-H1 / P-H2).
#
#   - SINGLE_PHASE_MODE=1 suppresses the ordering check (P-H2, was dead).
#   - STRICT_GATES=1 makes an ordering violation fail (exit 1) (P-H1).
#   - default (advisory) warns but exits 0.
#   - once the previous gate exists, the phase passes.
#
# Exit 0 = pass.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$REPO_ROOT/scripts/tools/phase_gate.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARGET="gate.example"
fail=0

run_gate() { # <phase> ; echoes nothing, returns gate exit code
  RECON_BASE="$WORK" bash "$GATE" "$1" "$TARGET" >/dev/null 2>&1
}

# 1. Phase 3 with NO phase 2 gate, STRICT → must fail (exit 1)
if RECON_BASE="$WORK" STRICT_GATES=1 bash "$GATE" 3 "$TARGET" >/dev/null 2>&1; then
  echo "FAIL: STRICT_GATES did not enforce ordering (phase 3 without phase 2)"; fail=1
else
  echo "ok: STRICT_GATES enforced ordering violation"
fi

# 2. Same situation, advisory (default) → must succeed (exit 0)
rm -rf "$WORK/$TARGET/.gates"
if RECON_BASE="$WORK" bash "$GATE" 3 "$TARGET" >/dev/null 2>&1; then
  echo "ok: advisory mode warned but continued"
else
  echo "FAIL: advisory mode should not fail"; fail=1
fi

# 3. SINGLE_PHASE_MODE suppresses the check even under STRICT
rm -rf "$WORK/$TARGET/.gates"
if RECON_BASE="$WORK" STRICT_GATES=1 SINGLE_PHASE_MODE=1 bash "$GATE" 6 "$TARGET" >/dev/null 2>&1; then
  echo "ok: SINGLE_PHASE_MODE suppressed ordering check"
else
  echo "FAIL: SINGLE_PHASE_MODE should suppress ordering enforcement"; fail=1
fi

# 4. With the previous gate present, STRICT passes
rm -rf "$WORK/$TARGET/.gates"
mkdir -p "$WORK/$TARGET/.gates"; date -Iseconds > "$WORK/$TARGET/.gates/phase2_done"
if RECON_BASE="$WORK" STRICT_GATES=1 bash "$GATE" 3 "$TARGET" >/dev/null 2>&1; then
  echo "ok: phase 3 passes once phase 2 gate exists"
else
  echo "FAIL: phase 3 should pass when phase 2 gate exists"; fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: phase_gate ordering tests" || { echo "FAILED"; exit 1; }
