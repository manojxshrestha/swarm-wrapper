#!/usr/bin/env bash
# =============================================================================
# Regression test: _scope_guard blocks an out-of-scope target BEFORE any
# active request (Phase 6). Uses phase-hunt.sh as a representative active phase.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HUNT="$REPO_ROOT/scripts/tools/phase-hunt.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT
fail=0

mkscope() { mkdir -p "$WORK/$1/scope"; echo "$2" > "$WORK/$1/scope/scope.txt"; }

# 1. OUT OF SCOPE → must abort with exit 1 and never reach candidate generation.
mkscope "evil.com" "*.example.com"
out="$(RECON_BASE="$WORK" bash "$HUNT" evil.com "$WORK/evil.com" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q "OUT OF SCOPE"; then
  echo "ok: out-of-scope target aborted (exit $rc)"
else
  echo "FAIL: out-of-scope target not blocked (exit $rc)"; fail=1
fi
if echo "$out" | grep -q "Candidate generation complete"; then
  echo "FAIL: hunt proceeded past the scope guard on an out-of-scope target"; fail=1
else
  echo "ok: no active work happened before the block"
fi

# 2. IN SCOPE → must NOT print OUT OF SCOPE (proceeds).
mkscope "app.example.com" "*.example.com"
out2="$(RECON_BASE="$WORK" bash "$HUNT" app.example.com "$WORK/app.example.com" 2>&1)"
if echo "$out2" | grep -q "OUT OF SCOPE"; then
  echo "FAIL: in-scope target was wrongly blocked"; fail=1
else
  echo "ok: in-scope target allowed"
fi

# 3. STRICT_SCOPE with no scope file → fail-closed.
out3="$(RECON_BASE="$WORK" STRICT_SCOPE=1 bash "$HUNT" noscope.com "$WORK/noscope.com" 2>&1)"; rc3=$?
if [ "$rc3" -ne 0 ] && echo "$out3" | grep -q "Scope not registered"; then
  echo "ok: STRICT_SCOPE fail-closed when scope missing"
else
  echo "FAIL: STRICT_SCOPE did not fail-closed (exit $rc3)"; fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: scope guard tests" || { echo "FAILED"; exit 1; }
