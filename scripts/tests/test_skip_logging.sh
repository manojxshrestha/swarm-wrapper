#!/usr/bin/env bash
# =============================================================================
# Regression test: phase-hunt.sh logs missing tool scripts (P-M2) and does not
# duplicate param_extract when recon already produced params/ output (P-M3).
#
# Assertions key off deterministic log lines (the launch decisions), not the
# side effects of backgrounded nohup jobs.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
# Tolerant cleanup: phase-hunt launches background (nohup) jobs that may still
# hold the temp dir at exit (esp. on Windows), so ignore rm failures.
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT
cp -r "$REPO_ROOT/scripts" "$WORK/scripts"

HUNT="$WORK/scripts/tools/phase-hunt.sh"
TOOLS="$WORK/scripts/tools"
TARGET="skip.example"
fail=0

rm -f "$TOOLS/vhost_fuzz.sh" "$TOOLS/bypass_403.sh"

run_hunt() { RECON_BASE="$1" bash "$HUNT" "$TARGET" "$1/$TARGET" 2>&1 || true; }

# --- P-M2: missing scripts are logged ---
O1="$WORK/o1"; mkdir -p "$O1/$TARGET"
out1="$(run_hunt "$O1")"
for tool in vhost_fuzz bypass_403; do
  if echo "$out1" | grep -q "$tool: script not found"; then
    echo "ok: $tool missing-script warning logged"
  else
    echo "FAIL: missing $tool not logged"; fail=1
  fi
done

# --- P-M3: param_extract runs when there is no recon params/ output ---
if echo "$out1" | grep -q "param_extract: recon already produced"; then
  echo "FAIL: param_extract wrongly skipped with empty params/"; fail=1
else
  echo "ok: param_extract runs when params/ empty"
fi

# --- P-M3: param_extract skipped when recon already produced params/ ---
O2="$WORK/o2"; mkdir -p "$O2/$TARGET/params"
echo "https://skip.example/?id=1" > "$O2/$TARGET/params/gf_sqli.txt"
out2="$(run_hunt "$O2")"
if echo "$out2" | grep -q "param_extract: recon already produced"; then
  echo "ok: param_extract skipped (no duplicate of recon)"
else
  echo "FAIL: param_extract should be skipped when params/ has recon output"; fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: skip-logging / dedup tests" || { echo "FAILED"; exit 1; }
