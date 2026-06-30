#!/usr/bin/env bash
# =============================================================================
# Regression test: pipeline.sh must reach and execute the phase loop.
#
# Guards against P-C1 — `local` used outside a function inside the top-level
# phase loop, which aborts the script under `set -euo pipefail` with
# "local: can only be used in a function" *before any phase runs*.
#
# Strategy: build a throwaway copy of scripts/, stub the phase scripts and the
# env-validation gate, run a single phase, and assert the stub actually ran and
# no "local: can only be used in a function" error was emitted.
#
# Exit 0 = pass, non-zero = fail.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -r "$REPO_ROOT/scripts" "$WORK/scripts"

# Stub the environment-validation gate (it requires a real git repo + tools;
# irrelevant to the phase-loop regression we are testing).
rm -f "$WORK/scripts/tools/validate-env.sh"

# Stub a couple of phase scripts so the loop has something to execute.
for p in scope auth; do
  cat > "$WORK/scripts/tools/phase-${p}.sh" <<EOF
#!/usr/bin/env bash
echo "STUB phase-${p} ran"
EOF
  chmod +x "$WORK/scripts/tools/phase-${p}.sh"
done

OUT="$WORK/out"
LOG="$WORK/run.log"
set +e
RECON_BASE="$OUT" bash "$WORK/scripts/pipeline.sh" smoke.example 1 2 >"$LOG" 2>&1
rc=$?
set -e

fail=0
if grep -q "local: can only be used in a function" "$LOG"; then
  echo "FAIL: pipeline emitted 'local: can only be used in a function' (P-C1 regression)"
  fail=1
fi
if ! grep -q "STUB phase-scope ran" "$LOG"; then
  echo "FAIL: phase-scope stub never executed — loop did not run"
  fail=1
fi
if ! grep -q "STUB phase-auth ran" "$LOG"; then
  echo "FAIL: phase-auth stub never executed — multi-phase loop broken"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "----- pipeline output -----"
  cat "$LOG"
  exit 1
fi

echo "PASS: pipeline phase loop executed (rc=$rc)"
