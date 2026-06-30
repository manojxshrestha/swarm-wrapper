#!/usr/bin/env bash
# =============================================================================
# Regression test: Phase 7 (deepthink) skip logic (P-M1).
#
# Deepthink must RUN when hunt produced no real candidate output, and be
# SKIPPED only when params/ or secrets/ contain non-empty files. It must NOT
# be fooled by dispatch artifacts (dispatch_list.json / *.log) in hunt/.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r "$REPO_ROOT/scripts" "$WORK/scripts"
rm -f "$WORK/scripts/tools/validate-env.sh"
for p in hunt deepthink; do
  printf '#!/usr/bin/env bash\necho "STUB phase-%s ran"\n' "$p" > "$WORK/scripts/tools/phase-${p}.sh"
  chmod +x "$WORK/scripts/tools/phase-${p}.sh"
done

TARGET="dt.example"
run() { RECON_BASE="$1" bash "$WORK/scripts/pipeline.sh" "$TARGET" 6 7 2>&1; }

fail=0

# Case A: only a dispatch artifact in hunt/ (no real output) → deepthink RUNS.
# NB: capture to a var first — piping into `grep -q` would SIGPIPE the pipeline
# and, with pipefail, mask its real exit code.
A="$WORK/outA"; mkdir -p "$A/$TARGET/hunt"
echo '{"summary":{"total":5}}' > "$A/$TARGET/hunt/dispatch_list.json"
out_a="$(run "$A")"
if echo "$out_a" | grep -q "STUB phase-deepthink ran"; then
  echo "ok: deepthink runs when only dispatch artifacts exist"
else
  echo "FAIL: deepthink should run (no real hunt output)"; fail=1
fi

# Case B: real candidate output under params/ → deepthink SKIPPED.
B="$WORK/outB"; mkdir -p "$B/$TARGET/params"
echo "https://dt.example/?id=1" > "$B/$TARGET/params/gf_sqli.txt"
out_b="$(run "$B")"
if echo "$out_b" | grep -q "deepthink): skipped"; then
  echo "ok: deepthink skipped when params/ has real output"
else
  echo "FAIL: deepthink should be skipped when params/ non-empty"; fail=1
fi
if echo "$out_b" | grep -q "STUB phase-deepthink ran"; then
  echo "FAIL: deepthink stub ran despite real hunt output"; fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: deepthink skip tests" || { echo "FAILED"; exit 1; }
