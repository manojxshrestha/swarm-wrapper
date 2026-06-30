#!/usr/bin/env bash
# =============================================================================
# Phase 12: REPORT — Coverage check, generate final report
#
# Usage: ./tools/phase-report.sh <domain> [output_dir]
#        ./tools/phase-report.sh <engagement_id> <domain> [output_dir]
#
# Prepares report context for @report-writing agent.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FINDINGS_CLI="$SCRIPT_DIR/../findings.sh"

# Support both old (<domain> [outdir]) and new (<eid> <domain> [outdir]) signatures
if [ $# -ge 3 ]; then
  ENGAGEMENT_ID="${1:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  TARGET="${2:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  OUT_DIR="${3:-${RECON_BASE}/${TARGET}}"
else
  TARGET="${1:?Usage: $0 <domain>}"
  ENGAGEMENT_ID="$TARGET"
  OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"
fi

REPORT_DIR="$OUT_DIR/report"
mkdir -p "$REPORT_DIR"

log_info "Compiling report context..."

# Summarize everything
{
  echo "=== Engagement Summary ==="
  echo "Target: $TARGET"
  echo "Started: $(cat "$OUT_DIR/scope/started.txt" 2>/dev/null || echo 'N/A')"
  echo ""

  echo "--- Scope ---"
  cat "$OUT_DIR/scope/target.txt" 2>/dev/null || echo "N/A"
  echo ""

  echo "--- Findings from SQLite Database ---"
  $FINDINGS_CLI stats "$ENGAGEMENT_ID" 2>/dev/null || echo "  (no findings database for $ENGAGEMENT_ID)"
  echo ""

  echo "--- Validated Findings ---"
  cat "$OUT_DIR/validate/findings_for_validation.txt" 2>/dev/null | head -30 || echo "N/A"
  echo ""

  echo "=== End ==="
} > "$REPORT_DIR/report_context.txt"

log_ok "Report context saved to $REPORT_DIR/report_context.txt"
log_info "Run: @report-writing (HackerOne format) or @bugcrowd-reporting (Bugcrowd)"
log_info "Phase 12 (report) prepared"
