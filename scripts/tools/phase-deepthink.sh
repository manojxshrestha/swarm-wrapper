#!/usr/bin/env bash
# =============================================================================
# Phase 7: DEEPTHINK (conditional) — Gap analysis when HUNT yields zero
#
# Usage: ./tools/phase-deepthink.sh <engagement_id> <domain> [output_dir]
#        ./tools/phase-deepthink.sh <domain> [output_dir]
#
# Creates a gap analysis brief from the SQLite findings database.
# Call @deepthink agent to perform first-principles analysis on the gaps.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

# Support both positional signatures: <eid> <domain> [outdir] and <domain> [outdir]
if [ $# -ge 3 ]; then
  ENGAGEMENT_ID="${1:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  TARGET="${2:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  OUT_DIR="${3:-${RECON_BASE}/${TARGET}}"
else
  TARGET="${1:?Usage: $0 <domain>}"
  ENGAGEMENT_ID="$TARGET"
  OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"
fi

_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FINDINGS_CLI="$SCRIPT_DIR/../findings.sh"

DEEP_DIR="$OUT_DIR/deepthink"
mkdir -p "$DEEP_DIR"

log_info "Preparing deepthink gap analysis context..."

# Query SQLite findings database via findings.sh CLI
STATS_OUTPUT="$($FINDINGS_CLI stats "$ENGAGEMENT_ID" 2>/dev/null || echo "N/A")"
VULNS_OUTPUT="$($FINDINGS_CLI list vulns "$ENGAGEMENT_ID" 2>/dev/null || echo "N/A")"
HOSTS_OUTPUT="$($FINDINGS_CLI list hosts "$ENGAGEMENT_ID" 2>/dev/null || echo "N/A")"

# Collect what we have
{
  echo "=== DeepThink Gap Analysis ==="
  echo "Engagement: $ENGAGEMENT_ID"
  echo "Target: $TARGET"
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""

  echo "## Findings Database Stats"
  echo "$STATS_OUTPUT" | head -30
  echo ""

  echo "## Logged Vulnerabilities"
  echo "$VULNS_OUTPUT" | head -50
  [ "$(echo "$VULNS_OUTPUT" | wc -l)" -gt 50 ] && echo "  ... (truncated)"
  echo ""

  echo "## Discovered Hosts"
  echo "$HOSTS_OUTPUT" | head -20
  echo ""

  echo "## Attack Surface"
  endpoint_map="$OUT_DIR/surface/endpoint_map_ranked.txt"
  if [ -f "$endpoint_map" ]; then
    echo "  Endpoint tiers:"
    head -10 "$endpoint_map"
  else
    echo "  No endpoint map found (Phase 5 not run?)"
  fi
  echo ""

  echo "## Gaps & Questions"
  echo "  1. Are there hidden endpoints not discovered by crawling?"
  echo "  2. Could WAF be blocking payloads? What bypasses remain untested?"
  echo "  3. Are there business logic flaws that automated scanners miss?"
  echo "  4. Is the attack surface fully enumerated?"
  echo "  5. What manual techniques would a human researcher try next?"
  echo ""

  echo "## Coverage Gaps"
  echo "  Review which HUNT agents returned 0 findings or failed status."
  echo "  Check coverage matrix for agents with 'failed' or 'skipped' status."
  echo "  If coverage < 90%, re-dispatch agents for under-tested classes."
  echo ""
  echo "## Chain Opportunities"
  echo "  Run find_chains() to discover multi-step attack paths."
  echo "  If chains exist, findings may need severity upgrades."
} > "$DEEP_DIR/gap_analysis.txt"

log_ok "Gap analysis context saved to $DEEP_DIR/gap_analysis.txt"
log_info "Run: @deepthink — loads gap context and performs first-principles analysis"
log_info "Phase 7 (deepthink) prepared (conditional — activate if HUNT gaps detected)"
