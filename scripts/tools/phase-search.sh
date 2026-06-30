#!/usr/bin/env bash
# =============================================================================
# Phase 9: SEARCH (conditional) — Research payloads, CVEs, bypasses
#
# Usage: ./tools/phase-search.sh <domain> [output_dir]
#        ./tools/phase-search.sh <engagement_id> <domain> [output_dir]
#
# Prepares research context for @search agent when exploit stalls.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope
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

SEARCH_DIR="$OUT_DIR/search"
mkdir -p "$SEARCH_DIR"

log_info "Preparing research context..."

# Query SQLite findings database for blocked/potential findings
BLOCKED_OUTPUT="$($FINDINGS_CLI list vulns "$ENGAGEMENT_ID" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    blocked = [v for v in data if v.get('status') in ('potential', 'blocked', 'open')]
    if blocked:
        for v in blocked:
            print(f\"  [{v.get('severity','?')}] {v.get('title','?')} — {v.get('affected_url','?')} ({v.get('status','?')})\")
    else:
        print('  (none captured from findings DB)')
except (json.JSONDecodeError, IndexError):
    print('  (none captured from findings DB)')
" 2>/dev/null || echo "  (none captured)")"

{
  echo "=== Search Research Context ==="
  echo "Target: $TARGET"
  echo "Engagement: $ENGAGEMENT_ID"
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""
  echo "## Exploitation Blockers (from findings DB)"
  echo "$BLOCKED_OUTPUT"
  echo ""
  echo "## Research Needs"
  echo "  - Stale/missing payload techniques for blocked vulnerability classes"
  echo "  - Recent CVEs for identified tech stack"
  echo "  - WAF bypass techniques not yet attempted"
  echo "  - New OOB/interaction methods"
  echo ""
  echo "## Triggers (from autopilot.md)"
  echo "  Phase 9 activates when ANY trigger is true:"
  echo "  - Tech stack identified but no CVEs checked"
  echo "  - Critical/High findings lack disclosed report reference"
  echo "  - Payload success rate < 20%"
  echo "  - All WAF bypass techniques exhausted"
  echo "  - Target uses technology not in local knowledge base"
} > "$SEARCH_DIR/research_context.txt"

log_ok "Research context saved to $SEARCH_DIR/research_context.txt"
log_info "Run: @search — research payloads, CVEs, and bypass techniques"
log_info "Phase 9 (search) prepared (conditional — activate if exploit stalls)"
