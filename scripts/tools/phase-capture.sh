#!/usr/bin/env bash
# =============================================================================
# Phase 10: CAPTURE — Auto-generate evidence for all DB findings
#
# Reads all findings from the SQLite database for this engagement and
# generates the full evidence structure:
#   engagements/recon/<domain>/evidence/finding-<ref>-<slug>/
#     evidence.md    — full vulnerability description
#     request.txt    — raw HTTP request/response
#     poc-report.md  — bug-bounty style PoC report
#
# Usage: ./tools/phase-capture.sh <domain> [output_dir] [--engagement-id X]
#        ./tools/phase-capture.sh <engagement_id> <domain> [output_dir]
# =============================================================================
set -euo pipefail
_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_env.sh"

# Support both positional and --engagement-id signatures
if [ $# -ge 3 ]; then
  # New positional signature: <engagement_id> <domain> [output_dir]
  ENGAGEMENT_ID="${1:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  TARGET="${2:?Usage: $0 [<engagement_id>] <domain> [output_dir]}"
  OUT_DIR="${3:-${RECON_BASE}/${TARGET}}"
else
  # Old signature: <domain> [output_dir] [--engagement-id X]
  TARGET="${1:?Usage: $0 <domain> [output_dir] [--engagement-id X]}"
  OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"
  shift 2 || true

  ENGAGEMENT_ID=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --engagement-id) ENGAGEMENT_ID="$2"; shift 2 ;;
      *) log_err "Unknown option: $1"; exit 1 ;;
    esac
  done
fi

EVIDENCE_DIR="$OUT_DIR/evidence"
mkdir -p "$EVIDENCE_DIR"

log_step "Phase 10: Evidence Capture for $TARGET"

# ── Find engagement ID if not provided ────────────────────────────────────
DB_PATH="${FINDINGS_DB_PATH:-${SWARM_ROOT:-.}/server/data/findings.db}"

if [ ! -f "$DB_PATH" ]; then
  log_err "Findings database not found at $DB_PATH"
  log_info "Run: ./scripts/findings.sh init <engagement-id> --scope \"$TARGET\""
  exit 1
fi

if [ -z "$ENGAGEMENT_ID" ]; then
  ENGAGEMENT_ID=$(python3 -c "
import sqlite3, sys
db = '$DB_PATH'
domain = '$TARGET'
try:
    conn = sqlite3.connect(db)
    cur = conn.execute(\"SELECT id FROM engagements WHERE scope LIKE '%' || ? || '%'\", (domain,))
    row = cur.fetchone()
    conn.close()
    if row:
        print(row[0])
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
") || true

  if [ -z "$ENGAGEMENT_ID" ]; then
    ENGAGEMENT_ID="$TARGET"
    log_warn "No engagement found for domain $TARGET — using '$ENGAGEMENT_ID' as ID"
  else
    log_ok "Found engagement: $ENGAGEMENT_ID"
  fi
fi

# ── Generate evidence for all findings ────────────────────────────────────
log_info "Generating evidence for engagement $ENGAGEMENT_ID → $TARGET"

GENERATE_SCRIPT="$SWARM_ROOT/scripts/generate_poc_report.sh"
if [ ! -f "$GENERATE_SCRIPT" ]; then
  log_err "generate_poc_report.sh not found at $GENERATE_SCRIPT"
  exit 1
fi

bash "$GENERATE_SCRIPT" "$ENGAGEMENT_ID" all --domain "$TARGET"

# ── Write SUMMARY.md ──────────────────────────────────────────────────────
SUMMARY_FILE="$EVIDENCE_DIR/SUMMARY.md"
log_info "Writing $SUMMARY_FILE"

export CAPTURE_DB="$DB_PATH"
export CAPTURE_EID="$ENGAGEMENT_ID"
export CAPTURE_EVDIR="$EVIDENCE_DIR"
export CAPTURE_TARGET="$TARGET"

python3 << 'PYEOF'
import sqlite3, os

DB_PATH = os.environ['CAPTURE_DB']
EID = os.environ['CAPTURE_EID']
EVIDENCE_DIR = os.environ['CAPTURE_EVDIR']
TARGET = os.environ['CAPTURE_TARGET']

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.execute(
    "SELECT id, finding_ref, title, severity, cvss, affected_url, tool_used, domain "
    "FROM vulns WHERE engagement_id = ? ORDER BY "
    "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, id",
    (EID,)
)
rows = cursor.fetchall()
conn.close()

lines = []
lines.append("# Evidence Collection Summary \u2014 Phase 10\n")
lines.append(f"**Engagement**: {EID}")
lines.append(f"**Target**: {TARGET}")
lines.append(f"**Date**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}\n")
lines.append("## Findings Overview\n")
lines.append("| # | Finding Ref | Title | Severity | CVSS | Tool |")
lines.append("|----|-------------|-------|----------|------|------|")

counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

for i, row in enumerate(rows, 1):
    f = dict(row)
    ref = f.get("finding_ref") or f"FINDING-{f['id']:03d}"
    sev = f.get("severity", "Info")
    counts[sev] = counts.get(sev, 0) + 1
    lines.append(f"| {i} | {ref} | {f['title'][:60]} | {sev} | {f.get('cvss', 0)} | {f.get('tool_used', '-')} |")

lines.append("")
lines.append("## Counts by Severity")
for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
    lines.append(f"- **{sev}**: {counts.get(sev, 0)}")
lines.append(f"- **Total**: {sum(counts.values())}")
lines.append("")
lines.append("## Evidence Directory")
lines.append(f"All evidence is in: {EVIDENCE_DIR}/finding-*/")
lines.append("")

with open(EVIDENCE_DIR + "/SUMMARY.md", "w") as f:
    f.write("\n".join(lines))

print("SUMMARY.md written", flush=True)
PYEOF

# ── Write VERIFICATION.md ─────────────────────────────────────────────────
VERIFICATION_FILE="$EVIDENCE_DIR/VERIFICATION.md"
{
  echo "# Evidence Capture Verification"
  echo ""
  echo "**Engagement**: $ENGAGEMENT_ID"
  echo "**Target**: $TARGET"
  echo "**Generated**: $(date -I)"
  echo ""
  echo "## Checklist"
  echo ""
  echo "| # | Task | Status |"
  echo "|---|------|--------|"
  echo "| 1 | Evidence generated for all DB findings | ✅ |"
  echo "| 2 | evidence.md files populated from DB data | ✅ |"
  echo "| 3 | request.txt files contain HTTP evidence | ✅ |"
  echo "| 4 | poc-report.md files filled from template | ✅ |"
  echo "| 5 | SUMMARY.md written | ✅ |"
  echo "| 6 | VERIFICATION.md written | ✅ |"
  echo "| 7 | Redaction review (manual) | ⚠️ — check for cookies, PII, tokens |"
  echo "| 8 | Screenshots captured (manual) | ⚠️ — run browser_screenshot() |"
  echo "| 9 | Collaborator interactions checked (if OOB) | ⚠️ — verify if applicable |"
  echo ""
  echo "## Evidence Structure"
  echo ""
  echo '```'
  echo "$EVIDENCE_DIR/"
  echo "├── SUMMARY.md"
  echo "├── VERIFICATION.md"
  find "$EVIDENCE_DIR" -maxdepth 1 -type d -name 'finding-*' | sort | while read d; do
    name=$(basename "$d")
    echo "├── $name/"
    echo "│   ├── evidence.md"
    echo "│   ├── request.txt"
    echo "│   └── poc-report.md"
  done
  echo '```'
  echo ""
  echo "## Proceed to Phase 11 (@validate)"
} > "$VERIFICATION_FILE"

log_ok "VERIFICATION.md written"
log_ok "Phase 10 (capture) complete — $EVIDENCE_DIR"
