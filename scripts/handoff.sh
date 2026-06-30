#!/usr/bin/env bash
# ── Swarm Session Handoff Report Generator ──────────────────────────────────
# Produces a structured Markdown report of all engagement state for
# cross-session continuity. Pipe to a file and load into the next session.
#
# Usage:
#   ./scripts/handoff.sh <engagement_id> [output.md]
#   ./scripts/handoff.sh <engagement_id>           # prints to stdout
#   ./scripts/handoff.sh <engagement_id> handoff.md # writes to file
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/../server" && pwd)"
DB_PATH="${DST_FINDINGS_DB:-$SERVER_DIR/data/findings.db}"
PYTHON="${SWARM_PYTHON:-}"
if [ -z "$PYTHON" ]; then
  PYTHON="$SERVER_DIR/venv/bin/python3"
  [ ! -f "$PYTHON" ] && PYTHON="python3"
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <engagement_id> [output.md]"
    echo ""
    echo "Generates a structured handoff report from the SQLite findings database."
    echo "Set DST_FINDINGS_DB env var for a custom DB path."
    exit 1
fi

ENGAGEMENT_ID="$1"
OUTPUT="${2:-}"

# Generate the handoff report
REPORT=$(SERVER_DIR="$SERVER_DIR" DB_PATH="$DB_PATH" ENGAGEMENT_ID="$ENGAGEMENT_ID" "$PYTHON" -c '
import os, sys
sys.path.insert(0, os.environ["SERVER_DIR"])
from findings_db import get_db
db = get_db(os.environ["DB_PATH"])
print(db.handoff_markdown(os.environ["ENGAGEMENT_ID"]))
')

if [[ -z "$REPORT" || "$REPORT" == "None" ]]; then
    echo "No data found for engagement '$ENGAGEMENT_ID'."
    echo "Use ./scripts/findings.sh init $ENGAGEMENT_ID first."
    exit 1
fi

if [[ -n "$OUTPUT" ]]; then
    echo "$REPORT" > "$OUTPUT"
    echo "Handoff report saved to: $OUTPUT"
else
    echo "$REPORT"
fi
