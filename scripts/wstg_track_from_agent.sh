#!/usr/bin/env bash
# =============================================================================
# wstg_track_from_agent.sh — Bridge hunt agent completion to WSTG track_test()
#
# Reads configs/wstg_mapping.json to find WSTG tests covered by a given hunt
# agent, then calls wstg_track_test() for each mapped test.
#
# Usage:
#   bash scripts/wstg_track_from_agent.sh <engagement_id> <domain> <agent_id> <status>
#
# Status: completed, skipped, not_applicable
#
# Example:
#   bash scripts/wstg_track_from_agent.sh intercom target.com hunt-xss completed
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWARM_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ENGAGEMENT_ID="${1:?Usage: $0 <engagement_id> <domain> <agent_id> <status>}"
DOMAIN="${2:?}"
AGENT_ID="${3:?}"
STATUS="${4:?}"

MAPPING="$SWARM_ROOT/configs/wstg_mapping.json"
HUNT_DIR="$SWARM_ROOT/engagements/runtime/${ENGAGEMENT_ID:-default-engagement}/recon/$DOMAIN/hunt"
mkdir -p "$HUNT_DIR"
BATCH_FILE="$HUNT_DIR/wstg_tracking_batch.json"

if [ ! -f "$MAPPING" ]; then
  echo "[!] wstg_track_from_agent: $MAPPING not found, skipping"
  exit 0
fi

MAPPING="$MAPPING" ENGAGEMENT_ID="$ENGAGEMENT_ID" AGENT_ID="$AGENT_ID" STATUS="$STATUS" BATCH_FILE="$BATCH_FILE" \
python3 << 'PYEOF'
import json
import os
import sys

mapping_path = os.environ.get("MAPPING", "")
engagement_id = os.environ.get("ENGAGEMENT_ID", "")
agent_id = os.environ.get("AGENT_ID", "")
status = os.environ.get("STATUS", "")
batch_file = os.environ.get("BATCH_FILE", "")

with open(mapping_path) as f:
    mapping = json.load(f)

if agent_id not in mapping:
    sys.exit(0)

tests = mapping[agent_id]
if not tests:
    sys.exit(0)

for test_id in tests:
    notes = f"Covered by {agent_id} agent"
    entry = {
        "engagement_id": engagement_id,
        "test_id": test_id,
        "status": status,
        "notes": notes
    }
    with open(batch_file, "a") as batch:
        batch.write(json.dumps(entry) + "\n")
    print(f"[+] wstg_track_test({engagement_id}, {test_id}, {status}) — {notes}")

print(f"[+] Tracked {len(tests)} WSTG tests for {agent_id}")
PYEOF
