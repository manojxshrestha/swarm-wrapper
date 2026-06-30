#!/usr/bin/env bash
# =============================================================================
# todo-export.sh — Export completed phases for AI todowrite integration
#
# Reads .pipeline_checkpoint and outputs JSON lines the AI can use to
# mark phases as ✅ in the AI's todo list.
#
# Usage:
#   bash scripts/tools/todo-export.sh <target>
#   export ENGAGEMENT_ID=... && bash scripts/tools/todo-export.sh <target>
#
# Output (one JSON line per phase):
#   {"num":1,"name":"scope","desc":"Scope registration","done":true}
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/tools/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${RECON_BASE}/${TARGET}"
CHECKPOINT_FILE="$OUT_DIR/.pipeline_checkpoint"

if [ ! -f "$CHECKPOINT_FILE" ]; then
  echo "[]"
  exit 0
fi

# Phase definitions (must match pipeline.sh)
source "$SCRIPT_DIR/tools/_phase_defs.sh"

ENTRIES=()
for entry in "${PHASES[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  name="${rest%%:*}"
  desc="${rest#*:}"
  if grep -qx "phase_$num" "$CHECKPOINT_FILE" 2>/dev/null; then
    ENTRIES+=("{\"num\":$num,\"name\":\"$name\",\"desc\":\"$desc\",\"done\":true}")
  fi
done

echo "["
for i in "${!ENTRIES[@]}"; do
  sep=","
  [ "$i" -eq "$((${#ENTRIES[@]}-1))" ] && sep=""
  echo "  ${ENTRIES[$i]}$sep"
done
echo "]"
