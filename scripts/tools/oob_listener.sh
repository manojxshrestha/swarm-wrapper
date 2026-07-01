#!/usr/bin/env bash
# =============================================================================
# OOB Listener — Start/stop/poll interactsh-client for blind PoC confirmation
#
# Usage:
#   oob_listener.sh start              # Start background listener, print URL
#   oob_listener.sh poll [payload_id]  # Poll for interactions (optional filter)
#   oob_listener.sh stop               # Stop background listener
#   oob_listener.sh url                # Print current OOB URL without starting
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_env.sh"

OOB_PID_FILE="/tmp/swarm_oob.pid"
OOB_URL_FILE="/tmp/swarm_oob.url"
OOB_OUT_FILE="/tmp/swarm_oob.out"
OOB_CLIENT="interactsh-client"

case "${1:-help}" in
  start)
    if [ -f "$OOB_PID_FILE" ] && kill -0 "$(cat "$OOB_PID_FILE")" 2>/dev/null; then
        log_warn "OOB listener already running (PID $(cat "$OOB_PID_FILE"))"
        cat "$OOB_URL_FILE" 2>/dev/null || true
        exit 0
    fi
    log_info "Starting OOB listener..."
    $OOB_CLIENT -v 2>"$OOB_OUT_FILE" &
    PID=$!
    echo $PID > "$OOB_PID_FILE"
    # Wait for URL to appear in output (up to 5s)
    URL=""
    for i in 1 2 3 4 5; do
        sleep 1
        # FIX #8: grep -oE (portable) instead of grep -oP (GNU-only)
        URL=$(grep -oE '[^[:space:]]+[.]oast[.][^[:space:]]+' "$OOB_OUT_FILE" 2>/dev/null | head -1 || true)
        # END FIX #8
        [ -n "$URL" ] && break
    done
    if [ -z "$URL" ]; then
        log_warn "Could not detect OOB URL from interactsh-client output"
        URL="start.oast.fun"
    fi
    echo "$URL" > "$OOB_URL_FILE"
    log_ok "OOB URL: $URL"
    echo "$URL"
    ;;
  poll)
    PAYLOAD_ID="${2:-}"
    if [ ! -f "$OOB_OUT_FILE" ]; then
        echo "[]"
        exit 0
    fi
    if [ -n "$PAYLOAD_ID" ]; then
        grep -i "$PAYLOAD_ID" "$OOB_OUT_FILE" 2>/dev/null || echo ""
    else
        cat "$OOB_OUT_FILE" 2>/dev/null || echo ""
    fi
    ;;
  stop)
    if [ -f "$OOB_PID_FILE" ]; then
        kill "$(cat "$OOB_PID_FILE")" 2>/dev/null || true
        rm -f "$OOB_PID_FILE"
        log_ok "OOB listener stopped"
    fi
    ;;
  url)
    cat "$OOB_URL_FILE" 2>/dev/null || echo ""
    ;;
  *)
    echo "Usage: $0 {start|stop|poll [id]|url}"
    exit 1
    ;;
esac
