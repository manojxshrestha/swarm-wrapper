#!/bin/bash
# auto_hunt.sh - full recon + hunt pipeline

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'


[ $# -eq 0 ] && { echo "Usage: $0 <domain> [--skip xss,sqli,secrets]" >&2; exit 1; }
TARGET="$1"
SKIP_ARRAY=()
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --skip)
            IFS=',' read -ra SKIP_ARRAY <<< "$2"
            shift 2
            ;;
        *)
            log_err "Unknown option: $1"
            exit 1
            ;;
    esac
done

skip() {
    for s in "${SKIP_ARRAY[@]}"; do
        [ "$s" = "$1" ] && return 0
    done
    return 1
}

trap 'log_warn "Interrupted by user"; exit 130' INT

# source auth helper if present
AUTH_HELPER="$SCRIPT_DIR/_auth_helper.sh"
if [ -f "$AUTH_HELPER" ]; then
    # shellcheck source=./_auth_helper.sh
    source "$AUTH_HELPER"
    bb_auth_banner
fi

START_TS=$(date +%s)
log_info "Auto Hunt for: $TARGET"
echo ""

if [ ! -x "$SCRIPT_DIR/phase-recon.sh" ]; then
    log_warn "$SCRIPT_DIR/phase-recon.sh not found or not executable"
else
    log_info "=== Phase 0-3: Recon ==="
    bash "$SCRIPT_DIR/phase-recon.sh" "$TARGET"
    echo ""
fi

if ! skip xss; then
    if [ ! -x "$SCRIPT_DIR/auto_xss.sh" ]; then
        log_warn "$SCRIPT_DIR/auto_xss.sh not found or not executable"
    else
        log_info "=== Phase 4: XSS ==="
        bash "$SCRIPT_DIR/auto_xss.sh" "$TARGET"
        echo ""
    fi
fi
if ! skip sqli; then
    if [ ! -x "$SCRIPT_DIR/auto_sqli.sh" ]; then
        log_warn "$SCRIPT_DIR/auto_sqli.sh not found or not executable"
    else
        log_info "=== Phase 5: SQLi ==="
        bash "$SCRIPT_DIR/auto_sqli.sh" "$TARGET"
        echo ""
    fi
fi
if ! skip secrets; then
    if [ ! -x "$SCRIPT_DIR/auto_secrets.sh" ]; then
        log_warn "$SCRIPT_DIR/auto_secrets.sh not found or not executable"
    else
        log_info "=== Phase 6: Secrets ==="
        bash "$SCRIPT_DIR/auto_secrets.sh" "$TARGET"
        echo ""
    fi
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
log_ok "Auto Hunt Complete"
log_ok "Results: ${RECON_BASE}/$TARGET/"
log_ok "Time: $((ELAPSED / 60))m $((ELAPSED % 60))s"
