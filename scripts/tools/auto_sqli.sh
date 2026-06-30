#!/bin/bash
# =============================================================================
# Automated SQLi Hunting — dispatch sqlmap for SQL injection testing
#
# Usage:
#   ./tools/auto_sqli.sh <domain>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="${1:?Usage: $0 <domain>}"
RECON_DIR="${RECON_BASE}/$TARGET"
OUT_DIR="${RECON_DIR}/sqli"
mkdir -p "$OUT_DIR"

log_info "SQLi Hunting for: $TARGET"

# Collect parameterized endpoints from recon
PARAMS_FILE="${RECON_DIR}/recon/params.txt"
ENDPOINTS_FILE="${RECON_DIR}/recon/urls.txt"

if [ -f "$PARAMS_FILE" ] && [ -s "$PARAMS_FILE" ]; then
    log_info "Testing $(wc -l < "$PARAMS_FILE") param endpoints with sqlmap..."
    if command -v sqlmap &>/dev/null; then
        sqlmap -m "$PARAMS_FILE" \
            --batch \
            --random-agent \
            --level 1 \
            --risk 1 \
            --tamper=space2comment \
            --output-dir="$OUT_DIR/sqlmap_output" \
            --flush-session \
            2>&1 | tail -10 || true
        log_ok "sqlmap scan complete — results: $OUT_DIR/sqlmap_output"
    else
        log_warn "sqlmap not installed — install with: pip install sqlmap"
    fi
elif [ -f "$ENDPOINTS_FILE" ] && [ -s "$ENDPOINTS_FILE" ]; then
    log_info "Scanning endpoints with sqlmap (no params file found)..."
    if command -v sqlmap &>/dev/null; then
        sqlmap -m "$ENDPOINTS_FILE" \
            --batch \
            --random-agent \
            --level 1 \
            --risk 1 \
            --forms \
            --output-dir="$OUT_DIR/sqlmap_output" \
            2>&1 | tail -10 || true
        log_ok "sqlmap scan complete — results: $OUT_DIR/sqlmap_output"
    fi
else
    log_warn "No param or endpoint files found — run phase-recon.sh first"
fi

log_ok "SQLi Hunting complete for $TARGET"
