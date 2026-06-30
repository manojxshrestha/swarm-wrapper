#!/bin/bash
# =============================================================================
# Automated XSS Hunting — dispatch dalfox + httpx for reflected XSS
#
# Usage:
#   ./tools/auto_xss.sh <domain>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="${1:?Usage: $0 <domain>}"
RECON_DIR="${RECON_BASE}/$TARGET"
OUT_DIR="${RECON_DIR}/xss"
mkdir -p "$OUT_DIR"

log_info "XSS Hunting for: $TARGET"

# Collect endpoints from recon output
ENDPOINTS_FILE="${RECON_DIR}/recon/urls.txt"
PARAMS_FILE="${RECON_DIR}/recon/params.txt"

if [ -f "$ENDPOINTS_FILE" ] && [ -s "$ENDPOINTS_FILE" ]; then
    log_info "Scanning $(wc -l < "$ENDPOINTS_FILE") endpoints with dalfox..."
    if command -v dalfox &>/dev/null; then
        dalfox file "$ENDPOINTS_FILE" \
            --mining-dict \
            --only-custom-payload \
            --skip-bav \
            --follow-redirects \
            --deep-domxss \
            --output "$OUT_DIR/dalfox_results.txt" 2>&1 | tail -5 || true
        log_ok "dalfox scan complete — results: $OUT_DIR/dalfox_results.txt"
    else
        log_warn "dalfox not installed — install with: go install github.com/hahwul/dalfox/v2@latest"
    fi
else
    log_warn "No endpoint file found at $ENDPOINTS_FILE"
fi

# Check for reflected XSS with httpx
if [ -f "$PARAMS_FILE" ] && [ -s "$PARAMS_FILE" ]; then
    log_info "Testing params for reflection..."
    while IFS= read -r url; do
        test_param="${url}&xss_test=<script>alert(1)</script>"
        response=$(curl -s -o /dev/null -w "%{http_code}" "$test_param" 2>/dev/null || echo "000")
        echo "$response $test_param"
    done < "$PARAMS_FILE" > "$OUT_DIR/reflection_test.txt"
    log_ok "Reflection test complete — results: $OUT_DIR/reflection_test.txt"
fi

log_ok "XSS Hunting complete for $TARGET"
