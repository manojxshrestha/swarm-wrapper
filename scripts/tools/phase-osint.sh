#!/bin/bash
# =============================================================================
# OSINT — Email & subdomain enumeration via theHarvester
#
# Runs theHarvester with multiple search source sets for comprehensive OSINT:
#   - Subdomains: crtsh, rapiddns, subdomaincenter, hackertarget, otx,
#                 urlscan, dnsdumpster, bevigil, certspotter, bufferoverun,
#                 threatcrowd, virustotal, waybackarchive, commoncrawl,
#                 securityTrails, chaos, fullhunt, projectdiscovery, robtex
#   - Emails:    yahoo, duckduckgo, hunter, intelx, haveibeenpwned,
#                 hudsonrock, leakix, leaklookup, mojeek, tomba
#
# Usage:
#   ./tools/phase-osint.sh <domain> [output_dir]
#
# Output (in output_dir/osint/):
#   theharvester_subdomains.json  — Raw theHarvester JSON (subdomain sources)
#   theharvester_emails.json      — Raw theHarvester JSON (email sources)
#   subdomains.txt                — Extracted unique subdomains
#   emails.txt                    — Extracted unique emails
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARVESTER_DIR="${HARVESTER_DIR:-$HOME/theHarvester}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'


export PATH="$HOME/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

if [ "${1:-}" = "--install" ]; then
    echo "Run: bash scripts/setup/install.sh"
    exit 0
fi

TARGET="${1:?Usage: $0 <domain> [output_dir]}"
OUT_DIR="${2:-${RECON_BASE}/$TARGET}"
OSINT_DIR="$OUT_DIR/osint"
mkdir -p "$OSINT_DIR"

log_info "Target: $TARGET"
log_info "Output: $OSINT_DIR"

_run_harvester() {
    local basename="$1"
    local sources="$2"
    local label="$3"

    if [ ! -d "$HARVESTER_DIR/.git" ]; then
        log_warn "theHarvester not found at $HARVESTER_DIR — skipping"
        log_info "  Install: bash scripts/setup/install.sh"
        return 1
    fi

    log_info "Running theHarvester ($label) — sources: $sources"
    # theHarvester -f writes JSON/HTML to cwd, so cd into OSINT_DIR first
    HARVESTER_BIN="$HARVESTER_DIR/.venv/bin/theHarvester"
    (
        cd "$OSINT_DIR"
        "$HARVESTER_BIN" \
            -d "$TARGET" \
            -b "$sources" \
            -n -r \
            -f "$basename"
    ) 2>&1 | tee -a "$OSINT_DIR/theharvester.log"
    return ${PIPESTATUS[0]}
}

_extract_json() {
    local json_file="$1"
    local output_file="$2"
    local key="$3"

    if [ ! -f "$json_file" ]; then
        return 1
    fi

    python3 -c "
import json, sys
try:
    with open('$json_file') as f:
        data = json.load(f)
    items = data.get('$key', [])
    with open('$output_file', 'a') as out:
        for item in items:
            out.write(str(item) + '\n')
    print('  Extracted ' + str(len(items)) + ' $key')
except Exception as e:
    print('Parse error ($json_file): ' + str(e), file=sys.stderr)
" 2>&1 | tee -a "$OSINT_DIR/parse.log"
}

log_step "OSINT — Email & subdomain enumeration"

# Supported sources as of theHarvester 4.11.1
SUB_SOURCES="crtsh,rapiddns,subdomaincenter,hackertarget,otx,urlscan,dnsdumpster,bevigil,certspotter,bufferoverun,threatcrowd,virustotal,waybackarchive,commoncrawl,securityTrails,chaos,fullhunt,projectdiscovery,robtex"
_run_harvester "theharvester_subdomains" "$SUB_SOURCES" "subdomains" || true

EMAIL_SOURCES="yahoo,duckduckgo,hunter,intelx,haveibeenpwned,hudsonrock,leakix,leaklookup,mojeek,tomba"
_run_harvester "theharvester_emails" "$EMAIL_SOURCES" "emails" || true

: > "$OSINT_DIR/subdomains.txt"
: > "$OSINT_DIR/emails.txt"

_extract_json "${OSINT_DIR}/theharvester_subdomains.json" "$OSINT_DIR/subdomains.txt" "hosts" || true
_extract_json "${OSINT_DIR}/theharvester_emails.json" "$OSINT_DIR/emails.txt" "emails" || true

sort -u -o "$OSINT_DIR/subdomains.txt" "$OSINT_DIR/subdomains.txt" 2>/dev/null || true
sort -u -o "$OSINT_DIR/emails.txt" "$OSINT_DIR/emails.txt" 2>/dev/null || true

SUB_COUNT=$(wc -l < "$OSINT_DIR/subdomains.txt" 2>/dev/null | tr -d ' ' || echo 0)
EMAIL_COUNT=$(wc -l < "$OSINT_DIR/emails.txt" 2>/dev/null | tr -d ' ' || echo 0)

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
log_ok "Results in $OSINT_DIR"
log_ok "$SUB_COUNT subdomains found"
log_ok "$EMAIL_COUNT emails found"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
