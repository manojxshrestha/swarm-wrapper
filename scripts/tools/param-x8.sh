#!/bin/bash
# =============================================================================
# Active Parameter Discovery — x8 only (fast active param probing)
#
# Probes endpoints with wordlist to find hidden parameters.
# Hidden params are gold for IDOR, SSRF, LFI, redirect.
#
# Usage:
#   ./tools/param-x8.sh <url>
#   ./tools/param-x8.sh -l <urls-file>
#   ./tools/param-x8.sh --domain <domain>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
hit()  { echo -e "${MAG}[PARAM]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

DOMAIN=""; URL=""; LIST=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -l|--list) shift; LIST="${1:-}" ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    --domain) shift; DOMAIN="${1:-}" ;;
    *) 
      # Detect: URL (has ://) vs domain (has dot, no scheme)
      if echo "$1" | grep -q '://'; then
        URL="$1"
      else
        DOMAIN="$1"
      fi
      ;;
  esac
  shift
done

# Resolve domain → list mode: auto-discover crawl output
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -n "$DOMAIN" ]; then
  RECON_DIR="${RECON_BASE}/$DOMAIN"
  CRAWL_FILE="$RECON_DIR/crawl/crawledurls.txt"
  if [ -f "$CRAWL_FILE" ] && [ -s "$CRAWL_FILE" ]; then
    LIST="$CRAWL_FILE"
    log "domain mode: using $CRAWL_FILE ($(wc -l < "$CRAWL_FILE" | tr -d ' ') URLs)"
  else
    err "no crawl output for '$DOMAIN' at $CRAWL_FILE — run phase-recon.sh first"
    exit 2
  fi
fi

# Must have URL, LIST, or DOMAIN resolved to LIST
[ -z "$URL" ] && [ -z "$LIST" ] && { err "url, domain, or -l <file> required"; exit 2; }

# Output dir: domain-scoped when domain known, else env override or fallback
if [ -n "$DOMAIN" ]; then
  OUT_DIR="${PARAM_OUT_DIR:-$RECON_DIR/params}"
else
  OUT_DIR="${PARAM_OUT_DIR:-${RECON_BASE}/$(echo "${URL:-$(head -1 "$LIST")}" | sed 's|https\?://||;s|/.*||')/params}"
fi
mkdir -p "$OUT_DIR"

# Check for x8
if ! _have x8; then
  err "x8 not installed — run: bash scripts/setup/install.sh"
  exit 1
fi

log "x8 discovery..."

WL="$SCRIPT_DIR/../wordlists/params.txt"
[ -f "$WL" ] || WL=""

if [ -n "$URL" ]; then
  log "x8 single URL: $URL"
  x8 -u "$URL" ${WL:+-w "$WL"} -o "$OUT_DIR/x8.txt" 2>/dev/null || true
else
  log "x8 bulk scan from list: $LIST"
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    x8 -u "$u" ${WL:+-w "$WL"} >> "$OUT_DIR/x8.txt" 2>/dev/null || true
  done < "$LIST"
fi

# Generate summary
if [ -f "$OUT_DIR/x8.txt" ] && [ -s "$OUT_DIR/x8.txt" ]; then
  python3 -c "
import json
with open('$OUT_DIR/x8.txt') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        # x8 output format: URL  →  param1,param2
        if '→' in line:
            ep, params = line.split('→', 1)
            ep = ep.strip()
            params = params.strip()
            if params:
                print(f'{ep}  →  {params}')
  " > "$OUT_DIR/x8_summary.txt" || true
  n=$(wc -l < "$OUT_DIR/x8_summary.txt" | tr -d ' ')
  [ "$n" -gt 0 ] && hit "x8: $n endpoint(s) had hidden params" || ok "x8: no hits"
else
  ok "x8: no hits"
fi

ok "Done. Output → $OUT_DIR/"