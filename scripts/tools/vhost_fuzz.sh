#!/bin/bash
# =============================================================================
# VHost Fuzzing — ffuf-based virtual host discovery
#
# Finds hidden vhosts that don't have DNS records but still respond
# to the right Host header on the same IP.
#
# Usage:
#   ./tools/vhost_fuzz.sh <domain> [--url <base-url>] [--ip <origin-ip>] [--quick] [--delay <ms>] [--wordlist <file>]
#
# Examples:
#   ./tools/vhost_fuzz.sh humo.be
#   ./tools/vhost_fuzz.sh humo.be --ip 192.0.2.10          # bypass CDN
#   ./tools/vhost_fuzz.sh humo.be --url https://origin.com
#   ./tools/vhost_fuzz.sh humo.be --quick                  # first 500 entries
#   ./tools/vhost_fuzz.sh humo.be --delay 500              # 500ms between requests
# =============================================================================

set -euo pipefail

ENV_FILE="$(dirname "$0")/_env.sh"
if [ -f "$ENV_FILE" ]; then
  source "$ENV_FILE"
else
  echo "[-] _env.sh not found at $ENV_FILE" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  echo "Usage: $0 <domain> [--url <base-url>]"
  exit 0
fi

TARGET="$1"
BASE_URL="https://$TARGET"
ORIGIN_IP=""
QUICK=false
CUSTOM_WL=""
DELAY=""
shift
while [ $# -gt 0 ]; do
  case "$1" in
    --url)      BASE_URL="$2"; shift 2 ;;
    --ip)       ORIGIN_IP="$2"; shift 2 ;;
    --quick)    QUICK=true; shift ;;
    --wordlist) CUSTOM_WL="$2"; shift 2 ;;
    --delay)    DELAY="$2"; shift 2 ;;
    *) shift ;;
  esac
done
BASE_URL="${BASE_URL%/}"

: "${RECON_BASE:?RECON_BASE not set}"

OUT_DIR="${RECON_BASE}/$TARGET/vhost"
mkdir -p "$OUT_DIR"

WORDLIST_DIR="$BASE_DIR/wordlists/vhost"
mkdir -p "$WORDLIST_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Wordlist selection ──────────────────────────────────────────────
DNS_WL="$BASE_DIR/wordlists/dns/subdomains-top1million-20000.txt"
if [ -n "$CUSTOM_WL" ]; then
  WORDLIST="$CUSTOM_WL"
elif [ -f "$DNS_WL" ]; then
  WORDLIST="$DNS_WL"
else
  WORDLIST="$WORDLIST_DIR/common.txt"
fi
if [ ! -f "$WORDLIST" ]; then
  log_info "Downloading vhost wordlist from manojxshrestha/wordlists..."
  wget -q "https://raw.githubusercontent.com/manojxshrestha/wordlists/main/common.txt" -O "$WORDLIST" || true
  if [ -f "$WORDLIST" ]; then
    log_ok "Downloaded $(wc -l < "$WORDLIST" | tr -d ' ') entries"
  else
    log_warn "Wordlist download failed — vhost fuzzing needs a wordlist"
    exit 0
  fi
fi
if [ "$QUICK" = true ]; then
  QUICKFILE=$(mktemp /tmp/vhost_quick_XXXXXX.txt)
  head -500 "$WORDLIST" > "$QUICKFILE"
  WORDLIST="$QUICKFILE"
  log_info "Quick mode: first 500 entries only"
fi

# ── Sanity check: target reachable ──────────────────────────────────
log_info "Checking reachability of $BASE_URL..."
if ! curl -sk --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" "$BASE_URL/" 2>/dev/null | grep -qE '^[0-9]+$' ; then
  log_warn "$BASE_URL is not reachable — skipping vhost fuzzing"
  rm -f "${QUICKFILE:-}"
  exit 0
fi
log_ok "Target reachable"

# ── Rate limit (ffuf) ──────────────────────────────────────────────
RATE_FLAG=""
if [ -n "$DELAY" ]; then
  RATE_FLAG="-p $DELAY"
fi

# ── Run vhost fuzzing ─────────────────────────────────────────────
if [ -n "$ORIGIN_IP" ]; then
  # Direct-to-origin mode (bypasses CDN, uses parallel curl — 20 jobs)
  log_info "Direct-to-origin vhost fuzzing via $ORIGIN_IP..."
  log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
  TMPFILE=$(mktemp /tmp/vhost_results_XXXXXX.txt)
  WORDLIST_TMP=$(mktemp /tmp/vhost_words_XXXXXX.txt)
  cp "$WORDLIST" "$WORDLIST_TMP"
  _check_vhost() {
    local vhost="$1"
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      --resolve "${vhost}:443:${ORIGIN_IP}" \
      --connect-timeout 5 --max-time 8 \
      "https://${vhost}/" 2>/dev/null || true)
    local status="${resp%%:*}"
    local size="${resp##*:}"
    if [ "$status" != "000" ] && [ "$status" != "" ]; then
      echo "${vhost} -> ${status} (${size}b)"
    fi
  }
  export -f _check_vhost
  export ORIGIN_IP TARGET
  cat "$WORDLIST_TMP" | parallel -j 20 "_check_vhost {}.${TARGET}" 2>/dev/null > "$TMPFILE" || true
  sort -u "$TMPFILE" > "$OUT_DIR/vhost_results.txt" 2>/dev/null || true
  rm -f "$TMPFILE" "$WORDLIST_TMP"
  if [ -s "$OUT_DIR/vhost_results.txt" ]; then
    N=$(wc -l < "$OUT_DIR/vhost_results.txt" | tr -d ' ')
    log_ok "Found $N responding vhosts (review $OUT_DIR/vhost_results.txt)"
  else
    log_warn "No vhosts found via origin IP $ORIGIN_IP"
  fi
else
  # ffuf-based vhost fuzzing (works best for non-CDN targets)
  if ! command -v ffuf &>/dev/null; then
    log_warn "ffuf not found — skipping vhost fuzzing (install: go install github.com/ffuf/ffuf/v2@latest)"
    log_info "Use --ip <origin-ip> for curl-based direct fuzzing instead"
    exit 0
  fi
  log_warn "CDN targets (Akamai, Cloudflare) route on SNI not Host header — results likely empty"
  log_info "Use --ip <origin-ip> to bypass CDN and fuzz directly against the origin"
  log_info "Fuzzing vhosts on $TARGET via $BASE_URL..."
  log_info "  Wordlist: $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') entries)"
  ffuf \
    -w "$WORDLIST:FUZZ" \
    -u "$BASE_URL/" \
    -H "Host: FUZZ.$TARGET" \
    -r \
    -ac \
    -o "$OUT_DIR/vhost_results.json" \
    -of json \
    "$RATE_FLAG" \
    -v \
    2>/dev/null || true
  if [ -s "$OUT_DIR/vhost_results.json" ]; then
    python3 <<EOF
import json
with open("$OUT_DIR/vhost_results.json") as f:
    data = json.load(f)
results = data.get("results", [])
if results:
    print(f"Found {len(results)} vhosts:")
    for r in results:
        word = r.get("input", {}).get("FUZZ", "?")
        url = r.get("url", "")
        redirect = r.get("redirectlocation", "")
        status = r.get("status", "?")
        length = r.get("length", "?")
        line = f"  {word}.$TARGET -> {status} ({length}b)"
        if redirect:
            line += f" -> {redirect}"
        print(line)
else:
    print("No vhosts found.")
EOF
  else
    log_warn "No results from ffuf"
  fi
fi

rm -f "${QUICKFILE:-}"
log_ok "Done. Results in $OUT_DIR/"
