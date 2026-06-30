#!/bin/bash
# =============================================================================
# DNS Brute-Force — puredns + massdns with curated wordlists
#
# Usage:
#   ./tools/dns_bruteforce.sh <domain>
#   ./tools/dns_bruteforce.sh <domain> --wordlist <custom.txt>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'


TARGET="${1:?Usage: $0 <domain> [--wordlist <file>]}"
WORDLIST="${3:-}"

OUT_DIR="${RECON_OUT_DIR:-${RECON_BASE}/$TARGET}"
mkdir -p "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"

# ── Prepare wordlists ──────────────────────────────────────────────
WORDLIST_DIR="$BASE_DIR/wordlists/dns"
mkdir -p "$WORDLIST_DIR"

SUB_LIST="$WORDLIST_DIR/subdomains-top1million-20000.txt"
RESOLVER_FILE="${RESOLVERS_FILE:-$WORDLIST_DIR/resolvers.txt}"

# Use local wordlists (pre-downloaded to wordlists/dns/)
if [ ! -f "$SUB_LIST" ]; then
  log_err "Subdomain wordlist not found: $SUB_LIST"
  log_err "Place file at: $HOME/swarm/wordlists/dns/subdomains-top1million-20000.txt"
  exit 1
fi
log_ok "Subdomain wordlist: $(wc -l < "$SUB_LIST" | tr -d ' ') entries"

if [ ! -f "$RESOLVER_FILE" ]; then
  log_warn "Resolvers file not found: $RESOLVER_FILE"
  log_warn "Place file at: $HOME/swarm/wordlists/dns/resolvers.txt"
  log_warn "Falling back to built-in defaults (13 resolvers)..."
  RESOLVER_FILE=$(mktemp)
  {
    echo "1.1.1.1"; echo "1.0.0.1"
    echo "8.8.8.8"; echo "8.8.4.4"
    echo "9.9.9.9"; echo "149.112.112.112"
    echo "208.67.222.222"; echo "208.67.220.220"
    echo "77.88.8.8"; echo "74.82.42.42"
    echo "64.6.64.6"; echo "185.228.168.9"
    echo "76.76.19.19"
  } > "$RESOLVER_FILE"
fi

log_ok "Resolvers: $(wc -l < "$RESOLVER_FILE" | tr -d ' ') entries"

USE_LIST="${WORDLIST:-$SUB_LIST}"

if ! command -v puredns &>/dev/null; then
  log_err "puredns not found — install via: go install github.com/d3mondev/puredns/v2@latest"
  exit 1
fi

# ── Run puredns bruteforce ──────────────────────────────────────────

log_info "Running puredns bruteforce on $TARGET..."
log_info "  Wordlist: $USE_LIST ($(wc -l < "$USE_LIST" | tr -d ' ') entries)"
log_info "  Resolvers: $RESOLVER_FILE ($(wc -l < "$RESOLVER_FILE" | tr -d ' ') entries)"

puredns bruteforce "$USE_LIST" "$TARGET" -r "$RESOLVER_FILE" \
  | tee "$OUT_DIR/dns_bruteforce.txt"

COUNT=$(wc -l < "$OUT_DIR/dns_bruteforce.txt" | tr -d ' ')
log_ok "Found $COUNT resolved subdomains"
log_ok "Saved to $OUT_DIR/dns_bruteforce.txt"
