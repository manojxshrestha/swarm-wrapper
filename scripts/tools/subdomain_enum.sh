#!/bin/bash
# =============================================================================
# Subdomain Enumeration — passive discovery + DNS resolution + live probe
#
# Chain: subfinder + assetfinder + findomain → dnsx → httpx (with tech-detect)
# Outputs:
#   all_subdomains.txt — all unique domains from passive sources
#   alive-domains.txt  — clean domain names (resolved + alive)
#   https-subs.txt     — full HTTPS URLs for downstream tools
#   live_domains.txt   — httpx raw output (status, tech, title, server)
#   live_urls.txt      — HTTPS URLs (for auto_recon.sh autodetect)
#
# Usage:
#   ./tools/subdomain_enum.sh <domain>
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'


# Normalize target: strip protocol and trailing path
RAW_TARGET="${1:?Usage: $0 <domain>}"
TARGET=$(echo "$RAW_TARGET" | sed -E 's|https?://||' | sed 's|/.*||')

cleanup() { rm -rf "${TMP_DIR:-}"; }
trap cleanup EXIT INT TERM

OUT_DIR="${RECON_BASE}/$TARGET/subdomains"
TMP_DIR="$OUT_DIR/.tmp"
mkdir -p "$TMP_DIR" "$OUT_DIR"

export PATH="$HOME/go/bin:/usr/local/bin:$PATH"
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  export PATH="$PATH:$HOME/go/bin"
fi

# ── Verify tools ────────────────────────────────────────────────────
for tool in subfinder assetfinder httpx dnsx; do
  if ! command -v "$tool" &>/dev/null; then
    log_err "$tool not found — install required tool"
    exit 1
  fi
done

# ── Step 1: Passive subdomain enumeration ───────────────────────────
log_info "Running subfinder ..."
subfinder -d "$TARGET" -all -silent 2>/dev/null | sort -u > "$TMP_DIR/subfinder.txt" || true
log_ok "  subfinder: $(wc -l < "$TMP_DIR/subfinder.txt" | tr -d ' ') subs"

log_info "Running assetfinder ..."
assetfinder --subs-only "$TARGET" 2>/dev/null | sort -u > "$TMP_DIR/assetfinder.txt" || true
log_ok "  assetfinder: $(wc -l < "$TMP_DIR/assetfinder.txt" | tr -d ' ') subs"

log_info "Running findomain ..."
if command -v findomain &>/dev/null; then
  findomain -t "$TARGET" -q 2>/dev/null | sort -u > "$TMP_DIR/findomain.txt" || true
  log_ok "  findomain: $(wc -l < "$TMP_DIR/findomain.txt" | tr -d ' ') subs"
else
  log_warn "  findomain not installed — skipping"
  : > "$TMP_DIR/findomain.txt"
fi

# ── Step 2: Merge ───────────────────────────────────────────────────
cat "$TMP_DIR/subfinder.txt" "$TMP_DIR/assetfinder.txt" "$TMP_DIR/findomain.txt" \
  | sort -u > "$OUT_DIR/all_subdomains.txt"
TOTAL=$(wc -l < "$OUT_DIR/all_subdomains.txt" | tr -d ' ')
log_ok "Total unique subdomains: $TOTAL"

# ── Step 3: DNS resolution with dnsx ────────────────────────────────
log_info "Resolving subdomains with dnsx ..."
dnsx -l "$OUT_DIR/all_subdomains.txt" -silent 2>/dev/null \
  | sort -u > "$TMP_DIR/resolved.txt"
RESOLVED=$(wc -l < "$TMP_DIR/resolved.txt" | tr -d ' ')
log_ok "  Resolved: $RESOLVED"

if [ "$RESOLVED" -eq 0 ]; then
  log_warn "No resolved subdomains. Skipping httpx probe."
  exit 0
fi

# ── Step 4: Live probe with httpx (status + tech-detection) ─────────
log_info "Probing live hosts with httpx ..."
httpx -l "$TMP_DIR/resolved.txt" \
      -ports 80,443 \
      -status-code \
      -title \
      -tech-detect \
      -web-server \
      -content-length \
      -threads 100 \
      -silent \
      -o "$OUT_DIR/live_domains.txt" \
      2>/dev/null

LIVE=$(wc -l < "$OUT_DIR/live_domains.txt" | tr -d ' ')
log_ok "  Live hosts: $LIVE"

# ── Step 5: Extract clean domain lists for downstream tools ─────────
NDOMAINS=0
NURLS=0
if [ "$LIVE" -gt 0 ]; then
  # All live URLs (protocol + host) from httpx column 1
  awk '{print $1}' "$OUT_DIR/live_domains.txt" | sort -u \
    > "$OUT_DIR/live_urls.txt"

  # Clean domain names (strip protocol, strip port, strip path)
  awk -F/ '{print $3}' "$OUT_DIR/live_urls.txt" \
    | cut -d: -f1 \
    | sort -u > "$OUT_DIR/alive-domains.txt"

  # HTTPS-only URLs for tools that need it
  grep "^https://" "$OUT_DIR/live_urls.txt" \
    > "$OUT_DIR/https-subs.txt"

  NDOMAINS=$(wc -l < "$OUT_DIR/alive-domains.txt" | tr -d ' ')
  NURLS=$(wc -l < "$OUT_DIR/https-subs.txt" | tr -d ' ')
  log_ok "  Clean domains: $NDOMAINS"
  log_ok "  HTTPS URLs: $NURLS"
fi

log_ok "Done. Results in $OUT_DIR/"
log_ok "  all_subdomains.txt — $TOTAL subs (raw)"
if [ "$LIVE" -gt 0 ]; then
  log_ok "  live_urls.txt      — $NURLS live URLs (protocol+host)"
  log_ok "  alive-domains.txt  — $NDOMAINS clean domains"
  log_ok "  https-subs.txt     — HTTPS-only URLs"
  log_ok "  live_domains.txt   — $LIVE httpx output (tech + status)"
else
  log_ok "  No live hosts found."
fi
