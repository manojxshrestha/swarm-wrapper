#!/bin/bash
# =============================================================================
# Waymore — passive URL collection from Wayback Machine + AlienVault etc
#
# Usage:
#   ./tools/web_waymore.sh <domain>
#
# Output: <crawl>/waygauurls.txt
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="${1:?Usage: $0 <domain>}"

OUT_DIR="${RECON_BASE}/$TARGET/crawl"
mkdir -p "$OUT_DIR"

# ── Setup waymore venv ──────────────────────────────────────────────
WAYMORE_DIR="$BASE_DIR/tools/waymore"
WAYMORE_ACTIVATE="$WAYMORE_DIR/venv/bin/activate"

if [ ! -f "$WAYMORE_ACTIVATE" ]; then
  log_err "waymore not found — run: bash scripts/setup/install.sh"
  exit 1
fi

# ── Waymore ─────────────────────────────────────────────────────────
log_info "Running waymore ..."
(
  source "$WAYMORE_ACTIVATE"
  waymore -i "$TARGET" -mode U -oU "$OUT_DIR/wayurls.txt" 2>/dev/null
)
NWAY=$(wc -l < "$OUT_DIR/wayurls.txt" 2>/dev/null | tr -d ' ')
NWAY=${NWAY:-0}
log_ok "waymore: $NWAY URLs"

# ── Dedup with uro ──────────────────────────────────────────────────
log_info "Deduping waymore URLs with uro ..."
if ! command -v uro &>/dev/null; then
  log_info "uro not found — installing via pipx..."
  pipx install uro 2>/dev/null || {
    log_warn "uro install failed — skipping dedup"
    cp "$OUT_DIR/wayurls.txt" "$OUT_DIR/waygauurls.txt"
    NWAYGAU=$NWAY
    log_ok "waygauurls.txt: $NWAYGAU URLs (no dedup)"
    exit 0
  }
fi
uro < "$OUT_DIR/wayurls.txt" 2>/dev/null | sort -u > "$OUT_DIR/waygauurls.txt"
NWAYGAU=$(wc -l < "$OUT_DIR/waygauurls.txt" 2>/dev/null | tr -d ' ')
NWAYGAU=${NWAYGAU:-0}
log_ok "waygauurls.txt: $NWAYGAU URLs"
