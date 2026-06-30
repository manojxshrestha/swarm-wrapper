#!/usr/bin/env bash
# =============================================================================
# Phase 2: AUTH — Autonomous auth + WAF detection
#
# Two layers:
#   1. WAF fingerprinting (fast, always runs)
#   2. Auto-auth via browser (signup → verify → login → cookie capture)
#
# Usage: ./tools/phase-auth.sh <domain> [output_dir]
#   BBHUNT_AUTH_HEADERS=... ./tools/phase-auth.sh <domain>   # skip auto-auth
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"
_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope

AUTH_DIR="$OUT_DIR/auth"
mkdir -p "$AUTH_DIR"

# ── 1. WAF detection ───────────────────────────────────────────────────────
log_info "Detecting WAF..."
if command -v curl &>/dev/null; then
  {
    echo "=== WAF Detection ==="
    curl -sI "https://$TARGET" 2>&1 | grep -iE "server:|cf-ray|x-sucuri|x-iinfo|x-mod-security|x-waf|cloudflare|akamai|fastly" || true
    echo ""
    echo "=== Response Headers ==="
    curl -sI "https://$TARGET" 2>&1
  } > "$AUTH_DIR/waf_detection.txt"
  log_ok "WAF headers saved to $AUTH_DIR/waf_detection.txt"
fi

# ── 2. Auto-auth via browser ───────────────────────────────────────────────
# Skip if user already provided credentials
if [ -n "${BBHUNT_AUTH_HEADERS:-}" ] || [ -n "${BBHUNT_COOKIE:-}" ] || [ -n "${BBHUNT_BEARER:-}" ]; then
  log_info "Auth credentials already set via env — skipping browser auto-auth"
elif [ -f "$AUTH_DIR/session.json" ] && [ -s "$AUTH_DIR/session.json" ]; then
  log_info "Found existing session at $AUTH_DIR/session.json — skipping browser auto-auth"
else
  log_info "No credentials found — launching autonomous browser auth in background..."

  AUTO_AUTH_SCRIPT="$(dirname "$0")/auto_auth.py"
  if [ -f "$AUTO_AUTH_SCRIPT" ]; then
    if _skip_check "auto_auth"; then
      log_info "Skipping auto_auth (--skip auto_auth)"
    else
      nohup bash -c "python3 '$AUTO_AUTH_SCRIPT' '$TARGET' --output-dir '$OUT_DIR'" \
        > "$AUTH_DIR/auto_auth.log" 2>&1 &
      local _aa_pid=$!
      log_info "Auto-auth running in background (PID: $_aa_pid)"
      log_info "  Log: $AUTH_DIR/auto_auth.log"
      log_info "  Check later: cat $AUTH_DIR/auto_auth.log"
    fi
  else
    log_warn "auto_auth.py not found — skipping browser auth"
  fi
fi

log_ok "Phase 2 (auth) complete"
log_info "WAF: $(head -1 "$AUTH_DIR/waf_detection.txt" 2>/dev/null || echo 'unknown')"
if [ -f "$AUTH_DIR/session.json" ]; then
  log_info "Session: $(python3 -c "import json; d=json.load(open('$AUTH_DIR/session.json')); print(f'{len(d.get(\"cookies\",[]))} cookies captured at {d.get(\"captured_at\",\"?\")}')" 2>/dev/null || echo 'unknown')"
else
  log_info "Session: pending (auto-auth running in background)"
fi
log_info "Next: Run Phase 3 (intel) to gather passive intelligence"
log_info "Tip: Re-run Phase 2 later to pick up session once auto-auth completes"
