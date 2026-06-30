#!/usr/bin/env bash
# =============================================================================
# Phase 6: HUNT — Vulnerability hunting dispatcher
#
# Usage: ./tools/phase-hunt.sh <domain> [output_dir] [--active-param] [--root-only]
#
# This phase runs parameter extraction and prepares candidate lists for AI analysis.
# The AI agent (@hunt) should be called separately to analyze results.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET=""
OUT_DIR=""
ROOT_ONLY=false
ACTIVE_PARAM=false
SKIP_LIST="${SKIP_LIST:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root-only) ROOT_ONLY=true; shift ;;
    --active-param) ACTIVE_PARAM=true; shift ;;
    --skip) shift; SKIP_LIST="${SKIP_LIST:+"$SKIP_LIST,"}$1"; shift ;;
    *) [ -z "$TARGET" ] && TARGET="$1" || OUT_DIR="$1"; shift ;;
  esac
done
[ -z "$TARGET" ] && { log_err "Usage: $0 <domain> [output_dir] [--active-param] [--root-only]"; exit 1; }
[ -z "$OUT_DIR" ] && OUT_DIR="${RECON_BASE}/${TARGET}"
_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HUNT_DIR="$OUT_DIR/hunt"
mkdir -p "$HUNT_DIR"

# CRAWL_DIR must be defined for secrets hunting section
CRAWL_DIR="$OUT_DIR/crawl"

log_info "=== Phase 6: Vulnerability Hunting ==="

if [ "$ROOT_ONLY" = true ]; then
  log_info "Root-only mode — ensuring fallback crawledurls.txt exists"
  mkdir -p "$CRAWL_DIR"
  if [ ! -s "$CRAWL_DIR/crawledurls.txt" ]; then
    echo "https://$TARGET/" > "$CRAWL_DIR/crawledurls.txt"
    log_ok "Created fallback crawledurls.txt with root domain"
  fi
fi

# 1. Parameter extraction (passive) - GF patterns on crawled URLs.
# P-M3: recon (phase 4) already runs param_extract. Only run it here when recon
# left no params/ output (e.g. hunt invoked standalone) to avoid duplicate work
# racing on the same params/ directory.
if [ -f "$SCRIPT_DIR/param_extract.sh" ]; then
  if _skip_check "param_extract"; then
    log_info "Skipping param_extract (--skip)"
  elif [ -d "$OUT_DIR/params" ] && [ -n "$(find "$OUT_DIR/params" -type f -name 'gf_*.txt' 2>/dev/null | head -n1)" ]; then
    log_info "param_extract: recon already produced params/ output — skipping (no duplicate)"
  else
    nohup bash -c "bash '$SCRIPT_DIR/param_extract.sh' '$TARGET'" \
      > "$HUNT_DIR/param_extract.log" 2>&1 &
  fi
else
  log_warn "param_extract: script not found, skipped"   # P-M2
fi

# 2. Active parameter discovery (conditional) - x8 probing
ACTIVE_TRIGGER="${OUT_DIR}/.run_active_param"
if [ "$ACTIVE_PARAM" = true ] || [ -f "$ACTIVE_TRIGGER" ]; then
  if [ -f "$SCRIPT_DIR/param-x8.sh" ]; then
    if _skip_check "param-x8"; then
      log_info "Skipping param-x8 (--skip)"
    else
      CRAWLED="${OUT_DIR}/crawl/crawledurls.txt"
      nohup bash -c "bash '$SCRIPT_DIR/param-x8.sh' -l '$CRAWLED' -o '${OUT_DIR}/params'" \
        > "$HUNT_DIR/param-x8.log" 2>&1 &
      if [ -f "$ACTIVE_TRIGGER" ]; then
        rm -f "$ACTIVE_TRIGGER"
      fi
    fi
  else
    log_warn "param-x8: script not found, skipped"   # P-M2
  fi
else
  log_info "Skipping active param discovery (use --active-param or trigger file)"
fi

# 3. Secrets hunting
if [ -f "$SCRIPT_DIR/secrets_hunter.sh" ]; then
  if _skip_check "secrets_hunter"; then
    log_info "Skipping secrets_hunter (--skip)"
  else
    JS_LIST="$OUT_DIR/urls/js_files.txt"
    if [ -s "$JS_LIST" ]; then
      nohup bash -c "bash '$SCRIPT_DIR/secrets_hunter.sh' --js-bundle '$OUT_DIR'" \
        > "$HUNT_DIR/secrets_hunter.log" 2>&1 &
    else
      if [ -d "$CRAWL_DIR" ] && [ "$(find "$CRAWL_DIR" -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        nohup bash -c "bash '$SCRIPT_DIR/secrets_hunter.sh' --filesystem '$CRAWL_DIR'" \
          > "$HUNT_DIR/secrets_hunter.log" 2>&1 &
      else
        log_warn "No crawl output for secrets scanning — skipping (run web crawlers first)"
      fi
    fi
  fi
else
  log_warn "secrets_hunter: script not found, skipped"   # P-M2
fi
if [ -f "$SCRIPT_DIR/auto_secrets.sh" ]; then
  if _skip_check "auto_secrets"; then
    log_info "Skipping auto_secrets (--skip)"
  else
    nohup bash -c "bash '$SCRIPT_DIR/auto_secrets.sh' '$TARGET'" \
      > "$HUNT_DIR/auto_secrets.log" 2>&1 &
  fi
else
  log_warn "auto_secrets: script not found, skipped"   # P-M2
fi

# 4. Vhost fuzzing
if [ -f "$SCRIPT_DIR/vhost_fuzz.sh" ]; then
  if _skip_check "vhost_fuzz"; then
    log_info "Skipping vhost_fuzz (--skip)"
  else
    nohup bash -c "bash '$SCRIPT_DIR/vhost_fuzz.sh' '$TARGET'" \
      > "$HUNT_DIR/vhost_fuzz.log" 2>&1 &
  fi
else
  log_warn "vhost_fuzz: script not found, skipped"   # P-M2
fi

# 5. 403 bypass
if [ -f "$SCRIPT_DIR/bypass_403.sh" ]; then
  if _skip_check "bypass_403"; then
    log_info "Skipping bypass_403 (--skip)"
  else
    nohup bash -c "bash '$SCRIPT_DIR/bypass_403.sh' '$TARGET' --quick" \
      > "$HUNT_DIR/bypass_403.log" 2>&1 &
  fi
else
  log_warn "bypass_403: script not found, skipped"   # P-M2
fi

log_ok "Candidate generation complete"
log_info "Agent input files in: $OUT_DIR/params/ (gf_*.txt, x8_summary.txt if active)"
log_info "Review findings in: $OUT_DIR (subdirs: params/, secrets/, vhost/)"
log_info "Then call @hunt agent for AI-driven analysis of results"
log_ok "Phase 6 (hunt) complete"