#!/usr/bin/env bash
# =============================================================================
# Phase 4: RECON — Subdomains, crawling, parameter extraction, secrets
#
# Usage: ./tools/phase-recon.sh <domain> [output_dir]
# Dependency chain:
#   subdomain_enum ──WAIT──→ crawlers (parallel) ──WAIT──→ merge ──→ modules ──WAIT──→ done
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET=""
OUT_DIR=""
ROOT_ONLY=false
SKIP_LIST="${SKIP_LIST:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root-only) ROOT_ONLY=true; shift ;;
    --skip) shift; SKIP_LIST="${SKIP_LIST:+"$SKIP_LIST,"}$1"; shift ;;
    *) [ -z "$TARGET" ] && TARGET="$1" || OUT_DIR="$1"; shift ;;
  esac
done
[ -z "$TARGET" ] && { log_err "Usage: $0 <domain> [output_dir] [--root-only]"; exit 1; }
[ -z "$OUT_DIR" ] && OUT_DIR="${RECON_BASE}/${TARGET}"
_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRAWL_DIR="$OUT_DIR/crawl"
CRAWL_TIMEOUT="${CRAWL_TIMEOUT:-300}"

log_info "========================================"
log_info "Phase 4: Full Reconnaissance"
log_info "========================================"
log_info ""
log_info "  Target: $TARGET"
log_info "  Output: $OUT_DIR"
log_info ""

# ------------------------------------------------------------------
# Clean stale output from previous runs
# ------------------------------------------------------------------
rm -rf "$CRAWL_DIR/gooutput" 2>/dev/null || true
rm -f "$CRAWL_DIR/"*.txt 2>/dev/null || true
mkdir -p "$OUT_DIR/subdomains" "$CRAWL_DIR"

# ------------------------------------------------------------------
# Sub-phase 4a: Subdomain Enumeration
# ------------------------------------------------------------------
log_info "── Sub-phase 4a: Subdomain Enumeration ──"
log_info "  Script:   scripts/tools/subdomain_enum.sh"

if [ "$ROOT_ONLY" = true ]; then
  log_info "  Root-only mode — seeding with root domain"
  echo "https://$TARGET" > "$OUT_DIR/subdomains/live_urls.txt"
elif [ -f "$SCRIPT_DIR/subdomain_enum.sh" ]; then
  if _skip_check "subdomain_enum"; then
    log_info "  ⏭  Skipped (--skip subdomain_enum)"
  else
    log_info "  Running..."
    nohup bash -c "bash '$SCRIPT_DIR/subdomain_enum.sh' '$TARGET'" \
      > "$OUT_DIR/subdomains/subdomain_enum.log" 2>&1 &
    wait $! && log_ok "  subdomain_enum: OK" || log_warn "  subdomain_enum: failed (exit $?)"
  fi
else
  log_warn "  subdomain_enum.sh not found"
fi

# Validate subdomain output — seed with root domain if missing
if [ ! -s "$OUT_DIR/subdomains/live_urls.txt" ]; then
  log_warn "  live_urls.txt empty or missing — seeding with root domain"
  echo "https://$TARGET" > "$OUT_DIR/subdomains/live_urls.txt"
fi
N_SUBS=$(wc -l < "$OUT_DIR/subdomains/live_urls.txt" | tr -d ' ')
N_ALL=$(wc -l < "$OUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null | tr -d ' ')
N_ALIVE=$(wc -l < "$OUT_DIR/subdomains/alive-domains.txt" 2>/dev/null | tr -d ' ')
log_ok "  Output:"
log_ok "    subdomains/live_urls.txt       — $N_SUBS live HTTPS URLs"
log_ok "    subdomains/all_subdomains.txt  — ${N_ALL:-0} subdomains"
log_ok "    subdomains/alive-domains.txt   — ${N_ALIVE:-0} alive hosts"
log_info ""

# ------------------------------------------------------------------
# Sub-phase 4b: Web Crawling (3 parallel crawlers)
# ------------------------------------------------------------------
log_info "── Sub-phase 4b: Web Crawling (3 parallel crawlers) ──"
log_info "  gospider  → scripts/tools/web_gospider.sh"
log_info "  katana    → scripts/tools/web_katana.sh"
log_info "  waymore   → scripts/tools/web_waymore.sh"

CRAWLER_NAMES=()
CRAWLER_PIDS=()
CRAWLER_SKIPPED=()

for _entry in "gospider|web_gospider.sh" "katana|web_katana.sh" "waymore|web_waymore.sh"; do
  _name="${_entry%|*}"
  _script="${_entry#*|}"
  if [ -f "$SCRIPT_DIR/$_script" ]; then
    if _skip_check "$_name"; then
      CRAWLER_SKIPPED+=("$_name")
    else
      nohup bash -c "bash '$SCRIPT_DIR/$_script' '$TARGET'" \
        > "$CRAWL_DIR/${_name}.log" 2>&1 &
      CRAWLER_NAMES+=("$_name")
      CRAWLER_PIDS+=($!)
    fi
  else
    log_warn "  $_name: script not found ($_script), skipped"   # P-M2
  fi
done

_N_LAUNCHED=${#CRAWLER_PIDS[@]}
_N_SKIPPED=${#CRAWLER_SKIPPED[@]}

if [ $_N_LAUNCHED -gt 0 ]; then
  log_info "  Running ($_N_LAUNCHED job(s), timeout: ${CRAWL_TIMEOUT}s)..."
  for _i in "${!CRAWLER_PIDS[@]}"; do
    _name="${CRAWLER_NAMES[$_i]}"
    _pid="${CRAWLER_PIDS[$_i]}"
    _elapsed=0
    _timed_out=false
    while kill -0 "$_pid" 2>/dev/null; do
      sleep 2
      _elapsed=$((_elapsed + 2))
      if [ $_elapsed -ge "$CRAWL_TIMEOUT" ]; then
        log_warn "  $_name exceeded ${CRAWL_TIMEOUT}s timeout — killing"
        kill "$_pid" 2>/dev/null || true
        _timed_out=true
        break
      fi
    done
    if [ "$_timed_out" = false ]; then
      wait "$_pid" 2>/dev/null && log_ok "  $_name: OK" || log_warn "  $_name: failed (exit $?)"
    fi
  done
fi
for _name in "${CRAWLER_SKIPPED[@]}"; do
  log_info "  ⏭  $_name: skipped"
done
log_info ""

# Merge crawl output (sequential, after crawlers done)
{
  find "$CRAWL_DIR/gooutput" -type f 2>/dev/null -exec cat {} +
  find "$CRAWL_DIR" -maxdepth 2 -name '*.txt' -type f 2>/dev/null -exec cat {} +
  find "$CRAWL_DIR" -maxdepth 2 -name '*.json' -type f 2>/dev/null -exec cat {} +
} | grep -hoE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$CRAWL_DIR/merged-crawl.txt" 2>/dev/null || true

if [ -s "$CRAWL_DIR/merged-crawl.txt" ]; then
  cp "$CRAWL_DIR/merged-crawl.txt" "$CRAWL_DIR/crawledurls.txt"
  N_CRAWLED=$(wc -l < "$CRAWL_DIR/crawledurls.txt" | tr -d ' ')
  log_ok "  Output:"
  log_ok "    crawl/merged-crawl.txt   — $N_CRAWLED unique URLs (merged from all crawlers)"
  log_ok "    crawl/crawledurls.txt    — $N_CRAWLED URLs (hunt input)"
else
  log_warn "  No crawl output from any source — fallback with root domain"
  echo "https://$TARGET/" > "$CRAWL_DIR/crawledurls.txt"
  log_ok "  Output:"
  log_ok "    crawl/crawledurls.txt    — 1 URL (root domain fallback)"
fi
log_info ""

# ------------------------------------------------------------------
# Sub-phase 4c: URL extraction + filtering via extracturls.sh
# ------------------------------------------------------------------
if [ -f "$SCRIPT_DIR/extracturls.sh" ]; then
  log_info "── Sub-phase 4c: URL Extraction & Filtering ──"
  log_info "  Script: extracturls.sh"
  nohup bash "$SCRIPT_DIR/extracturls.sh" -f "$CRAWL_DIR" -d "$TARGET" \
    > "$CRAWL_DIR/extracturls.log" 2>&1 &
  _extract_pid=$!
  wait "$_extract_pid" 2>/dev/null && log_ok "  extracturls.sh: OK" || log_warn "  extracturls.sh: failed (exit $?)"
  log_info ""
  export EXTRACT_URLS_RAN=true
fi

# ------------------------------------------------------------------
# Sub-phase 4d: Recon Modules (7 parallel)
# ------------------------------------------------------------------
log_info "── Sub-phase 4d: Recon Modules (7 parallel) ──"
log_info "  dns_bruteforce → scripts/tools/dns_bruteforce.sh"
log_info "  param_extract  → scripts/tools/param_extract.sh"
log_info "  cariddi_scan   → scripts/tools/cariddi_scan.sh"
log_info "  vhost_fuzz     → scripts/tools/vhost_fuzz.sh"
log_info "  zone_transfer  → scripts/tools/zone_transfer.sh"
log_info "  github_dork    → scripts/tools/github_dork.sh"
log_info "  s3_buckets     → scripts/tools/s3_buckets.sh"

MODULE_NAMES=()
MODULE_PIDS=()
MODULE_SKIPPED=()

for _module in dns_bruteforce param_extract cariddi_scan vhost_fuzz zone_transfer github_dork s3_buckets; do
  if [ ! -f "$SCRIPT_DIR/${_module}.sh" ]; then
    log_warn "  ${_module}: script not found, skipped"   # P-M2: log instead of silent skip
    continue
  fi
  if _skip_check "$_module"; then
    MODULE_SKIPPED+=("$_module")
  else
    nohup bash -c "bash '$SCRIPT_DIR/${_module}.sh' '$TARGET'" \
      > "$OUT_DIR/${_module}.log" 2>&1 &
    MODULE_NAMES+=("$_module")
    MODULE_PIDS+=($!)
  fi
done

_N_LAUNCHED=${#MODULE_PIDS[@]}
_N_SKIPPED=${#MODULE_SKIPPED[@]}
_TOTAL=$((_N_LAUNCHED + _N_SKIPPED))

if [ $_N_LAUNCHED -gt 0 ]; then
  log_info "  Running ($_N_LAUNCHED/${_TOTAL} job(s))..."
  for _i in "${!MODULE_PIDS[@]}"; do
    _name="${MODULE_NAMES[$_i]}"
    _pid="${MODULE_PIDS[$_i]}"
    wait "$_pid" 2>/dev/null && log_ok "  $_name: OK" || log_warn "  $_name: failed (exit $?)"
  done
fi
for _name in "${MODULE_SKIPPED[@]}"; do
  log_info "  ⏭  $_name: skipped"
done
log_info ""

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
log_info "========================================"
log_ok "Phase 4 (recon) complete"
log_info "  Output root: $OUT_DIR"
log_info "========================================"
