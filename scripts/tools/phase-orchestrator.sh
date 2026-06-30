#!/usr/bin/env bash
# =============================================================================
# Phase 0: ORCHESTRATOR — Scope setup, AI autopilot, interactive init
#
# Usage: ./tools/phase-orchestrator.sh <domain> [output_dir]
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/_env.sh"

TARGET="${1:?Usage: $0 <domain>}"
OUT_DIR="${2:-${RECON_BASE}/${TARGET}}"

mkdir -p "$OUT_DIR"

log_ok "Orchestrator phase initialized for $TARGET"
log_info "Output directory: $OUT_DIR"

# Create scope directory structure if not exists
mkdir -p "$OUT_DIR"/{scope,intel,recon,crawl,subdomains,secrets,directories,vhost,evidence,screenshots}

# Touch engagement metadata
echo "$TARGET" > "$OUT_DIR/scope/target.txt"
: > "$OUT_DIR/scope/scope.txt"
date -I > "$OUT_DIR/scope/started.txt"

log_ok "Engagement scaffold ready. Ready for Phase 1 (SCOPE)."
