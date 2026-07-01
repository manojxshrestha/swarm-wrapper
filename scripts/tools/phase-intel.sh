#!/bin/bash
# =============================================================================
# Intel — Passive intelligence gathering
#
# Modules (no API keys required):
#   domain_info           — WHOIS lookup, M365/Azure tenant discovery, Scopify scope analysis
#   spoof                 — SPF/DMARC spoofability analysis via Spoofy
#   cloud_enum_scan       — Cloud storage bucket enumeration (AWS S3, Azure Blob, GCP, DO Spaces)
#
# Skipped: ip_info (requires WHOISXML_API key)
#
# Usage:
#   ./tools/phase-intel.sh <domain> [output_dir]
#   ./tools/phase-intel.sh --install            # Install missing tools
#
# Output (in output_dir/intel/):
#   domain_info_general.txt       — WHOIS + msftrecon output
#   azure_tenant_domains.txt      — Microsoft/Azure-related findings
#   scopify.txt                   — Scopify scope analysis
#   spoof.txt                     — SPF/DMARC spoofability report
#   cloud_enum.txt                — Discovered cloud storage buckets
# =============================================================================

set -euo pipefail

source "$(dirname "$0")/_env.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

export PATH="$HOME/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

# ── venv paths (check venv/ then .venv/ — uv venv defaults to .venv/) ──
_MSFTRECON_ACTIVATE="$TOOLS_DIR/msftrecon/venv/bin/activate"
[ ! -f "$_MSFTRECON_ACTIVATE" ] && _MSFTRECON_ACTIVATE="$TOOLS_DIR/msftrecon/.venv/bin/activate"
_SCOPIFY_ACTIVATE="$TOOLS_DIR/Scopify/venv/bin/activate"
[ ! -f "$_SCOPIFY_ACTIVATE" ] && _SCOPIFY_ACTIVATE="$TOOLS_DIR/Scopify/.venv/bin/activate"
_SPOOFY_ACTIVATE="$TOOLS_DIR/Spoofy/venv/bin/activate"
[ ! -f "$_SPOOFY_ACTIVATE" ] && _SPOOFY_ACTIVATE="$TOOLS_DIR/Spoofy/.venv/bin/activate"
_CLOUD_ENUM_ACTIVATE="$TOOLS_DIR/cloud_enum/venv/bin/activate"
[ ! -f "$_CLOUD_ENUM_ACTIVATE" ] && _CLOUD_ENUM_ACTIVATE="$TOOLS_DIR/cloud_enum/.venv/bin/activate"

# ── Handle --install flag ──────────────────────────────────────────────
if [ "${1:-}" = "--install" ]; then
    echo "Run: bash scripts/setup/install.sh"
    exit 0
fi

# ── Argument parsing ────────────────────────────────────────────────
TARGET="${1:?Usage: $0 <domain> [output_dir]  or  $0 --install}"
OUT_DIR="${2:-${RECON_BASE}/$TARGET}"
_scope_guard "$TARGET"   # Phase 6: abort if target is out of scope
INTEL_DIR="$OUT_DIR/intel"
mkdir -p "$INTEL_DIR"

log_info "Target: $TARGET"
log_info "Output: $INTEL_DIR"

# ── Helper: tool check ───────────────────────────────────────────────
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_warn "$1 not found — skipping"
        return 1
    fi
    return 0
}

check_repo_tool() {
    local repo="$1"
    local script_path="$TOOLS_DIR/$repo/$2"
    if [ -f "$script_path" ] || [ -f "$TOOLS_DIR/$repo/venv/bin/activate" ]; then
        return 0
    fi
    log_warn "$repo not found at $TOOLS_DIR/$repo — skipping"
    log_info "  Install: bash scripts/setup/install.sh"
    return 1
}

# ── 1. domain_info — WHOIS + M365/Azure + Scopify ────────────────────
run_domain_info() {
    log_step "domain_info — WHOIS, M365/Azure tenant, Scopify"

    check_tool whois || return 0
    local whois_target
    if command -v unfurl &>/dev/null; then
        whois_target="$(unfurl format %r <<< "$TARGET" 2>/dev/null || true)"
    fi
    whois "${whois_target:-$TARGET}" 2>/dev/null | tee -a "$INTEL_DIR/domain_info_general.txt" || true
    if [ -s "$INTEL_DIR/domain_info_general.txt" ]; then
        log_ok "WHOIS data saved"
    else
        log_warn "WHOIS lookup failed"
    fi

    : > "$INTEL_DIR/azure_tenant_domains.txt"

    if check_repo_tool "msftrecon" "msftrecon/msftrecon.py"; then
        local msftrecon_script="$TOOLS_DIR/msftrecon/msftrecon/msftrecon.py"
        if [ -f "$msftrecon_script" ]; then
            local msftrecon_out
            msftrecon_out=$(mktemp)
            if [ -f "$_MSFTRECON_ACTIVATE" ]; then
                (
                    source "$_MSFTRECON_ACTIVATE"
                    python3 "$msftrecon_script" -d "$TARGET"
                ) > "$msftrecon_out" 2>&1 || true
                if [ -s "$msftrecon_out" ]; then
                    cat "$msftrecon_out" >> "$INTEL_DIR/domain_info_general.txt"
                    grep -iE 'microsoft|azure|tenant' "$msftrecon_out" > "$INTEL_DIR/azure_tenant_domains.txt" 2>/dev/null || true
                    log_ok "M365/Azure tenant info saved"
                fi
            else
                log_warn "msftrecon venv not found at $_MSFTRECON_ACTIVATE"
            fi
            rm -f "$msftrecon_out"
        else
            log_warn "msftrecon script not found"
        fi
    fi

    if check_repo_tool "Scopify" "scopify.py"; then
        if ! command -v unfurl &>/dev/null; then
            log_warn "unfurl not found — skipping Scopify"
            return 0
        fi
        local company_name
        company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')
        if [ -f "$_SCOPIFY_ACTIVATE" ]; then
            (
                source "$_SCOPIFY_ACTIVATE"
                python3 "$TOOLS_DIR/Scopify/scopify.py" -c "$company_name"
            ) > "$INTEL_DIR/scopify.txt" 2>&1 && log_ok "Scopify scope analysis saved" || log_warn "Scopify failed"
        else
            log_warn "Scopify venv not found at $_SCOPIFY_ACTIVATE"
        fi
    fi
}

# ── 2. spoof — SPF/DMARC spoofability ────────────────────────────────
run_spoof() {
    log_step "spoof — SPF/DMARC spoofability check"

    check_repo_tool "Spoofy" "spoofy.py" || return 0

    local spoofy_script="$TOOLS_DIR/Spoofy/spoofy.py"

    if [ -f "$spoofy_script" ] && [ -f "$_SPOOFY_ACTIVATE" ]; then
        (
            source "$_SPOOFY_ACTIVATE"
            cd "$TOOLS_DIR/Spoofy"
            python3 "$spoofy_script" -d "$TARGET"
        ) > "$INTEL_DIR/spoof.txt" 2>&1 || true
        if [ -s "$INTEL_DIR/spoof.txt" ]; then
            log_ok "Spoof report saved"
        else
            log_warn "Spoofy returned no results"
        fi
    elif [ ! -f "$_SPOOFY_ACTIVATE" ]; then
        log_warn "Spoofy venv not found at $_SPOOFY_ACTIVATE"
    fi
}

# ── 3. cloud_enum_scan — Cloud storage bucket enumeration ────────────
run_cloud_enum() {
    log_step "cloud_enum_scan — Cloud storage bucket enumeration"

    check_repo_tool "cloud_enum" "cloud_enum.py" || return 0

    local cloud_enum_script="$TOOLS_DIR/cloud_enum/cloud_enum.py"

    if [ -f "$cloud_enum_script" ] && [ -f "$_CLOUD_ENUM_ACTIVATE" ]; then
        local company_name
        company_name=$(unfurl format %r <<< "$TARGET" 2>/dev/null || echo "$TARGET" | awk -F. '{print $(NF-1)}')

        local fuzz_file="$TOOLS_DIR/cloud_enum/enum_tools/fuzz.txt"
        local mutations="$fuzz_file"
        local brute="$fuzz_file"
        if [ ! -f "$fuzz_file" ]; then
            mutations="$cloud_enum_script"
            brute="$cloud_enum_script"
        fi

        (
            source "$_CLOUD_ENUM_ACTIVATE"
            PYTHONWARNINGS=ignore python3 "$cloud_enum_script" \
                -k "$company_name" \
                -k "$TARGET" \
                -k "${TARGET%%.*}" \
                -t 50 \
                -m "$mutations" \
                -b "$brute" \
                -qs 2>/dev/null
        ) | anew -q "$INTEL_DIR/cloud_enum.txt" || true

        if [ -s "$INTEL_DIR/cloud_enum.txt" ]; then
            log_ok "$(wc -l < "$INTEL_DIR/cloud_enum.txt") cloud resources found"
        else
            log_info "No cloud resources found"
        fi
    elif [ ! -f "$_CLOUD_ENUM_ACTIVATE" ]; then
        log_warn "cloud_enum venv not found at $_CLOUD_ENUM_ACTIVATE"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
log_info "Starting intel for $TARGET"
log_info "Modules: domain_info, spoof, cloud_enum_scan"
log_warn "Skipped: ip_info (requires WHOISXML_API key)"

run_domain_info
run_spoof
run_cloud_enum

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
log_ok "Results in $INTEL_DIR"
for f in "$INTEL_DIR"/*; do
    [ -f "$f" ] && echo "  $(basename "$f"): $(wc -l < "$f") lines"
done
echo -e "${GREEN}════════════════════════════════════════════${NC}"
