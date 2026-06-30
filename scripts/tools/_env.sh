#!/usr/bin/env bash
# =============================================================================
# Shared Environment Resolution — source this in every tool script
# =============================================================================

# Auto-detect repo root and cd there
# If git rev-parse fails (outside git repo or no git), use fallback
# FIX #2: git rev-parse fallback — use BASH_SOURCE dir when outside git repo
SWARM_ROOT_FALLBACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SWARM_ROOT="${SWARM_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || echo "$SWARM_ROOT_FALLBACK")}"
# END FIX #2
cd "$SWARM_ROOT" 2>/dev/null || { echo "[!] Could not cd to $SWARM_ROOT" >&2; }

# ── Platform detection (WSL / Kali / Parrot / Debian / macOS) ──────────────
PLATFORM_OS="$(uname -s)"
PLATFORM_ARCH="$(uname -m)"
IS_LINUX=false; IS_MACOS=false
IS_WSL=false; IS_KALI=false; IS_PARROT=false; IS_DEBIAN=false
DISTRO_ID=""; DISTRO_VERSION=""

if [ "$PLATFORM_OS" = "Linux" ]; then
    IS_LINUX=true
    if [ -f /proc/sys/fs/binfmt_misc/WSLInterop ] || [ -n "${WSL_DISTRO_NAME:-}" ]; then
        IS_WSL=true
    fi
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID:-}"
        DISTRO_VERSION="${VERSION_ID:-}"
        [ "$ID" = "kali"   ] && IS_KALI=true
        [ "$ID" = "parrot" ] && IS_PARROT=true
        case "$ID" in debian|ubuntu|kali|parrot|linuxmint) IS_DEBIAN=true ;; esac
    fi
elif [ "$PLATFORM_OS" = "Darwin" ]; then
    IS_MACOS=true
fi

# Engagement ID (optional — no longer used in path construction)
ENGAGEMENT_ID="${ENGAGEMENT_ID:-}"

# Common output base — no default-engagement layer
RECON_BASE="${RECON_BASE:-$SWARM_ROOT/engagements/recon}"

# Tool paths — include Go bin dir (resolved from GOPATH)
GO_BIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
export PATH="$GO_BIN:$HOME/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

# Python tool venvs — install.sh creates these at $HOME/.local/bin/<tool>/venv/
TOOLS_DIR="${TOOLS_DIR:-$HOME/.local/bin}"

# Template directory for engagement scaffolding
TEMPLATE_DIR="${TEMPLATE_DIR:-$SWARM_ROOT/docs/templates}"

# Colors
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_step() { echo -e "\n${CYAN}════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}════════════════════════════════════════════${NC}"; }

# ── Tool existence check ──────────────────────────────────────────────
_have() { command -v "$1" >/dev/null 2>&1; }

# ── Scope guard (Phase 6) — block active phases on out-of-scope targets ──
# Call `_scope_guard "$TARGET"` at the top of any phase that sends requests.
# Reads $RECON_BASE/<target>/scope/scope.txt and aborts (exit 1) BEFORE any
# request if the target is out of scope. Missing/empty scope file → warn and
# allow, unless STRICT_SCOPE=1 (then fail-closed).
_scope_guard() {
    local target="$1"
    [ -z "$target" ] && return 0
    local scope_file="${RECON_BASE}/${target}/scope/scope.txt"
    local checker="$(dirname "${BASH_SOURCE[0]}")/scope_checker.py"
    if [ ! -s "$scope_file" ]; then
        if [ "${STRICT_SCOPE:-}" = "1" ]; then
            log_err "Scope not registered for $target (STRICT_SCOPE=1) — refusing to run active phase"
            exit 1
        fi
        log_warn "Scope file missing/empty for $target — proceeding (set STRICT_SCOPE=1 to enforce)"
        return 0
    fi
    local py; py="$(command -v python3 || command -v python)"
    if [ -n "$py" ] && ! "$py" "$checker" "$target" "$scope_file" >/dev/null 2>&1; then
        log_err "TARGET OUT OF SCOPE: $target not in $scope_file — aborting before any request"
        exit 1
    fi
}

# ── Check if a tool name is in the SKIP_LIST ────────────────────────
_skip_check() {
    local name="$1"
    [ -z "${SKIP_LIST:-}" ] && return 1
    local _saved_ifs="$IFS"
    IFS=','
    for _s in $SKIP_LIST; do
        IFS="$_saved_ifs"
        _s="${_s# }"; _s="${_s% }"
        [ "$_s" = "$name" ] || [ "$_s" = "all" ] && return 0
    done
    IFS="$_saved_ifs"
    return 1
}
