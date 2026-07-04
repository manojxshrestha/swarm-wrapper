#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# setup.sh — Swarm config refresh
#
# Lightweight — refreshes agent symlinks, commands, rules, and shell aliases.
# Run install.sh first for full tool installation + MCP config.
#
# What this script does:
#   - Checks prerequisites (go, python3, git, curl, uv)
#   - Verifies Python venv exists
#   - Symlinks Swarm agents, commands, rules
#   - Adds shell aliases
#   - Verifies installation state
#
# What it does NOT do (use install.sh instead):
#   - Install Go/Python/cargo security tools
#   - Clone GF patterns
#   - Create or overwrite .mcp.json (MCP config)
#   - Install Playwright Chromium
#   - Install system packages (apt/brew)
#
# Idempotent — safe to re-run.
# Usage:  bash scripts/setup/setup.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

DST="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd | tr -d '\n')"
SWARM_CONFIG="$DST/.mcp.json"
BACKUP_DIR="$HOME/.swarm/backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$HOME/.swarm/install.log"

# ── Color output ──────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
header(){ echo -e "\n${BOLD}${B}════════════════════════════════════════${N}"; echo -e "${BOLD}$*${N}"; echo -e "${B}════════════════════════════════════════${N}"; }

mkdir -p "$HOME/.swarm" "$DST"

exec > >(tee -a "$LOG_FILE") 2>&1

# ── Platform detection ────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
print_banner() {
    echo -e "${BOLD}${C}                                     
   ________  _  _______ _______  _____   
  /  ___/\ \/ \/ /\__  \\_  __ \/     \  
  \___ \  \     /  / __ \|  | \/  Y Y  \ 
 /____  >  \/\_/  (____  /__|  |__|_|  / 
      \/               \/            \/  
         by ~/.manojxshrestha${N}"
}
print_banner
echo "  Target:    $DST"
echo "  Platform:  $OS / $ARCH"
echo "  Log:       $LOG_FILE"
echo ""

# Check prerequisites
for cmd in go python3 git curl; do
  if ! command -v "$cmd" &>/dev/null; then
    err "$cmd not found — install it first"
    case "$cmd" in
      go) echo "  https://go.dev/dl/" ;;
      python3) echo "  https://www.python.org/downloads/" ;;
      *) echo "  apt install $cmd || brew install $cmd" ;;
    esac
    exit 1
  fi
done

# Install uv if missing
if ! command -v uv &>/dev/null; then
  info "uv not found — installing..."
  curl -sSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi

# Check swarm binary
SWARM_BIN=""
for p in "$DST/swarm" "$HOME/.local/bin/swarm" "$HOME/.swarm/bin/swarm"; do
  [ -f "$p" ] && { SWARM_BIN="$p"; break; }
done
if [ -n "$SWARM_BIN" ]; then
  ok "Swarm binary found — $SWARM_BIN"
  export PATH="$(dirname "$SWARM_BIN"):$PATH"
else
  info "Swarm binary not found — build it: cd $DST && bun run build"
  export PATH="$DST:$PATH"
fi



# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Swarm MCP server — verify venv exists
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 1: Swarm MCP server"

if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Python venv ready"
else
  info "Python venv — creating..."
  (cd "$DST/server" && uv venv venv && uv sync) && ok "Python venv — created" || warn "Python venv — creation failed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Playwright (browser automation for browser_driver.py)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 2: Playwright (browser automation for browser-use)"

_PW_VENV="$DST/.venv"
if [ -f "$_PW_VENV/bin/python" ]; then
  ok "Project venv — already exists"
else
  info "Project venv — creating..."
  if uv venv "$_PW_VENV" --python 3.13 2>/dev/null; then ok "Project venv — created"; else warn "Project venv — creation failed"; fi
fi

if "$_PW_VENV/bin/python" -c "import playwright" 2>/dev/null; then
  ok "Playwright — already installed"
else
  info "Playwright — installing in project venv..."
  if uv pip install --python "$_PW_VENV/bin/python" playwright 2>/dev/null; then ok "Playwright installed (venv)"; else warn "Playwright install failed (pip install playwright)"; fi
fi

# Note: system Python is restricted on some OSes (e.g. Kali blocks pip).
# Playwright is installed in the project venv below and used by the MCP server.
# The auto_auth.py script auto-detects the venv Python, so no system install needed.

if "$_PW_VENV/bin/python" -c "import playwright" 2>/dev/null; then
  info "Playwright — installing Chromium browser..."
  "$_PW_VENV/bin/python" -m playwright install chromium 2>&1 | tail -3
  ok "Playwright — Chromium ready"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Swarm .mcp.json — verify, don't overwrite
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 3: Swarm MCP configuration"

if [ -f "$SWARM_CONFIG" ]; then
  ok "Swarm MCP config exists — $SWARM_CONFIG"
else
  info "Swarm MCP config — generating .mcp.json..."
  export REPO_DIR="$DST"
  python3 << 'PYEOF'
import json, os
repo = os.environ['REPO_DIR']
mcp_path = os.path.join(repo, ".mcp.json")

# Detect WSL
is_wsl = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or bool(os.environ.get("WSL_DISTRO_NAME"))

mcp_servers = {}

# Burp Suite MCP via bridge script
bridge_script = os.path.join(repo, "scripts", "burp-mcp-bridge.py")
if os.path.exists(bridge_script):
    mcp_servers["burp"] = {
        "type": "stdio",
        "command": "python3",
        "args": [bridge_script]
    }

# WSTG server
mcp_servers["wstg"] = {
    "type": "stdio",
    "command": "bash",
    "args": [
        "-c",
        f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py"
    ]
}

# Write .mcp.json
config = {
    "mcpServers": mcp_servers
}

with open(mcp_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"[+] .mcp.json generated at {mcp_path}")
PYEOF
  ok "Swarm MCP config — generated ($SWARM_CONFIG)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Swarm agents, rules, commands
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 4: Swarm agents, rules"

# Agents → .swarm/agents (symlink from project)
if [ -d "$DST/.swarm/agents" ]; then
  for agent_file in "$DST/.swarm/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    ok "Agent $(basename "$agent_file") — available"
  done
fi

# Rules → .swarm/rules
mkdir -p "$DST/.swarm/rules"
if [ -d "$DST/.swarm/rules" ]; then
  for rule_file in "$DST/.swarm/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    ok "Rule $(basename "$rule_file") — available"
  done
fi

# Commands (.swarm/commands-bughunt/*.md) → .swarm/commands
if [ -d "$DST/.swarm/commands-bughunt" ]; then
  PROJECT_CMD_DIR="$DST/.swarm/commands"
  mkdir -p "$PROJECT_CMD_DIR"
  for cmd_file in "$DST/.swarm/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    cp "$cmd_file" "$PROJECT_CMD_DIR/$cmd_name"
    ok "Command $cmd_name — installed"
  done
fi

# Skills symlink
SKILLS_LINK="$HOME/.swarm/skills"
[ -L "$SKILLS_LINK" ] && rm "$SKILLS_LINK"
ln -s "$DST/skills" "$SKILLS_LINK" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Shell aliases
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 5: Shell aliases"

detect_shell_rc() {
    local shell_name
    shell_name="$(basename "${SHELL:-$(command -v sh)}" 2>/dev/null)"
    case "$shell_name" in
        zsh)
            if [ -n "${ZDOTDIR:-}" ] && [ -f "$ZDOTDIR/.zshrc" ]; then
                echo "$ZDOTDIR/.zshrc"
            elif [ -f "$HOME/.zshrc" ]; then
                echo "$HOME/.zshrc"
            fi
            ;;
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                echo "$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                echo "$HOME/.bash_profile"
            fi
            ;;
        *)
            [ -f "$HOME/.bashrc" ] && echo "$HOME/.bashrc" && return
            [ -f "$HOME/.bash_profile" ] && echo "$HOME/.bash_profile" && return
            [ -f "$HOME/.zshrc" ] && echo "$HOME/.zshrc" && return
            ;;
    esac
}
SHELL_RC="$(detect_shell_rc)"

SWARM_CONFIG_MARKER="# --- Swarm config ---"
ALIASES="
$SWARM_CONFIG_MARKER
export SWARM_HOME=\"$DST\"
export PATH=\"\$HOME/.swarm/bin:\$HOME/go/bin:\$HOME/.local/bin:\$PATH\"
alias swarm-recon='bash \$SWARM_HOME/scripts/tools/auto_recon.sh'
alias connect-burp='bash \$SWARM_HOME/scripts/connect-burp.sh'
# full-hunt removed — legacy auto-scan script. Use AI-driven pipeline instead.
alias swarm-browser='\$SWARM_HOME/.venv/bin/python \$SWARM_HOME/scripts/browser_driver.py'
"

if [ -n "$SHELL_RC" ]; then
  if grep -q "$SWARM_CONFIG_MARKER" "$SHELL_RC" 2>/dev/null; then
    sed -i "/$SWARM_CONFIG_MARKER/,/^# --- End Swarm/d" "$SHELL_RC"
  fi
  echo "$ALIASES" >> "$SHELL_RC"
  echo "# --- End Swarm ---" >> "$SHELL_RC"
  ok "Aliases added to $SHELL_RC"
else
  warn "No shell RC found — add these manually:"
  echo "$ALIASES"
fi

eval "$ALIASES" 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Verification
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 6: Verification"

# Swarm server venv
if [ -f "$DST/server/venv/bin/python" ]; then
  ok "Swarm server venv — ready"
else
  err "Swarm server venv — missing (run install.sh first)"
fi

# Swarm MCP config
if [ -f "$SWARM_CONFIG" ]; then
  ok "Swarm MCP config — $SWARM_CONFIG"
else
  warn "Swarm MCP config — not found (run connect-burp.sh)"
fi

# Playwright
if "$DST/.venv/bin/python" -c "import playwright; print('ready')" 2>/dev/null; then
  ok "Playwright — ready"
else
  warn "Playwright — not installed (run setup again)"
fi

# GF patterns (installed by install.sh, verify here)
GF_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
if [ "$GF_COUNT" -gt 0 ]; then
  ok "GF patterns — $GF_COUNT patterns in ~/.gf/"
else
  warn "GF patterns — none found in ~/.gf/ (run install.sh)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${G}
  ╔══════════════════════════════════════════════════════╗
  ║           Swarm Setup Complete!                      ║
  ╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Aliases refreshed:"
echo "    swarm              — cd to project root"
echo "    swarm-server       — Start the WSTG MCP server"
echo "    swarm-recon        — Run auto_recon.sh"
echo "    connect-burp        — Connect/reconnect Burp MCP bridge"
# echo "    full-hunt <target>  — (removed — legacy, use AI-driven pipeline)"
    echo "    swarm-browser      — Run browser_driver.py (legacy headed Chromium CLI)"
    echo "    swarm-browser-use  — Run browser_use_backend.py (browser-use debug CLI)"
echo ""
echo "  Swarm:"
echo "    swarm               — Launch Swarm CLI"
echo ""
echo "  To install tools: bash scripts/install.sh"
echo ""
echo "  Log: $LOG_FILE"
echo "  Backups: $BACKUP_DIR"
echo ""
