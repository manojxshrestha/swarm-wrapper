#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# setup.sh — Swarm config refresh
#
# Lightweight — refreshes agent symlinks, commands, rules, and shell aliases.
# Run install.sh first for full tool installation + MCP config.
#
# What this script does:
#   - Checks prerequisites (go, python3, git, curl, uv, opencode)
#   - Verifies Python venv exists
#   - Symlinks OpenCode agents, commands, rules
#   - Adds shell aliases
#   - Verifies installation state
#
# What it does NOT do (use install.sh instead):
#   - Install Go/Python/cargo security tools
#   - Clone GF patterns
#   - Create or overwrite opencode.json (MCP config)
#   - Install Playwright Chromium
#   - Install system packages (apt/brew)
#
# Idempotent — safe to re-run.
# Usage:  bash scripts/setup/setup.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

DST="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd | tr -d '\n')"
OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"
BACKUP_DIR="$HOME/.swarm/backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$HOME/.swarm/install.log"

# ── Color output ──────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
header(){ echo -e "\n${BOLD}${B}════════════════════════════════════════${N}"; echo -e "${BOLD}$*${N}"; echo -e "${B}════════════════════════════════════════${N}"; }

mkdir -p "$HOME/.swarm" "$HOME/.config/opencode"

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

# Install OpenCode if missing
OPENCODE_BIN="$HOME/.opencode/bin/opencode"
if command -v opencode &>/dev/null; then
  ok "OpenCode — already installed ($(opencode --version 2>/dev/null || echo 'unknown'))"
elif [ -x "$OPENCODE_BIN" ]; then
  info "OpenCode found at $OPENCODE_BIN — adding to PATH"
  export PATH="$HOME/.opencode/bin:$PATH"
  ok "OpenCode — already installed ($(opencode --version 2>/dev/null || echo 'unknown'))"
else
  info "OpenCode not found — installing..."
  curl -fsSL https://opencode.ai/install | bash >/dev/null 2>&1
  export PATH="$HOME/.opencode/bin:$PATH"
  ok "OpenCode installed"
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
# PHASE 3: OpenCode config — verify, don't overwrite
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 3: OpenCode configuration"

if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config exists — not modifying"
else
  info "OpenCode config — generating..."
  export REPO_DIR="$DST"
  python3 << 'PYEOF'
import json, os
repo = os.environ['REPO_DIR']
home = os.path.expanduser("~")
config_path = os.path.join(home, ".config", "opencode", "opencode.json")

# Detect WSL
is_wsl = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or bool(os.environ.get("WSL_DISTRO_NAME"))

mcp = {}

# Burp Suite MCP
if is_wsl:
    bridge_script = os.path.join(repo, "scripts", "burp-mcp-bridge.py")
    mcp["burp"] = {
        "type": "local",
        "command": ["bash", "-c", f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run ../scripts/burp-mcp-bridge.py"]
    }
else:
    mcp["burp"] = {
        "type": "remote",
        "url": "http://127.0.0.1:9876/",
        "enabled": True
    }

# WSTG server
mcp["wstg"] = {
    "type": "local",
    "prompt": "You are a Swarm WSTG penetration testing MCP server.",
    "command": [
        "bash",
        "-c",
        f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py"
    ]
}

# Write config
config = {
    "$schema": "https://opencode.ai/config.json",
    "mcp": mcp
}

os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print("[+] OpenCode config generated")
PYEOF
  ok "OpenCode config — generated"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: OpenCode agents, rules, commands, skills
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 4: OpenCode agents, rules"

OC_AGENTS_DIR="$HOME/.config/opencode/agents"
mkdir -p "$OC_AGENTS_DIR" "$HOME/.config/opencode/rules"

# Agents (flat .md files)
if [ -d "$DST/.opencode/agents" ]; then
  for agent_file in "$DST/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    target="$OC_AGENTS_DIR/$agent_name"
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$agent_file" ]; then
      ok "Agent $agent_name — already linked"
    else
      ln -sf "$agent_file" "$target"
      ok "Agent $agent_name — linked"
    fi
  done
fi

# Legacy home-level agent links
OC_HOME_AGENTS="$HOME/.opencode/agents"
mkdir -p "$OC_HOME_AGENTS"
if [ -d "$DST/.opencode/agents" ]; then
  for agent_file in "$DST/.opencode/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    target="$OC_HOME_AGENTS/$agent_name"
    ln -sf "$agent_file" "$target"
  done
fi

# Rules
if [ -d "$DST/.opencode/rules" ]; then
  for rule_file in "$DST/.opencode/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    target="$HOME/.config/opencode/rules/$rule_name"
    ln -sf "$rule_file" "$target"
    ok "Rule $rule_name — linked"
  done
fi

# Commands (.opencode/commands-bughunt/*.md) → all 3 locations
if [ -d "$DST/.opencode/commands-bughunt" ]; then
  OC_CMD_DIR="$HOME/.config/opencode/commands"
  PROJECT_CMD_DIR="$DST/.opencode/commands"
  HOME_CMD_DIR="$HOME/.opencode/commands"
  mkdir -p "$OC_CMD_DIR" "$PROJECT_CMD_DIR" "$HOME_CMD_DIR"
  for cmd_file in "$DST/.opencode/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    cp "$cmd_file" "$OC_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$PROJECT_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$HOME_CMD_DIR/$cmd_name"
    ok "Command $cmd_name — installed"
  done
fi

# Skills symlink (for manual browse)
SKILLS_LINK="$HOME/.swarm/skills"
mkdir -p "$HOME/.swarm"
[ -L "$SKILLS_LINK" ] && rm "$SKILLS_LINK"
ln -s "$DST/skills" "$SKILLS_LINK"

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
export PATH="\$HOME/.opencode/bin:\$HOME/go/bin:\$HOME/.local/bin:\$PATH"
alias swarm='cd \$SWARM_HOME'
alias swarm-server='cd \$SWARM_HOME/server && UV_PROJECT_ENVIRONMENT=venv uv run server.py'
alias swarm-browser-use='\$SWARM_HOME/server/venv/bin/python \$SWARM_HOME/server/browser_use_backend.py'
alias swarm-update='cd \$SWARM_HOME && git pull'
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

# OpenCode config
if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config — $OPENCODE_CONFIG"
else
  warn "OpenCode config — not found"
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
echo "  OpenCode:"
echo "    opencode            — Launch OpenCode with Swarm"
echo ""
echo "  To install tools: bash scripts/install.sh"
echo ""
echo "  Log: $LOG_FILE"
echo "  Backups: $BACKUP_DIR"
echo ""
