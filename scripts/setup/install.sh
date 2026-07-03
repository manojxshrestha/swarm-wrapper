#!/usr/bin/env bash
# =====================================================================
# install.sh — Swarm: Offensive Security MCP — Complete Installer
#
# A single script to install everything:
#   - System dependencies (libpcap, build-essential, etc.)
#   - OpenCode agents, rules, skills
#   - Go CLI security tools (subfinder, httpx, ffuf, gf, naabu, etc.)
#   - GF patterns, SecLists wordlists
#   - Playwright Chromium browser
#   - Python virtual environment for the Swarm MCP server
#   - Shell aliases
#
# Idempotent — safe to re-run. Existing config backed up before overwrite.
#
# Usage:
#   bash scripts/install.sh              # Full install
#   bash scripts/install.sh --quick      # Agents + config only, skip tools
# =====================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKUP_DIR="$HOME/.swarm/backups/$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$HOME/.swarm/install.log"

# ── Parse flags ──────────────────────────────────────────────────────────────
QUICK=false
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
  esac
done

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; N='\033[0m'; BOLD='\033[1m'
ok(){   echo -e "${G}[✓]${N} $*"; }
warn(){ echo -e "${Y}[!]${N} $*"; }
err(){  echo -e "${R}[✗]${N} $*"; }
info(){ echo -e "${C}[*]${N} $*"; }
header(){ echo -e "\n${BOLD}${B}════════════════════════════════════════${N}"; echo -e "${BOLD}$*${N}"; echo -e "${B}════════════════════════════════════════${N}"; }

mkdir -p "$HOME/.swarm" "$HOME/.config/opencode"
exec > >(tee -a "$LOG_FILE") 2>&1

# ── Platform detection ──────────────────────────────────────────────────────
OS="$(uname -s)"
HAS_SUDO=false
HAS_BREW=false
HAS_CARGO=false
HAS_PASSWORDLESS_SUDO=false
command -v sudo &>/dev/null && HAS_SUDO=true
sudo -n true 2>/dev/null && HAS_PASSWORDLESS_SUDO=true
command -v brew &>/dev/null && HAS_BREW=true
command -v cargo &>/dev/null && HAS_CARGO=true

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
echo "  Repo:      $REPO_DIR"
echo "  Platform:  $OS"
echo "  Log:       $LOG_FILE"
echo "  Mode:      $($QUICK && echo 'quick (agents + config only)' || echo 'full')"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0: Prerequisites
# ══════════════════════════════════════════════════════════════════════════════
header "PHASE 0: Prerequisites"

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
  curl -sSfL https://astral.sh/uv/install.sh | sh >>"$LOG_FILE" 2>&1
  if [ $? -eq 0 ]; then
    export PATH="$HOME/.local/bin:$PATH"
    if command -v uv &>/dev/null; then
      ok "uv installed"
    else
      warn "uv installed but not in PATH — check $HOME/.local/bin"
    fi
  else
    warn "uv install failed — see $LOG_FILE for details"
  fi
fi

# Install OpenCode if missing
OPENCODE_BIN="$HOME/.swarm/bin/opencode"
if command -v opencode &>/dev/null; then
  ok "OpenCode — already installed ($(opencode --version 2>/dev/null || echo 'unknown'))"
elif [ -x "$OPENCODE_BIN" ]; then
  info "OpenCode found at $OPENCODE_BIN — adding to PATH"
  export PATH="$HOME/.swarm/bin:$PATH"
  ok "OpenCode — already installed ($(opencode --version 2>/dev/null || echo 'unknown'))"
else
  info "OpenCode not found — installing..."
  curl -fsSL https://opencode.ai/install | bash >/dev/null 2>&1
  case "$SHELL" in
    *zsh*)  source ~/.zshrc 2>/dev/null || true ;;
    *bash*) source ~/.bashrc 2>/dev/null || true ;;
  esac
  export PATH="$HOME/.swarm/bin:$PATH"
  ok "OpenCode installed"
fi

export PATH="$HOME/go/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# Common base directory for cloned scanner repos (used in Phase 3+)
TOOLS_DIR="$HOME/.local/bin"
mkdir -p "$TOOLS_DIR"

# ── Quick mode? ─────────────────────────────────────────────────────────────
if $QUICK; then
  info "Quick mode — skipping tool installation"
  warn "Re-run without --quick for full tool setup"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: System dependencies
# ══════════════════════════════════════════════════════════════════════════════
if ! $QUICK; then
  header "PHASE 1: System dependencies"

  if [ "$OS" = "Linux" ]; then
    if $HAS_PASSWORDLESS_SUDO; then
      info "Installing Linux system packages..."
      sudo apt-get update -qq
      sudo apt-get install -y -qq \
        jq libpcap-dev libssl-dev build-essential pkg-config unzip \
        ca-certificates curl gnupg 2>/dev/null || true
      ok "System packages installed"
    else
      warn "No passwordless sudo — install manually: jq libpcap-dev build-essential unzip"
    fi
  elif [ "$OS" = "Darwin" ] && $HAS_BREW; then
    info "Installing macOS packages..."
    brew install jq libpcap 2>/dev/null || true
    ok "System packages installed"
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 2: Go CLI security tools
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 2: Go security tools"

  GO_TOOLS=(
    # ProjectDiscovery stack
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    # Tomnomnom tools
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    # Port scanning
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    # Fuzzing / discovery
    "github.com/ffuf/ffuf/v2@latest"
    # Crawlers / URL collectors
    "github.com/lc/gau@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/edoardottt/cariddi/cmd/cariddi@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"

  )

  for tool in "${GO_TOOLS[@]}"; do
    raw=$(echo "$tool" | sed 's/@.*//' | sed 's/\/\.\.\.$//')
    name="$(basename "$raw" | sed 's/v[0-9]*$//' | sed 's/v[0-9]*\/cmd\///')"
    # Handle cases like "github.com/OJ/gobuster/v3" -> gobuster
    name="$(echo "$name" | sed 's/^v[0-9]*$//')"
    [ -z "$name" ] && name="$(basename "$(dirname "$raw")")"
    if command -v "$name" &>/dev/null; then
      ok "$name — already installed"
    else
      info "Installing $name..."
      if go install "$tool" 2>/dev/null; then ok "$name installed"; else warn "$name install failed"; fi
    fi
  done

  # massdns (C DNS resolver — required by puredns)
  # Tries apt first, then builds from source. Both require sudo.
  if command -v massdns &>/dev/null; then
    ok "massdns — already installed"
  else
    info "Installing massdns... (building from source)"
    MASS_TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/blechschmidt/massdns.git "$MASS_TMP" 2>/dev/null
    (cd "$MASS_TMP" && make 2>/dev/null)
    sudo make install -C "$MASS_TMP" 2>/dev/null || {
      cp "$MASS_TMP/bin/massdns" "$HOME/go/bin/massdns" 2>/dev/null || \
      cp "$MASS_TMP/massdns" "$HOME/go/bin/massdns" 2>/dev/null || true
    }
    rm -rf "$MASS_TMP"
    if command -v massdns &>/dev/null; then ok "massdns installed"; else warn "massdns install failed — run manually: sudo apt install massdns or build from https://github.com/blechschmidt/massdns"; fi
  fi

  # Ensure httpx is projectdiscovery version (not httpx-toolkit or other)
  if command -v httpx &>/dev/null && ! httpx -version 2>&1 | grep -qi projectdiscovery; then
    info "Replacing non-projectdiscovery httpx..."
    OLD_HTTPX=$(which httpx 2>/dev/null || true)
    if [ -n "$OLD_HTTPX" ] && [ "$OLD_HTTPX" != "$HOME/go/bin/httpx" ] && [ "$OLD_HTTPX" != "$HOME/.local/bin/httpx" ]; then
      info "Removing old httpx at $OLD_HTTPX..."
      rm -f "$OLD_HTTPX" 2>/dev/null || true
    fi
    if go install -v "github.com/projectdiscovery/httpx/cmd/httpx@latest" 2>/dev/null; then
      ok "httpx reinstalled (projectdiscovery)"
    else
      warn "httpx reinstall failed"
    fi
    if ! command -v httpx &>/dev/null && [ -f "$HOME/go/bin/httpx" ]; then
      mkdir -p "$HOME/.local/bin"
      ln -sf "$HOME/go/bin/httpx" "$HOME/.local/bin/httpx"
      ok "linked httpx to \$HOME/.local/bin/"
    fi
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 3: Python tools (pip)
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 3: Python tools (pip)"

  # trufflehog (uses official install script; go install fails due to replace directives)
  if command -v trufflehog &>/dev/null; then
    ok "trufflehog — already installed ($(trufflehog --version 2>/dev/null))"
  else
    info "Installing trufflehog (official install script)..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$TOOLS_DIR" 2>/dev/null; then
      ok "trufflehog installed"
    else
      warn "trufflehog install failed — manual: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/.local/bin"
    fi
  fi

  # interactsh-client
  if command -v interactsh-client &>/dev/null; then
    ok "interactsh-client — already installed"
  else
    info "Installing interactsh-client..."
    if go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null; then
      ok "interactsh-client installed"
    else
      warn "interactsh-client install failed"
    fi
  fi

  # wafw00f
  WAFW00F_DIR="$TOOLS_DIR/wafw00f"
  if [ -d "$WAFW00F_DIR/.git" ]; then
    ok "wafw00f — already installed"
  else
    info "Installing wafw00f..."
    if git clone --depth 1 https://github.com/EnableSecurity/wafw00f.git "$WAFW00F_DIR" 2>/dev/null; then
      if [ -f "$WAFW00F_DIR/requirements.txt" ]; then
        uv venv "$WAFW00F_DIR/venv" &>/dev/null
        uv pip install --python "$WAFW00F_DIR/venv/bin/python" -r "$WAFW00F_DIR/requirements.txt" 2>/dev/null
      fi
      ok "wafw00f installed"
    else
      warn "wafw00f install failed"
    fi
  fi

  # ── Security scanner tools (git clone + venv, same pattern as msftrecon) ──
  install_scanner_repo() {
    local name="$1"
    local repo="$2"
    local main_script="$3"
    local target_dir="$TOOLS_DIR/$name"

    if [ -d "$target_dir/.git" ]; then
      ok "$name — already installed"
      return 0
    fi

    info "Installing $name..."
    git clone --depth 1 "https://github.com/$repo.git" "$target_dir" 2>/dev/null || {
      warn "$name — git clone failed"
      return 1
    }

    if [ -f "$target_dir/requirements.txt" ]; then
      uv venv "$target_dir/venv" &>/dev/null || true
      uv pip install --python "$target_dir/venv/bin/python" -r "$target_dir/requirements.txt" 2>/dev/null || true
    fi

    if [ -n "$main_script" ] && [ -f "$target_dir/$main_script" ]; then
      # Remove the cloned directory so we can replace it with a symlink to the main script
      rm -rf "$target_dir"
      ln -sf "$target_dir/$main_script" "$TOOLS_DIR/$name" 2>/dev/null || true
    fi

    ok "$name installed"
  }

  # sqlmap — self-contained, no dependencies
  install_scanner_repo "sqlmap" "sqlmapproject/sqlmap" "sqlmap.py"

  # commix — self-contained, no dependencies
  install_scanner_repo "commix" "commixproject/commix" "commix.py"

  # sstimap — self-contained, no dependencies
  install_scanner_repo "sstimap" "vladko312/SSTImap" "sstimap.py"

  # corscanner — has requirements.txt
  install_scanner_repo "corscanner" "chenjj/corscanner" "cors_scan.py"

  # smuggler — has requirements.txt
  install_scanner_repo "smuggler" "defparam/smuggler" "smuggler.py"

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 4: Cargo (Rust) tools
  # ═══════════════════════════════════════════════════════════════════════════
  header "PHASE 4: findomain (Rust)"
  if command -v findomain &>/dev/null; then
    ok "findomain — already installed"
  elif command -v cargo &>/dev/null; then
    info "Installing findomain (cargo)..."
    if cargo install findomain 2>/dev/null; then ok "findomain installed"; else warn "findomain install failed (try: cargo install findomain)"; fi
  elif command -v python3 &>/dev/null; then
    info "Installing findomain (binary download)..."
    fname=""
    if [ "$OS" = "Linux" ]; then
      fname="findomain-linux.zip"
    elif [ "$OS" = "Darwin" ]; then
      fname="findomain-macos.zip"
    else
      warn "Unsupported OS for findomain binary — install manually"
      fname=""
    fi
    if [ -n "$fname" ]; then
      if curl -sL "https://github.com/findomain/findomain/releases/latest/download/$fname" -o /tmp/findomain.zip && \
         python3 -c "
import zipfile, os
with zipfile.ZipFile('/tmp/findomain.zip', 'r') as z:
    z.extractall('/tmp/findomain')
" && \
         chmod +x /tmp/findomain/findomain && \
         cp /tmp/findomain/findomain "$HOME/.local/bin/findomain" && \
         rm -rf /tmp/findomain /tmp/findomain.zip; then
        ok "findomain installed"
      else
        warn "findomain download failed — manual: cargo install findomain"
      fi
    fi
  else
    warn "cargo or python3 needed to install findomain"
  fi

  # GF patterns
  header "Phase 5b: GF patterns"
  GF_PATTERNS_SRC="$REPO_DIR/wordlists/gf-patterns"
  mkdir -p "$HOME/.gf"
  if cp "$GF_PATTERNS_SRC"/*.json "$HOME/.gf/" 2>/dev/null; then
    ok "GF patterns installed → ~/.gf/ ($(ls "$GF_PATTERNS_SRC"/*.json 2>/dev/null | wc -l) patterns)"
  else
    warn "No GF patterns found in $GF_PATTERNS_SRC"
  fi

fi # end if ! $QUICK

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5e: Python reconnaissance tools (Spoofy, cloud_enum, msftrecon, Scopify, waymore)
# ═══════════════════════════════════════════════════════════════════════════════
if ! $QUICK; then
  header "Phase 5e: Python recon tools"

  TOOLS_DIR="$HOME/.local/bin"
  mkdir -p "$TOOLS_DIR"

  install_intel_repo() {
    local repo="$1"
    local github_path="$2"
    local target_dir="$TOOLS_DIR/$repo"

    if [ -d "$target_dir/.git" ]; then
      ok "$repo — already installed"
      return 0
    fi

    info "Installing $repo..."
    git clone --filter="blob:none" "https://github.com/$github_path" "$target_dir" 2>/dev/null || {
      warn "Failed to clone $repo"
      return 1
    }

    if [ -f "$target_dir/requirements.txt" ] || [ -f "$target_dir/pyproject.toml" ]; then
      uv venv "$target_dir/venv" &>/dev/null || true
      uv pip install --python "$target_dir/venv/bin/python" \
        -r "${target_dir}/requirements.txt" 2>/dev/null || \
      uv pip install --python "$target_dir/venv/bin/python" \
        dnspython requests requests-futures 2>/dev/null || true
    fi

    ok "$repo installed"
  }

  install_intel_repo "msftrecon" "Arcanum-Sec/msftrecon"
  install_intel_repo "Scopify" "Arcanum-Sec/Scopify"
  install_intel_repo "Spoofy" "MattKeeley/Spoofy"
  install_intel_repo "cloud_enum" "initstring/cloud_enum"

  # theHarvester (email/subdomain OSINT — uses uv run, no venv)
  if [ -d "$HOME/theHarvester/.git" ]; then
    ok "theHarvester — already installed"
  else
    info "Installing theHarvester..."
    git clone --depth 1 https://github.com/laramies/theHarvester.git "$HOME/theHarvester"
    cd "$HOME/theHarvester" && uv sync
    ok "theHarvester installed"
  fi

  # waymore (Python archive URL collector — installed via pip in venv)
  WAYMORE_DIR="$REPO_DIR/tools/waymore"
  if [ -f "$WAYMORE_DIR/venv/bin/waymore" ]; then
    ok "waymore — already installed"
  else
    info "Installing waymore..."
    mkdir -p "$WAYMORE_DIR"
    uv venv "$WAYMORE_DIR/venv" 2>/dev/null
    uv pip install --python "$WAYMORE_DIR/venv/bin/python" waymore 2>/dev/null
    if [ -f "$WAYMORE_DIR/venv/bin/waymore" ]; then
      ok "waymore installed"
    else
      warn "waymore install failed (manual: cd $WAYMORE_DIR && uv venv && source venv/bin/activate && pip install waymore)"
    fi
  fi

  # uro (URL deduplication — used by waymore/gospider)
  if command -v uro &>/dev/null; then
    ok "uro — already installed"
  else
    # Ensure pipx is available
    if ! command -v pipx &>/dev/null; then
      info "pipx not found — installing..."
      if command -v apt-get &>/dev/null && command -v sudo &>/dev/null; then
        sudo apt-get install -y pipx 2>/dev/null || true
      fi
    fi
    if command -v pipx &>/dev/null; then
      info "Installing uro via pipx..."
      if pipx install uro 2>/dev/null; then
        ok "uro installed"
      else
        warn "uro install failed (manual: pipx install uro)"
      fi
    else
      warn "pipx not available — install manually: sudo apt install pipx && pipx install uro"
    fi
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Playwright (browser automation for browser_driver.py)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 6: Playwright (browser automation for browser-use)"

_PW_VENV="$REPO_DIR/.venv"
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

# Note: system Python is restricted on this OS (Kali blocks pip/pip3).
# Playwright is installed in the project venv below and used by the MCP server.
# The auto_auth.py script auto-detects the venv Python, so no system install needed.

info "Playwright — installing Chromium browser..."
"$_PW_VENV/bin/python" -m playwright install chromium 2>&1 | tail -3
ok "Playwright — Chromium ready"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Swarm MCP server — Python venv
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 7: Swarm MCP server"

if [ -f "$REPO_DIR/server/venv/bin/python" ]; then
  ok "Python venv already exists"
else
  info "Creating Python virtual environment..."
  cd "$REPO_DIR/server"
  rm -rf venv
  uv venv venv
  UV_PROJECT_ENVIRONMENT=venv uv sync
  cd "$REPO_DIR"
  ok "Python venv created + dependencies installed"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: OpenCode agents + rules
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 8: OpenCode agents & rules"

OC_AGENTS_DIR="$HOME/.config/opencode/agents"
OC_RULES_DIR="$HOME/.config/opencode/rules"
OC_HOME_AGENTS="$HOME/.swarm/agents"
OC_HOME_RULES="$HOME/.swarm/rules"

mkdir -p "$OC_AGENTS_DIR" "$OC_RULES_DIR" "$OC_HOME_AGENTS" "$OC_HOME_RULES"

# Agents (.swarm/agents/*.md)
if [ -d "$REPO_DIR/.swarm/agents" ]; then
  for agent_file in "$REPO_DIR/.swarm/agents"/*.md; do
    [ -f "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    # Symlink to ~/.config/opencode/agents/
    ln -sf "$agent_file" "$OC_AGENTS_DIR/$agent_name"
    # Also to legacy ~/.swarm/agents/
    ln -sf "$agent_file" "$OC_HOME_AGENTS/$agent_name"
  done
  ok "Agents linked ($(ls "$REPO_DIR/.swarm/agents"/*.md 2>/dev/null | wc -l) files)"
fi

# Rules (.swarm/rules/*.md)
if [ -d "$REPO_DIR/.swarm/rules" ]; then
  for rule_file in "$REPO_DIR/.swarm/rules"/*.md; do
    [ -f "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    ln -sf "$rule_file" "$OC_RULES_DIR/$rule_name"
    ln -sf "$rule_file" "$OC_HOME_RULES/$rule_name"
  done
  ok "Rules linked ($(ls "$REPO_DIR/.swarm/rules"/*.md 2>/dev/null | wc -l) files)"
fi

# Commands (.swarm/commands-bughunt/*.md) → ~/.config/opencode/commands/
OC_COMMANDS_DIR="$HOME/.config/opencode/commands"
PROJECT_CMD_DIR="$REPO_DIR/.swarm/commands"
HOME_CMD_DIR="$HOME/.swarm/commands"
mkdir -p "$OC_COMMANDS_DIR" "$PROJECT_CMD_DIR" "$HOME_CMD_DIR"
if [ -d "$REPO_DIR/.swarm/commands-bughunt" ]; then
  for cmd_file in "$REPO_DIR/.swarm/commands-bughunt"/*.md; do
    [ -f "$cmd_file" ] || continue
    cmd_name="$(basename "$cmd_file")"
    cp "$cmd_file" "$OC_COMMANDS_DIR/$cmd_name"
    cp "$cmd_file" "$PROJECT_CMD_DIR/$cmd_name"
    cp "$cmd_file" "$HOME_CMD_DIR/$cmd_name"
  done
  ok "Commands installed ($(ls "$REPO_DIR/.swarm/commands-bughunt"/*.md 2>/dev/null | wc -l) files)"
fi

# Skills symlink (for manual browsing)
SWARM_SKILLS="$HOME/.swarm/skills"
mkdir -p "$HOME/.swarm"
[ -L "$SWARM_SKILLS" ] && rm "$SWARM_SKILLS"
ln -s "$REPO_DIR/skills" "$SWARM_SKILLS"
ok "Skills linked at $SWARM_SKILLS"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: OpenCode config (MCP servers)
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 9: OpenCode MCP configuration"

OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"

# Backup existing config
if [ -f "$OPENCODE_CONFIG" ]; then
  mkdir -p "$BACKUP_DIR"
  cp "$OPENCODE_CONFIG" "$BACKUP_DIR/opencode.json"
  info "Backed up existing config → $BACKUP_DIR/"
fi

# Build MCP config
export REPO_DIR
# Add nvm Node.js to PATH for npm/npx resolution
export NVM_DIR="$HOME/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  \. "$NVM_DIR/nvm.sh" 2>/dev/null
  LATEST_NODE=$(ls "$NVM_DIR/versions/node/" 2>/dev/null | tail -1)
  [ -n "$LATEST_NODE" ] && export PATH="$NVM_DIR/versions/node/$LATEST_NODE/bin:$PATH"
fi

python3 << 'PYEOF'
import json, os, shutil, sys

repo = os.environ['REPO_DIR']
home = os.path.expanduser("~")
config_path = os.path.join(home, ".config", "opencode", "opencode.json")

# ── Platform detection ─────────────────────────────────────────────────────
is_wsl = os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or bool(os.environ.get("WSL_DISTRO_NAME"))
distro_id = ""
if os.path.exists("/etc/os-release"):
    with open("/etc/os-release") as f:
        for line in f:
            if line.startswith("ID="):
                distro_id = line.split("=", 1)[1].strip().strip('"')
                break

mcp = {}

# ── Burp Suite MCP ─────────────────────────────────────────────────────────
if is_wsl:
    # WSL: Burp runs on Windows — use bridge script to auto-detect gateway IP
    bridge_script = os.path.join(repo, "scripts", "burp-mcp-bridge.py")
    mcp["burp"] = {
        "type": "local",
        "command": ["bash", "-c", f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run ../scripts/burp-mcp-bridge.py"]
    }
    sys.stderr.write("[install] WSL detected → Burp MCP via bridge script\n")
else:
    # Native Linux / macOS: Burp runs on localhost
    mcp["burp"] = {
        "type": "remote",
        "url": "http://127.0.0.1:9876/",
        "enabled": True
    }
    sys.stderr.write("[install] Native Linux/macOS → Burp MCP remote :9876\n")

# ── WSTG server ────────────────────────────────────────────────────────────
mcp["wstg"] = {
    "type": "local",
    "prompt": "You are a Swarm WSTG penetration testing MCP server.",
    "command": [
        "bash",
        "-c",
        f"cd {repo}/server && UV_PROJECT_ENVIRONMENT=venv exec uv run server.py"
    ]
}

# ── Write config ───────────────────────────────────────────────────────────
config = {
    "$schema": "https://opencode.ai/config.json",
    "mcp": mcp
}

os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print("[+] WSTG MCP server configured")
PYEOF

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 10: Shell aliases
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 10: Shell aliases"

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
            # Fallback: check common RC files
            [ -f "$HOME/.bashrc" ] && echo "$HOME/.bashrc" && return
            [ -f "$HOME/.bash_profile" ] && echo "$HOME/.bash_profile" && return
            [ -f "$HOME/.zshrc" ] && echo "$HOME/.zshrc" && return
            ;;
    esac
}
SHELL_RC="$(detect_shell_rc)"

SWARM_MARKER="# --- Swarm config ---"
ALIASES="
$SWARM_MARKER
export SWARM_HOME=\"$REPO_DIR\"
export PATH="\$HOME/.swarm/bin:\$HOME/go/bin:\$HOME/.local/bin:\$PATH"
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
  if grep -q "$SWARM_MARKER" "$SHELL_RC" 2>/dev/null; then
    sed -i "/$SWARM_MARKER/,/^# --- End Swarm/d" "$SHELL_RC"
  fi
  echo "$ALIASES" >> "$SHELL_RC"
  echo "# --- End Swarm ---" >> "$SHELL_RC"
  ok "Aliases added to $SHELL_RC"
else
  warn "No shell RC found — add aliases manually:"
  echo "$ALIASES"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 11: Verification
# ═══════════════════════════════════════════════════════════════════════════════
header "PHASE 11: Verification"

# Core tools
if ! $QUICK; then
  info "Checking core tools..."
  # tool list for command -v check (standalone binaries)
  for tool in subfinder dnsx httpx ffuf gf gau katana nuclei dalfox crlfuzz anew jq trufflehog interactsh-client naabu; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool — found"
    else
      warn "$tool — not in PATH"
    fi
  done
  # Python scanner tools (installed as cloned repos, available via direct venv activation)
  for tool in sqlmap commix sstimap smuggler; do
    if [ -f "$TOOLS_DIR/$tool/$tool.py" ]; then
      ok "$tool — found"
    else
      warn "$tool — not installed"
    fi
  done
  if [ -f "$TOOLS_DIR/corscanner/cors_scan.py" ]; then
    ok "corscanner — found"
  else
    warn "corscanner — not installed"
  fi
  # wafw00f (cloned repo, no standalone binary)
  if [ -d "$TOOLS_DIR/wafw00f/.git" ]; then
    ok "wafw00f — found"
  else
    warn "wafw00f — not installed"
  fi
fi

# Swarm server venv
if [ -f "$REPO_DIR/server/venv/bin/python" ]; then
  ok "Swarm server venv — ready"
else
  warn "Swarm server venv — missing (run: cd server && uv venv venv && uv sync)"
fi

# Playwright
if "$REPO_DIR/.venv/bin/python" -c "import playwright" 2>/dev/null; then
  ok "Playwright — ready"
else
  warn "Playwright — not installed (re-run install.sh)"
fi

# OpenCode config
if [ -f "$OPENCODE_CONFIG" ]; then
  ok "OpenCode config — $OPENCODE_CONFIG"
fi

# GF patterns
GF_COUNT=$(ls "$HOME/.gf/"*.json 2>/dev/null | wc -l)
[ "$GF_COUNT" -gt 0 ] && ok "GF patterns — $GF_COUNT in ~/.gf/" || warn "GF patterns — none in ~/.gf/"

# ═══════════════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${G}
  ╔══════════════════════════════════════════════════════╗
  ║          Swarm Installation Complete!                 ║
  ╚══════════════════════════════════════════════════════╝${N}"
echo ""
echo "  Commands:   swarm, swarm-server, swarm-update, swarm-recon, swarm-browser"
echo "  OpenCode:   opencode  (launches with Swarm pre-configured)"
  echo "  Agents:     87 OpenCode agents"
  echo "  Tools:      $($QUICK && echo 'skipped (re-run without --quick)' || echo '25 essential tools')"
echo ""
echo "  Quick start:"
echo "    1. opencode"
echo "    2. /hunt example.com"
echo ""
echo "  Log:      $LOG_FILE"
echo "  Backups:  $BACKUP_DIR"
echo ""
