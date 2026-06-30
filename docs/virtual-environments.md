# Virtual Environments

## Venv Summary

| Venv | Path | Python | Used By |
|------|------|--------|---------|
| **MCP Server** | `server/venv/` | `server/venv/bin/python3` | `server.py` (MCP), `browser_tools.py`, `handoff.sh`, `findings.sh`, `generate_poc_report.sh` |
| **Project CLI** | `.venv/` | `.venv/bin/python` | `browser_driver.py`, `auto_auth.py`, `bughunt.py`, `browser_use_backend.py` |
| **Third-party tools** | `$HOME/.local/bin/<name>/venv/` | per tool | `phase-intel.sh`, `s3_buckets.sh` |

Each tool auto-detects its venv via `_run_with_timeout_in_venv()` — no manual activation needed.

---

## MCP Server Venv (`server/venv/`)

**Path:** `server/venv/bin/python3`
**Created by:** `cd server && uv venv venv && UV_PROJECT_ENVIRONMENT=venv uv sync`
**Launched by:** `.mcp.json` → `server/venv/bin/python3 server/server.py`

### Installed packages

| Package | Purpose |
|---------|---------|
| `mcp[cli]` | MCP server framework |
| `browser-use[core]` | Browser automation (Browser class) |
| `pyyaml` | YAML config parsing |
| `cryptography` | Encryption utilities |
| `cvss` | CVSS 3.1/4.0 scoring |
| `playwright` | Browser engine (browser-use dep) |
| `httpx` | Async HTTP |
| `pydantic` | Data validation |
| `requests` | HTTP requests |
| `pillow` | Image processing |
| `psutil` | Process monitoring |

### Tools that use this venv

| Tool | File | How it finds the venv |
|------|------|-----------------------|
| **MCP Server** | `server/server.py` | `.mcp.json` launches via `server/venv/bin/python3` directly |
| **browser_tools** | `server/browser_tools.py` | Imported by server.py → same venv |
| **handoff.sh** | `scripts/handoff.sh` | `$SERVER_DIR/venv/bin/python3` (hardcoded) |
| **findings.sh** | `scripts/findings.sh` | `$SERVER_DIR/venv/bin/python3` (hardcoded) |
| **generate_poc_report.sh** | `scripts/generate_poc_report.sh` | `server/venv/bin/python3` (hardcoded) |

---

## Project CLI Venv (`.venv/`)

**Path:** `.venv/bin/python`
**Created by:** `uv venv .venv --python 3.13 && uv pip install playwright browser-use[core]`
**Activation:** `source .venv/bin/activate`

### Installed packages

| Package | Purpose |
|---------|---------|
| `playwright` | Browser automation engine |
| `browser-use[core]` | Browser class (for CLI testing) |
| `requests` | HTTP requests (Guerrilla Mail, APIs) |
| `pyotp` | TOTP code generation for MFA |

### Tools that use this venv

| Tool | File | How it finds the venv |
|------|------|-----------------------|
| **browser_driver.py** | `scripts/browser_driver.py` | CLI: `.venv/bin/python scripts/browser_driver.py` |
| **auto_auth.py** | `scripts/tools/auto_auth.py` | Auto-detects: `.venv/` → `server/venv/` → sys default |
| **browser_use_backend.py** | `server/browser_use_backend.py` | CLI: `.venv/bin/python server/browser_use_backend.py` |
| **bughunt.py** | `scripts/bughunt.py` | Checks `.venv/bin/python` before sys default |
| **swarm-browser alias** | `.bashrc`/`.zshrc` | `$SWARM_HOME/.venv/bin/python $SWARM_HOME/scripts/browser_driver.py` |

---

## Third-Party Tool Venvs

Some recon tools create their own venvs under `$HOME/.local/bin/` (installed by `scripts/setup/install.sh`):

| Tool | Venv Location | Activation in `phase-intel.sh` |
|------|---------------|-------------------------------|
| `msftrecon` | `$HOME/.local/bin/msftrecon/venv/` | `source "$venv/bin/activate" && python3 ...` |
| `Scopify` | `$HOME/.local/bin/Scopify/venv/` | `source "$venv/bin/activate" && python3 ...` |
| `Spoofy` | `$HOME/.local/bin/Spoofy/venv/` | `source "$venv/bin/activate" && python3 ...` |
| `cloud_enum` | `$HOME/.local/bin/cloud_enum/venv/` | `source "$venv/bin/activate" && python3 ...` |
| `waymore` | `$HOME/.local/bin/waymore/venv/` | N/A (used by `install.sh` only) |

`phase-intel.sh` uses `_run_with_timeout_in_venv()` which calls `source "$venv/bin/activate"` before executing each tool — no manual activation needed.

---

## Quick Reference: Which Python to use

```bash
# MCP server (browser-use, all MCP tools)
server/venv/bin/python3 server/server.py

# CLI browser testing (browser-use backend)
.venv/bin/python server/browser_use_backend.py navigate|state|click|type|...

# Legacy browser CLI (playwright)
.venv/bin/python scripts/browser_driver.py navigate|state|click|type|...

# Autonomous auth (auto-detects venv)
.venv/bin/python scripts/tools/auto_auth.py <domain>

# Scripts
server/venv/bin/python3 scripts/generate_poc_report.sh  # uses server/venv
.venv/bin/python scripts/bughunt.py                     # uses .venv
```

---

## LD_LIBRARY_PATH for Chromium

Playwright's bundled Chromium requires NSS/NSPR shared libraries at `~/.local/lib/`:

```python
os.environ["LD_LIBRARY_PATH"] = "~/.local/lib:" + os.environ.get("LD_LIBRARY_PATH", "")
```

Set at module import time in:
- `scripts/browser_driver.py` (via `_ensure_lib_path()`)
- `server/browser_tools.py` (module-level)
- `server/browser_use_backend.py` (module-level)

---

## Setup

```bash
# MCP server venv
cd server && uv venv venv && UV_PROJECT_ENVIRONMENT=venv uv sync

# Project CLI venv
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python playwright browser-use[core]

# Install Chromium for Playwright
.venv/bin/python -m playwright install chromium
```

**Note:** System `pip3` is not available on Kali — only the venv-based install path works.
