# Browser-Based Pentest Engagement Plan

## Overview

This plan defines how we drive a browser like a human to perform security testing on any
web target. The core mechanic: **the LLM acts as the brain**, using MCP browser tools
(`browser_analyze`, `browser_act`, `browser_login`, etc.) as hands and eyes to
interact with the target site visually, step by step.

> **Note:** All browser interactions go through MCP tools. The underlying engine
> uses Playwright-backed Chromium on port 9222. See `docs/browser-flow.md` for
> the technical reference.

---

## Pre-Flight — Environment & Tools

### 0.1 Start Standalone Headed Browser

The MCP server auto-starts Chromium when needed. To launch it manually:

```bash
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Kill any old instance
fuser -k 9222/tcp 2>/dev/null; sleep 1

# Start Chrome as independent process (stays alive between commands)
# Path auto-resolved by Playwright — find yours with:
#   ls ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome
"${HOME}/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome" \
  --remote-debugging-port=9222 \
  --no-sandbox \
  --disable-setuid-sandbox \
  --disable-dev-shm-usage \
  --window-size=1280,720 \
  --new-window "about:blank" \
  > /tmp/chrome.log 2>&1 &
```

### 0.2 Verify Connection

```bash
# Check that Chrome is listening:
curl http://127.0.0.1:9222/json/version

# Test via MCP tool:
browser_analyze(engagement_id, url="https://example.com")
browser_act(engagement_id, "state")
```

### 0.3 Initialize Engagement

```bash
engagement_id="target-name-$(date +%s)"
wstg findings_init engagement_id="$engagement_id" client="$TARGET"
wstg create_task_tree engagement_id="$engagement_id"
```

### 0.4 Register Scope

- Parse bug bounty scope table or user-provided scope
- Register in-scope domains/endpoints via `wstg register_scope`

---

## Pipeline Integration

Browser auth is Phase 2b of the 12-phase pipeline. See `docs/pipeline.md` for the full phase structure and `docs/phases/browser-auth.md` for the Phase 2b methodology.

```
SCOPE(1) → AUTH(2) → [BROWSER AUTH(2b)] → INTEL(3) → RECON(4) → SURFACE(5) → HUNT(6) → ...
```

Phase 2b is a conditional sub-phase of Phase 2 (AUTH). It runs when the target requires browser-based authentication (OAuth, SSO, MFA, complex signup) that cannot be completed via API calls alone.

---

## Pre-Auth Analysis (before Phase 2b)

---

## Browser Authentication Loop (Phase 2b)

This is the central mechanism. The LLM drives the browser step-by-step using
MCP browser tools (`browser_analyze`, `browser_act`, `browser_login`, etc.).

See `docs/phases/browser-auth.md` for the full Phase 2b methodology and `skills/browser-auth/SKILL.md` for the auth flow details.

### The Interaction Loop

```
repeat until goal achieved:
  1. browser_analyze(eid, url)
     → Returns: title, URL, base64 screenshot, visible text,
       interactive elements with indices, cookie count
     → LLM "sees" the page visually
  2. Analyze:
     - What elements are on the page? (buttons, inputs, links)
     - What state is the form in? (errors, success, next step)
     - What should I do next?
  3. Act:
     - browser_act(eid, "type", index=N, text="...")    → fill input
     - browser_act(eid, "click", index=N)                → click element
     - browser_act(eid, "navigate", url="...")           → navigate
     - browser_act(eid, "state")                         → get page state
     - browser_act(eid, "screenshot")                    → capture evidence
  4. Wait/Check:
     - Page changed? New elements appeared?
     - Error message? Success message?
  5. Adapt:
     - If error → diagnose, fix, retry
     - If unexpected popup → dismiss, continue
     - If new step → proceed
```

The browser stays alive because Chrome runs independently with `--remote-debugging-port`.
The MCP server's `_ensure_browser()` reconnects to it on every invocation.

### Element Identification

`browser_analyze(eid, url)` returns interactive elements with indices.
Each element includes: tag, text, placeholder, href, type, name, value, aria-label, role,
class, id, data-testid, title, alt, for, rect (bounding box), center (viewport coords).

### Clicking Strategies

1. **Index click**: `click <index>` — clicks element by DOM index (most reliable)
2. **Coordinate click**: `click_at <x> <y>` — click at viewport pixel (for custom elements not in DOM tree)
3. **Scroll then click**: `scroll down 300` then `click <index>` — for off-screen elements

### Typing Strategies

```python
browser_act(eid, "type", index=3, text="John")
browser_act(eid, "type", index=5, text="Doe")
browser_act(eid, "type", index=2, text="user@temp.com")
```

Internally: click center → Ctrl+A → Delete → keyboard.type(text, delay=50ms)

### Handling Dropdowns

Use JavaScript to set value and dispatch change event:

```python
browser_act(eid, "js", code="document.getElementById('country').value = 'US'; document.getElementById('country').dispatchEvent(new Event('change', {bubbles: true})); 'done'")
```

### Handling Dynamic Content & SPAs

1. Navigate → wait 2-3 seconds
2. Get state to see current DOM
3. If loading indicator → wait, re-check
4. Use `screenshot` to visually confirm

---

## Session Capture & Reuse

```python
# Capture cookies + storage
storage = browser_extract_storage(eid, agent_id="auth-agent", url="https://target.com/")

# Verify session
state = browser_act(eid, "state")
browser_screenshot(eid, agent_id="auth-agent", url="https://target.com/dashboard")

# Store credentials metadata
Save to engagements/<eid>/runtime/<eid>/session.json (via auto_auth.py)
or engagements/<eid>/runtime/<eid>/cookies-<agent_id>.json
```

---

## Pentest Pipeline (downstream phases)

| Phase | Purpose | Learn More |
|-------|---------|------------|
| Phase 3 (INTEL) | Passive OSINT: WHOIS, M365, spoof, cloud | `docs/pipeline.md` |
| Phase 4 (RECON) | Subdomains, crawl, params, secrets | `docs/pipeline.md` |
| Phase 5 (SURFACE) | Endpoint classification, risk scoring | `docs/pipeline.md` |
| Phase 6 (HUNT) | Per-class vulnerability testing (57 agents) | `docs/pipeline.md` |
| Phase 8 (EXPLOIT) | Multi-auth-context PoC exploitation | `docs/pipeline.md` |
| Phase 10 (CAPTURE) | Evidence collection, screenshots | `docs/pipeline.md` |
| Phase 12 (REPORT) | Coverage check, report generation | `docs/pipeline.md` |

---

## Utility Playbooks

### Email Verification

**Guerrilla Mail API (works):**

```bash
# Create inbox
INBOX=$(curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_address")
EMAIL=$(echo "$INBOX" | python3 -c "import json,sys; print(json.load(sys.stdin)['email_addr'])")
SID=$(echo "$INBOX" | python3 -c "import json,sys; print(json.load(sys.stdin)['sid_token'])")

# Use $EMAIL for signup, then poll:
sleep 10
LIST=$(curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_list&sid_token=$SID")
EMAIL_ID=$(echo "$LIST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['list'][0]['mail_id'])")

# Fetch full email:
MAIL=$(curl -s "https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id=$EMAIL_ID&sid_token=$SID")
# Extract 5-6 digit verification code from HTML body
```

### CAPTCHA
Identify CAPTCHA element (reCAPTCHA, hCaptcha). If present → report as finding.
May need manual intervention or CAPTCHA solving service.

### MFA/2FA
After password step → identify MFA challenge type:
- **TOTP**: Extract secret from QR code → generate codes
- **SMS**: May need manual intervention
- Report MFA quality (rate limiting, backup code strength)

### Error Recovery

If a browser action fails:
1. `state` → re-check current page state
2. If page changed → adapt actions
3. If element not found → try coordinate click or scroll
4. If browser dead → re-start Chrome, re-navigate, re-auth if needed

---

## Command Reference

| MCP Tool | Purpose | Example |
|----------|---------|---------|
| `browser_analyze(eid, url)` | Navigate + capture page state + screenshot | `browser_analyze(eid, "https://target.com/login")` |
| `browser_act(eid, "navigate", url=...)` | Go to URL | `browser_act(eid, "navigate", url="https://target.com/login")` |
| `browser_act(eid, "state")` | Get page state | `browser_act(eid, "state")` |
| `browser_act(eid, "click", index=N)` | Click element by DOM index | `browser_act(eid, "click", index=3)` |
| `browser_act(eid, "type", index=N, text=...)` | Type into input | `browser_act(eid, "type", index=3, text="john")` |
| `browser_act(eid, "js", code=...)` | Execute JavaScript | `browser_act(eid, "js", code="document.cookie")` |
| `browser_act(eid, "screenshot")` | Take screenshot | `browser_act(eid, "screenshot")` |
| `browser_act(eid, "html")` | Get page HTML | `browser_act(eid, "html")` |
| `browser_act(eid, "cookies")` | List all cookies | `browser_act(eid, "cookies")` |
| `browser_act(eid, "close")` | Close browser | `browser_act(eid, "close")` |
| `browser_login(eid, agent_id, url, ...)` | Form login (auto-detect fields) | `browser_login(eid, "agent", url, user, pass)` |
| `browser_auto_auth(eid, url, ...)` | Autonomous signup → login | `browser_auto_auth(eid, "https://target.com")` |
| `browser_extract_storage(eid, agent_id, url)` | Extract cookies + storage | `browser_extract_storage(eid, "agent", url)` |
| `browser_screenshot(eid, agent_id, url)` | Save evidence screenshot | `browser_screenshot(eid, "agent", url)` |

---

## Environment

| Component | Path |
|-----------|------|
| Chromium | Resolved dynamically by `server/browser_tools.py` |
| Mode | Headed (GUI) — `--remote-debugging-port=9222` |
| Display | `DISPLAY=:0` (Xvfb) |
| Libraries | `LD_LIBRARY_PATH=$HOME/.local/lib` (libnspr4, libnss3) |
| Driver | MCP server (`browser_analyze`, `browser_act`, `browser_login`, etc.) |
| Backend | `server/browser_tools.py` (browser-use based) |

---

## Execution Checklist

Pre-Flight:
- [ ] Chrome running on port 9222
- [ ] Engagement initialized via wstg
- [ ] Scope registered
- [ ] Task tree created

Auth:
- [ ] Target auth type identified
- [ ] Temp email ready (if signup)
- [ ] Browser interaction loop active
- [ ] Session cookies captured

Testing:
- [ ] WAF identified
- [ ] Tech stack fingerprinted
- [ ] Auth flow completed
- [ ] Endpoints discovered
- [ ] Vulnerabilities hunted
- [ ] Findings logged

Reporting:
- [ ] Phase gates passed
- [ ] Report generated
- [ ] Handoff ready
