# Browser Flow — Headed Chromium Automation

Swarm uses **browser-use** (`Browser` class) for browser-based testing via `server/browser_tools.py`. The browser runs headed on DISPLAY=:0 and persists across calls via CDP port 9222.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `browser_login(engagement_id, agent_id, url, username, password)` | Login form automation with auto-detected fields + cookie persistence |
| `browser_auto_auth(engagement_id, url, email, headless)` | Full autonomous signup → email verification → login. Uses auto_auth.py with Guerrilla Mail |
| `browser_analyze(engagement_id, url)` | Capture screenshot + page text + interactive elements for LLM-driven analysis |
| `browser_act(engagement_id, action, ...)` | Low-level browser control: navigate, click, type, js, state, cookies, html |
| `browser_screenshot(engagement_id, agent_id, url, full_page)` | Evidence screenshot save to engagement evidence dir |
| `browser_crawl(engagement_id, start_url, depth)` | Link crawling to discover endpoints/routes |
| `browser_extract_storage(engagement_id, agent_id, url)` | Extract cookies, localStorage, sessionStorage |

## Low-Level Commands

For direct CLI testing, use `server/browser_use_backend.py`:

```
.venv/bin/python server/browser_use_backend.py navigate <url> [--wait=N]
.venv/bin/python server/browser_use_backend.py state [--screenshot]
.venv/bin/python server/browser_use_backend.py click <index>
.venv/bin/python server/browser_use_backend.py type <index> <text>
.venv/bin/python server/browser_use_backend.py screenshot [--full]
.venv/bin/python server/browser_use_backend.py js <code>
.venv/bin/python server/browser_use_backend.py cookies
.venv/bin/python server/browser_use_backend.py close
```

The browser is shared across all commands — MCP tools reuse the same persistent browser process.

## Auto-Auth (browser_auto_auth)

Autonomous signup → email verification → login for any platform. Uses `scripts/tools/auto_auth.py` with:

1. **Email**: Auto-generated via Guerrilla Mail (swarm-NNNNNNNN@guerrillamailblock.com)
2. **Password/Username**: Randomly generated per run
3. **Browser**: Playwright via project venv (auto-detected, falls back to system python)
4. **Email verification**: Polls Guerrilla Mail inbox for verification links or OTP codes
5. **Session**: Saves cookies + env vars to `engagements/<id>/runtime/<id>/session.json`

```python
browser_auto_auth(
    engagement_id="my-engagement",
    url="https://target.com",
    email="optional@override.com",  # omit for auto-generated
    headless=True,
)
```

Returns:
- `ok` — account created and logged in
- `partial` — some cookies captured but login may have failed
- `skip` — no auth form found
- `captcha` — CAPTCHA or phone verification blocked automation
- `fail` — dependency error or unexpected failure

### Auto-detect venv Python

`auto_auth.py` automatically finds the project venv Python (`.venv/bin/python`) before the system Python so playwright is always available. Checks:
1. `repo_root/.venv/bin/python`
2. `repo_root/server/venv/bin/python`
3. Falls back to `sys.executable`

## LLM-Driven Browser Testing (browser_analyze + browser_act)

For sites where auto-detection fails (SPAs, CSP-restricted pages, custom UIs), use the LLM-driven flow:

```
1. browser_analyze(engagement_id, url)
   → Returns: page title, URL, base64 screenshot, visible text, interactive elements
   
2. Subagent LLM analyzes the output:
   "This is a signup form with email, password, name fields + reCAPTCHA"
   
3. browser_act(engagement_id, "type", index=3, text="user@email.com")
   browser_act(engagement_id, "type", index=4, text="password123")
   browser_act(engagement_id, "click", index=5)
   
4. Repeat analyze → decide → act until authenticated
```

This works on any site — the LLM reads the page content directly instead of relying on injected JS that CSP blocks.

## Auth Session Management

### Method 1: browser_login (preferred for known credentials)

```python
browser_login(
    engagement_id="my-engagement",
    agent_id="auth-agent",
    url="https://target.com/login",
    username="test@test.com",
    password="Test123!",
)
```

Form fields are auto-detected. Cookies saved to `engagements/<id>/runtime/<id>/cookies-<agent_id>.json`.

### Method 2: browser_auto_auth (autonomous signup + verify + login)

For fully automated account creation. See section above.

### Method 3: Manual login via state inspection

```python
browser_act(engagement_id, "navigate", url="https://target.com/login")
state = browser_analyze(engagement_id)
# state["interactive_elements"] shows all inputs, buttons, etc.
browser_act(engagement_id, "type", index=5, text="test@test.com")
browser_act(engagement_id, "type", index=6, text="Test123!")
browser_act(engagement_id, "click", index=7)
cookies = browser_act(engagement_id, "cookies")
```

### Method 4: Load existing cookies

Drop a cookie JSON file into `engagements/<id>/runtime/<id>/cookies-<agent_id>.json` before calling `browser_screenshot()` etc.

## Browser + Burp Integration

Browser → Burp Proxy → Target

1. Set HTTP_PROXY/HTTPS_PROXY or configure Burp system proxy
2. `scripts/browser_driver.py` respects `HTTP_PROXY` env var
3. All browser traffic flows through Burp — check `burp_get_proxy_http_history()` to review

## Per-Phase Browser Workflow

### P2: AUTH

- `browser_login()` to authenticate
- `browser_extract_storage()` to capture JWT tokens / session IDs
- `browser_screenshot()` for evidence of authenticated session

### P4: RECON

- `browser_crawl()` to discover client-side routes
- `_run_driver("navigate", url)` to trigger SPA route changes visible in Burp

### P6: HUNT

- Navigate to crafted payload URLs to verify DOM-based bugs
- `_run_driver("js", "document.cookie")` to inspect cookie flags
- Take screenshots of rendered PoCs

### P10: CAPTURE

- `browser_screenshot()` with full_page to capture complete evidence
- `browser_extract_storage()` to log cookie/localStorage state

## Browser Tools Architecture

### Engine: browser-use (hands)

`server/browser_tools.py` imports browser-use's `Browser` class directly (NOT `browser_driver.py` subprocess). The `_ensure_browser()` function:
1. Launches Chromium on CDP port 9222 via `_ensure_chromium()`
2. Connects via `Browser.connect(cdp_url=ws_url)`
3. Attaches watchdogs via `Browser.attach_all_watchdogs()` (required for DOM scanning)

### Decision-maker: Swarm AI (brain)

browser-use provides the execution engine; Swarm's LLM drives the observe→decide→act loop by calling `browser_analyze()` → analyzing elements → calling `browser_act()` to interact.

### DOM Scanning

Element indices are populated by `get_browser_state_summary()` which triggers the DOMWatchdog event handler. The `_ensure_selector_map()` helper ensures this runs before any `get_element_by_index()` call — without it, click/type actions fail with "No element at index".

### Bug Fixes Applied

| Issue | Fix |
|-------|-----|
| `_click_element()` / `_type_text()` called `get_element_by_index()` on empty selector map | Added `_ensure_selector_map()` call before every index lookup |
| `Element.type()` doesn't exist — method is `fill()` | Changed `el.type(text)` → `el.fill(text)` |

## Universal Auth Page Discovery (analyze agent + browser_analyze/browser_act)

For **any** website, the analyze agent can discover the signup/login page by following this observe→decide→act loop:

```
1. browser_analyze(engagement_id, "https://example.com")
   → Returns: page title, URL, visible text, interactive elements, screenshot
   
2. AI examines output:
   - Buttons: "Sign Up", "Register", "Log In", "Get Started"
   - Links: /signup, /login, /register
   - Text: "Create account", "Already have an account?"
   
3. browser_act(engagement_id, "click", index=N)          # follow signup button
   browser_analyze(engagement_id)                         # analyze new page
   
4. If no signup button → try common paths:
   browser_act(engagement_id, "navigate", url="https://example.com/signup")
   browser_analyze(engagement_id)
   
5. Repeat until auth form is detected (email/password fields, OAuth buttons, etc.)
6. Save deliverable: save_deliverable(engagement_id, "auth_page_discovery", report, "analyze")
```

The AI never hardcodes paths — it reads each page and decides what to click. See `skills/analyze/SKILL.md` §8 for the full algorithm with detection patterns by site type.

## Performance Tips

- `browser_crawl()` depth > 1 can be slow — prefer depth=1 for most cases
- The browser stays open between calls — call `browser_act(engagement_id, "close")` only when done
- `_ensure_selector_map()` adds ~500ms-2s overhead per action — batching via `_get_state()` first avoids redundant scans

## Setup

Requires browser-use[core] + Playwright + Chromium (installed in `.venv/`). See `docs/virtual-environments.md` for details.

## Agent Type Caching

New agent types (like `analyze`, `browser-auth`) are only recognized after an swarm session restart. This is because swarm caches the agent registry at session start from `~/.config/swarm/agents/`.

### Workaround

If you create a new agent file and need to use it in the current session:

```bash
# Option 1: Restart swarm (guaranteed to work)
# Exit and re-launch swarm

# Option 2: Force-load the agent content via general subagent
# Use @general or @deepthink with the agent's methodology injected into
# the prompt instead of relying on auto-detection

# Option 3: Symlink the agent (if it exists but isn't detected)
ls ~/.config/swarm/agents/ | grep <agent-name>
```

The `analyze` and `browser-auth` agents are already registered in the agent registry and will auto-load in new sessions. For any new agents created mid-session, use Option 2 (dispatch with methodology injected).

## See Also

- `skills/analyze/SKILL.md` — Read-only page analysis methodology (auth mechanism, tech fingerprinting, storage analysis)
- `prompts/analyze.md` — Subagent prompt for the `analyze` agent
- `skills/browser-auth/SKILL.md` — Full browser auth methodology for the subagent
- `prompts/browser-auth.md` — Subagent prompt for Phase 2b browser auth
- `agents/registry.yaml` — Agent registry (analyze + browser-auth under auth-session/specialized)
- `docs/virtual-environments.md` — Python venv setup for all browser tools
