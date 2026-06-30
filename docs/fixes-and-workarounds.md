# Fixes & Workarounds

This document catalogs every issue encountered while building the browser-based pentesting
workflow, the root cause analysis, and the fix applied.

---

## 1. browser-use MCP Tools Disappear After Server Kill

### Symptom
After the `browser_use.mcp` server process was killed (SIGKILL), all browser-use MCP tools
(`browser_navigate`, `browser_click`, `browser_type`, etc.) vanished from the agent's tool
list and never came back.

### Root Cause
OpenCode spawns MCP server subprocesses at session start from `.mcp.json`. When a subprocess
dies, **OpenCode does not auto-restart it**. The tools are only registered during the initial
handshake. There is no built-in `restart` command.

```
opencode mcp list     # shows "connected" even with dead process
opencode mcp add      # adds to global config but doesn't restart
```

### Related Files
- `.mcp.json` — project-level MCP config (the canonical source)
- `~/.config/opencode/opencode.jsonc` — global MCP config (modified by `opencode mcp add`)

### Fix
We abandoned the MCP tools entirely and built a standalone Python script
(`scripts/browser_driver.py`) that uses Playwright directly. This is more reliable and
avoids all MCP-layer issues.

---

## 2. browser-use BrowserSession CDP WebSocket Disconnection

### Symptom
Using browser-use's `BrowserSession` on Linux, the CDP WebSocket drops within seconds of
connecting:

```
WARNING  [BrowserSession] 🔌 CDP WebSocket message handler exited unexpectedly (connection closed)
WARNING  [BrowserSession] 🔄 WebSocket reconnection attempt 1/3...
INFO     [BrowserSession] [SessionManager] Cleared all owned data (targets, sessions, mappings)
INFO     [BrowserSession] 🔄 WebSocket reconnected after 0.1s (attempt 1)
```

After reconnection, browser-use's event-driven operations (NavigateToUrlEvent,
ClickElementEvent) **hang forever** because the event completion callback is lost.

The MCP server's `_navigate` uses the same events, so it has the same bug.

### Root Cause
Known browser-use bug on headful Linux environments. After CDP connects, browser-use runs
post-connect steps (viewport config, session manager probes) that destabilize the
connection. Documented in:
- [browser-use issue #4471](https://github.com/browser-use/browser-use/issues/4471)
- [browser-use issue #3613](https://github.com/browser-use/browser-use/issues/3613)
- Fixed in PR #4858 / PR #4875 (not released in our version)

### browser-use Page.goto is broken
Even when CDP stays connected, browser-use's `Page.goto()` does not wait for page load:

```python
# browser-use Page.goto:
async def goto(self, url: str) -> None:
    params: NavigateParameters = {'url': url}
    await self._client.send.Page.navigate(params, session_id=session_id)
    # ^ No wait_until. No timeout. No return value.
```

Compare with Playwright's native `page.goto()` which waits for `domcontentloaded`,
accepts timeouts, and returns the HTTP response.

### Fix
**Bypass browser-use entirely.** Use Playwright's async API directly:

```python
from playwright.async_api import async_playwright

# Before (broken):
session = BrowserSession(browser_profile=profile)
await session.start()
page = await session.get_current_page()
await page.goto(url)  # fires and forgets

# After (works):
pw = await async_playwright().start()
browser = await pw.chromium.launch(headless=False)
page = await browser.new_page()
await page.goto(url, wait_until="domcontentloaded", timeout=30000)
```

---

## 3. Browser Session Persistence Across Invocations

### Symptom
Each bash command gets a fresh Python process. When `browser_driver.py navigate ...` exits,
Playwright closes the browser — the next `browser_driver.py click ...` has no browser to
use.

### Root Cause
Playwright's `launch()` spawns Chromium as a child process. When the controlling Python
process exits, Playwright sends SIGTERM to the child. By default, Chromium dies.

### Fix (Two-Part)

**A) Launch Chrome independently with `--remote-debugging-port`**

```bash
# Start Chrome as a standalone process (not a child of Python):
chrome --remote-debugging-port=9222 --no-sandbox --window-size=1280,720
```

Chrome exposes a REST API at `http://127.0.0.1:9222/json/version` that returns the CDP
WebSocket URL:

```json
{
  "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/477c78e9-..."
}
```

**B) Reconnect via `connect_over_cdp` on each invocation**

```python
import urllib.request
resp = urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=3)
ws_url = json.loads(resp.read())["webSocketDebuggerUrl"]

pw = await async_playwright().start()
browser = await pw.chromium.connect_over_cdp(ws_url)
context = browser.contexts[0]
page = context.pages[0]  # or await context.new_page()
```

The browser process stays alive between calls because `connect_over_cdp` does not manage
the browser lifecycle — it only opens a CDP channel.

**State file:** `/tmp/browser-driver-state.json` stores the CDP port so subsequent
invocations know where to reconnect.

### Session Flow

```
Invocation 1: navigate
  → _ensure_browser()
    → connect_over_cdp fails (not running)
    → launch new Chrome with --remote-debugging-port=9222
    → page.goto(url)
  → Python exits
  → Chrome stays running (independent process)

Invocation 2: click
  → _ensure_browser()
    → fetch http://127.0.0.1:9222/json/version
    → connect_over_cdp(ws_url) ← reconnects to same browser
    → click element
  → Python exits
  → Chrome stays running

Invocation 3: close
  → browser.close() → kills Chrome
```

---

## 4. Missing System Libraries for Chromium

### Symptom
```
error while loading shared libraries: libnspr4.so: cannot open shared object file
```

### Root Cause
The Playwright Chromium binary requires NSS/NSPR shared libraries that aren't installed on
this system.

### Fix
Extract the needed libraries from the Playwright system dependencies package and symlink
them to `~/.local/lib/`:

```
find ~/.cache/ms-playwright -name "*.so*" | xargs -I{} cp -n {} ~/.local/lib/
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
```

This is now set automatically by `browser_driver.py`'s `_ensure_lib_path()` before
launching Chrome. No manual setup needed.

---

## 5. Interactive Element Discovery (Playwright vs browser-use)

### Symptom
browser-use's `get_browser_state_summary()` returns a `SelectorMap` with indexed elements,
but after bypassing browser-use we lost this.

### Fix
Implement our own element discovery via `page.evaluate()` that runs JavaScript in the
browser context:

```javascript
const sel = 'input, button, a, select, textarea, label, ' +
    '[role="button"], [role="link"], [role="combobox"], [role="option"], ' +
    '[tabindex]:not([tabindex="-1"]), [onclick]';
const all = document.querySelectorAll(sel);
```

For each element we capture:
- `index` — sequential number (1-based)
- `tag` — lowercase tag name
- `text` — `textContent` (trimmed, max 100 chars)
- `rect` — `getBoundingClientRect()` (top, left, width, height)
- `center` — viewport center coordinates `(left+width/2, top+height/2)`
- `attrs` — key attributes: placeholder, href, type, name, value, aria-label, role, class,
  id, data-testid, title, alt, for

Only **visible** elements are returned (width > 0, height > 0, top < viewport + 50px).

### Element Rebuild
Elements are rebuilt from scratch on every `state`, `click`, and `type` command. This means
indices change when the DOM changes — the agent must re-fetch state after each navigation
or dynamic update.

---

## 6. Form Field Typing: Clear Before Type

### Symptom
Playwright's `page.fill(selector, text)` requires a CSS selector, but our element index
system uses coordinates. Calling `page.fill(coordinates, text)` throws.

### Fix
Use keyboard actions instead:

```python
# Click the element center
await page.mouse.click(center_x, center_y)
await asyncio.sleep(0.3)

# Select all + delete to clear existing text
await page.keyboard.press("Control+a")
await asyncio.sleep(0.1)
await page.keyboard.press("Delete")
await asyncio.sleep(0.1)

# Type character by character (human-like)
await page.keyboard.type(text, delay=50)
```

---

## 7. Dropdown / Select Elements

### Symptom
`<select>` elements are visible in the state but clicking them via index doesn't always
open the options dropdown (custom styled selects), and even when it does, selecting an
option by another click is fragile.

### Fix
Use JavaScript to set the value directly and dispatch the change event to trigger any
listeners:

```python
await page.evaluate("""
    document.getElementById('country').value = 'US';
    document.getElementById('country').dispatchEvent(
        new Event('change', {bubbles: true})
    );
""")
```

---

## 8. Temp Email for Verification Codes

### Symptom
Multiple temp email services failed:
- **mail.tm**: `429 Too Many Requests` (rate-limited)
- **Mailinator**: `404` on inbox API
- **Guerrilla Mail**: Worked, but API responses were intermittently parsed as empty

### Fix
Use Guerrilla Mail API with explicit SID token management:

```bash
# Step 1: Create inbox
GET https://api.guerrillamail.com/ajax.php?f=get_email_address
→ {"email_addr":"xxx@guerrillamailblock.com", "sid_token":"yyy"}

# Step 2: Use the email for signup
# Step 3: Poll for incoming mail
GET https://api.guerrillamail.com/ajax.php?f=get_email_list&sid_token=yyy
→ {"list": [{"mail_id": "123", "mail_subject": "...", ...}]}

# Step 4: Fetch full email to extract verification code
GET https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id=123&sid_token=yyy
→ {"mail_body": "<html>...056153...</html>"}
```

The verification code is extracted by searching the HTML body for a styled 5-6 digit number
(`font-size:32px;font-weight:600`) that appears exactly once.

Also note: `guerrillamailblock.com` is the actual delivery domain. The web interface uses
`sharklasers.com` as an alias.

---

## 9. CSS Selector for Element Query

The element query selector in `_build_elements()` was refined through trial and error. The
final selector covers:

| Selector | Matches |
|----------|---------|
| `input` | All input fields (text, email, password, checkbox, etc.) |
| `button` | All `<button>` elements |
| `a` | All links |
| `select` | Dropdowns |
| `textarea` | Multi-line text inputs |
| `label` | Labels (to find associated inputs via `for` attribute) |
| `[role="button"]` | ARIA-styled buttons |
| `[role="link"]` | ARIA-styled links |
| `[role="combobox"]` | Autocomplete dropdowns |
| `[role="option"]` | Dropdown options |
| `[tabindex]:not([tabindex="-1"])` | Keyboard-focusable elements |
| `[onclick]` | Elements with click handlers |

---

## 10. Sensitive Data Redaction

### Symptom
Excessive logging of typed text reveals credentials in plain text.

### Fix
`cmd_type()` classifies text as "sensitive" if it either:

- Contains `@` (email addresses)
- Is >= 16 characters long (passwords, API keys, tokens)

Sensitive text is logged as `<sensitive>` instead of the actual value:

```python
label = "<sensitive>" if ("@" in text or len(text) >= 16) else text[:50]
print(f"OK typed into {index}: {label}")
```

---

## 11. Kali Externally-Managed Python Blocks Playwright Install

### Symptom
```
uv pip install --system playwright
error: The interpreter at /usr is externally managed, and indicates the following:
  To install Python packages system-wide, try apt install python3-xyz
```

### Root Cause
Kali Linux marks its system Python as externally managed to prevent pip from
overwriting system packages. The `install.sh` script called `uv pip install --system`
which fails silently (error swallowed by `2>/dev/null`).

### Fix
Install Playwright into a project-level virtual environment instead of system packages:

```bash
cd /home/pwn/swarm
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python playwright
.venv/bin/python -m playwright install chromium
```

`server/browser_tools.py` now checks for `.venv/bin/python` first before falling
back to `sys.executable`, so the MCP server spawns the correct Python for
`browser_driver.py` subprocesses.

## 12. Chrome Process Dies When Python Exits

### Symptom
After `browser_driver.py navigate ...` completes and Python exits,
the Chrome browser process is killed. The next invocation gets
"Connection refused" on port 9222 and must launch Chrome again.

### Root Cause
Playwright's `pw.chromium.launch()` spawns Chrome as a child process.
When the controlling Python process exits, Playwright's cleanup handlers
send SIGTERM to the child. Even with `--remote-debugging-port`, Chrome
does not survive.

### Fix
Launch Chrome via `subprocess.Popen` instead of Playwright's `launch()`.
This decouples the lifecycle — Chrome is an independent process:

```python
import subprocess
proc = subprocess.Popen([CHROMIUM_PATH, "--remote-debugging-port=9222", ...])
# Wait for CDP endpoint, then connect via Playwright:
pw = await async_playwright().start()
browser = await pw.chromium.connect_over_cdp(ws_url)
```

The `cmd_close()` function kills the independent process by PID (saved in
state file) and via `fuser -k PORT/tcp` as fallback.

## File Manifest

| File | Purpose |
|------|---------|
| `scripts/browser_driver.py` | Playwright-based headed browser driver (366 lines) |
| `scripts/.venv/bin/python` | Project venv Python (Playwright installed here) |
| `.mcp.json` | MCP server config (wstg, burp) |
| `plan.md` | Full engagement plan with methodology |
| `docs/fixes-and-workarounds.md` | This file |

## How to Replicate the Fixed Setup

```bash
# 0. Ensure project venv exists with Playwright
cd /home/pwn/swarm
uv venv .venv --python 3.13
uv pip install --python .venv/bin/python playwright
.venv/bin/python -m playwright install chromium

# 1. Start browser and navigate (auto-launches Chrome via subprocess.Popen)
.venv/bin/python scripts/browser_driver.py navigate "https://target.com"

# 2. Interact — each call reconnects to the persistent Chrome
.venv/bin/python scripts/browser_driver.py state --screenshot
.venv/bin/python scripts/browser_driver.py click 3
.venv/bin/python scripts/browser_driver.py type 3 "Hello World"
.venv/bin/python scripts/browser_driver.py cookies

# 3. Close browser (kills the independent Chrome process)
.venv/bin/python scripts/browser_driver.py close
```

No need to manually start Chrome — `browser_driver.py navigate` handles
everything: launches Chrome independently, waits for CDP, and connects.
The `_ensure_lib_path()` function auto-sets `LD_LIBRARY_PATH`, so no
environment setup is needed either.
```
