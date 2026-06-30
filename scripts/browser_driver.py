#!/usr/bin/env python
"""browser_driver.py — Drive a headed Chromium browser via Playwright (DEPRECATED).

⚠️  DEPRECATED — This is the LEGACY browser backend. Use the browser-use MCP tools
   in server/browser_tools.py instead (browser_analyze, browser_act, etc.).
   Kept for backwards compatibility with auto_auth.py.

Persists browser via fixed CDP port (9222) so commands survive across invocations.

Usage:
  python browser_driver.py start                     # Start browser (headed)
  python browser_driver.py navigate <url> [--wait N] # Navigate to URL
  python browser_driver.py state [--screenshot]       # Page state + screenshot
  python browser_driver.py click <index>              # Click element by index
  python browser_driver.py click_at <x> <y>           # Click at viewport coords
  python browser_driver.py type <index> <text>        # Type into element
  python browser_driver.py scroll <up|down> [px]      # Scroll page
  python browser_driver.py screenshot [--full]        # Take screenshot (base64)
  python browser_driver.py html [selector]            # Get page HTML
  python browser_driver.py js <code>                  # Execute JavaScript
  python browser_driver.py cookies                    # Get cookies
  python browser_driver.py close                      # Close browser
"""

import asyncio
import base64
import glob as _glob
import json
import os
import shutil
import subprocess
import sys

CDP_PORT = int(os.environ.get("SWARM_CDP_PORT", "9222"))
CDP_URL = f"http://127.0.0.1:{CDP_PORT}"
WS_URL = f"ws://127.0.0.1:{CDP_PORT}/devtools/browser"


# FIX #5: Dynamic Chromium path instead of hardcoded chromium-1223
def _resolve_chromium_path() -> str:
    """Resolve Playwright Chromium path dynamically.
    Tries Playwright's cache directory, then falls back to PATH.
    """
    playwright_cache = os.path.expanduser("~/.cache/ms-playwright")
    matches = _glob.glob(os.path.join(playwright_cache, "chromium-*/chrome-linux64/chrome"))
    if matches:
        return sorted(matches)[-1]
    for name in ("google-chrome", "chromium-browser", "chromium", "google-chrome-stable"):
        path = shutil.which(name)
        if path:
            return path
    return os.path.expanduser("~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome")


CHROMIUM_PATH = _resolve_chromium_path()
# END FIX #5
STATE_FILE = f"/tmp/browser-driver-state-{os.getpid()}.json"


# ── State ─────────────────────────────────────────────────────────────────

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(**kw):
    state = load_state()
    state.update(kw)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


# ── Library path helper ───────────────────────────────────────────────────

def _ensure_lib_path():
    """Add ~/.local/lib to LD_LIBRARY_PATH so Chromium can find NSS/NSPR libs."""
    lib_path = os.path.expanduser("~/.local/lib")
    if os.path.isdir(lib_path):
        existing = os.environ.get("LD_LIBRARY_PATH", "")
        paths = [p for p in existing.split(":") if p] if existing else []
        if lib_path not in paths:
            paths.insert(0, lib_path)
        os.environ["LD_LIBRARY_PATH"] = ":".join(paths)


# ── Browser lifecycle ─────────────────────────────────────────────────────

_playwright = None
_browser = None
_context = None
_page = None


async def _ensure_browser():
    """Connect to existing headed browser or start a new one."""
    global _playwright, _browser, _context, _page

    # Ensure Playwright can find NSS/NSPR shared libraries
    _ensure_lib_path()

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("ERROR: playwright Python package not installed.", file=sys.stderr)
        print("Run: pip install playwright && python -m playwright install chromium", file=sys.stderr)
        sys.exit(1)

    # If we have a live connection, use it
    if _browser and _browser.is_connected():
        try:
            pages = _context.pages if _context else []
            if pages:
                _page = pages[0]
                return
        except Exception:
            pass

    # Try connecting to existing browser on CDP port
    # First discover the WebSocket URL from the browser's debug endpoint
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=3)
        info = json.loads(resp.read())
        ws_url = info.get("webSocketDebuggerUrl")
        if ws_url:
            pw = await async_playwright().start()
            _browser = await pw.chromium.connect_over_cdp(ws_url)
            _context = _browser.contexts[0] if _browser.contexts else await _browser.new_context()
            _page = (_context.pages[0] if _context.pages else await _context.new_page())
            _playwright = pw
            print("[session] Reconnected to headed browser", file=sys.stderr)
            return
    except Exception as e:
        if _playwright:
            try:
                await _playwright.stop()
            except Exception:
                pass
            _playwright = None
        print(f"[session] No existing browser ({e})", file=sys.stderr)

    # Launch Chrome as an independent process (survives Python exit)
    _ensure_lib_path()
    import subprocess
    chrome_args = [
        CHROMIUM_PATH,
        f"--remote-debugging-port={CDP_PORT}",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-zygote",
        "--disable-audio-output",
        "--window-size=1280,720",
    ]
    env = os.environ.copy()
    env["DISPLAY"] = os.environ.get("DISPLAY", ":0")
    proc = subprocess.Popen(chrome_args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

    # Wait for CDP endpoint to become available
    import urllib.request
    for attempt in range(20):
        await asyncio.sleep(0.5)
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
            info = json.loads(resp.read())
            ws_url = info.get("webSocketDebuggerUrl")
            if ws_url:
                pw = await async_playwright().start()
                _browser = await pw.chromium.connect_over_cdp(ws_url)
                _context = _browser.contexts[0] if _browser.contexts else await _browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )
                _page = (_context.pages[0] if _context.pages else await _context.new_page())
                _playwright = pw
                save_state(cdp_port=CDP_PORT, pid=proc.pid)
                print(f"[session] Started headed browser (PID {proc.pid})", file=sys.stderr)
                return
        except Exception:
            pass
    raise RuntimeError(f"Chrome failed to start on port {CDP_PORT} after 10 seconds")


async def _build_elements(page):
    """Get interactive elements from the page (async)."""
    elements = []
    try:
        result = await page.evaluate("""() => {
            const sel = 'input, button, a, select, textarea, label, ' +
                '[role="button"], [role="link"], [role="combobox"], [role="option"], ' +
                '[tabindex]:not([tabindex="-1"]), [onclick]';
            const all = document.querySelectorAll(sel);
            const items = [];
            let idx = 1;
            all.forEach(el => {
                const tag = el.tagName.toLowerCase();
                const text = (el.textContent || '').trim().substring(0, 100);
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) return;
                if (rect.top > window.innerHeight + 50 || rect.bottom < -50) return;
                const attrs = {};
                ['placeholder','href','type','name','value','aria-label','role',
                 'class','id','data-testid','title','alt','for'].forEach(a => {
                    const v = el.getAttribute(a);
                    if (v) attrs[a] = v.substring(0, 80);
                });
                items.push({
                    index: idx++,
                    tag, text, ...attrs,
                    rect: {top: Math.round(rect.top), left: Math.round(rect.left),
                           width: Math.round(rect.width), height: Math.round(rect.height)},
                    center: {x: Math.round(rect.left + rect.width/2),
                             y: Math.round(rect.top + rect.height/2)},
                });
            });
            return items;
        }""")
        elements = result or []
    except Exception as e:
        print(f"[warn] build_elements: {e}", file=sys.stderr)
    return elements


# ── Commands ──────────────────────────────────────────────────────────────

async def cmd_start(args):
    await _ensure_browser()
    print("OK browser started")


async def cmd_navigate(args):
    await _ensure_browser()
    url = args[0]
    wait = 3
    for a in args:
        if a.startswith("--wait="):
            wait = float(a.split("=")[1])
    # Wait for page to be fully loaded — networkidle ensures SPAs hydrate
    try:
        resp = await _page.goto(url, wait_until="load", timeout=30000)
        await asyncio.sleep(1)
        # Wait for network idle (SPAs finish async requests)
        await _page.wait_for_load_state("networkidle", timeout=15000)
        # Extra wait for JS rendering
        await asyncio.sleep(wait)
        print(f"OK navigated {url}")
        print(f"Status: {resp.status if resp else 'N/A'}")
    except Exception as e:
        print(f"WARN goto: {e}")
        # Even if timeout, wait for page to settle
        await asyncio.sleep(max(wait, 3))
        # Check if we got a page anyway
        try:
            title = await _page.title()
            print(f"OK navigated {url} (title: {title[:60]})")
        except Exception:
            print(f"OK navigated {url} (maybe)")


async def cmd_state(args):
    await _ensure_browser()
    inc_ss = "--screenshot" in args
    try:
        url = _page.url
    except Exception:
        url = "unknown"
    # Handle Cloudflare challenge pages — wait for them to pass
    for _ in range(10):
        try:
            html_sample = await _page.evaluate("document.body?.innerHTML?.substring(0,200) || ''")
            if "checking your browser" in html_sample.lower() or "cloudflare" in html_sample.lower() and "ray" in html_sample.lower():
                print("[browser] Cloudflare challenge — waiting 3s...", file=sys.stderr)
                await asyncio.sleep(3)
                continue
        except Exception:
            pass
        break
    title = await _page.title()
    viewport = await _page.evaluate("({w: innerWidth, h: innerHeight})")
    scroll = await _page.evaluate("({x: pageXOffset, y: pageYOffset})")
    page_size = await _page.evaluate("({w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight})")
    elements = await _build_elements(_page)
    result = {"url": url, "title": title, "viewport": viewport,
              "page_size": page_size, "scroll": scroll,
              "interactive_elements": elements}
    print(json.dumps(result, indent=2))
    if inc_ss:
        data = await _page.screenshot(full_page=False, type="png")
        print("---SCREENSHOT---")
        print(base64.b64encode(data).decode())
        print("---END SCREENSHOT---")


async def cmd_click(args):
    await _ensure_browser()
    index = int(args[0])
    elements = await _build_elements(_page)
    target = next((e for e in elements if e.get("index") == index), None)
    if not target:
        print(f"ERROR element {index} not found ({len(elements)} available)")
        return
    cx, cy = target["center"]["x"], target["center"]["y"]
    await _page.mouse.click(cx, cy)
    await asyncio.sleep(1.5)
    print(f"OK clicked element {index} ({target['tag']}: {target.get('text','')[:40]})")


async def cmd_click_at(args):
    await _ensure_browser()
    x, y = int(args[0]), int(args[1])
    await _page.mouse.click(x, y)
    await asyncio.sleep(1.5)
    print(f"OK clicked at ({x}, {y})")


async def cmd_type(args):
    await _ensure_browser()
    index = int(args[0])
    text = " ".join(args[1:])
    elements = await _build_elements(_page)
    target = next((e for e in elements if e.get("index") == index), None)
    if not target:
        print(f"ERROR element {index} not found")
        return
    tx, ty = target["center"]["x"], target["center"]["y"]
    await _page.mouse.click(tx, ty)
    await asyncio.sleep(0.3)
    await _page.keyboard.press("Control+a")
    await asyncio.sleep(0.1)
    await _page.keyboard.press("Delete")
    await asyncio.sleep(0.1)
    await _page.keyboard.type(text, delay=50)
    await asyncio.sleep(0.3)
    label = "<sensitive>" if ("@" in text or len(text) >= 16) else text[:50]
    print(f"OK typed into {index}: {label}")


async def cmd_scroll(args):
    await _ensure_browser()
    direction = args[0] if args else "down"
    amount = int(args[1]) if len(args) > 1 else 500
    dy = -amount if direction == "up" else amount
    await _page.evaluate(f"window.scrollBy(0, {dy})")
    await asyncio.sleep(0.3)
    print(f"OK scrolled {direction} {amount}px")


async def cmd_screenshot(args):
    await _ensure_browser()
    full = "--full" in args
    data = await _page.screenshot(full_page=full, type="png")
    print(f"Screenshot: {len(data)} bytes")
    print("---IMAGE---")
    print(base64.b64encode(data).decode())
    print("---END IMAGE---")


async def cmd_html(args):
    await _ensure_browser()
    sel = args[0] if args else None
    if sel:
        html = await _page.evaluate("""(s) => {
            const el = document.querySelector(s);
            return el ? el.outerHTML : null;
        }""", sel)
    else:
        html = await _page.content()
    print(html[:10000] if html else "No content")


async def cmd_js(args):
    await _ensure_browser()
    code = " ".join(args)
    try:
        result = await _page.evaluate(code)
        print(json.dumps(result, indent=2, default=str) if result is not None else "undefined")
    except Exception as e:
        print(f"ERROR: {e}")


async def cmd_cookies(args):
    await _ensure_browser()
    c = await _context.cookies()
    print(json.dumps(c, indent=2, default=str))


async def cmd_close(args):
    global _playwright, _browser, _context, _page
    # Close Playwright CDP connection
    if _browser:
        try:
            await _browser.close()
        except Exception:
            pass
    if _playwright:
        try:
            await _playwright.stop()
        except Exception:
            pass
    _playwright = _browser = _context = _page = None
    # Kill the independent Chrome process (any process on our CDP port)
    import urllib.request
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
        info = json.loads(resp.read())
        # Close via CDP first
        for ws_url in [info.get("webSocketDebuggerUrl")]:
            if ws_url:
                break
    except Exception:
        pass
    # Kill Chrome by PID from state file
    state = load_state()
    state_pid = state.get("pid", 0)
    if state_pid:
        try:
            os.kill(state_pid, 9)
        except (OSError, ProcessLookupError):
            pass
    try:
        lsof_out = subprocess.check_output(["lsof", "-ti", f":{CDP_PORT}"], stderr=subprocess.DEVNULL, timeout=5)
        pids = [int(p) for p in lsof_out.decode().strip().split() if p]
        for pid in pids:
            os.kill(pid, 9)
    except Exception:
        pass
    clear_state()
    print("OK browser closed")


# ── Main ──────────────────────────────────────────────────────────────────

async def main():
    if len(sys.argv) < 2:
        print("Usage: browser_driver.py <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    cmds = {
        "start": cmd_start, "navigate": cmd_navigate, "state": cmd_state,
        "click": cmd_click, "click_at": cmd_click_at, "type": cmd_type,
        "scroll": cmd_scroll, "screenshot": cmd_screenshot, "html": cmd_html,
        "js": cmd_js, "cookies": cmd_cookies, "close": cmd_close,
    }

    if cmd not in cmds:
        print(f"Unknown: {cmd}. Available: {', '.join(cmds.keys())}")
        sys.exit(1)

    try:
        await cmds[cmd](args)
    except Exception as e:
        import traceback
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
