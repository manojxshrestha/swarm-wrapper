"""Synchronous wrapper around browser-use Browser for use by browser_tools.py.

Same persistent-browser pattern as scripts/browser_driver.py:
1. Launch Chromium via subprocess on port 9222 (if not already running)
2. Connect to it via browser-use's Browser.connect()
3. Browser persists across invocations
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

# Portable, best-effort advisory file lock (POSIX fcntl / Windows msvcrt / no-op).
try:
    import fcntl as _fcntl

    def _flock(fileobj) -> None:
        try:
            _fcntl.flock(fileobj.fileno(), _fcntl.LOCK_EX)
        except OSError:
            pass

except ImportError:  # pragma: no cover - platform-specific
    try:
        import msvcrt as _msvcrt

        def _flock(fileobj) -> None:
            try:
                _msvcrt.locking(fileobj.fileno(), _msvcrt.LK_LOCK, 1)
            except OSError:
                pass

    except ImportError:  # pragma: no cover

        def _flock(fileobj) -> None:
            pass


# Ensure Chromium can find NSS/NSPR libraries (same as browser_driver.py)
_lib_path = os.path.expanduser("~/.local/lib")
if os.path.isdir(_lib_path):
    existing = os.environ.get("LD_LIBRARY_PATH", "")
    if _lib_path not in existing:
        os.environ["LD_LIBRARY_PATH"] = f"{_lib_path}:{existing}" if existing else _lib_path

CDP_PORT = int(os.environ.get("SWARM_CDP_PORT", "9222"))
STATE_FILE = "/tmp/browser-use-backend-state.json"


def _load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        _flock(f)
        return json.load(f)


def _save_state(**kw):
    with open(STATE_FILE, "w+") as f:
        _flock(f)
        try:
            f.seek(0)
            state = json.load(f)
        except (json.JSONDecodeError, ValueError):
            state = {}
        state.update(kw)
        f.seek(0)
        f.truncate()
        json.dump(state, f)


def _clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


def _resolve_chromium():
    """Resolve Chromium path (same as browser_driver.py)."""
    import glob

    playwright_cache = os.path.expanduser("~/.cache/ms-playwright")
    matches = glob.glob(os.path.join(playwright_cache, "chromium-*/chrome-linux64/chrome"))
    if matches:
        return sorted(matches)[-1]
    import shutil

    for name in ("google-chrome", "chromium-browser", "chromium", "google-chrome-stable"):
        path = shutil.which(name)
        if path:
            return path
    return os.path.expanduser("~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome")


def _ensure_chromium():
    """Launch Chromium on CDP port if not already running."""
    state = _load_state()
    pid = state.get("pid")
    if pid:
        try:
            os.kill(pid, 0)
            urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
            return
        except Exception:
            pass

    chromium_path = _resolve_chromium()
    chrome_args = [
        chromium_path,
        f"--remote-debugging-port={CDP_PORT}",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-audio-output",
        "--window-size=1280,720",
    ]
    env = os.environ.copy()
    if sys.platform != "win32":
        # Linux/X11-only sandbox + display flags (invalid on Windows).
        chrome_args[2:2] = ["--no-sandbox", "--disable-setuid-sandbox", "--disable-zygote"]
        env["DISPLAY"] = os.environ.get("DISPLAY", ":0")
    proc = subprocess.Popen(chrome_args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for attempt in range(20):
        time.sleep(0.5)
        try:
            resp = urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
            info = json.loads(resp.read())
            ws_url = info.get("webSocketDebuggerUrl")
            if ws_url:
                _save_state(cdp_port=CDP_PORT, pid=proc.pid, ws_url=ws_url)
                return
        except Exception:
            pass

    raise RuntimeError(f"Failed to start Chromium on port {CDP_PORT}")


def _get_loop():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def _get_browser():
    """Connect to running Chromium via browser-use Browser."""
    from browser_use import Browser as BUBrowser

    state = _load_state()
    ws_url = state.get("ws_url", f"http://127.0.0.1:{CDP_PORT}")
    loop = _get_loop()
    browser = BUBrowser(headless=False, keep_alive=True)
    loop.run_until_complete(browser.connect(cdp_url=ws_url))
    return browser, loop


def navigate(url: str, wait_sec: int = 3) -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        loop.run_until_complete(browser.navigate_to(url))
        if wait_sec > 0:
            loop.run_until_complete(asyncio.sleep(wait_sec))
        return "ok"
    finally:
        loop.run_until_complete(browser.stop())


def get_state(include_screenshot: bool = False) -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        summary = loop.run_until_complete(browser.get_browser_state_summary(include_screenshot=include_screenshot))
        url = summary.url
        title = summary.title
        screenshot_b64 = summary.screenshot or ""

        elements = []
        if summary.dom_state and summary.dom_state.selector_map:
            for idx, node in sorted(summary.dom_state.selector_map.items()):
                el = {
                    "index": idx,
                    "tag": getattr(node, "node_name", "") or "",
                    "type": (node.attributes or {}).get("type", ""),
                    "name": (node.attributes or {}).get("name", ""),
                    "id": (node.attributes or {}).get("id", ""),
                    "class": (node.attributes or {}).get("class", ""),
                    "placeholder": (node.attributes or {}).get("placeholder", ""),
                    "text": getattr(node, "node_value", "") or "",
                    "label": (node.attributes or {}).get("aria-label", ""),
                }
                elements.append(el)

        result = {
            "url": url,
            "title": title,
            "viewport": {},
            "page_size": {},
            "scroll": {},
            "interactive_elements": elements,
        }

        result_json = json.dumps(result)
        if include_screenshot and screenshot_b64:
            return result_json + f"\n---IMAGE---\n{screenshot_b64}\n---END IMAGE---\n"
        return result_json
    finally:
        loop.run_until_complete(browser.stop())


def click(index: int) -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        node = loop.run_until_complete(browser.get_element_by_index(index))
        if node is None:
            raise RuntimeError(f"No element at index {index}")
        page = loop.run_until_complete(browser.must_get_current_page())
        el = loop.run_until_complete(page.get_element(node.backend_node_id))
        loop.run_until_complete(el.click())
        return "ok"
    finally:
        loop.run_until_complete(browser.stop())


def type_text(index: int, text: str) -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        node = loop.run_until_complete(browser.get_element_by_index(index))
        if node is None:
            raise RuntimeError(f"No element at index {index}")
        page = loop.run_until_complete(browser.must_get_current_page())
        el = loop.run_until_complete(page.get_element(node.backend_node_id))
        loop.run_until_complete(el.fill(text))
        return "ok"
    finally:
        loop.run_until_complete(browser.stop())


def run_js(code: str) -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        page = loop.run_until_complete(browser.must_get_current_page())
        result = loop.run_until_complete(page.evaluate(code))
        return str(result)
    finally:
        loop.run_until_complete(browser.stop())


def take_screenshot() -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        png_bytes = loop.run_until_complete(browser.take_screenshot())
        b64 = base64.b64encode(png_bytes).decode()
        return f"---IMAGE---\n{b64}\n---END IMAGE---\n"
    finally:
        loop.run_until_complete(browser.stop())


def get_cookies() -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        cookies = loop.run_until_complete(browser.cookies())
        return json.dumps(cookies)
    finally:
        loop.run_until_complete(browser.stop())


def get_html() -> str:
    _ensure_chromium()
    browser, loop = _get_browser()
    try:
        page = loop.run_until_complete(browser.must_get_current_page())
        html = loop.run_until_complete(page.evaluate("() => document.documentElement.outerHTML"))
        return html
    finally:
        loop.run_until_complete(browser.stop())


def close_browser() -> str:
    state = _load_state()
    pid = state.get("pid")
    if pid:
        try:
            os.kill(pid, 15)
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.3)
                except OSError:
                    break
            os.kill(pid, 9)
        except Exception:
            pass
    _clear_state()
    return "closed"


def _is_dialog_msg(raw: str | bytes) -> bool:
    """True if a raw CDP message is a Page.javascriptDialogOpening event."""
    try:
        return json.loads(raw).get("method") == "Page.javascriptDialogOpening"
    except (json.JSONDecodeError, ValueError, AttributeError):
        return False


def capture_js_dialog(url: str, wait_sec: int = 5) -> bool:
    """Navigate `url` and report whether a JS dialog (alert/confirm/prompt)
    fired — real evidence an XSS payload executed, to back mark_browser_verified.

    Best-effort: returns False on any failure so it can never break the gate.
    ponytail: raw page-level CDP via websockets (a browser-use runtime dep);
    swap for browser-use's event API if it later exposes dialog events.
    """
    try:
        import asyncio

        import websockets  # provided at runtime by the browser-use stack

        _ensure_chromium()
        pages = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json", timeout=2).read())
        ws = next((p["webSocketDebuggerUrl"] for p in pages if p.get("type") == "page"), None)
        if not ws:
            return False

        async def _watch() -> bool:
            async with websockets.connect(ws, max_size=None) as c:
                await c.send(json.dumps({"id": 1, "method": "Page.enable"}))
                await c.send(json.dumps({"id": 2, "method": "Page.navigate", "params": {"url": url}}))
                try:
                    while True:
                        raw = await asyncio.wait_for(c.recv(), timeout=wait_sec)
                        if _is_dialog_msg(raw):
                            await c.send(json.dumps({"id": 3, "method": "Page.handleJavaScriptDialog", "params": {"accept": True}}))
                            return True
                except asyncio.TimeoutError:
                    return False

        return asyncio.new_event_loop().run_until_complete(_watch())
    except Exception:
        return False


COMMANDS = {
    "navigate": lambda args: navigate(args[0], int(args[1]) if len(args) > 1 else 3),
    "dialog": lambda args: str(capture_js_dialog(args[0], int(args[1]) if len(args) > 1 else 5)),
    "state": lambda args: get_state("--screenshot" in args),
    "click": lambda args: click(int(args[0])),
    "type": lambda args: type_text(int(args[0]), " ".join(args[1:])),
    "js": lambda args: run_js(" ".join(args)),
    "screenshot": lambda args: take_screenshot(),
    "cookies": lambda args: get_cookies(),
    "html": lambda args: get_html(),
    "close": lambda args: close_browser(),
}


def main():
    if len(sys.argv) < 2:
        print("Usage: browser_use_backend.py <command> [args...]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]

    if command not in COMMANDS:
        print(f"Unknown command: {command}", file=sys.stderr)
        print(f"Available: {', '.join(sorted(COMMANDS.keys()))}", file=sys.stderr)
        sys.exit(1)

    try:
        result = COMMANDS[command](args)
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
