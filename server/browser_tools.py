"""Swarm browser automation MCP tools.

Uses **browser-use** (Browser class) for browser operations and **opencode AI**
as the decision-maker (via browser-auth subagent). The browser persists across
calls via CDP on port 9222.

Tools:
  browser_analyze     — LLM-friendly page analysis (screenshot + text + elements)
  browser_act         — Low-level browser actions (navigate, click, type, js)
  browser_login       — Auth flow automation with cookie persistence
  browser_auto_auth   — Autonomous signup/verify/login via auto_auth.py
  browser_screenshot  — Evidence screenshot capture
  browser_crawl       — SPA route discovery via link crawling
  browser_extract_storage — Cookie/localStorage/sessionStorage extraction
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

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

_SERVER_DIR = Path(__file__).parent
_REPO_ROOT = _SERVER_DIR.parent
_ENGAGEMENTS_DIR = _REPO_ROOT / "engagements"

HEADLESS_DEFAULT = os.environ.get("SWARM_BROWSER_HEADLESS", "true").lower() == "true"

# --- Chromium process management (same pattern as browser_driver.py) ---

_LIB_PATH = str(Path.home() / ".local" / "lib")
if os.path.isdir(_LIB_PATH):
    existing = os.environ.get("LD_LIBRARY_PATH", "")
    if _LIB_PATH not in existing:
        os.environ["LD_LIBRARY_PATH"] = f"{_LIB_PATH}:{existing}" if existing else _LIB_PATH

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
    """Launch Chromium subprocess on CDP port if not already running."""
    state = _load_state()
    pid = state.get("pid")
    if pid:
        try:
            os.kill(pid, 0)
            import urllib.request

            urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
            return
        except Exception:
            pass

    chromium_path = _resolve_chromium()
    chrome_args = [
        chromium_path,
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
    proc = subprocess.Popen(chrome_args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    import urllib.request

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


def _close_chromium():
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
            else:
                os.kill(pid, 9)
        except Exception:
            pass
    _clear_state()


# --- Browser-use singleton management ---

_BROWSER = None
_LOOP = None


def _get_loop():
    global _LOOP
    if _LOOP is None or _LOOP.is_closed():
        _LOOP = asyncio.new_event_loop()
        asyncio.set_event_loop(_LOOP)
    return _LOOP


def _ensure_browser():
    """Get or create browser-use Browser connected to the persistent Chromium."""
    global _BROWSER
    _ensure_chromium()
    if _BROWSER is None:
        from browser_use import Browser as BUBrowser

        state = _load_state()
        ws_url = state.get("ws_url", f"http://127.0.0.1:{CDP_PORT}")
        _BROWSER = BUBrowser(headless=False, keep_alive=True)
        _get_loop().run_until_complete(_BROWSER.connect(cdp_url=ws_url))
        _get_loop().run_until_complete(_BROWSER.attach_all_watchdogs())
    return _BROWSER


def _reset_browser():
    global _BROWSER
    if _BROWSER is not None:
        loop = _get_loop()
        try:
            loop.run_until_complete(_BROWSER.close())
        except Exception:
            pass
        _BROWSER = None


# --- Shared helpers ---


def _engagement_dir(engagement_id: str) -> Path:
    safe = "".join(c for c in engagement_id if c.isalnum() or c in "._-").rstrip(".")[:100]
    if not safe:
        raise ValueError(f"Invalid engagement_id: {engagement_id!r}")
    return _ENGAGEMENTS_DIR / safe


def _get_headless() -> bool:
    if HEADLESS_DEFAULT:
        return True
    return False


def _state_to_elements(summary) -> list[dict]:
    """Convert browser-use BrowserStateSummary to our element list format."""
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
                "value": (node.attributes or {}).get("value", ""),
                "role": (node.attributes or {}).get("role", ""),
            }
            elements.append(el)
    return elements


def _get_state(include_screenshot: bool = False) -> tuple[dict, str | None]:
    """Get browser state via browser-use. Returns (state_dict, screenshot_b64_or_None)."""
    b = _ensure_browser()
    loop = _get_loop()
    summary = loop.run_until_complete(b.get_browser_state_summary(include_screenshot=include_screenshot))
    elements = _state_to_elements(summary)
    state = {
        "url": summary.url,
        "title": summary.title,
        "viewport": {},
        "page_size": {},
        "scroll": {},
        "interactive_elements": elements,
    }
    return state, summary.screenshot


def _ensure_selector_map():
    """Ensure the selector map is populated by triggering a DOM scan."""
    b = _ensure_browser()
    loop = _get_loop()
    loop.run_until_complete(b.get_browser_state_summary(include_screenshot=False))


def _click_element(index: int) -> str:
    """Click an element by its highlight index."""
    b = _ensure_browser()
    loop = _get_loop()
    node = loop.run_until_complete(b.get_element_by_index(index))
    if node is None:
        raise RuntimeError(f"No element at index {index}")
    page = loop.run_until_complete(b.must_get_current_page())
    el = loop.run_until_complete(page.get_element(node.backend_node_id))
    loop.run_until_complete(el.click())
    return "ok"


def _type_text(index: int, text: str) -> str:
    """Type text into an element by its highlight index."""
    b = _ensure_browser()
    loop = _get_loop()
    node = loop.run_until_complete(b.get_element_by_index(index))
    if node is None:
        raise RuntimeError(f"No element at index {index}")
    page = loop.run_until_complete(b.must_get_current_page())
    el = loop.run_until_complete(page.get_element(node.backend_node_id))
    loop.run_until_complete(el.fill(text))
    return "ok"


def _run_js(code: str) -> str:
    """Execute JavaScript in the current page."""
    b = _ensure_browser()
    loop = _get_loop()
    page = loop.run_until_complete(b.must_get_current_page())
    if not code.strip().startswith("("):
        code = f"() => {code}"
    result = loop.run_until_complete(page.evaluate(code))
    return str(result)


def _get_cookies() -> list[dict]:
    """Get all browser cookies."""
    b = _ensure_browser()
    loop = _get_loop()
    return loop.run_until_complete(b.cookies())


def _get_screenshot() -> bytes:
    """Take a screenshot and return raw PNG bytes."""
    b = _ensure_browser()
    loop = _get_loop()
    return loop.run_until_complete(b.take_screenshot())


def _navigate(url: str, wait_sec: int = 3):
    """Navigate to a URL."""
    b = _ensure_browser()
    loop = _get_loop()
    loop.run_until_complete(b.navigate_to(url))
    if wait_sec > 0:
        loop.run_until_complete(asyncio.sleep(wait_sec))


def _get_html() -> str:
    """Get the outerHTML of the current page."""
    b = _ensure_browser()
    loop = _get_loop()
    page = loop.run_until_complete(b.must_get_current_page())
    return loop.run_until_complete(page.evaluate("() => document.documentElement.outerHTML"))


def _find_field(elements: list, field_type: str, hint: str = "") -> int | None:
    """Find interactive element index by field type and optional hint."""
    if field_type == "username":
        if hint:
            hl = hint.lower()
            for el in elements:
                for attr in ("id", "name", "placeholder", "label", "class"):
                    if hl in el.get(attr, "").lower():
                        return el["index"]
        for el in elements:
            t = el.get("tag", "")
            type_ = el.get("type", "")
            placeholder = el.get("placeholder", "").lower()
            name = el.get("name", "").lower()
            text = el.get("text", "").lower()
            aria = el.get("label", "").lower()
            if t == "input" and type_ == "email":
                return el["index"]
            if t == "input" and type_ == "text" and any(k in name or k in (el.get("id", "").lower()) for k in ("user", "login", "email", "account")):
                return el["index"]
            if any(k in placeholder for k in ("email", "username", "user id", "login", "account")):
                return el["index"]
            if any(k in aria for k in ("email", "username", "user", "login")):
                return el["index"]
            if any(k in text for k in ("username", "email", "user id")):
                return el["index"]

    elif field_type == "password":
        if hint:
            hl = hint.lower()
            for el in elements:
                for attr in ("id", "name", "placeholder", "label", "class"):
                    if hl in el.get(attr, "").lower():
                        return el["index"]
        for el in elements:
            t = el.get("tag", "")
            type_ = el.get("type", "")
            placeholder = el.get("placeholder", "").lower()
            aria = el.get("label", "").lower()
            if t == "input" and type_ == "password":
                return el["index"]
            if "password" in placeholder:
                return el["index"]
            if "password" in aria:
                return el["index"]

    elif field_type == "submit":
        if hint:
            hl = hint.lower()
            for el in elements:
                for attr in ("id", "text", "label", "class", "value"):
                    if hl in el.get(attr, "").lower():
                        return el["index"]
        for el in elements:
            t = el.get("tag", "")
            type_ = el.get("type", "")
            text = el.get("text", "").lower()
            aria = el.get("label", "").lower()
            value = el.get("value", "").lower()
            role = el.get("role", "").lower()
            if t == "button" and type_ == "submit":
                return el["index"]
            if t == "input" and type_ == "submit":
                return el["index"]
            if t == "button" and any(
                k in text
                for k in (
                    "sign in",
                    "log in",
                    "login",
                    "sign-in",
                    "log-in",
                    "signin",
                    "continue",
                    "submit",
                    "create account",
                    "register",
                    "create",
                )
            ):
                return el["index"]
            if role == "button" and any(k in text for k in ("sign in", "log in", "login", "continue", "submit")):
                return el["index"]
            if any(k in aria for k in ("sign in", "log in", "login", "submit", "continue")):
                return el["index"]
            if any(k in value for k in ("sign in", "log in", "login", "continue", "submit")):
                return el["index"]

    return None


# ── MCP Tools ───────────────────────────────────────────────────────


def browser_login(
    engagement_id: str,
    agent_id: str,
    url: str,
    username: str = "",
    password: str = "",
    username_field: str = "",
    password_field: str = "",
    submit_field: str = "",
    wait_for: str = "",
) -> str:
    """Log in to a target application using browser automation.

    Navigates to the login URL, fills credentials (auto-detecting form fields),
    submits, and saves cookies to the agent's cookie jar.

    Args:
        engagement_id: The engagement identifier
        agent_id: Subagent identifier (e.g., 'auth-agent', 'xss-agent')
        url: The login page URL
        username: Login username or email
        password: Login password
        username_field: Optional CSS selector or label text for the username field (auto-detected if empty)
        password_field: Optional CSS selector or label text for the password field (auto-detected if empty)
        submit_field: Optional CSS selector or label text for the submit button (auto-detected if empty)
        wait_for: Optional CSS selector to wait for after successful login
    """
    runtime_dir = _engagement_dir(engagement_id) / "runtime" / engagement_id
    runtime_dir.mkdir(parents=True, exist_ok=True)
    cookie_jar = str(runtime_dir / f"cookies-{agent_id}.json")

    _navigate(url)
    state, _ = _get_state(include_screenshot=False)
    elements = state.get("interactive_elements", [])

    idx = _find_field(elements, "username", hint=username_field)
    if idx is not None and username:
        _type_text(idx, username)
        time.sleep(0.5)

    idx = _find_field(elements, "password", hint=password_field)
    if idx is not None and password:
        _type_text(idx, password)
        time.sleep(0.5)

    idx = _find_field(elements, "submit", hint=submit_field)
    if idx is not None:
        _click_element(idx)
        time.sleep(3)
    else:
        time.sleep(2)

    if wait_for:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                result = _run_js(f"document.querySelector({json.dumps(wait_for)}) !== null")
                if result.strip().strip('"') == "true":
                    break
            except Exception:
                pass
            time.sleep(1)

    state, _ = _get_state(include_screenshot=False)
    page_title = state.get("title", "")
    current_url = state.get("url", url)

    cookies = _get_cookies()
    cookie_count = len(cookies)
    Path(cookie_jar).write_text(json.dumps(cookies, indent=2))

    return f"## Login: {page_title}\n\n- **URL:** {current_url}\n- **Cookies saved:** {cookie_count}\n- **Cookie jar:** `{cookie_jar}`\n"


def browser_screenshot(
    engagement_id: str,
    agent_id: str,
    url: str,
    full_page: bool = False,
    label: str = "",
) -> str:
    """Take a screenshot of a web page for evidence collection.

    Saves the screenshot to engagements/runtime/{engagement_id}/evidence/.
    Returns the file path and page metadata.

    Args:
        engagement_id: The engagement identifier
        agent_id: Subagent identifier
        url: The URL to screenshot
        full_page: Whether to capture the full scrollable page
        label: Optional label for the filename (e.g., 'login-page', 'config-leak')
    """
    runtime_dir = _engagement_dir(engagement_id) / "runtime" / engagement_id
    evidence_dir = runtime_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    safe_label = "".join(c for c in (label or agent_id) if c.isalnum() or c in "-_").rstrip("._-")[:50]
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{safe_label}-{timestamp}.png"
    output_path = evidence_dir / filename

    _navigate(url)

    png_bytes = _get_screenshot()
    output_path.write_bytes(png_bytes)

    state, _ = _get_state(include_screenshot=False)
    page_title = state.get("title", "")
    cookies = _get_cookies()

    return (
        f"## Screenshot: {page_title}\n\n"
        f"- **URL:** {url}\n"
        f"- **File:** `{output_path}`\n"
        f"- **Page title:** {page_title}\n"
        f"- **Cookies:** {len(cookies)}\n"
        f"- **Full page:** {full_page}\n"
        f"\nUse this screenshot as evidence in `log_finding()` calls."
    )


def browser_crawl(
    engagement_id: str,
    start_url: str,
    depth: int = 2,
    agent_id: str = "crawler",
) -> str:
    """Crawl a web application to discover pages and endpoints.

    Uses Playwright to navigate and follow links, capturing discovered URLs.
    Results can be fed into `prioritize_endpoints()` for risk scoring.

    Args:
        engagement_id: The engagement identifier
        start_url: The starting URL for crawling
        depth: Maximum crawl depth (default 2)
        agent_id: Subagent identifier (default 'crawler')
    """
    runtime_dir = _engagement_dir(engagement_id) / "runtime" / engagement_id
    runtime_dir.mkdir(parents=True, exist_ok=True)
    safe_url = start_url.replace("://", "-").replace("/", "-")[:80]
    output_path = runtime_dir / "evidence" / f"crawl-{safe_url}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    discovered: set[str] = set()
    visited: set[str] = set()

    def _get_links() -> set[str]:
        raw = _run_js("Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h.startsWith('http'))")
        if raw and raw != "undefined":
            try:
                return set(json.loads(raw))
            except json.JSONDecodeError:
                pass
        return set()

    _navigate(start_url)
    visited.add(start_url)
    links = _get_links()
    discovered.update(links)

    if depth > 1:
        for link in sorted(links)[:30]:
            if link not in visited and link.startswith(("http://", "https://")):
                try:
                    _navigate(link, wait_sec=2)
                    visited.add(link)
                    sub_links = _get_links()
                    discovered.update(sub_links)
                except Exception:
                    pass

    result = {
        "start_url": start_url,
        "depth": depth,
        "discovered_count": len(discovered),
        "visited_count": len(visited),
        "urls": sorted(discovered),
    }
    output_path.write_text(json.dumps(result, indent=2))

    lines = [
        f"## Crawl Results: {start_url}",
        "",
        f"- **Depth:** {depth}",
        f"- **URLs discovered:** {result['discovered_count']}",
        f"- **URLs visited:** {result['visited_count']}",
        "",
        "### Discovered URLs",
    ]
    for u in sorted(discovered)[:50]:
        lines.append(f"- {u}")
    lines.append("")
    lines.append(f"Full results saved to: `{output_path}`")
    lines.append("")
    lines.append("Use `prioritize_endpoints()` to score and rank these URLs for testing.")

    return "\n".join(lines)


def browser_extract_storage(
    engagement_id: str,
    agent_id: str,
    url: str,
) -> str:
    """Extract cookies, localStorage, and sessionStorage from a web page.

    Useful for examining JWT tokens, OAuth state, session identifiers,
    and client-side storage during auth/SSO testing.

    Args:
        engagement_id: The engagement identifier
        agent_id: Subagent identifier
        url: The URL to extract storage from
    """
    runtime_dir = _engagement_dir(engagement_id) / "runtime" / engagement_id
    runtime_dir.mkdir(parents=True, exist_ok=True)
    output_path = runtime_dir / "evidence" / f"storage-{agent_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    _navigate(url)

    cookies = _get_cookies()

    try:
        raw = _run_js("JSON.parse(JSON.stringify(localStorage))")
        local_storage = json.loads(raw) if raw.strip() not in ("", "undefined", "null") else {}
    except (json.JSONDecodeError, RuntimeError):
        local_storage = {}

    try:
        raw = _run_js("JSON.parse(JSON.stringify(sessionStorage))")
        session_storage = json.loads(raw) if raw.strip() not in ("", "undefined", "null") else {}
    except (json.JSONDecodeError, RuntimeError):
        session_storage = {}

    result = {
        "cookies": cookies,
        "localStorage": local_storage,
        "sessionStorage": session_storage,
    }
    output_path.write_text(json.dumps(result, indent=2))

    cookie_summary = "\n".join(f"  - `{c['name']}` ({c.get('domain', '')})" for c in cookies[:20])

    return (
        f"## Storage Extraction: {url}\n\n"
        f"- **Cookies:** {len(cookies)}\n"
        f"- **localStorage keys:** {len(local_storage)}\n"
        f"- **sessionStorage keys:** {len(session_storage)}\n"
        f"\n### Cookies\n{cookie_summary}\n"
        f"\nFull storage dump saved to: `{output_path}`\n"
        f"\nUse this data for JWT analysis, OAuth token inspection, and SSO flow testing."
    )


# ── Autonomous browser auth (signup → verify → login) ──────────────

_AUTO_AUTH_SCRIPT = _REPO_ROOT / "scripts" / "tools" / "auto_auth.py"


def browser_auto_auth(
    engagement_id: str,
    url: str,
    email: str = "",
    headless: bool | None = None,
) -> str:
    """Perform autonomous browser auth (signup → verify → login).

    Uses auto_auth.py which handles: email generation via Guerrilla Mail,
    form filling, email verification polling, and session capture.

    Args:
        engagement_id: The engagement identifier
        url: The signup/login page URL
        email: Optional email override (auto-generated if empty)
        headless: Whether to run headless (defaults to SWARM_BROWSER_HEADLESS env or true)
    """
    from urllib.parse import urlparse

    domain = urlparse(url).netloc or urlparse(f"https://{url}").netloc

    python = str(_REPO_ROOT / ".venv" / "bin" / "python")
    if not Path(python).exists():
        python = sys.executable

    cmd = [python, str(_AUTO_AUTH_SCRIPT), domain]
    if email:
        cmd += ["--email", email]
    is_headless = _get_headless() if headless is None else headless
    if is_headless:
        cmd.append("--headless")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return "## Auto-Auth\n\n- **Status:** ❌ Timed out after 180s\n"

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    result = {}
    if stdout:
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError:
            pass

    status = result.get("status", "fail") if result else "fail"
    lines = [
        f"## Auto-Auth: {url}",
        "",
    ]

    if status == "ok":
        session_file = result.get("session_file", "")
        cookie_count = result.get("cookies", 0)
        auth_count = result.get("auth_cookies", 0)
        email_used = result.get("email", email)
        lines.append("- **Status:** ✅ Authenticated")
        lines.append(f"- **Email:** {email_used}")
        lines.append(f"- **Cookies captured:** {cookie_count} ({auth_count} auth)")
        if session_file:
            lines.append(f"- **Session file:** `{session_file}`")
        lines.append("")
        lines.append("Account created and logged in successfully. Session is ready.")
    elif status == "partial":
        lines.append("- **Status:** ⚠️ Partial (login may have failed)")
        lines.append(f"- **Cookies:** {result.get('cookies', 0)}")
    elif status == "skip":
        lines.append(f"- **Status:** ⏭️ Skipped — {result.get('reason', 'no auth form found')}")
    elif status == "captcha":
        lines.append(f"- **Status:** 🛑 Blocked — {result.get('reason', 'CAPTCHA or phone verification')}")
        lines.append("")
        lines.append("The platform detected automation. Try manual login via browser_login().")
    else:
        error = result.get("error", proc.returncode)
        lines.append("- **Status:** ❌ Failed")
        lines.append(f"- **Error:** {error}")
        if stderr:
            lines.append(f"- **Stderr:** {stderr}")

    lines.append("")
    lines.append(f"Exit code: {proc.returncode}")
    return "\n".join(lines)


# ── LLM-driven browser analysis and actions ─────────────────────────


def browser_analyze(
    engagement_id: str,
    url: str = "",
    agent_id: str = "llm-agent",
) -> str:
    """Capture page state for LLM-driven analysis.

    Navigates to the URL (if provided), then returns:
      - Page title and current URL
      - Base64 screenshot (for vision models)
      - Visible text content (for language analysis)
      - Interactive elements (inputs, buttons, links with indices)
      - Cookie count

    The calling LLM subagent can use this output to decide what actions
    to take next via browser_act().

    Args:
        engagement_id: The engagement identifier
        url: URL to navigate to (empty = use current page)
        agent_id: Agent label for cookie jar isolation
    """
    import html as html_mod

    if url:
        _navigate(url)

    state, screenshot_b64 = _get_state(include_screenshot=True)
    page_title = state.get("title", "")
    current_url = state.get("url", url)
    elements = state.get("interactive_elements", [])

    try:
        page_text = _run_js("document.body.innerText")[:5000]
    except RuntimeError:
        page_text = ""

    try:
        page_html = html_mod.unescape(_get_html()[:3000])
    except RuntimeError:
        page_html = ""

    cookies = _get_cookies()
    cookie_count = len(cookies)

    element_lines = []
    for el in elements:
        tag = el.get("tag", "")
        idx = el.get("index", "")
        etype = el.get("type", "")
        name = el.get("name", "")
        placeholder = el.get("placeholder", "")
        text = el.get("text", "")
        label = el.get("label", "")
        parts = [f"[{idx}] <{tag}>"]
        if name:
            parts.append(f'name="{name}"')
        if placeholder:
            parts.append(f'placeholder="{placeholder}"')
        if label:
            parts.append(f'label="{label}"')
        if text:
            parts.append(f'text="{text[:60]}"')
        if etype:
            parts.append(f"type={etype}")
        element_lines.append("  " + " ".join(parts))

    elements_str = "\n".join(element_lines[:30])
    if len(element_lines) > 30:
        elements_str += f"\n  ... and {len(element_lines) - 30} more"

    result = {
        "title": page_title,
        "url": current_url,
        "screenshot_b64": screenshot_b64 or "",
        "visible_text": page_text[:3000],
        "page_html": page_html[:2000],
        "interactive_elements": element_lines[:30],
        "element_count": len(element_lines),
        "cookie_count": cookie_count,
    }

    return (
        f"## Page Analysis: {page_title}\n\n"
        f"- **URL:** {current_url}\n"
        f"- **Interactive elements:** {result['element_count']}\n"
        f"- **Cookies:** {cookie_count}\n"
        f"\n### Visible Text\n```\n{result['visible_text'][:1500]}\n```\n"
        f"\n### Interactive Elements\n{elements_str}\n"
        f"\n### Screenshot\n"
        f"![Page screenshot](data:image/png;base64,{screenshot_b64})\n"
        f"\nCall `browser_act()` to interact with elements by index."
    )


def browser_act(
    engagement_id: str,
    action: str,
    index: int | None = None,
    text: str = "",
    url: str = "",
    code: str = "",
) -> str:
    """Execute a low-level browser action.

    Provides direct access to browser-use Browser for LLM-driven
    testing. Combine with browser_analyze() in an observe→decide→act loop.

    Args:
        engagement_id: The engagement identifier
        action: One of:
            - "navigate" — go to a URL (provide url)
            - "click" — click element by index (provide index)
            - "type" — type text into field by index (provide index + text)
            - "js" — run JavaScript (provide code)
            - "state" — get current page state (no params needed)
            - "cookies" — get all cookies (no params needed)
            - "screenshot" — take screenshot (no params needed)
            - "html" — get page HTML (no params needed)
            - "close" — close the browser (no params needed)
        index: Element index for click/type actions
        text: Text to type for type action
        url: URL for navigate action
        code: JavaScript code for js action
    """
    try:
        if action == "navigate":
            _navigate(url)
            return f"Navigated to {url}"
        elif action == "click":
            assert index is not None
            return _click_element(index)
        elif action == "type":
            assert index is not None
            return _type_text(index, text)
        elif action == "js":
            return _run_js(code)
        elif action == "state":
            state, screenshot_b64 = _get_state(include_screenshot=True)
            return f"## Page State\n\n```json\n{json.dumps(state, indent=2)[:2000]}\n```"
        elif action == "cookies":
            cookies = _get_cookies()
            return f"## Cookies ({len(cookies)})\n\n" + "\n".join(f"- `{c['name']}` ({c.get('domain', '')})" for c in cookies[:20])
        elif action == "screenshot":
            return "Screenshot captured. Use a vision-capable model to analyze it."
        elif action == "html":
            return f"## Page HTML\n\n```html\n{_get_html()[:2000]}\n```"
        elif action == "close":
            _reset_browser()
            _close_chromium()
            return "Browser closed."
        else:
            valid = ", ".join(sorted(["navigate", "click", "type", "js", "state", "cookies", "screenshot", "html", "close"]))
            return f"Invalid action '{action}'. Valid actions: {valid}"
    except Exception as e:
        return f"Action '{action}' failed: {e}"
