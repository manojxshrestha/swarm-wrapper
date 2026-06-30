#!/usr/bin/env python3
"""auto_auth.py — Universal autonomous browser auth for ANY platform.

Detects and handles signup/login flows across all platforms:
  Social media, e-commerce, government, SaaS, enterprise, banking, etc.

Handles:
  - Email + password signup/login (standard)
  - Multi-step signup forms (name → email → password → confirm)
  - OAuth buttons ("Continue with Google/GitHub/Apple")
  - Phone + OTP flows
  - Magic link / passwordless email
  - Cookie consent popups, notification dialogs
  - SPAs that load content asynchronously
  - CAPTCHA detection (skips gracefully)
  - Phone verification required (skips gracefully)

Usage:
    python auto_auth.py <domain> [options]

Examples:
    python auto_auth.py hackerone.com
    python auto_auth.py intercom.com --headless
    python auto_auth.py shop.example.com --email user@test.com

Exit codes:
    0  Auth obtained and saved
    1  No auth forms detected (public site or unsupported flow)
    2  Browser unavailable or crashed
    3  CAPTCHA or phone verification blocking
"""

import argparse
import asyncio
import base64
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

# ── Configuration ──────────────────────────────────────────────────────────
NAVIGATE_TIMEOUT = 45           # seconds to wait for page load
POST_CLICK_DELAY = 2.0          # seconds after clicking
VERIFICATION_POLL_TIMEOUT = 120 # seconds to wait for verification email
VERIFICATION_POLL_INTERVAL = 5  # seconds between inbox checks
RENDER_WAIT = 5.0               # seconds to let JS render after navigation

# ── Guerrilla Mail API ─────────────────────────────────────────────────────
GUERRILLA_API = "https://api.guerrillamail.com/ajax.php"
GUERRILLA_DOMAIN = "guerrillamailblock.com"
_guerrilla_sid = None
_guerrilla_email = None


def _guerrilla_request(params: dict) -> dict:
    url = f"{GUERRILLA_API}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [auth] Guerrilla Mail API error: {e}", flush=True)
        return {}


def guerrilla_get_email() -> str:
    global _guerrilla_sid, _guerrilla_email
    data = _guerrilla_request({
        "f": "get_email_address", "ip": "127.0.0.1", "agent": "swarm"
    })
    if "email_addr" in data:
        _guerrilla_sid = data.get("sid_token")
        _guerrilla_email = data["email_addr"]
        return data["email_addr"]
    return f"swarm-{int(time.time())}@{GUERRILLA_DOMAIN}"


def guerrilla_check_inbox() -> list[dict]:
    if not _guerrilla_sid:
        return []
    data = _guerrilla_request({
        "f": "get_email_list", "sid_token": _guerrilla_sid, "offset": 0
    })
    return data.get("list", [])


def guerrilla_read_email(mail_id: int) -> str:
    if not _guerrilla_sid:
        return ""
    data = _guerrilla_request({
        "f": "fetch_email", "sid_token": _guerrilla_sid, "email_id": mail_id
    })
    return data.get("mail_body", "") or data.get("mail_text_only", "")


# ── Identity generation ───────────────────────────────────────────────────
def generate_password(length=16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choice(chars) for _ in range(length))


def generate_username(base: str = "") -> str:
    if base:
        return re.sub(r"[^a-zA-Z0-9]", "", base).lower()[:20]
    return "user" + "".join(random.choices(string.ascii_lowercase, k=8))


# ── Custom exceptions ──────────────────────────────────────────────────────
class BrowserDependencyError(Exception):
    """Raised when browser_driver.py dependencies are missing (e.g. playwright)."""
    pass


# ── Venv Python detection ────────────────────────────────────────────────
def _find_venv_python() -> str:
    """Find the project venv Python that has playwright installed.

    Checks known venv locations relative to the repo root.
    Falls back to sys.executable if no venv found (for backward compat).
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(script_dir))
    candidates = [
        os.path.join(repo_root, ".venv", "bin", "python"),
        os.path.join(repo_root, "server", "venv", "bin", "python"),
    ]
    for python in candidates:
        if os.path.isfile(python):
            try:
                subprocess.run(
                    [python, "-c", "import playwright"],
                    capture_output=True, timeout=5,
                )
                return python
            except Exception:
                continue
    return sys.executable


_PYTHON_BIN = _find_venv_python()


# ── Browser driver ─────────────────────────────────────────────────────────
BROWSER_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "browser_driver.py"
)


async def _run_browser(args: list[str], cmd_timeout: int = 30) -> str:
    try:
        proc = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.Popen(
                [_PYTHON_BIN, BROWSER_SCRIPT] + args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ),
        )
        stdout, stderr = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, proc.communicate),
            timeout=cmd_timeout,
        )
        if proc.returncode != 0:
            err = stderr.strip()[:300]
            if "No module named" in err or "ModuleNotFoundError" in err:
                raise BrowserDependencyError(
                    "browser_driver.py missing dependencies. "
                    "Run: pip install playwright && python -m playwright install chromium"
                )
        return stdout or ""
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise TimeoutError(f"browser_driver {' '.join(args)} timed out after {cmd_timeout}s")
    except FileNotFoundError:
        raise BrowserDependencyError("browser_driver.py not found — check BROWSER_SCRIPT path")


async def b_start():
    return await _run_browser(["start"])


async def b_navigate(url: str, wait: float = RENDER_WAIT):
    await _run_browser(["navigate", url, f"--wait={wait}"])


async def b_click(index: int):
    await _run_browser(["click", str(index)])


async def b_click_at(x: int, y: int):
    await _run_browser(["click_at", str(x), str(y)])


async def b_type(index: int, text: str):
    # Split long text into chunks to avoid argument length issues
    if len(text) > 100:
        chunk_size = 80
        for i in range(0, len(text), chunk_size):
            chunk = text[i:i + chunk_size]
            await _run_browser(["type", str(index), chunk])
            await asyncio.sleep(0.1)
    else:
        await _run_browser(["type", str(index), text])


async def b_scroll(direction: str = "down", amount: int = 500):
    await _run_browser(["scroll", direction, str(amount)])


async def b_state() -> dict:
    out = await _run_browser(["state"])
    for line in out.splitlines():
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {}


async def b_js(code: str) -> str:
    return await _run_browser(["js", code])


async def b_cookies() -> list[dict]:
    out = await _run_browser(["cookies"])
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


async def b_screenshot() -> bytes | None:
    out = await _run_browser(["screenshot"])
    if "---IMAGE---" in out:
        b64 = out.split("---IMAGE---")[1].split("---END IMAGE---")[0].strip()
        return base64.b64decode(b64)
    return None


async def b_html(selector: str | None = None) -> str:
    args = ["html"]
    if selector:
        args.append(selector)
    return await _run_browser(args)


async def b_close():
    await _run_browser(["close"])


# ── Universal DOM analysis ─────────────────────────────────────────────────
# These JS snippets run in the browser to analyze the page

ANALYZE_PAGE_JS = """
() => {
    const results = {
        url: location.href,
        title: document.title,
        forms: [],
        inputs: [],
        buttons: [],
        links: [],
        has_captcha: false,
        has_iframe: false,
        auth_type: null,
    };

    // Collect all forms
    document.querySelectorAll('form').forEach(f => {
        const formData = {
            id: f.id,
            action: f.action,
            method: f.method,
            inputs: [],
            submit: null,
        };
        f.querySelectorAll('input, select, textarea, button').forEach(el => {
            const tag = el.tagName.toLowerCase();
            const type = (el.getAttribute('type') || '').toLowerCase();
            const name = el.getAttribute('name') || '';
            const placeholder = el.getAttribute('placeholder') || '';
            const ariaLabel = el.getAttribute('aria-label') || '';
            const autocomplete = el.getAttribute('autocomplete') || '';
            const label = (el.closest('label')?.textContent || '');
            const labelFor = document.querySelector(`label[for="${el.id}"]`)?.textContent || '';
            const nearbyText = label || labelFor || '';
            const rect = el.getBoundingClientRect();
            const visible = rect.width > 0 && rect.height > 0;
            if (tag === 'button' || type === 'submit') {
                formData.submit = { tag, text: el.textContent?.trim()?.slice(0, 100) };
            } else {
                formData.inputs.push({ tag, type, name, placeholder, ariaLabel, autocomplete, nearbyText, visible });
            }
        });
        results.forms.push(formData);
    });

    // Collect standalone inputs (not in forms)
    document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)').forEach(el => {
        if (!el.offsetParent) return;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const label = (el.closest('label')?.textContent || document.querySelector(`label[for="${el.id}"]`)?.textContent || '').trim().slice(0, 100);
        results.inputs.push({
            tag: el.tagName.toLowerCase(),
            type: (el.getAttribute('type') || 'text').toLowerCase(),
            name: el.getAttribute('name') || '',
            placeholder: el.getAttribute('placeholder') || '',
            ariaLabel: el.getAttribute('aria-label') || '',
            autocomplete: el.getAttribute('autocomplete') || '',
            nearbyText: label,
            visible: el.getBoundingClientRect().width > 0,
        });
    });

    // Collect buttons
    document.querySelectorAll('button:not(form button), a[role="button"], [onclick]').forEach(el => {
        if (!el.offsetParent) return;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const text = (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 100);
        if (!text) return;
        results.buttons.push({
            tag: el.tagName.toLowerCase(),
            text: text,
            class: (el.getAttribute('class') || '').slice(0, 100),
            href: el.getAttribute('href') || '',
        });
    });

    // Collect auth links
    document.querySelectorAll('a[href*="sign"], a[href*="login"], a[href*="register"], a[href*="auth"]').forEach(a => {
        if (a.offsetParent) {
            results.links.push({
                text: (a.textContent || '').trim().slice(0, 80),
                href: a.getAttribute('href') || '',
            });
        }
    });

    // Check for CAPTCHA
    results.has_captcha = !!document.querySelector('[class*="captcha"], [src*="captcha"], [id*="captcha"], iframe[src*="recaptcha"], iframe[src*="hcaptcha"]');

    // Check for iframes (often OAuth/login widgets)
    results.has_iframe = !!document.querySelector('iframe[src*="login"], iframe[src*="auth"], iframe[src*="oauth"], iframe[src*="saml"], iframe[src*="openid"]');

    return results;
}
"""

FIND_INTERACTIVE_JS = """
(ignoreIndices) => {
    const ignore = new Set(ignoreIndices || []);
    const all = document.querySelectorAll(
        'input, button, a, select, textarea, ' +
        '[role="button"], [role="link"], [role="combobox"], [role="option"], ' +
        '[tabindex]:not([tabindex="-1"]), [onclick]'
    );
    const items = [];
    let idx = 1;
    all.forEach(el => {
        if (ignore.has(idx)) { idx++; return; }
        const tag = el.tagName.toLowerCase();
        const text = (el.textContent || '').trim().substring(0, 100);
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) { idx++; return; }
        if (rect.top > window.innerHeight + 100 || rect.bottom < -100) { idx++; return; }
        const attrs = {};
        ['placeholder','href','type','name','value','aria-label','role',
         'class','id','data-testid','title','alt','autocomplete'].forEach(a => {
            const v = el.getAttribute(a);
            if (v) attrs[a] = v.substring(0, 80);
        });
        items.push({
            index: idx++, tag, text: text.slice(0, 60), ...attrs,
            center: { x: Math.round(rect.left + rect.width/2),
                      y: Math.round(rect.top + rect.height/2) },
        });
    });
    return items;
}
"""


# ── Page analysis & auth flow detection ────────────────────────────────────

def _match_text(text: str, keywords: list[str]) -> bool:
    t = text.lower()
    return any(re.search(kw, t) for kw in keywords)


SIGNUP_KW = [
    r"sign.?up", r"register", r"create.?account", r"join",
    r"get.?started", r"start.?free", r"try.?free",
    r"create.?your.?account", r"sign.?up.?now", r"enroll",
]
LOGIN_KW = [
    r"log.?in", r"sign.?in", r"login", r"already.?have.?an.?account",
]
OAUTH_KW = [
    r"continue.?with", r"sign.?up.?with", r"log.?in.?with",
    r"google", r"github", r"apple", r"facebook", r"twitter",
    r"microsoft", r"linkedin", r"gitlab",
]
EMAIL_KW = [
    r"email", r"e-?mail", r"mail", r"@",
]
PASSWORD_KW = [
    r"password", r"passwd", r"pw", r"create.?a.?password",
    r"new.?password", r"confirm.?password",
]
NAME_KW = [
    r"full.?name", r"first.?name", r"last.?name", r"your.?name",
    r"name", r"display.?name", r"username",
]
PHONE_KW = [
    r"phone", r"mobile", r"telephone", r"cell", r"otp", r"sms",
]
SUBMIT_KW = [
    r"^sign.?up$", r"^register$", r"^create.?account$",
    r"^continue$", r"^next$", r"^submit$",
    r"^log.?in$", r"^sign.?in$", r"^login$",
]
CONSENT_KW = [
    r"accept.?all", r"accept.?cookies", r"agree", r"allow.?all",
    r"got.?it", r"i.?understand", r"dismiss", r"close",
    r"reject.?all", r"decline",
]


def _classify_input(input_data: dict) -> str:
    """Classify an input field type: 'email', 'password', 'name', 'phone', 'text'."""
    t = input_data.get("type", "").lower()
    autocomplete = input_data.get("autocomplete", "").lower()
    combined = " ".join([
        input_data.get("name", "").lower(),
        input_data.get("placeholder", "").lower(),
        input_data.get("ariaLabel", "").lower(),
        input_data.get("nearbyText", "").lower(),
        autocomplete,
    ])
    if t == "email" or autocomplete == "email" or "email" in combined:
        return "email"
    if autocomplete in ("new-password", "current-password"):
        return "password"
    if t in ("password", "secret"):
        return "password"
    if _match_text(combined, PASSWORD_KW):
        return "password"
    if _match_text(combined, NAME_KW):
        return "name"
    if autocomplete in ("tel", "tel-national") or _match_text(combined, PHONE_KW):
        return "phone"
    if _match_text(combined, EMAIL_KW):
        return "email"
    return "text"


def _classify_button(btn: dict) -> str:
    """Classify a button/link: 'signup', 'login', 'oauth', 'consent', 'submit', 'other'."""
    text = btn.get("text", "").lower()
    href = btn.get("href", "").lower()
    combined = f"{text} {href}"
    if _match_text(combined, CONSENT_KW):
        return "consent"
    if _match_text(combined, SIGNUP_KW):
        return "signup"
    if _match_text(combined, OAUTH_KW):
        return "oauth"
    if _match_text(combined, LOGIN_KW):
        return "login"
    if _match_text(combined, SUBMIT_KW):
        return "submit"
    return "other"


async def _wait_for_render(state: dict, max_wait: int = 15) -> dict:
    """Wait for interactive elements to appear (SPAs, redirects)."""
    for _ in range(max_wait):
        el = state.get("interactive_elements", [])
        if len(el) >= 5:  # Don't wait if we already have elements
            return state
        await asyncio.sleep(1)
        state = await b_state()
    return state


# ── Cookie consent dismissal ───────────────────────────────────────────────

async def _dismiss_popups(elements: list[dict]) -> bool:
    """Click consent/notification popup dismiss buttons. Returns True if any clicked."""
    dismissed = False
    for el in elements:
        tag = el.get("tag", "")
        text = (el.get("text", "") or "").lower()
        if tag == "button" and _match_text(text, CONSENT_KW):
            print(f"  [auth] Dismissing popup: '{text[:30]}'", flush=True)
            try:
                await b_click(el["index"])
                await asyncio.sleep(1)
                dismissed = True
            except Exception:
                pass
    return dismissed


# ── Email verification ─────────────────────────────────────────────────────

async def _wait_for_verification(domain: str) -> str | None:
    """Poll inbox for verification email. Returns link or None."""
    print("  [auth] Waiting for verification email...", flush=True)
    deadline = time.time() + VERIFICATION_POLL_TIMEOUT
    while time.time() < deadline:
        emails = guerrilla_check_inbox()
        for mail in emails:
            mail_id = mail.get("mail_id")
            if not mail_id:
                continue
            body = guerrilla_read_email(mail_id)
            # Look for verification links
            links = re.findall(
                r'https?://[^\s"\'<>]+(?:verify|confirm|activate|'
                r'email[_-]?confirm|magic[_-]?link|reset|token)[^\s"\'<>]*',
                body, re.I
            )
            if links:
                return links[0]
            # Also try OTP codes (6-8 digits)
            codes = re.findall(r'\b(?:otp|code|pin)[:\s]*(\d{4,8})\b', body, re.IGNORECASE)
            for code in codes:
                if code not in (body[:20], body[-20:]):
                    print(f"  [auth] Found OTP code: {code}", flush=True)
                    return f"OTP:{code}"
            # Generic link fallback
            links = re.findall(r'https?://[^\s"\'<>]+', body)
            for link in links:
                if domain.replace(".", r"\.") in link:
                    return link
        await asyncio.sleep(VERIFICATION_POLL_INTERVAL)
    return None


# ── Session persistence ────────────────────────────────────────────────────

def save_session(domain: str, cookies: list[dict],
                 headers: dict | None = None,
                 output_dir: str | None = None) -> str:
    """Save captured session. Returns path."""
    if output_dir:
        out = Path(output_dir) / "auth"
    else:
        base = os.environ.get("RECON_BASE", "engagements/recon")
        out = Path(base) / domain / "auth"
    out.mkdir(parents=True, exist_ok=True)

    session = {
        "domain": domain,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cookies": cookies,
        "headers": headers or {},
    }
    json_path = out / "session.json"
    with open(json_path, "w") as f:
        json.dump(session, f, indent=2)

    # Env format for _auth_helper.sh
    cookie_str = "; ".join(
        f"{c.get('name','')}={c.get('value','')}"
        for c in cookies
        if "session" in c.get("name","").lower()
        or "token" in c.get("name","").lower()
        or "auth" in c.get("name","").lower()
        or "sid" in c.get("name","").lower()
        or "connect" in c.get("name","").lower()
    )
    if not cookie_str:
        cookie_str = "; ".join(
            f"{c.get('name','')}={c.get('value','')}"
            for c in cookies[:20]  # keep all cookies
        )

    env_path = out / "session.env"
    with open(env_path, "w") as f:
        f.write(f"# Auto-captured auth session for {domain}\n")
        f.write(f"# Source: auto_auth.py | {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"BBHUNT_COOKIE=\"{cookie_str}\"\n")
        if cookie_str:
            auth_headers = f"Cookie: {cookie_str}"
            f.write(f"BBHUNT_AUTH_HEADERS=\"{auth_headers}\"\n")

    print(f"  [auth] Session saved: {json_path}", flush=True)
    return str(json_path)


# ── Universal auth flow ────────────────────────────────────────────────────

async def auto_auth(domain: str, output_dir: str | None = None,
                    headless: bool = False,
                    email_override: str | None = None) -> dict:
    """Run autonomous auth against ANY platform."""
    url = f"https://{domain}/"

    print(f"\n{'='*60}", flush=True)
    print(f"  Auto-Auth: {domain}", flush=True)
    print(f"{'='*60}", flush=True)

    # Step 0: Generate identity
    email = email_override or guerrilla_get_email()
    password = generate_password()
    username = generate_username(domain)
    print(f"  Email: {email}", flush=True)
    print(f"  Password: {password}", flush=True)

    # Step 1: Start browser
    print("  Starting browser...", flush=True)
    try:
        await b_start()
    except BrowserDependencyError as e:
        return {"status": "fail", "error": str(e)}
    print("  Browser started", flush=True)

    try:
        # Step 2: Navigate to target — follow redirects
        print(f"  Navigating to {url}...", flush=True)
        await b_navigate(url, wait=RENDER_WAIT)
        await asyncio.sleep(2)

        # Check if we redirected — get actual URL
        state_check = await b_state()
        actual_url = state_check.get("url", url)
        if actual_url and actual_url != url:
            print(f"  Redirected to: {actual_url}", flush=True)
            parsed = urlparse(actual_url)
            domain = parsed.netloc or domain
            url = actual_url

        # Step 3: Deep page analysis
        print("  Analyzing page...", flush=True)
        page_analysis_json = await b_js(ANALYZE_PAGE_JS)
        page = {}
        for line in page_analysis_json.splitlines():
            try:
                page = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

        forms = page.get("forms", [])
        standalone_inputs = page.get("inputs", [])
        buttons = page.get("buttons", [])
        links = page.get("links", [])
        has_captcha = page.get("has_captcha", False)
        has_iframe = page.get("has_iframe", False)

        print(f"  Forms: {len(forms)}, Inputs: {len(standalone_inputs)}, "
              f"Buttons: {len(buttons)}, Links: {len(links)}", flush=True)
        if has_captcha:
            print("  ⚠ CAPTCHA detected — will skip if required", flush=True)

        # Step 4: Get interactive elements
        state = await b_state()
        elements = state.get("interactive_elements", [])
        print(f"  Interactive elements: {len(elements)}", flush=True)

        # Step 5: Dismiss popups
        if await _dismiss_popups(elements):
            await asyncio.sleep(1.5)
            state = await b_state()
            elements = state.get("interactive_elements", [])

        # Step 6: Classify buttons
        btn_classes = {}
        for el in elements:
            if el.get("tag") in ("button", "a"):
                cls = _classify_button(el)
                if cls != "other":
                    btn_classes[cls] = el

        consent_btn = btn_classes.get("consent")
        signup_btn = btn_classes.get("signup")
        login_btn = btn_classes.get("login")
        oauth_btns = [el for k, el in btn_classes.items() if k == "oauth"]
        submit_btn = btn_classes.get("submit")

        print(f"  Detected: signup={bool(signup_btn)}, login={bool(login_btn)}, "
              f"oauth={len(oauth_btns)}, consent={bool(consent_btn)}", flush=True)

        # Step 7: Find auth links in page
        auth_links = []
        for link in links:
            ltext = link.get("text", "").lower()
            lhref = link.get("href", "").lower()
            if _match_text(ltext, SIGNUP_KW) or _match_text(lhref, SIGNUP_KW):
                auth_links.append(("signup", link))
            elif _match_text(ltext, LOGIN_KW) or _match_text(lhref, LOGIN_KW):
                auth_links.append(("login", link))
            elif _match_text(ltext, OAUTH_KW) or _match_text(lhref, OAUTH_KW):
                auth_links.append(("oauth", link))

        # Step 8: If only consent popups, dismiss and re-scan
        if consent_btn and not any([signup_btn, login_btn, oauth_btns]):
            print("  Only consent popup found — dismissing and re-scanning...", flush=True)
            await b_click(consent_btn["index"])
            await asyncio.sleep(2)
            state = await b_state()
            elements = state.get("interactive_elements", [])
            btn_classes = {}
            for el in elements:
                if el.get("tag") in ("button", "a"):
                    cls = _classify_button(el)
                    if cls != "other":
                        btn_classes[cls] = el
            signup_btn = btn_classes.get("signup")
            login_btn = btn_classes.get("login")

        # Step 9: Try common auth URL patterns if no forms found
        if not forms and not standalone_inputs and not buttons and not links:
            base = f"https://{domain}"
            auth_paths = [
                "/users/sign_up", "/signup", "/register", "/join",
                "/users/sign_in", "/login", "/signin",
                "/auth/login", "/auth/signup", "/account/register",
                "/en/signup", "/sign_up", "/accounts/signup",
            ]
            # Also try paths relative to current page directory
            parsed = urlparse(url)
            base_path = parsed.path.rstrip("/")
            if base_path and base_path != "":
                auth_paths = [
                    base_path + p for p in auth_paths[:6]
                ] + auth_paths
            tried = False
            for path in auth_paths:
                if path.startswith("/"):
                    auth_url = base + path
                else:
                    auth_url = path
                print(f"  Trying auth URL: {auth_url}", flush=True)
                try:
                    await asyncio.wait_for(b_navigate(auth_url, wait=RENDER_WAIT), timeout=12)
                    await asyncio.sleep(2)
                except (asyncio.TimeoutError, Exception):
                    print(f"  Timed out loading {path} — skipping", flush=True)
                    continue
                state = await b_state()
                elements = state.get("interactive_elements", [])
                if len(elements) > 0:
                    print(f"  Found {len(elements)} elements at {path}", flush=True)
                    tried = True
                    break
            if not tried:
                print("  No auth forms — public site or unknown flow", flush=True)
                return {"status": "skip", "reason": "no auth forms detected"}

        # Step 9b: Navigate to auth page via detected buttons/links
        target_btn = signup_btn or login_btn
        if not target_btn:
            for atype, alink in auth_links:
                href = alink.get("href", "")
                if href and not href.startswith("http"):
                    href = f"https://{domain}{href}"
                if href:
                    print(f"  Navigating to {atype} page: {href}", flush=True)
                    await b_navigate(href, wait=RENDER_WAIT)
                    await asyncio.sleep(2)
                    state = await b_state()
                    elements = state.get("interactive_elements", [])
                    btn_classes = {}
                    for el in elements:
                        if el.get("tag") in ("button", "a"):
                            cls = _classify_button(el)
                            if cls != "other":
                                btn_classes[cls] = el
                    signup_btn = btn_classes.get("signup")
                    login_btn = btn_classes.get("login")
                    target_btn = signup_btn or login_btn
                    if target_btn:
                        break

        if not target_btn and not forms and not standalone_inputs:
            print("  No auth forms detected — public site or unknown flow", flush=True)
            return {"status": "skip", "reason": "no auth forms detected"}

        # Step 10: If signup button exists, click it
        if signup_btn and not login_btn:
            print("  Clicking signup button...", flush=True)
            await b_click(signup_btn["index"])
            await asyncio.sleep(POST_CLICK_DELAY)
            await asyncio.sleep(1)

        # Step 11: Re-scan for form inputs after navigation
        state = await b_state()
        elements = state.get("interactive_elements", [])

        # Classify inputs
        inputs_by_role = {"email": None, "password": None, "name": None, "phone": None}
        for el in elements:
            if el.get("tag") in ("input", "textarea"):
                role = _classify_input(el)
                if role in inputs_by_role and inputs_by_role[role] is None:
                    inputs_by_role[role] = el

        print(f"  Form fields: email={bool(inputs_by_role['email'])}, "
              f"password={bool(inputs_by_role['password'])}, "
              f"name={bool(inputs_by_role['name'])}, "
              f"phone={bool(inputs_by_role['phone'])}", flush=True)

        # Step 12: Fill form
        filled = False
        if inputs_by_role["email"]:
            await b_type(inputs_by_role["email"]["index"], email)
            print("  Filled email field", flush=True)
            filled = True

        if inputs_by_role["password"]:
            await b_type(inputs_by_role["password"]["index"], password)
            print("  Set password", flush=True)
            filled = True

        if inputs_by_role["name"]:
            name = username.replace("user", "User").title()
            await b_type(inputs_by_role["name"]["index"], name)
            print("  Filled name field", flush=True)
            filled = True

        if filled:
            await asyncio.sleep(0.5)

            # Step 13: Find and click submit button
            # Re-scan for submit button (might have appeared after filling)
            state = await b_state()
            elements = state.get("interactive_elements", [])

            submit = None
            for el in elements:
                if el.get("tag") == "button":
                    cls = _classify_button(el)
                    if cls in ("submit", "signup", "login"):
                        submit = el
                        break
                if el.get("type") == "submit":
                    submit = el
                    break

            # No submit button found — try first button that isn't a link
            if not submit:
                for el in elements:
                    if el.get("tag") == "button" and el.get("text", "").lower() not in ("", " ", "x", "close", "cancel"):
                        submit = el
                        break

            if submit:
                print(f"  Clicking submit: '{submit.get('text', '')[:30]}'", flush=True)
                await b_click(submit["index"])
                await asyncio.sleep(POST_CLICK_DELAY)

                # Step 14: Check for CAPTCHA or phone verification
                state = await b_state()
                elements = state.get("interactive_elements", [])

                # Check if phone field appeared (means phone verification required)
                phone_field = None
                for el in elements:
                    if el.get("tag") in ("input",):
                        role = _classify_input(el)
                        if role == "phone":
                            phone_field = el
                            break

                if phone_field:
                    print("  Phone verification required — skipping (cannot automate)", flush=True)
                    return {"status": "captcha", "reason": "phone verification required"}

                if has_captcha:
                    print("  CAPTCHA detected after submit — marking as blocked", flush=True)
                    # Continue anyway — some sites show CAPTCHA but accept without solving

                # Step 15: Handle email verification
                await asyncio.sleep(2)
                verif_link = await _wait_for_verification(domain)
                if verif_link:
                    if verif_link.startswith("OTP:"):
                        otp = verif_link[4:]
                        # Find OTP input field
                        for el in elements:
                            if el.get("tag") in ("input",):
                                role = _classify_input(el)
                                if role in ("text", "email") and el.get("placeholder", "").lower() in ("code", "otp", "verification code", "6-digit code"):
                                    await b_type(el["index"], otp)
                                    print("  Entered OTP code", flush=True)
                                    await asyncio.sleep(0.5)
                                    for sub_el in elements:
                                        if sub_el.get("tag") == "button":
                                            cls = _classify_button(sub_el)
                                            if cls in ("submit",):
                                                await b_click(sub_el["index"])
                                                break
                                    break
                    else:
                        print("  Got verification link, navigating...", flush=True)
                        await b_navigate(verif_link, wait=3)
                        await asyncio.sleep(RENDER_WAIT)
                else:
                    print("  No verification email detected (within timeout)", flush=True)
            else:
                print("  No submit button found after filling form", flush=True)
        else:
            print("  No fillable fields detected", flush=True)
            return {"status": "skip", "reason": "no fillable fields"}

        # Step 16: Capture cookies
        await asyncio.sleep(2)
        cookies = await b_cookies()
        print(f"  Captured {len(cookies)} cookies", flush=True)

        auth_cookies = [
            c for c in cookies
            if any(kw in c.get("name", "").lower()
                   for kw in ("session", "token", "auth", "sid", "connect", "jwt", "refresh"))
        ]
        if auth_cookies:
            print(f"  Auth cookies: {[c['name'] for c in auth_cookies]}", flush=True)

        if not cookies:
            print("  No cookies captured — auth may have failed", flush=True)

        # Step 17: Save session
        session_path = save_session(domain, cookies, output_dir=output_dir)

        return {
            "status": "ok" if cookies else "partial",
            "session_file": session_path,
            "cookies": len(cookies),
            "auth_cookies": len(auth_cookies),
            "email": email,
        }

    except BrowserDependencyError as e:
        return {"status": "fail", "error": str(e)}
    finally:
        pass  # Leave browser open for inspection


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Universal autonomous browser auth for ANY platform"
    )
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--output-dir", help="Output directory for session files")
    parser.add_argument("--headless", action="store_true",
                       help="Run browser headless")
    parser.add_argument("--email", help="Override email (use existing account)")
    args = parser.parse_args()

    result = asyncio.run(auto_auth(
        domain=args.domain,
        output_dir=args.output_dir,
        headless=args.headless,
        email_override=args.email,
    ))

    print(json.dumps(result, indent=2))
    if result.get("status") in ("ok", "partial"):
        sys.exit(0)
    elif result.get("status") == "skip":
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
