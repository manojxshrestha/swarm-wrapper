# Phase 2b: BROWSER AUTH

Browser-based authentication for flows that cannot be completed via simple API calls: OAuth, SSO, SAML, MFA forms, SPA login pages, and complex signup flows.

---

## Objectives

- Authenticate to the target using browser-based methods (form login, OAuth, SSO, SAML)
- Handle MFA challenges (TOTP, email OTP) when possible
- Extract and persist session data (cookies, JWT tokens, localStorage)
- Save session artifacts for all downstream phases (recon, hunt, exploit)

---

## Dependencies

| Dependency | Required | Notes |
|------------|----------|-------|
| Playwright | Yes | Browser automation engine |
| Python 3 | Yes | For `auto_auth.py` |
| Guerrilla Mail API | For auto-signup | Email verification polling |
| Browser running | Yes | Headed mode on port 9222 |

---

## Auth Methods

### Method 1: `browser_login` (preferred — known credentials)

When valid credentials are available:

```python
browser_login(
    engagement_id="<eid>",
    agent_id="auth-agent",
    url="https://target.com/login",
    username="test@test.com",
    password="Test123!",
)
```

Form fields are auto-detected (email, password, submit). After success:
- Save cookies via `browser_extract_storage()`
- Verify session by navigating to a protected endpoint

### Method 2: `browser_analyze` + `browser_act` (LLM-driven — SPAs, CSP)

For sites where auto-detection fails (React SPAs, CSP-restricted pages, custom UI, anti-bot pages):

```
loop: observe → decide → act
  1. browser_analyze(eid, url)
     → Returns: title, URL, base64 screenshot, visible text,
       interactive elements with indices, cookie count
  2. Analyze: identify form fields, submit buttons, OAuth buttons,
     CAPTCHA blockers, MFA challenges
  3. Act:
     - browser_act(eid, "type", index=3, text="user@email.com")
     - browser_act(eid, "click", index=5)
     - browser_act(eid, "navigate", url="...")
  4. Repeat until authenticated or blocked
```

### Method 3: `browser_auto_auth` (autonomous signup → verify → login)

When no credentials exist and signup is available:

```python
browser_auto_auth(
    engagement_id="<eid>",
    url="https://target.com/signup",
    email="custom@email.com",    # omit for auto-generated Guerrilla Mail
    headless=True,
)
```

Returns: `ok` / `partial` / `skip` / `captcha` / `fail`

The autonomous flow:
1. Generate identity (email via Guerrilla Mail, random password, username)
2. Navigate to target, dismiss popups, detect auth forms
3. Fill signup form, submit
4. Poll inbox for verification link/OTP
5. Navigate verification link or enter OTP code
6. Capture cookies and save session

### Method 4: Cookie / Token Injection

When cookies or tokens exist from another source:

```
1. Save cookies to engagements/<eid>/runtime/<eid>/cookies-<agent_id>.json
2. browser_act(eid, "navigate", url="https://target.com/")
3. browser_extract_storage(eid, agent_id="auth-agent", url="https://target.com/")
```

---

## Flow-Specific Handling

### Google / Social OAuth

```
1. browser_analyze(eid, url)                    # find OAuth button
2. browser_act(eid, "click", index=N)           # click "Login with Google"
3. browser_analyze(eid)                          # now on Google login page
4. browser_act(eid, "type", index=N, text="user@gmail.com")
5. browser_act(eid, "click", index=N)            # "Next"
6. browser_act(eid, "type", index=N, text="password")
7. browser_act(eid, "click", index=N)            # "Sign in"
8. browser_analyze(eid)                          # should redirect back
9. browser_extract_storage(eid, agent_id, url)   # capture final session
```

Google may trigger SMS/2FA → report as `captcha`.

### SSO / SAML

Same pattern as OAuth: analyze → click IdP redirect → analyze IdP page → fill credentials → analyze redirect back → extract storage.

### Form-Based Login

Standard email/password with submit button. Use `browser_login` first. If auto-detection fails, use `browser_analyze` → `browser_act`.

---

## MFA Handling

| Type | Handling |
|------|----------|
| TOTP | Generate code via `pyotp.TOTP(secret)` if shared secret is available |
| Email OTP | Guerrilla Mail polling + OTP code entry (automated by `browser_auto_auth`) |
| SMS / Phone | Cannot automate → report `captcha` status |
| Push notification | Cannot automate → report `captcha` status |

---

## Anti-Bot Handling

1. **Detect**: `browser_analyze` output shows "captcha", "verify you're human", reCAPTCHA iframe, or Cloudflare challenge
2. **Report**: return `captcha` status — do NOT attempt to bypass
3. **Fallback**: recommend manual login via real browser

---

## Session Verification

After any auth method, verify the session:

```
1. browser_act(eid, "cookies")
2. browser_act(eid, "navigate", url="https://target.com/")
3. state = browser_analyze(eid)
   → should show authenticated page, not login redirect
4. browser_extract_storage(eid, agent_id="auth-agent", url="https://target.com/")
5. browser_screenshot(eid, agent_id="auth-agent", url="https://target.com/dashboard")
```

---

## Session Artifacts

Saved to `engagements/<eid>/runtime/<eid>/`:

| File | Contents | Source |
|------|----------|--------|
| `cookies-<agent_id>.json` | Browser cookies | `browser_extract_storage` |
| `session.json` | Full session state | `auto_auth.py` |
| `storage-<agent_id>.json` | localStorage + sessionStorage | `browser_extract_storage` |
| `screenshots/` | Evidence screenshots | `browser_screenshot` |

---

## Workflow Integration

```
1. Read target config from engagement config (credentials, auth type, URL)
2. Run analyze agent to discover auth page and classify mechanism
3. Choose auth method:
   - Credentials known → browser_login
   - No creds, signup allowed → browser_auto_auth
   - Complex UI / SPA → browser_analyze + browser_act loop
   - Tokens/cookies from other source → inject and verify
4. Execute auth flow (max 2 retries)
5. Verify session (cookies, protected endpoint)
6. Save artifacts (cookies, storage, screenshot)
7. Log: findings_log_action(eid, "browser-auth", "auth", summary)
8. Track: track_tool(eid, "browser-auth", "run", notes=summary, target=url)
```

---

## Related Files

| File | Role |
|------|------|
| `skills/browser-auth/SKILL.md` | Full browser auth methodology |
| `prompts/browser-auth.md` | Subagent prompt |
| `.swarm/agents/browser-auth.md` | Agent orchestration |
| `skills/analyze/SKILL.md` | Pre-auth page analysis methodology |
| `.swarm/agents/analyze.md` | Read-only page analysis agent |
| `docs/phases/auth.md` | Phase 2 (AUTH) — API-level auth + WAF detection |
| `docs/browser-flow.md` | Browser tools technical reference |
| `scripts/tools/auto_auth.py` | Autonomous browser auth pipeline |
