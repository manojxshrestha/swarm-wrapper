# Session Management Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="session")` — Session management test cases (WSTG-SESS-*)
- `search_wstg("session")` — Find relevant session test procedures

## Key Test Categories
1. Session token predictability (entropy analysis)
2. Session token exposure (URL, Referer, logs)
3. Session fixation (pre/post-login token comparison)
4. Session termination (logout, timeout, concurrent sessions)
5. Cookie attribute analysis (HttpOnly, Secure, SameSite, Path)
6. CSRF token validation bypass
7. Weak token generation (timestamp-based, sequential)
8. Session replay attack (token reuse after logout)

## Burp Workflow
```bash
# Capture session tokens
burp_send_to_repeater("https://target.com/login", headers, body)

# Analyze cookie attributes
burp_send_to_repeater("https://target.com/", method="GET")  # check Set-Cookie headers

# Test session fixation
burp_send_to_repeater("https://target.com/session", headers, body)  # pre-auth
burp_send_to_repeater("https://target.com/login", headers, body)  # login
burp_send_to_repeater("https://target.com/profile", headers)  # check if session ID changed

# Test CSRF
burp_send_to_repeater(url, headers={"Origin": "https://evil.com"}, body)
burp_send_to_repeater(url, headers, body={"csrf_token": "attacker-generated"})
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-SESS-01 | Session management schema — how tokens are generated, structured, and transmitted |
| WSTG-SESS-02 | Cookie attributes — HttpOnly, Secure, SameSite, Path, Domain, Max-Age |
| WSTG-SESS-03 | Session fixation — attacker sets victim's session ID before login; post-login ID unchanged |
| WSTG-SESS-04 | Exposed session variables — session data leaked in URLs, logs, error messages, referrer headers |
| WSTG-SESS-05 | CSRF — missing or predictable anti-CSRF token, SameSite bypass, JSON content-type CSRF |
| WSTG-SESS-06 | Logout functionality — session not invalidated on server-side logout |
| WSTG-SESS-07 | Session timeout — idle and absolute timeout not enforced |
| WSTG-SESS-08 | Session puzzling — manipulation of session variables across different application states |
| WSTG-SESS-09 | Session hijacking — theft, prediction, or brute-force of session tokens |
| WSTG-SESS-10 | JSON Web Tokens — JWT algorithm confusion, none alg, weak signing key, claim injection |
| WSTG-SESS-11 | Session replay — reuse of old/invalidated session tokens after logout or timeout |

## Attack Playbook

### Cookie Audit (WSTG-SESS-02)
1. Check each cookie for: `HttpOnly` (prevent JS access), `Secure` (HTTPS only), `SameSite` (Lax/Strict vs None)
2. Check `Domain` scope — too broad (`domain=.com`) exposes cookie to all subdomains
3. Check `Path` scope — too broad (`Path=/`) exposes cookie across the entire site
4. Check `Max-Age`/`Expires` — persistent cookies should have reasonable expiry
5. Chain: missing HttpOnly + XSS → cookie theft via `document.cookie`

### Token Entropy (WSTG-SESS-09)
1. Capture 50+ session tokens (sequential logins or concurrent sessions)
2. Analyze: are tokens sequential (`sess-1`, `sess-2`)? timestamp-based (`20250620120000-abc123`)?
3. If tokens look predictable → brute-force next valid token
4. Check token length: <128 bits of entropy is weak
5. Chain: weak token prediction → hijack any active session → account takeover

### Session Fixation (WSTG-SESS-03)
1. Capture pre-login session cookie from server (before login)
2. Complete login with that session cookie
3. After login → check if session cookie value CHANGED
4. If same cookie used before and after login → vulnerable to fixation
5. Chain: fixation → attacker sends victim a pre-set session link → victim logs in → attacker uses same session

### CSRF (WSTG-SESS-05)
1. Check for anti-CSRF token in forms → capture valid request, modify body/token
2. Test SameSite bypass: if `SameSite=None` → CSRF works cross-site
3. Test JSON Content-Type CSRF: send POST with `Content-Type: application/json` (browsers can't do this cross-origin without CORS)
4. Test CSRF token validation: is token per-session or per-request? Can old token be reused?
5. Test token in URL: if CSRFT token is in query param → Referer leaks it
6. Chain: CSRF → change victim's email → trigger password reset → account takeover

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Only checking Secure flag on the main auth cookie** | Check ALL cookies set by the application, not just the session cookie |
| **Testing CSRF without SameSite analysis first** | `SameSite=Lax` blocks CSRF on state-changing requests from third-party origins |
| **Not checking if session token changes after login** | Same token before and after login = instant fixation vulnerability |
| **Testing session timeout with a single long wait** | Log out immediately after login and try to reuse the token — timeout may be enforced on server on logout |
| **Only testing CSRF on POST endpoints** | PUT and DELETE endpoints often lack CSRF protection even when POST has it |

## Evidence Requirements
- [ ] Cookie attributes (HttpOnly, Secure, SameSite, Path, Domain)
- [ ] Session token analysis (length, character set, randomness)
- [ ] CSRF PoC (HTML form that replays the action)
- [ ] Session timeout measurement
- [ ] WSTG SESS test ID
- [ ] Pre/post-login session token comparison (fixation test)

## Phase Gates
- Phase 3 (INFO-GATHERING): Document session management mechanisms
- Phase 6 (HUNT): Test each session management vector
- Phase 8 (EXPLOIT): Chain session flaws to account takeover
