# Browser Authentication — Swarm Workflow

## MCP Tools
- `browser_login(engagement_id, agent_id, url, username, password)` — Login form with auto-detected fields
- `browser_auto_auth(engagement_id, url, email)` — Autonomous signup → verify → login
- `browser_analyze(engagement_id, url)` — Screenshot + text + elements for LLM-driven analysis
- `browser_act(engagement_id, action, index, text, url, code)` — navigate, click, type, js, cookies, state
- `browser_extract_storage(engagement_id, agent_id, url)` — Cookies + localStorage + sessionStorage
- `browser_screenshot(engagement_id, agent_id, url)` — Evidence screenshot

## When to Use Each Method

| Method | When |
|--------|------|
| `browser_login` | Credentials known, standard login form |
| `browser_analyze` + `browser_act` | SPA, CSP-blocked, custom UI, anti-bot pages |
| `browser_auto_auth` | Need to create account automatically |
| Cookie injection | Tokens/cookies from other source |

## Flow

1. Read engagement config for credentials and auth type
2. Choose method (form login, OAuth, signup)
3. Execute auth with retries (max 2)
4. If SPA/CSP: use analyze→act loop (observe → decide → execute)
5. Verify session (check cookies, protected endpoint)
6. Extract storage: `browser_extract_storage(engagement_id, agent_id, url)`
7. Save evidence: `browser_screenshot(engagement_id, agent_id, url)`

## Anti-Bot

- analyze→act loop bypasses CSP and bot detection (LLM reads the page directly)
- If CAPTCHA detected → report `captcha` status, do NOT attempt bypass
- If page loads but elements not interactive → try longer wait, check state
- Google OAuth may trigger SMS/2FA → report as `captcha`

## Session Verification

```python
cookies = browser_act(engagement_id, "cookies")
browser_act(engagement_id, "navigate", url="https://target.com/api/me")
state = browser_analyze(engagement_id)
# Should show user profile, not login page
```

## See Also
- `skills/browser-auth/SKILL.md` — full methodology with auth category deep-dives
- `docs/browser-flow.md` — technical reference for all browser tools
- `prompts/authentication.md` — API-level auth testing (Phase 2)
