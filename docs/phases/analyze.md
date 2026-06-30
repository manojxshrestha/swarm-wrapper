# ANALYZE — Web Page Analysis Agent

Cross-phase browser-based analysis agent. Read-only — navigates URLs, captures page state, classifies auth mechanisms, fingerprints tech stacks. Does NOT modify pages or submit forms.

---

## When It's Used

| Phase | Purpose | Deliverable Type |
|-------|---------|-----------------|
| Phase 0 — Pre-Scope | Auth page discovery — find signup/login URLs from root domain | `auth_page_discovery` |
| Phase 2b — Auth Analysis | Before `@browser-auth` — classify auth mechanism, capture redirect chain, detect MFA | `auth_analysis` |
| Phase 4 — Recon | Surface analysis on discovered endpoints — identify forms, hidden fields, tech stack | `surface_analysis` |
| Phase 5 — Surface | Deep-dive on high-priority endpoints — interactive elements, API surface | `surface_analysis` |
| Phase 6 — Hunt | Per-class endpoint analysis — check CORS headers, CSP, DOM structure | `surface_analysis` |
| Any | Ad-hoc page inspection (tech fingerprinting, cookie extraction, storage dump) | `surface_analysis` |

---

## Analysis Flow

### 1. Navigate & Capture

```
browser_analyze(engagement_id, url)
  → page title, URL, visible text, interactive elements, screenshot, cookie count
```

Supplement with:
- `browser_act(eid, "state")` — detailed element state
- `browser_act(eid, "html")` — raw DOM for hidden fields, scripts, metadata
- `browser_act(eid, "cookies")` — all cookies

### 2. Track Redirect Chain

Use navigation timing to capture every redirect:

```
browser_act(eid, "navigate", url=start_url)
browser_act(eid, "js", code="JSON.stringify(performance.getEntriesByType('navigation'))")
```

Document: Start URL → Intermediate URLs → Final URL. Identify auth provider domains.

### 3. Classify Auth Mechanism

| Signal | Detection |
|--------|-----------|
| `scope=openid` + `response_type=code` + `nonce` | OIDC (Okta, Auth0, Azure AD) |
| `response_type=code` + `client_id` + `redirect_uri` (no `openid`) | OAuth 2.0 |
| Hidden `SAMLResponse` input or `SAMLRequest` in URL | SAML |
| `<input type="password">` present | Form login |
| "check your email", "enter the code" text | Magic link / Email OTP |
| "Sign in with Google" buttons | Social OAuth |

### 4. Extract Storage

```
browser_extract_storage(eid, agent_id, url)
  → cookies, localStorage, sessionStorage
```

Check for: session tokens, CSRF tokens, OAuth state, OIDC artifacts (id_token, access_token).

### 5. Detect MFA

Look for: "verification code", "authenticator", "OTP", "2FA", "MFA", WebAuthn, QR code display, SMS/push options.

### 6. Fingerprint Tech Stack

| Signal | Where |
|--------|-------|
| Auth provider | URL domains (login.auth0.com), headers (x-okta-request-id), cookie names (okta-oauth-state) |
| Framework | Cookie names (connect.sid → Express, PHPSESSID → PHP, JSESSIONID → Java), meta tags, X-Powered-By |
| WAF/CDN | Response headers (CF-Ray, x-sucuri-id, x-amz-cf-id, Server) |
| SPA | Single entry HTML + JS bundle + client-side routing via XHR/fetch |

---

## Anti-Bot Handling

If blocked (CAPTCHA, Cloudflare challenge, JS challenge):
1. Document blocking mechanism
2. Return status `blocked`
3. Do NOT attempt bypass

---

## Output

`save_deliverable(engagement_id, deliverable_type, content, producer_agent="analyze")`

The deliverable is consumed by the calling phase agent. Full report format reference: `skills/analyze/SKILL.md` (Section 7).

---

## Reference

- Agent: `.opencode/agents/analyze.md`
- Full methodology: `skills/analyze/SKILL.md`
