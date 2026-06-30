# Phase 2: AUTH

Authentication setup, WAF fingerprinting, and credential/session capture.

---

## Objectives

- Detect and fingerprint WAF (Web Application Firewall)
- Sign up / log in to the target application
- Capture session cookies, JWT tokens, and auth headers
- Save auth context deliverable for all downstream phases
- (Conditional) Handle Cloudflare WAF — redirect effort to API subdomain

---

## Steps

### 1. WAF Fingerprinting

Uses response headers and block page analysis to identify the WAF vendor.

```python
identify_waf(response_headers, response_body, status_code)
```

Detection methods:
- **Header signatures** — `cf-ray` → Cloudflare, `x-sucuri-id` → Sucuri, `x-iinfo` → Imperva, `server: AkamaiGHost` → Akamai
- **Block page content** — Known blocking page HTML patterns per vendor
- **Status code patterns** — 403/503/406 patterns specific to WAFs

WAF detection is also performed by `scripts/tools/phase-auth.sh` which saves raw response headers:

```bash
curl -sI "https://<domain>" > auth/waf_detection.txt
```

### 2. Browser Auto-Auth (Autonomous)

If no credentials are provided via env vars (`BBHUNT_AUTH_HEADERS`, `BBHUNT_COOKIE`, `BBHUNT_BEARER`) or an existing `session.json`, the pipeline launches autonomous browser auth:

```bash
python3 scripts/tools/auto_auth.py <domain> --output-dir <out_dir>
```

The auto-auth flow:
1. **Signup page discovery** — Navigate to `/signup`, `/register`, or detect from page analysis
2. **Guerrilla Mail** — Generate a temporary email for account creation
3. **Form filling** — Fill username, email, password fields
4. **Email verification** — Poll Guerrilla Mail for verification link
5. **Login** — Use created credentials to authenticate
6. **Session capture** — Extract cookies and save to `auth/session.json`

Runs in background — log at `auth/auto_auth.log`.

### 3. Manual Auth via Browser Login

```python
browser_login(engagement_id, agent_id, url, username, password,
              username_field, password_field, submit_field, wait_for)
```

Custom selectors can be specified for non-standard login forms. Auto-detects fields if left empty.

### 4. Session Token Extraction

```python
browser_extract_storage(engagement_id, agent_id, url)
```

Extracts:
- **Cookies** — Session IDs, auth tokens
- **localStorage** — JWTs, refresh tokens, client-side state
- **sessionStorage** — Per-tab session data

### 5. Save Auth Deliverable

```python
save_deliverable(engagement_id, "auth_analysis", content, "auth")
```

The auth deliverable contains:
- WAF vendor + fingerprint details
- Session cookies / JWT tokens
- Login URL and auth mechanism (form, OAuth, SSO, header)
- Credentials used / auto-created
- Auth context IDs for multi-context probing

---

## WAF Handling

| WAF Vendor | Action |
|------------|--------|
| Cloudflare | Redirect 80% of effort to API subdomain (`api.*`); use headed browser for CF-challenged pages |
| Akamai | Apply WAF bypass techniques; check `knowledge/waf/` for vendor KB |
| AWS WAF | IP allowlist enumeration; rate-based rule evasion |
| Imperva | Known origin IP discovery (Censys/Shodan/favicon/SSL); client classification bypass |
| ModSecurity | CRS rule evasion; false positive abuse |
| Sucuri | Known origin IP via leaked DNS; header spoofing |
| None | Normal testing without evasion |

After WAF identification, apply vendor-specific bypasses during Phase 6 (HUNT):

```python
get_waf_bypass(waf_vendor, vuln_class, bypass_level)
```

WAF reference libraries:
- `knowledge/waf/waf-knowledge-base/02-waf-fingerprints/` — 144 vendor fingerprints
- `knowledge/waf/waf-knowledge-base/04-known-bypasses/` — 24 vendor bypass files
- `skills/waf-*/` — 15 loadable WAF bypass skills

---

## Auth Contexts for Multi-Auth Probing

Each captured session becomes an auth context used in Phases 6-8. Standard contexts:

| Context | Description | Captured By |
|---------|-------------|-------------|
| Anonymous | No session / default state | N/A |
| User-1 | Primary low-privilege user | auto-auth or browser_login |
| User-2 | Secondary user (different account) | browser_login with separate creds |
| Admin | High-privilege / administrative user | browser_login with admin creds |

Every finding in Phase 8 (EXPLOIT) is replayed against ALL contexts.

---

## Gate

```python
phase_gate_check(engagement_id, phase_completed=1)
```

Gate passes when:
- WAF detection complete (result documented)
- Auth deliverable saved (or documented as N/A for public-only targets)

---

## Output

| Artifact | Location | Description |
|----------|----------|-------------|
| waf_detection.txt | `auth/waf_detection.txt` | Raw response headers + WAF analysis |
| session.json | `auth/session.json` | Captured cookies and session metadata |
| auto_auth.log | `auth/auto_auth.log` | Browser auto-auth output |
| auth_analysis | deliverable | Structured auth context for downstream phases |

---

## Script

```bash
bash $HOME/swarm/scripts/tools/phase-auth.sh <domain>
```

With pre-set credentials:

```bash
BBHUNT_COOKIE="session=abc123" bash $HOME/swarm/scripts/tools/phase-auth.sh <domain>
BBHUNT_BEARER="eyJ..." bash $HOME/swarm/scripts/tools/phase-auth.sh <domain>
```
