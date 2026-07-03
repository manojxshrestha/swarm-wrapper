# Phase 6: HUNT (Vulnerability Hunting)

4-layer vulnerability discovery pipeline: prep → batch test → AI dispatch → per-class deep exploitation. Runs after SURFACE (Phase 5), feeds DEEPTHINK (Phase 7).

---

## Objectives

- Extract parameters, secrets, virtual hosts, and 403 bypass candidates (Layer A)
- Run automated 17-class payload detection against all live URLs (Layer B)
- Route hits + tech signals to specialized hunting agents via 4-tier dispatch (Layer C)
- Deep-test and exploit each class via dedicated subagents (Layer D)
- Validate, log, and chain findings for reporting

---

## Hard Rules

1. **NEVER install tools.** All tools are pre-installed at `scripts/tools/`. Never run `pip install`, `go install`, `apt install`, or any package manager.
2. **ALWAYS use `scripts/tools/` wrappers.** Never invoke tool binaries directly. Use `bash $HOME/swarm/scripts/tools/<name>.sh` instead.
3. **NO independent recon.** Do not re-run subdomain enum or crawl. Use the `endpoint_map` deliverable from Phase 5.
4. **NEVER install wordlists.** Use `scripts/tools/` wrappers which handle wordlist paths correctly.
5. **Browser FIRST** — For OAuth flows, SPA testing, and PoC evidence, use browser MCP tools before falling back to curl/Burp.

---

## Behavior Modes

The hunt agent behaves differently depending on how it was invoked:

| Mode | Behavior |
|------|----------|
| **`@autopilot`** | Test ALL applicable classes automatically. Do not ask permission. Prioritize by impact. |
| **Loaded directly by user** | Be interactive. Ask which classes to test, suggest priorities, brainstorm approaches. |

---

## Browser Hygiene

When using the browser (CF-challenged domains, DOM inspection, PoC screenshots):
1. `browser_screenshot(engagement_id, agent_id, url, label)` — always pass a descriptive `label`
2. `browser_act(engagement_id, "close")` — immediately after, every time
3. NEVER call `browser.newContext()` — the default context already routes through Burp via `--proxy-server`

All evidence screenshots are saved to `$RECON_BASE/<domain>/evidence/`.

---

## Consume Surface Deliverable

Before any testing, load the endpoint map from Phase 5:

```
get_deliverable(deliverable_type='endpoint_map')
```

This gives the prioritized endpoint list:
- **Tier 0:** Public endpoints that accept input — test first (no auth barrier)
- **Tier 1:** Auth-gated endpoints that accept input — test after getting credentials
- **Tier 2:** Infrastructure findings — test last (lower impact, passive detection)

If no deliverable exists, triage endpoints yourself:
1. Which endpoints accept user input? (params, body, headers, upload)
2. Which are public? (no auth)
3. Which need auth? (401/403 without credentials)

---

## Critical Mindset: Entry Point First

**Stop looking at what the server sends you. Start looking at what the server accepts from you.**

Before running any class-specific tests (XSS, SQLi, etc.), you MUST first find the **entry point** — the primitive that opens the door for everything else. Working without an entry point means every test is blind.

Questions to ask yourself:
- **Do I have auth?** If yes, what can I do now? If no, getting auth is priority #1.
- **Does the API accept unexpected input?** Try JSON→XML→form→multipart. Try HTTP method override headers. Try parameter pollution.
- **Are there race conditions?** Test auth flows: signup, login, password reset, OTP validation.
- **Is there GraphQL?** Test introspection, batching, alias-based enumeration.
- **Are there JWTs?** Decode them, test alg confusion, kid injection, jwk header injection.
- **Are there UUIDs?** Analyze patterns, try enumeration, path traversal, type confusion.
- **Is there a mobile API?** Different User-Agent, different endpoints, weaker auth.

**The #1 mistake: jumping to class-based hunting without finding an entry point first.**

---

## Entry Point Testing (Run Before Layer B)

Run these techniques first. They find the precondition that everything else depends on.

### 0. Cloudflare Check

```bash
curl -svI https://<target>/ 2>&1 | grep -i "cf-\|cloudflare\|server: cloudflare"
```

If Cloudflare is blocking curl (`cf-mitigated`, `cf-challenge`, 403 with CF headers):
- **Redirect 80% of effort to the API subdomain** (`api.<target>`) — rarely CF-protected
- Use the **browser** for testing on CF domains (browser passes CF challenge)
- Focus on non-CF endpoints: API, mobile API, staging subdomains
- Document `CF_STATUS: active`

### 1. Auth Status Check

```bash
curl -sv https://<target>/api/me -H "Authorization: Bearer <token>" 2>&1
curl -sv https://<target>/api/user/profile -b "session=<cookie>" 2>&1
```

Label all findings as `[AUTHENTICATED]` or `[UNAUTHENTICATED]`.

### 2. API Fuzzing (Hidden Params)

Run `bash "$HOME/swarm/scripts/tools/param_extract.sh" <target>` to discover hidden params.
Look for: `admin`, `role`, `is_admin`, `is_public`, `user_id`, `debug`, `bypass`, `override`, `test`.

### 3. HTTP Method Override

Try `X-HTTP-Method-Override: PUT/PATCH/DELETE` on every endpoint.
Try `X-Method-Override`, `X-HTTP-Method`.
A GET-only endpoint might accept POST when overridden.

### 4. Content-Type Switching

Send JSON endpoints as XML → may expose XXE.
Send JSON as form-encoded → may bypass validation.
Send as multipart → may bypass content-type checks.

### 5. GraphQL Probing (if detected)

- Introspection query
- Batching attack (rate limit bypass via array)
- Alias-based resource enumeration

### 6. Auth Flow Race Conditions

- Race signup (same email 20x)
- Race password reset
- Race OTP/2FA validation

### 7. UUID Analysis

- Check for sequential/timestamp patterns
- Try null UUID, all-zeros, all-ffs
- Path traversal in UUID param

### 8. JWT Manipulation (if found)

- Decode with `jwt_tool`
- Test `alg: none` bypass
- Test `kid` injection (path traversal)
- Test JWK header injection

### 9. Mobile API Surface

- Different User-Agent: `curl -H "User-Agent: Mobile/1.0"`
- Different API version: try `/v1/`, `/v2/`, `/mobile/`

### If Entry Point Found

- Log it as a finding
- Re-run entry point techniques with the new access level
- Then proceed to class-based hunting (Layer B→C→D)

### If No Entry Point Found

- Proceed with `[UNAUTHENTICATED]` label on all findings
- Focus on auth-free bugs: source leaks, open buckets, CORS, subdomain takeover
- Accept that the target is hardened — adjust expectations

---

## Layer A — Prep: `scripts/tools/phase-hunt.sh`

Background preparation that runs in parallel via `nohup`. Produces candidate lists consumed by AI agents.

```bash
# Standard — passive param extraction + secrets + vhost + 403
bash "$HOME/swarm/scripts/tools/phase-hunt.sh" <domain>

# With active parameter discovery (slower, more thorough):
bash "$HOME/swarm/scripts/tools/phase-hunt.sh" <domain> --active-param

# Root-only mode — single page crawl (for narrow-scope targets):
bash "$HOME/swarm/scripts/tools/phase-hunt.sh" <domain> --root-only

# Skip certain checks:
bash "$HOME/swarm/scripts/tools/phase-hunt.sh" <domain> --skip vhost
```

| Step | Script | Trigger | What it finds | Output |
|------|--------|---------|---------------|--------|
| Param extraction | `param_extract.sh` | Always | GF-filtered candidate URLs by bug class | `params/gf_*.txt` |
| Active params | `param-x8.sh` | `--active-param` or `.run_active_param` trigger | Hidden parameters via `x8` fuzzing | `params/x8_summary.txt` |
| JS secrets | `secrets_hunter.sh` | JS files exist in crawl output | API keys, tokens, endpoints in JS bundles | `secrets/js_*` |
| Auto secrets | `auto_secrets.sh` | Always (after JS scan) | Regex-based secret discovery in all files | `secrets/auto_*` |
| Vhost fuzzing | `vhost_fuzz.sh` | Always | Virtual hosts on the same IP | `vhost/vhosts.txt` |
| 403 bypass | `bypass_403.sh` | Always (`--quick` mode) | 403 restrictions that can be bypassed | `vhost/bypass_403.txt` |

All jobs use `nohup` to survive shell death.

**Output directory structure** (under `$RECON_BASE/<domain>/`):
```
hunt/
├── param_extract.log
├── param-x8.log         (if --active-param)
├── secrets_hunter.log
├── auto_secrets.log
├── vhost_fuzz.log
└── bypass_403.log
params/
├── gf_sqli.txt
├── gf_xss.txt
├── gf_ssrf.txt
├── gf_ssti.txt
├── gf_cmdi.txt
├── gf_lfi.txt
├── gf_redirect.txt
├── gf_idor.txt
├── gf_xxe.txt
└── x8_summary.txt       (if active param run)
secrets/
├── js_secrets.txt
├── auto_secrets.txt
└── api_keys.txt
vhost/
├── vhosts.txt
└── bypass_403.txt
```

---

## Layer B — Automated Batch: `scripts/payloads/hunt.sh`

17-class automated payload test against all live URLs. This is the **first pass** — results determine which classes get prioritized in Layer C.

```bash
# Quick: 100 requests per class
bash "$HOME/swarm/scripts/payloads/hunt.sh" <engagement-id>

# Deep: 5000 requests per class
bash "$HOME/swarm/scripts/payloads/hunt.sh" <engagement-id> --deep
```

### How Layer B Works

1. Reads `live.txt` from recon output
2. Phase 1: GF-filters `live.txt` into per-class URL lists (`recon/urls/<class>.txt`)
3. Phase 2: Runs each class's `test.sh` payload detection script against its URL list
4. Saves hits to `recon/hits/<class>/` for AI review

### Batch-Testable Classes (17)

**Classes with GF URL filtering (9):**

| Class | GF pattern | Test script | Dispatches to |
|-------|-----------|-------------|---------------|
| SQLi | `gf sqli` | `payloads/sqli/test.sh` | `@hunt-sqli` |
| XSS | `gf xss` | `payloads/xss/test.sh` | `@hunt-xss` |
| SSTI | `gf ssti` | `payloads/ssti/test.sh` | `@hunt-ssti` |
| SSRF | `gf ssrf` | `payloads/ssrf/test.sh` | `@hunt-ssrf` |
| CMDI | `gf cmdi` | `payloads/cmdi/test.sh` | `@hunt-rce` |
| LFI | `gf lfi` | `payloads/lfi/test.sh` | `@hunt-lfi` |
| Open Redirect | `gf redirect` | `payloads/redirect/test.sh` | `@hunt-open-redirect` |
| IDOR | `gf idor` | `payloads/idor/test.sh` | `@hunt-idor` |
| XXE | `gf xxe` | `payloads/xxe/test.sh` | `@hunt-xxe` |

**Classes tested against all live URLs (no GF filter, 8):**

| Class | Test script | Dispatches to |
|-------|-------------|---------------|
| CORS | `payloads/cors/test.sh` | `@hunt-cors` |
| CRLF | `payloads/crlf/test.sh` | `@hunt-crlf` |
| NoSQLi | `payloads/nosqli/test.sh` | `@hunt-nosqli` |
| Clickjacking | `payloads/clickjacking/test.sh` | `@hunt-clickjacking` |
| Prototype Pollution | `payloads/prototype-pollution/test.sh` | `@hunt-prototype-pollution` |
| HTTP Param Pollution | `payloads/http-param-pollution/test.sh` | `@hunt-http-param-pollution` |
| Mass Assignment | `payloads/mass-assignment/test.sh` | `@hunt-mass-assignment` |
| Dependency Confusion | `payloads/dependency-confusion/test.sh` | `@hunt-dependency-confusion` |

### Output Structure

```
$RECON_BASE/<domain>/
├── live.txt                          # Input: all live URLs
├── urls/                             # GF-filtered per-class URL lists
│   ├── sqli.txt
│   ├── xss.txt
│   ├── ssrf.txt
│   └── ... (17 files)
└── hits/                             # Payload detection hits
    ├── sqli/
    │   └── *.txt                     # Hit details for AI review
    ├── xss/
    │   └── *.txt
    └── ... (per-class subdirs)
```

### Important Notes

- Do NOT re-run `payloads/hunt.sh` after it completes
- If the script is not deployed, skip to Layer C directly
- Classes with hits → prioritize for manual verification and deep testing
- Classes without hits → skip automated retesting, but still test if the attack surface suggests the class applies

---

## Deep Testing — Required Before Dispatch

Before loading any `@hunt-*` agent, run the deep testing sequence on every candidate endpoint. This finds the **entry point primitive** that class-specific payloads exploit.

### Minimum deep testing per endpoint (9 techniques):

| # | Technique | Command | Time |
|---|-----------|---------|------|
| 1 | Parameter fuzzing | `bash $HOME/swarm/scripts/tools/param_extract.sh <target>` | ~2m |
| 2 | HTTP method mutation | Test all verbs + override headers | ~2m |
| 3 | Content-Type switching | JSON→XML→form→multipart | ~2m |
| 4 | IDOR probes | Numeric enumeration + UUID manipulation | ~2m |
| 5 | JSON parameter pollution | `__proto__`, duplicate keys, array injection | ~2m |
| 6 | Race condition | Parallel requests on auth flows | ~2m |
| 7 | JWT decode/manipulate | alg confusion, kid injection | ~2m |
| 8 | GraphQL deep probe | Introspection, batching, aliases | ~2m |
| 9 | Rate limit bypass | X-Forwarded-For rotation, HTTP/2 multiplex | ~2m |

Each technique takes ~2 minutes. Running all 9 on a single endpoint takes ~15 minutes. Budget 30 minutes per critical endpoint with params + IDOR.

**Do NOT skip this.** The deep testing techniques find the entry point primitive. Class-specific payloads exploit it. Without the primitive, class-specific payloads are just noise.

---

## Layer C — Dispatch: `@hunt-dispatch` 4-Tier System

After Layer B completes, collect hit classes from `recon/hits/` — any non-empty subdirectory is a hit. Then invoke `@hunt-dispatch`.

### Invocation

```
task(subagent_type="hunt-dispatch",
     description="hunt-dispatch: route hits to agents",
     prompt="engagement_id=<eid>, hit_classes=<hits>, tech_signals=<signals>, mode=wapt")
```

### Tier 1 — Batch Hit Priority (High Priority)

Each class with hits in `recon/hits/<class>/` adds its agent to the top of the dispatch list. These are **confirmed** to have surface detections and get tested **first**.

| Batch hit class | Agent |
|-----------------|-------|
| `sqli` | `@hunt-sqli` |
| `xss` | `@hunt-xss` |
| `ssrf` | `@hunt-ssrf` |
| `ssti` | `@hunt-ssti` |
| `cmdi` | `@hunt-rce` |
| `lfi` | `@hunt-lfi` |
| `redirect` | `@hunt-open-redirect` |
| `idor` | `@hunt-idor` |
| `xxe` | `@hunt-xxe` |
| `cors` | `@hunt-cors` |
| `crlf` | `@hunt-crlf` |
| `nosqli` | `@hunt-nosqli` |
| `clickjacking` | `@hunt-clickjacking` |
| `prototype-pollution` | `@hunt-prototype-pollution` |
| `http-param-pollution` | `@hunt-http-param-pollution` |
| `mass-assignment` | `@hunt-mass-assignment` |
| `dependency-confusion` | `@hunt-dependency-confusion` |

If `hit_classes` is empty, skip Tier 1.

### Tier 2 — Platform Signal Dispatch

Platform/enterprise signals detected during fingerprinting. Each match adds its specialized agent unconditionally (regardless of batch hits):

| Tech signal | Agent | What it does |
|-------------|-------|-------------|
| `okta.com`, `auth0.com`, `pingidentity` | `@okta-attack` | Okta identity platform exploitation |
| `login.microsoftonline.com`, `outlook`, `sts` | `@m365-entra-attack` | M365/Entra ID attack chains |
| `pulse`, `fortinet`, `ivanti`, `citrix` | `@enterprise-vpn-attack` | Enterprise VPN CVE exploitation |
| `vsphere`, `vcenter`, `:9443` | `@vmware-vcenter-attack` | VMware vCenter exploitation |
| `amazonaws`, `azure`, `googleapis`, `gcp` | `@cloud-iam-deep` | Cloud IAM privilege escalation |
| `github.com/<org>/` | `@supply-chain-attack-recon` | Supply chain recon (dep confusion, GH Actions) |
| `.apk`, `play.google.com` | `@apk-redteam-pipeline` | Android APK reverse engineering |
| `:6443`, `:10250`, `:2379`, `kubectl` | `@hunt-k8s` | Kubernetes security assessment |

Multiple matches → dispatch all matching agents.

### Tier 3 — OWASP Stack Signal Dispatch

Framework and technology signals that target specific vulnerability classes:

| Tech signal | Agent |
|-------------|-------|
| `MongoDB`, `mongoose`, `CouchDB`, `Redis` | `@hunt-nosqli` |
| `?page=`, `?file=`, `?path=`, `php wrapper` | `@hunt-lfi` |
| `rO0A`, `VIEWSTATE`, `rememberMe cookie` | `@hunt-deserialization` |
| `Access-Control-Allow-Origin header` | `@hunt-cors` |
| `/forgot-password`, `/reset`, `X-Forwarded` | `@hunt-host-header` |
| `?redirect=`, `?next=`, `?return=`, `?url=` | `@hunt-open-redirect` |
| `OTP`, `/verify`, `/2fa`, `no-rate-limit` | `@hunt-brute-force` |
| `Set-Cookie session`, `PHPSESSID` | `@hunt-session` |
| `Active Directory`, `LDAP`, `OpenLDAP`, `ADFS` | `@hunt-ldap` |
| `__NEXT_DATA__`, `/_next/`, `buildId` | `@hunt-nextjs` |
| `X-Powered-By: Express`, `Node.js`, `.js stack` | `@hunt-nodejs` |
| `postMessage`, `dangerouslySetInnerHTML` | `@hunt-dom` |
| `WebSocket`, `ws://`, `socket.io` | `@hunt-websocket` |
| `gRPC`, `:50051`, `application/grpc` | `@hunt-grpc` |
| `laravel_session`, `Ignition`, `Telescope` | `@hunt-laravel` |
| `X-Application-Context`, `Whitelabel`, `/actuator` | `@hunt-springboot` |
| `.github/workflows`, `Jenkins`, `GitLab CI` | `@hunt-cicd` |
| `.js.map`, `swagger.json`, `/.env` | `@hunt-source-leak` |
| `HSTS missing`, `SPF`, `DMARC`, `AXFR` | `@hunt-tls-network` |
| `ASP.NET`, `X-AspNet-Version`, `__VIEWSTATE` | `@hunt-aspnet` |
| `SharePoint`, `_layouts/`, `_vti_bin` | `@hunt-sharepoint` |
| `NTLM`, `WWW-Authenticate: NTLM` | `@hunt-ntlm-info` |
| `SAML`, `samlp:`, `AssertionConsumerService` | `@hunt-saml` |
| `oauth`, `/authorize`, `/token`, `state=` | `@hunt-oauth` |
| `graphql`, `/graphql`, `__typename` | `@hunt-graphql` |
| `JWT`, `Bearer eyJ`, `alg:` | `@hunt-jwt-confusion` |
| `X-Forwarded-For`, `X-Real-IP`, `Client-IP` | `@hunt-ssrf` |
| `169.254.169.254`, `metadata.google`, `instance-data` | `@hunt-ssrf-cloud` |

### Tier 4 — Universal OWASP Dispatch (Always-On)

These agents fire on **every** target. They are the floor — no target gets fewer than this. Mode controls the breadth:

**mode=redteam** (13 high-impact agents):
```
@hunt-rce, @hunt-sqli, @hunt-ssrf, @hunt-ato, @hunt-auth-bypass,
@hunt-saml, @hunt-oauth, @hunt-mfa-bypass, @hunt-file-upload,
@hunt-http-smuggling, @hunt-cloud-misconfig, @hunt-sharepoint, @hunt-aspnet
```

**mode=wapt** (56 agents — full OWASP-relevant set):
```
@hunt-xss,  @hunt-sqli,  @hunt-ssrf,  @hunt-idor,
@hunt-csrf,  @hunt-xxe,  @hunt-rce,  @hunt-graphql,
@hunt-oauth,  @hunt-saml,  @hunt-mfa-bypass,  @hunt-auth-bypass,
@hunt-ato,  @hunt-file-upload,  @hunt-business-logic,  @hunt-race-condition,
@hunt-llm-ai,  @hunt-api-misconfig,  @hunt-ssti,  @hunt-cache-poison,
@hunt-http-smuggling,  @hunt-subdomain,  @hunt-cloud-misconfig,  @hunt-misc,
@hunt-aspnet,  @hunt-sharepoint,  @hunt-ntlm-info,
@hunt-lfi,  @hunt-nosqli,  @hunt-deserialization,
@hunt-cors,  @hunt-host-header,  @hunt-open-redirect,
@hunt-brute-force,  @hunt-session,  @hunt-ldap,
@hunt-nextjs,  @hunt-nodejs,  @hunt-dom,
@hunt-websocket,  @hunt-grpc,  @hunt-laravel, @hunt-soap,
@hunt-springboot,  @hunt-k8s,  @hunt-cicd,
@hunt-source-leak,  @hunt-tls-network,
@hunt-clickjacking,  @hunt-crlf,  @hunt-dependency-confusion,
@hunt-http-param-pollution,  @hunt-mass-assignment,  @hunt-prototype-pollution,
@hunt-jwt-confusion, @hunt-ssrf-cloud
```

### Dispatch vs Always-On Summary

Not all agents dispatch on every target. Here is exactly what fires and when:

| Category | Count | Dispatch trigger | Examples |
|----------|-------|-----------------|----------|
| **Tier 4 always-on (wapt)** | 56 agents | Always — every target | `@hunt-xss`, `@hunt-sqli`, `@hunt-idor`, ... |
| **Tier 4 always-on (redteam)** | 13 agents | Always — every red team target | `@hunt-rce`, `@hunt-ato`, `@hunt-sqli`, ... |
| **Tier 2 platform** | 8 agents | Only on fingerprint match | `@okta-attack`, `@apk-redteam-pipeline`, `@hunt-k8s` |
| **Tier 3 stack** | ~28 signal rules | Only on tech pattern match | `@hunt-nextjs`, `@hunt-graphql`, `@hunt-springboot` |
| **Tier 1 batch hits** | 17 possible | Only if Layer B found hits | `@hunt-xss`, `@hunt-sqli`, etc. (already in Tier 4) |

**For a web-only target like `hackerone.com`**: all 56 Tier 4 agents fire. Platform agents (Okta, M365, APK, VPN, vCenter, cloud-iam, supply-chain) stay silent. Stack agents (Next.js, GraphQL, JWT) may also fire if their signal is detected.

**For an Android app target with Okta SSO**: 56 Tier 4 agents fire + `@apk-redteam-pipeline` (Tier 2, `.apk` signal) + `@okta-attack` (Tier 2, `okta.com` signal).

### Deduplication

An agent can appear in multiple tiers. `@hunt-sqli` could be in Tier 1 (batch hit) AND Tier 4 (always-on). Deduplicate: each agent is invoked **once** per dispatch cycle.

### Consume Dispatch Output

After dispatch returns, read the deliverable:

```
get_deliverable(deliverable_type='hunt_dispatch')
```

This returns the ordered agent list (Tier 1 → 2 → 3 → 4) with duplicates removed.

---

## Layer D — Agent Execution

Each dispatched agent runs autonomously. The calling hunt agent collects findings via `task()`.

### Invocation

```
task(subagent_type="hunt-<class>",
     description="hunt-<class>: deep test + exploit",
     prompt="{endpoints to test, auth context, engagement_id}")
```

### Per Invocation

For each agent in the dispatch list:

1. Spawn via `task()` with:
   - Target endpoints and parameters
   - Auth context (token, session cookie)
   - Engagement ID for finding logging

2. On finding confirmed:
   - `validate_poc()` — verify exploitability in real time
   - `log_finding()` — persist to findings database
   - `track_test()` — record WSTG coverage
   - `create_exploitation_queue()` — if chainable to other classes

3. On stuck (tool failure, unfamiliar tech, chain dead-end):
   - `task(@deepthink)` with trigger context
   - `task(@search)` for stale payloads or missing CVEs

### Per-Class Agent Reference

| Agent | Class | Entry point | Typical WSTG tests |
|-------|-------|-------------|-------------------|
| `@hunt-xss` | Cross-Site Scripting | Params, forms, DOM sinks | WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01 |
| `@hunt-sqli` | SQL Injection | DB-interacting params | WSTG-INPV-05 |
| `@hunt-ssrf` | Server-Side Request Forgery | URL params, file fetch | WSTG-INPV-19 |
| `@hunt-ssrf-cloud` | Cloud Metadata SSRF | `169.254.169.254`, IMDSv1/v2 | WSTG-INPV-19 |
| `@hunt-idor` | Insecure Direct Object Reference | UUIDs, numeric IDs | WSTG-ATHZ-01 |
| `@hunt-ssti` | Server-Side Template Injection | Template-rendered params | WSTG-INPV-18 |
| `@hunt-lfi` | Local File Inclusion | `?file=`, `?page=`, `?path=` | WSTG-ATHZ-01 |
| `@hunt-rce` | Remote Code Execution | OS command sinks, eval() | WSTG-INPV-12 |
| `@hunt-graphql` | GraphQL API | Introspection, batching, aliases | WSTG-APIT-01 |
| `@hunt-csrf` | Cross-Site Request Forgery | State-changing endpoints | WSTG-SESS-05 |
| `@hunt-xxe` | XML External Entity | XML-accepting endpoints | WSTG-INPV-20 |
| `@hunt-oauth` | OAuth 2.0 / OpenID Connect | Redirect URIs, state, tokens | WSTG-ATHZ-05 |
| `@hunt-mfa-bypass` | MFA Bypass | OTP, backup codes, push | WSTG-ATHN-11 |
| `@hunt-auth-bypass` | Authentication Bypass | Forced browsing, method override | WSTG-ATHN-04 |
| `@hunt-ato` | Account Takeover | Password reset, OAuth theft | WSTG-ATHN-10 |
| `@hunt-file-upload` | File Upload | Upload endpoints, content-type | WSTG-BUSL-08 |
| `@hunt-business-logic` | Business Logic Flaw | Pricing, workflows, coupons | WSTG-BUSL-01 through -10 |
| `@hunt-race-condition` | Race Condition | TOCTOU, payment, OTP race | WSTG-BUSL-04 |
| `@hunt-llm-ai` | LLM/AI Security | Prompt injection, RAG poisoning | WSTG-INPV-20 |
| `@hunt-api-misconfig` | API Misconfiguration | Mass assignment, rate limiting | WSTG-APIT-01 |
| `@hunt-cache-poison` | Web Cache Poisoning | Unkeyed inputs, CDN bypass | WSTG-CLNT-12 |
| `@hunt-http-smuggling` | HTTP Request Smuggling | CL.TE, TE.CL, H2.CL | WSTG-INPV-15 |
| `@hunt-subdomain` | Subdomain Takeover | CNAME dangling, NS delegation | WSTG-CONF-10 |
| `@hunt-cloud-misconfig` | Cloud Misconfiguration | S3, Azure Blob, GCP buckets | WSTG-CONF-11 |
| `@hunt-aspnet` | ASP.NET Security | ViewState, machineKey | WSTG-CONF-04 |
| `@hunt-sharepoint` | SharePoint Security | Exposed web parts, WF abuse | WSTG-CONF-04 |
| `@hunt-ntlm-info` | NTLM Information Disclosure | NTLM challenge capture | WSTG-INFO-09 |
| `@hunt-deserialization` | Insecure Deserialization | Java, PHP, .NET, Python | WSTG-INPV-10 |
| `@hunt-cors` | CORS Misconfiguration | Origin reflection, wildcard | WSTG-CLNT-07 |
| `@hunt-host-header` | Host Header Injection | Password reset poisoning | WSTG-INPV-17 |
| `@hunt-open-redirect` | Open Redirect | URL parser bypass | WSTG-CLNT-04 |
| `@hunt-brute-force` | Brute Force | Rate limit bypass, JWT brute | WSTG-ATHN-03 |
| `@hunt-session` | Session Management | Session fixation, prediction | WSTG-SESS-01 through -06 |
| `@hunt-ldap` | LDAP Injection | LDAP query params | WSTG-INPV-06 |
| `@hunt-nextjs` | Next.js Security | SSG/SSR leakage, middleware | WSTG-CONF-04 |
| `@hunt-nodejs` | Node.js Security | Prototype pollution, unsafe eval | WSTG-INPV-10 |
| `@hunt-dom` | DOM-based Vulnerabilities | postMessage, DOM clobbering | WSTG-CLNT-01 |
| `@hunt-websocket` | WebSocket Security | WS injection, CSWSH | WSTG-CLNT-09 |
| `@hunt-grpc` | gRPC API Security | Reflection, proto leakage | WSTG-APIT-02 |
| `@hunt-soap` | SOAP/XML Web Service | WSDL, XXE, XML bomb | WSTG-APIT-03 |
| `@hunt-laravel` | Laravel Security | APP_KEY, serialization RCE | WSTG-CONF-04 |
| `@hunt-springboot` | Spring Boot Security | Actuator, SpEL injection | WSTG-CONF-05 |
| `@hunt-k8s` | Kubernetes Security | RBAC, pod escape, kubelet | N/A (custom) |
| `@hunt-cicd` | CI/CD Pipeline Security | GH Actions, Jenkins, GitLab | N/A (custom) |
| `@hunt-source-leak` | Source Code Leak | `.git/config`, `.env`, swagger | WSTG-INFO-05 |
| `@hunt-tls-network` | TLS/SSL Security | Weak ciphers, HSTS missing | WSTG-CRYP-01 |
| `@hunt-clickjacking` | Clickjacking | X-Frame-Options, CSP | WSTG-CLNT-08 |
| `@hunt-crlf` | CRLF Injection | Header injection, response split | N/A (custom) |
| `@hunt-dependency-confusion` | Dependency Confusion | Package squatting | N/A (custom) |
| `@hunt-http-param-pollution` | HTTP Parameter Pollution | Duplicate params | WSTG-INPV-04 |
| `@hunt-mass-assignment` | Mass Assignment | Extra JSON fields | WSTG-BUSL-01 |
| `@hunt-prototype-pollution` | Prototype Pollution | `__proto__`, constructor | WSTG-CLNT-14 |
| `@hunt-jwt-confusion` | JWT Algorithm Confusion | alg:none, kid injection | WSTG-SESS-10 |
| `@hunt-nosqli` | NoSQL Injection | MongoDB `$where`, `$regex` | WSTG-INPV-05 |
| `@hunt-misc` | General / Misc | Catch-all | Varies |

### Platform-Specific Agents

| Agent | What it tests | Trigger signal | When it dispatches |
|-------|-------------|----------------|--------------------|
| `@okta-attack` | Okta identity platform | `okta.com`, `auth0.com` | Only if Tier 2 matches |
| `@m365-entra-attack` | Microsoft 365 / Entra ID | `login.microsoftonline.com` | Only if Tier 2 matches |
| `@enterprise-vpn-attack` | Enterprise VPN appliances | `pulse`, `fortinet`, `citrix` | Only if Tier 2 matches |
| `@vmware-vcenter-attack` | VMware vCenter | `vsphere`, `:9443` | Only if Tier 2 matches |
| `@cloud-iam-deep` | Cloud IAM priv-esc | `amazonaws`, `azure`, `gcp` | Only if Tier 2 matches |
| `@supply-chain-attack-recon` | Supply chain recon | `github.com/<org>/` | Only if Tier 2 matches |
| `@apk-redteam-pipeline` | Android APK reverse engineering | `.apk`, `play.google.com` | Only if Tier 2 matches |
| `@hunt-k8s` | Kubernetes cluster security | `:6443`, `:10250`, `kubectl` | Always (Tier 4) + Tier 2 priority |

---

## Pipeline Admin

After all agents complete:

1. **Track pipeline tools**:
   ```
   track_tool(engagement_id, '<eid>', 'phase-hunt.sh', 'run',
              notes='Parameter extraction, secrets, vhost, 403 bypass')
   track_tool(engagement_id, '<eid>', 'payloads-hunt.sh', 'run',
              notes='Automated 17-class payload testing')
   ```

2. **Chain findings**: `findings_add_chain()` to record multi-step attack paths

3. **Gate check**: `phase_gate_check(engagement_id='<eid>', phase_completed=6)`

4. **Next phase**: If via `@autopilot`, proceed to `@capture` automatically. If loaded directly, tell the user what was found and ask how to proceed.

---

## Fallback System

When any `@hunt-*` agent encounters a blocker:

| Situation | Fallback | What to pass |
|-----------|----------|--------------|
| Tool/script failure | `task(@deepthink)` | `{"trigger":"tool_failure","target":"<domain>","engagement_id":"<eid>"}` |
| Unfamiliar technology | `task(@deepthink)` | `{"trigger":"unfamiliar_tech","detail":"<signal>"}` |
| Chain dead-end | `task(@deepthink)` | `{"trigger":"chain_dead_end","findings":["..."]}` |
| Bypass exhaustion | `task(@deepthink)` | `{"trigger":"bypass_exhausted","class":"<class>"}` |
| Stale payloads | `task(@search)` | `{"trigger":"stale_payloads","class":"<class>","context":"<detected_stack>"}` |
| Missing CVE | `task(@search)` | `{"trigger":"missing_cve","software":"<name>","version":"<v>"}` |
| Severity precedent | `task(@search)` | `{"trigger":"severity_precedent","class":"<class>","impact":"<claim>"}` |

---

## Complete Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│ SURFACE (Phase 5)                                                │
│   └─ endpoint_map deliverable (tiered endpoint priority list)    │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ ENTRY POINT TESTING                                              │
│   CF check → auth status → param fuzz → method override →       │
│   content-type switch → GraphQL → race → UUID → JWT → mobile   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ LAYER A — PREP (phase-hunt.sh)        [✔ track_tool() required] │
│   param_extract.sh → param-x8.sh → secrets_hunter.sh →          │
│   auto_secrets.sh → vhost_fuzz.sh → bypass_403.sh               │
│   All via nohup in parallel                                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ LAYER B — BATCH TEST (payloads/hunt.sh)  [✔ track_tool() req.]  │
│   17 classes × curated payloads → recon/hits/<class>/            │
│                                                                  │
│   GF-filtered:  sqli xss ssrf ssti cmdi lfi redirect idor xxe  │
│   All URLs:     cors crlf nosqli clickjacking prototype-poll    │
│   Special:      http-param-pollution mass-assignment dep-conf   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ DEEP TESTING (mandatory before dispatch)                         │
│   1. Parameter fuzzing      6. Race condition                    │
│   2. Method mutation         7. JWT manipulation                 │
│   3. Content-type switch     8. GraphQL deep probe               │
│   4. IDOR probes             9. Rate limit bypass                │
│   5. JSON param pollution                                       │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ LAYER C — DISPATCH (task @hunt-dispatch)                         │
│   Input: hit_classes + tech_signals + mode                       │
│                                                                  │
│   Tier 1: Batch hits from Layer B ── high priority              │
│   Tier 2: Platform signals ────────── only on match             │
│   Tier 3: OWASP stack signals ─────── only on match             │
│   Tier 4: Universal set ───────────── always                    │
│                    wapt=56 agents | redteam=13 agents            │
│                                                                  │
│   Output: get_deliverable(hunt_dispatch) → ordered agent list   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ LAYER D — AGENT EXECUTION (for each agent in dispatch list)     │
│                                                                  │
│   For agent in deduplicated_priority_list:                       │
│     task(subagent_type="hunt-<class>", ...)                      │
│                                                                  │
│   On finding confirmed:                                          │
│     1. validate_poc() ─── verify exploitability                 │
│     2. log_finding() ──── persist to findings database          │
│     3. track_test() ──── record WSTG coverage                   │
│     4. create_exploitation_queue() ── if chainable              │
│                                                                  │
│   On stuck: task(@deepthink) or task(@search)                   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ PIPELINE ADMIN                                                   │
│   track_tool() for phase-hunt.sh + payloads-hunt.sh             │
│   findings_add_chain() ── multi-step attack paths                │
│   phase_gate_check(phase_completed=6) ── quality gate           │
│   If autopilot: proceed to DEEPTHINK → EXPLOIT → CAPTURE        │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│ DEEPTHINK (Phase 7) → EXPLOIT (Phase 8) → SEARCH (Phase 9)     │
│ CAPTURE (Phase 10) → VALIDATE (Phase 11) → REPORT (Phase 12)   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Tool Registration (TOOL_REGISTRY)

| Tool | Script | Status | Phase requirement |
|------|--------|--------|-------------------|
| `phase-hunt.sh` | `scripts/tools/phase-hunt.sh` | Mandatory | Must be tracked via `track_tool()` |
| `payloads-hunt.sh` | `scripts/payloads/hunt.sh` | Mandatory | Must be tracked via `track_tool()` |
| `sqlmap` | Conditional | Conditional | `@hunt-sqli` may use manually |
| `dalfox` | Conditional | Conditional | `@hunt-xss` may use manually |
| `crlfuzz` | Conditional | Conditional | `@hunt-crlf` may use manually |
| `smuggler` | Conditional | Conditional | `@hunt-http-smuggling` may use manually |

---

## Privacy Rules

From `hunt-dispatch.md` — applies to all dispatched agents:
- Never echo back, log, or persist SOW / scope-of-work / engagement-letter content
- Never write grey box credentials to disk (kept in session memory by your calling agent)
- Never persist client identifiers in user-level memory

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `payloads/hunt.sh` fails: "No live.txt found" | Recon not run yet | Run Phase 4/5 first, or ensure live hosts were discovered |
| All 17 classes return zero hits | WAF blocking payloads, or target is SPA without params | Check `CF_STATUS`, run browser-based testing, focus on API endpoints |
| `phase-hunt.sh` jobs don't complete | `nohup` background processes | Check `hunt/*.log` files for errors, re-run with specific flags |
| Dispatch returns empty agent list | `mode` not set, or engagement_id missing | Verify invocation context has `mode=wapt` and `engagement_id` |
| Agent times out after 10+ minutes | API rate limiting, or large parameter set | Reduce scope (fewer endpoints), use `--quick` mode |
| No findings despite 56 agents firing | Target is well-hardened, or entry point not found | Re-run entry point testing, focus on auth-free bugs |

---

## Related Files

### Agent files (in `.swarm/agents/`)
- `hunt.md` — Main hunt orchestrator agent
- `hunt-dispatch.md` — 4-tier dispatch engine
- `hunt-{class}.md` — 57 total hunt agents (56 per-class + `hunt-dispatch` dispatcher)
- Platform agents: `okta-attack.md`, `m365-entra-attack.md`, `enterprise-vpn-attack.md`, `vmware-vcenter-attack.md`, `cloud-iam-deep.md`, `supply-chain-attack-recon.md`, `apk-redteam-pipeline.md`

### Scripts (in `scripts/`)
- `tools/phase-hunt.sh` — Layer A: prep pipeline (param extraction, secrets, vhost, 403 bypass)
- `tools/param_extract.sh` — GF parameter extraction
- `tools/param-x8.sh` — Active parameter discovery via x8
- `tools/secrets_hunter.sh` — JS bundle secret scanning
- `tools/auto_secrets.sh` — Auto regex secret hunting
- `tools/vhost_fuzz.sh` — Virtual host discovery
- `tools/bypass_403.sh` — 403 bypass probing
- `tools/_env.sh` — Environment and logging setup
- `payloads/hunt.sh` — Layer B: 17-class batch test pipeline
- `payloads/<class>/test.sh` — Per-class payload detection executors

### Docs
- `docs/phases/hunt.md` — This document
- `docs/browser-flow.md` — Browser automation reference
- `docs/deep-testing.md` — Deep testing sequence reference
- `docs/pipeline.md` — OOB detection workflow
- `knowledge/payloads/` — Reference-only payload documentation (not executed)

### Output directories
- `$RECON_BASE/<domain>/hunt/` — Layer A logs
- `$RECON_BASE/<domain>/params/` — GF-filtered URLs + x8 results
- `$RECON_BASE/<domain>/secrets/` — Discovered secrets
- `$RECON_BASE/<domain>/vhost/` — Vhost + 403 bypass results
- `$RECON_BASE/<domain>/hits/<class>/` — Layer B batch test hits
- `$RECON_BASE/<domain>/evidence/` — Browser screenshots and PoC evidence
