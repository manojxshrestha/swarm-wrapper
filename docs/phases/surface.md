# Phase 5: SURFACE — Classify & Prioritize Attack Surface

Analysis-only phase. No testing tools are run. Takes recon output from Phase 4 and produces a ranked "test these N endpoints first" list consumed by Phase 6 (HUNT).

---

## Pipeline

```
Step 1: phase-surface.sh       — keyword pre-classification into tiers
Step 2: load deliverable        — get_deliverable('endpoint_map') from Phase 4
Step 3: classify by tier        — T0 (public+input), T1 (auth+input), T2 (infra)
Step 4: prioritize              — prioritize_endpoints() scoring engine
Step 5: save deliverable        — save_deliverable('endpoint_map') for Phase 6
Step 6: gate check              — phase_gate_check(phase_completed=5)
```

---

## Step 1: `phase-surface.sh` (Keyword Pre-Classification)

```bash
bash "$HOME/swarm/scripts/tools/phase-surface.sh" <domain>
```

Collects URLs from 7 recon sources, deduplicates, then classifies by keyword:

| Tier | Keywords | Description |
|------|----------|-------------|
| **Tier 1** | login, signin, auth, oauth, saml, logout, register, signup, admin, api, graphql, swagger, v1/, v2/, rest/ | Auth-gated + input endpoints |
| **Tier 0** | .js, .json, .xml, .yaml, .conf, .bak, .old, robots.txt, sitemap.xml, .git/, .env | Public + input endpoints |
| **Tier 2** | everything else | Infrastructure / passive info |

**Limitation:** Keyword-based only — no auth check, no content-type analysis. The AI agent does the real work in Step 3.

**Output:** `surface/endpoint_map_ranked.txt`

---

## Step 2: Load Phase 4 Deliverable

```
get_deliverable(engagement_id, deliverable_type='endpoint_map')
```

If no deliverable exists, fall back to raw files at `engagements/recon/<domain>/`:
- `crawl/merged-crawl.txt`
- `params/paramurls.txt` + `gf_*.txt`
- `cariddi/cariddi.txt`
- `directories/interesting_surface.txt`
- `directories/critical_exposure.txt`

---

## Step 3: Tier Classification (AI-Driven)

For every endpoint that accepts user input, answer:

| Question | What to check |
|----------|---------------|
| Q1: Input type? | params (GET/POST/JSON/XML), body, headers (User-Agent, Referer, X-Forwarded-For), cookies, file upload, file paths, GraphQL, HTTP method |
| Q2: Auth status? | public (no auth — returns data without Authorization header), auth-gated (returns 401/403), unknown |
| Q3: Impact if exploitable? | data read (low), data write (medium), code exec (high), auth bypass (critical) |

### Tier 0 — Public + Input
Endpoints that accept user input AND are public. No auth barrier. Feed directly into Phase 6 entry point testing.

**Examples:** public API endpoints, GraphQL introspection, WebSocket messages, search bars, redirect params, contact forms, public file uploads, registration flows.

### Tier 1 — Auth-Gated (60-90% of attack surface)
Endpoints that accept user input AND need authentication. This is where IDOR, BOLA, business logic, and privilege escalation live.

**Requires credentials from Phase 2.** If auth unavailable, Tier 1 is blind — focus on Tier 0.

### Tier 2 — Infrastructure & Passive
Endpoints that don't accept input but reveal attack surface:

| Finding | What it reveals |
|---------|----------------|
| Tech stack | Framework, DB, cloud provider — determines which bug classes apply |
| Subdomains | Potential takeover targets |
| CORS headers | Need auth to exploit, but misconfig enables cross-origin data theft |
| CSP headers | XSS mitigation strength — can you bypass? |
| Cookie flags | Session security (Secure, HttpOnly, SameSite) |
| Server banners | Version info for CVE lookup |

---

## Step 4: Prioritization

### 6 Rules (override scoring engine if needed)

1. **Public + accepts input** always beats auth-gated (no barrier to test)
2. **Write operations** (POST/PUT/PATCH/DELETE) beat read (GET) for same auth level
3. **File upload** beats structured data (JSON) beats unstructured data (query params)
4. **GraphQL** beats REST (single endpoint exposes entire schema)
5. **Known framework** with historical CVEs beats unknown stack
6. **Secrets in JS/HTML** are always P1 — they bypass all auth

### `prioritize_endpoints()` Scoring Engine

```python
prioritize_endpoints(engagement_id=<eid>, endpoints_json=<json_array>)
```

Each endpoint JSON: `method`, `path`, `parameters` (list), `auth_required` (bool), `tech_stack`, `has_taint_chain` (bool), `tool_count` (int).

**7-factor algorithm (from `server/endpoint_priority.py`):**

| Factor | Max | Description |
|--------|-----|-------------|
| Parameter count | +10 | Capped at 5 params → +10 |
| Technology risk | +5 | PHP/ASP=5, JSP=4, Java/Node/Ruby=3, Python/Flask=2, Go/Rust=1, static/CDN=0 |
| Taint chain | +5 | User input reaches dangerous sink |
| Tool convergence | +3 | +1 per tool (max 3) |
| User input | +2 | Endpoint accepts user input |
| No auth | +3 | Public endpoint |
| HTTP method | +3 | POST/PUT=3, PATCH/DELETE=2, GET=1 |
| Path indicator | +2 | /api/, /admin/, /upload, /import, /exec, /eval, /search, /login, /auth |
| Injectable params | +6 | 19 known injectable param names (id, file, url, page, redirect, etc.) |

Higher score = test first.

---

## Step 5: Save Deliverable

```python
save_deliverable(
    engagement_id='<eid>',
    deliverable_type='endpoint_map',
    content=<tier-0/tier-1/tier-2 list>,
    producer_agent='surface'
)
```

Consumed by Phase 6 (HUNT) via `get_deliverable('endpoint_map')`.

---

## Step 6: Gate

```python
phase_gate_check(phase_completed=5)
```

Passes when:
- `phase-surface.sh` completed
- Endpoint map deliverable loaded from Phase 4
- Tiers classified and prioritized
- `prioritize_endpoints()` called
- Deliverable saved for Phase 6
- `track_tool()` submitted

---

## Scripts

| Script | Location | Purpose |
|--------|----------|---------|
| `phase-surface.sh` | `scripts/tools/phase-surface.sh` | Keyword-based URL collection + tier classification |
| `endpoint_priority.py` | `server/endpoint_priority.py` | 7-factor risk scoring engine (called via MCP) |

## Commands

| Command | Location | Purpose |
|---------|----------|---------|
| `/surface` | `.opencode/commands/surface.md` | Interactive surface ranking via `recon-ranker` subagent — bypasses agent pipeline |
| `/surface` (bughunt) | `.opencode/commands-bughunt/surface.md` | Duplicate — identical to `commands/surface.md` |

## Reference

- Agent: `.opencode/agents/surface.md`
- Pipeline doc: `docs/pipeline.md` (Phase 5 section)
- Scoring engine: `server/endpoint_priority.py:64-164`
- Bug report: documented per program guidelines
