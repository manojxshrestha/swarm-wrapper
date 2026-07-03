---
description: Pipeline Phase 5 — Analyze recon output, rank P1/P2/P3 attack surface
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# SURFACE

Analyze the recon output and build a ranked, actionable attack surface. The output of this phase is a concrete **"test these N endpoints first"** list that `@hunt` consumes.

## ⚠ HARD RULES — DO NOT VIOLATE

1. **ALWAYS run `phase-surface.sh` first** — it pre-classifies URLs by keyword into tiers. Your analysis refines this, it doesn't replace it.
2. **NEVER install tools.** Run `"$HOME/swarm/scripts/tools/*.sh"` wrappers only. Never invoke tool binaries directly.
3. **Every endpoint gets 3 questions answered** — input type, auth status, impact. Skip nothing.
4. **ALWAYS call `prioritize_endpoints()`** before saving the deliverable. The scoring engine catches factors you might miss.
5. **Track every phase step** with `track_tool()`. Surface is analysis-only but still needs coverage tracking.

## ⚠ Mandatory Setup

**Working directory:** `cd "$HOME/swarm"`.

## Input

### Step 1: Run pre-classification script

```bash
bash "$HOME/swarm/scripts/tools/phase-surface.sh" <target>
```

This collects URLs from all recon sources, deduplicates, and classifies by keyword into `surface/endpoint_map_ranked.txt`. The keyword-based tiers are a starting point — you will refine them.

**Track:** `track_tool(tool_name='phase-surface', status='run', notes='Pre-classification via phase-surface.sh')`

### Step 2: Load endpoint map

Read the endpoint_map_raw deliverable from Phase 4 (recon):

```
get_deliverable(deliverable_type='endpoint_map')
```

If no deliverable exists, read the raw recon files from `$HOME/swarm/engagements/recon/<domain>/`:
- `crawl/merged-crawl.txt`
- `params/paramurls.txt` + `gf_*.txt`
- `cariddi/cariddi.txt`
- `directories/interesting_surface.txt`
- `directories/critical_exposure.txt`

### Step 3: Classify by Tier

For every endpoint that accepts user input, answer these 3 questions:

**Q1: Input type?** — params, body, headers, cookies, file upload, GraphQL, method
**Q2: Auth status?** — public (no auth), auth-gated (needs creds), unknown
**Q3: Impact if exploitable?** — data read (low), data write (medium), code exec (high), auth bypass (critical)

#### Tier 0 — Public + Accepts Input

Endpoints that accept user input AND are public. No auth barrier. Feed directly into Phase 6 entry point testing.

```
<tier-0-list>
<method> <url> [input: <type>] — test: <class>
</tier-0-list>
```

**Examples:** public API endpoints, GraphQL introspection, WebSocket messages, search bars, redirect params, contact forms, public file uploads, registration flows

#### Tier 1 — Auth-Gated (60-90% of attack surface)

Endpoints that accept user input AND need authentication. This is where IDOR, BOLA, business logic, and privilege escalation live.

```
<tier-1-list>
<method> <url> [input: <type>] [needs: <cred_type>] — test: <class>
</tier-1-list>
```

**Get credentials before testing these** (see Phase 2). If you can't get auth, note that Tier 1 is blind and focus on Tier 0.

#### Tier 2 — Infrastructure & Passive

Endpoints and technologies that don't accept input but reveal attack surface:
- Tech stack (framework, DB, cloud provider)
- Subdomains (potential takeover targets)
- CORS headers (need auth to exploit)
- CSP headers (XSS mitigation)
- Cookie flags (session security)
- Server banners

```
<tier-2-list>
<finding> <details> — actionable: <yes|no>
</tier-2-list>
```

## Step 4: Prioritize

### Prioritization Rules

1. **Public + accepts input** always beats auth-gated + accepts input (no barrier to test)
2. **Write operations** (POST/PUT/PATCH/DELETE) beat read operations (GET) for same auth level
3. **File upload** beats structured data (JSON) beats unstructured data (query params)
4. **GraphQL** beats REST (single endpoint exposes entire schema)
5. **Known framework** with historical CVEs beats unknown stack
6. **Secrets in JS/HTML** are always P1 — they bypass all auth

### Prioritize Endpoints (Score & Sort)

Run the MCP prioritization engine to score all endpoints by risk:

```
prioritize_endpoints(
  engagement_id=<eid>,
  endpoints_json=<json_array_of_endpoints>
)
```

Each endpoint JSON object: `method`, `path`, `parameters` (list), `auth_required` (bool), `tech_stack`, `has_taint_chain` (bool), `tool_count` (int). The engine scores by: parameter count, tech risk, taint chains, tool convergence, auth requirements, HTTP method, and injectable parameter names.

Higher score = test first. Override the engine's ranking with the 6 prioritization rules if needed.

## Step 5: Save Deliverable for Phase 6

After classification and prioritization, save the ranked list:

```
save_deliverable(
  engagement_id='<eid>',
  deliverable_type='endpoint_map',
  content=<the tier-0/tier-1/tier-2 list>,
  producer_agent='surface'
)
```

## Step 6: Gate Check

```
phase_gate_check(phase_completed=5)
```

If PASS → `save_checkpoint()` → proceed to Phase 6 HUNT.
If FAIL → fix blockers, re-run gated steps, retry gate.

## Verification Checklist

- [ ] `phase-surface.sh` run and output inspected
- [ ] Endpoint map deliverable loaded from Phase 4 (or raw files read)
- [ ] Tier 0 list: public endpoints that accept input
- [ ] Tier 1 list: auth-gated endpoints that accept input
- [ ] Tier 2 list: infrastructure findings (not directly exploitable)
- [ ] `prioritize_endpoints()` called with endpoint data
- [ ] Deliverable saved for Phase 6 consumption
- [ ] `track_tool()` called for surface
- [ ] Phase 5 gate passed
