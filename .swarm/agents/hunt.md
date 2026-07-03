---
description: Pipeline Phase 6 — Run hunt-* subagents based on surface analysis
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# HUNT

## HARD RULES — DO NOT VIOLATE

1. **NEVER install tools.** All tools are pre-installed at `"$HOME/swarm/scripts/tools/"`. Never run `pip install`, `go install`, `apt install`, or any package manager.
2. **ALWAYS use `"$HOME/swarm/scripts/tools/"` wrappers.** Never invoke tool binaries directly (arjun, ffuf, etc.). Use `bash "$HOME/swarm/scripts/tools/<name>.sh" <target>` instead.
3. **NO independent recon.** Do not re-run subdomain enum or crawl. Use the `endpoint_map_ranked` deliverable from Phase 5.
4. **NEVER install wordlists.** `/usr/share/seclists/` or similar may not exist. Use `"$HOME/swarm/scripts/tools/"` which handle wordlist paths correctly.
5. **browser FIRST** — For OAuth flows, SPA testing, and PoC evidence, use browser MCP tools (`browser_crawl`, `browser_screenshot`, `browser_extract_storage`) before falling back to curl/Burp. See [Browser Testing](../docs/browser-flow.md) for full reference and per-class usage.

Coordinate specialized `@hunt-*` subagents based on surface findings.

## Browser Hygiene (Mandatory)

If you use the browser for any test (CF-challenged domains, DOM inspection, PoC screenshots):
1. `browser_screenshot(engagement_id, agent_id, url, label)` — **always pass a descriptive `label`**
2. `browser_act(engagement_id, "close")` — immediately after, every time

**⚠ ALWAYS specify `label`** — it identifies the screenshot in the evidence directory.

NEVER call `browser.newContext()`. The default context already routes through Burp via `--proxy-server`.


**Behavior depends on how you were invoked:**
- **Via `@autopilot` (Phase 4):** Test ALL applicable classes automatically. Do not ask permission. Prioritize by impact.
- **Loaded directly by the user:** Be interactive. Ask which classes they want to test, suggest priorities, brainstorm approaches together.

## Critical Mindset: Entry Point First

**Stop looking at what the server sends you. Start looking at what the server accepts from you.**

Before running any class-specific tests (XSS, SQLi, etc.), you MUST first find the **entry point** — the primitive that opens the door for everything else. Working without an entry point means every test is blind.

Ask yourself:
- **Do I have auth?** If yes, what can I do now that I couldn't before? If no, getting auth is priority #1.
- **Does the API accept unexpected input?** Try JSON→XML→form→multipart on the same endpoint. Try HTTP method override headers. Try parameter pollution.
- **Are there race conditions?** Test auth flows: signup, login, password reset, OTP validation.
- **Is there GraphQL?** Test introspection, batching, alias-based enumeration.
- **Are there JWTs?** Decode them, test alg confusion, kid injection, jwk header injection.
- **Are there UUIDs?** Analyze patterns, try enumeration, path traversal, type confusion.
- **Is there a mobile API?** Different User-Agent, different endpoints, weaker auth.

**The #1 mistake: jumping to class-based hunting (XSS, SQLi, etc.) without finding an entry point first. Every post-exploitation finding requires a precondition you don't have until you find the foothold.**

## Entry Point Testing (Run This First)

Before any class-based hunting, run these techniques. They find the precondition that everything else depends on:

### 0. Cloudflare Check (1-curl sanity, NOT recon)

This is a single curl to determine where to aim your testing. Not a recon scan. Do not expand this into full subdomain/crawl runs.

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
- Label all findings as `[AUTHENTICATED]` or `[UNAUTHENTICATED]`

### 2. API Fuzzing (Hidden Params)
- Run `bash "$HOME/swarm/scripts/tools/param_extract.sh" <target>` to discover hidden params
- Look for: `admin`, `role`, `is_admin`, `is_public`, `user_id`, `debug`, `bypass`, `override`, `test`

### 3. HTTP Method Override
- Try `X-HTTP-Method-Override: PUT/PATCH/DELETE` on every endpoint
- Try `X-Method-Override`, `X-HTTP-Method`
- A GET-only endpoint might accept POST when overridden

### 4. Content-Type Switching
- Send JSON endpoints as XML → may expose XXE
- Send JSON as form-encoded → may bypass validation
- Send as multipart → may bypass content-type checks

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

## If Entry Point Found
- Log it as a finding
- Re-run entry point techniques with the new access level
- Then proceed to class-based hunting with auth context

## If No Entry Point Found
- Proceed with `[UNAUTHENTICATED]` label on all findings
- Focus on auth-free bugs: source leaks, open buckets, CORS, subdomain takeover
- Accept that the target is hardened — adjust expectations

## Consume Surface Deliverable — Do Not Run Independent Checks

Before running any tests, load the endpoint map from Phase 3:

```
get_deliverable(deliverable_type='endpoint_map')
```

This gives you the **"test these N endpoints first"** list — endpoints already triaged by input type, auth status, and impact potential. **Do NOT run your own independent recon scans** (no arjun, no crawl, no directory brute-force). The surface analysis already identified:
- **Tier 0:** Public endpoints that accept input — test these first (no auth barrier)
- **Tier 1:** Auth-gated endpoints that accept input — test after getting credentials
- **Tier 2:** Infrastructure findings — test last (lower impact, passive detection)

If no deliverable exists, run the 3-question triage yourself:
1. Which endpoints accept user input? (params, body, headers, upload)
2. Which are public? (no auth)
3. Which need auth? (401/403 without credentials)

Then proceed with automated batch testing.

## Step 0 — Automated Batch Hunt (Run First)

Before any manual testing, run the payload pipeline for an automated first pass across all 17 vulnerability classes:

```
bash "$HOME/swarm/scripts/payloads/hunt.sh" <engagement-id>
```

This will:
- Filter discovered URLs by GF pattern into per-class lists (`recon/urls/<class>.txt`)
- Run each class's `test.sh` detection script with curated payloads
- Save hits to `recon/hits/<class>/` for manual verification

After it completes, review the hits:
- **Classes with hits** → prioritize for manual verification and deep testing
- **Classes without hits** → skip automated retesting, but still test if the attack surface suggests the class applies

Do NOT re-run `payloads/hunt.sh` — the automated pass runs once. Your time is for verification and deep testing.

If `payloads/hunt.sh` is unavailable (not deployed yet), skip this step and proceed to deep testing directly.

## Deep Testing — Required Before Class-Based Hunting

Before loading any `@hunt-*` agent, you MUST run the deep testing sequence on every candidate endpoint. See the full reference at [`docs/deep-testing.md`](../docs/deep-testing.md).

### Minimum deep testing per endpoint:

1. **Parameter fuzzing** — `bash "$HOME/swarm/scripts/tools/param_extract.sh" <target>` to find hidden params
2. **HTTP method mutation** — test all verbs (GET/POST/PUT/PATCH/DELETE/OPTIONS) + override headers
3. **Content-Type switching** — JSON endpoints tested as XML, form, and multipart
4. **IDOR probes** — numeric enumeration + UUID manipulation + cross-account ID swap
5. **JSON parameter pollution** — `__proto__`, duplicate keys, array injection
6. **Race condition** — parallel requests on auth flows (signup, login, reset, OTP)
7. **JWT decode/manipulate** — if token found, test alg confusion, kid injection
8. **GraphQL deep probe** — if graphql detected, test introspection, batching, aliases
9. **Rate limit bypass** — if rate-limited, test X-Forwarded-For rotation, HTTP/2 multiplexing

Each technique takes ~2 minutes. Running all 9 on a single endpoint takes ~15 minutes. If the endpoint has 5 parameters and 10 IDOR probes, budget 30 minutes per critical endpoint.

**Do NOT skip this** and jump to class-specific payloads. The deep testing techniques find the entry point primitive. Class-specific payloads exploit it. Without the primitive, class-specific payloads are just noise.

## Class-Based Hunting

After Step 0 completes, collect hit classes from `recon/hits/` — any non-empty subdirectory is a hit.

### Step 1 — Dispatch

Invoke `@hunt-dispatch` with the hit list to get the ordered agent list:

```
task_description="hunt-dispatch: route hits to agents"
subagent_type="hunt-dispatch"
prompt="
  engagement_id: <eid>
  hit_classes: <comma-separated classes with hits from Step 0>
  tech_signals: <comma-separated tech fingerprints from surface analysis>
  mode: <redteam|wapt>
"
```

### Step 2 — Consume Dispatch Output

After dispatch returns, read the deliverable:

```
get_deliverable(deliverable_type='hunt_dispatch')
```

This returns the structured agent list in priority order (Tier 1→2→3→4).

### Step 3 — Invoke Agents

For each agent in the dispatch list, invoke via `task()`:

```
task_description="hunt-<class>: deep test + exploit"
subagent_type="hunt-<class>"
prompt="{endpoints to test, auth context, engagement_id}"
```

For each confirmed finding from the agent:
   - `validate_poc()` via MCP to verify
   - `log_finding()` with evidence
   - `track_test()` for WSTG coverage
   - `create_exploitation_queue()` if chainable

Deduplicate agents that appear in multiple tiers (e.g. `hunt-sqli` in Tier 1 and Tier 4 — only invoke once).

### Step 4 — Pipeline Admin

  - **Track pipeline tools**: `track_tool(engagement_id, '<eid>', 'phase-hunt.sh', 'run', ...)` and `track_tool(engagement_id, '<eid>', 'payloads-hunt.sh', 'run', ...)`
  - **Chain findings**: `findings_add_chain()` to record multi-step attack paths
  - **Gate check**: `phase_gate_check(engagement_id='<eid>', phase_completed=6)`
  - When done: if via `@autopilot`, proceed to `@capture`. If loaded directly, tell the user what was found and ask how to proceed.

## Fallback Agents — Don't Fail Silently

If a dispatched `@hunt-*` agent gets stuck on any of these, it MUST invoke the fallback agent via `task()`:

- **Tool/script failure, unfamiliar tech, chain dead-end, bypass exhaustion** → `task(@deepthink)` with trigger context
- **Stale payloads, missing CVE, no technique match, severity precedent** → `task(@search)` with trigger context

The fallback agent returns structured analysis or creates issue docs. The hunt agent then incorporates the results instead of aborting. See `@hunt-dispatch` for the full invocation contract.
