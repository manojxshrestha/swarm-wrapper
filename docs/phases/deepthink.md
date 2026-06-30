# Phase 7: DEEPTHINK (Gap Analysis)

Conditional meta-phase for first-principles reasoning when HUNT (Phase 6) produces zero findings, tools fail, script errors occur, or chaining dead-ends. Does NOT scan or inject payloads — it thinks, diagnoses, and documents.

Runs conditionally after HUNT (Phase 6), feeds back into HUNT dispatch or forward to EXPLOIT (Phase 8).

---

## When It Activates

Phase 7 is **conditional** — it only runs when one or more triggers fire. If all triggers are false, it's skipped entirely.

### Pipeline-Level Triggers

| Trigger | How to detect |
|---------|---------------|
| Pipeline exit code != 0 | Tools failed or timed out during HUNT |
| Coverage < 90% | HUNT agents were skipped or failed. Run coverage gate check |
| Zero confirmed findings | No findings logged after ALL 57 HUNT agents dispatched |
| Chains empty | `find_chains()` returns empty array — no attack paths found |
| WAF bypass exhausted | All payloads from `get_waf_bypass()` return 403/400/blocked |
| Unclear findings | HUNT findings don't map to any known vulnerability class |
| Tool/script failures | `phase-hunt.sh` or `payloads/hunt.sh` produced errors or empty output |
| Static knowledge gap | Target technology has no matching WSTG tests, payloads, or WAF fingerprints |

### Agent-Invocation Triggers

`@deepthink` is also invoked via `task()` from `@hunt-dispatch` / `@hunt-*` agents when they hit a dead-end:

| Trigger | Context passed |
|---------|---------------|
| Tool/script failure | `{"trigger":"tool_failure","engagement_id":"<eid>"}` |
| Unfamiliar technology | `{"trigger":"unfamiliar_tech","detail":"<signal>"}` |
| Chain dead-end | `{"trigger":"chain_dead_end","findings":["..."]}` |
| Bypass exhaustion | `{"trigger":"bypass_exhausted","class":"<class>","waf":"<vendor>"}` |

---

## Invocation

### From autopilot

```
If ANY trigger is true:
  1. bash $HOME/swarm/scripts/tools/phase-deepthink.sh <engagement_id> <domain>
  2. Read $RECON_BASE/<domain>/deepthink/gap_analysis.txt
  3. Read coverage matrix — identify agents with 0 findings or failed status
  4. Dispatch: task(subagent_type="deepthink", prompt="Gap analysis for <domain> — focus on gaps: <list>")
  5. If deepthink found new attack surface → re-run Phase 6 dispatch for remaining agents

If NO triggers are true → skip Phase 7 (all coverage adequate).
```

### From hunt agents

```
task(subagent_type="deepthink",
     description="deepthink: resolve dead-end",
     prompt="engagement_id=<eid>, trigger=<reason>, target=<domain>, class=<vuln_class>")
```

---

## Gap Context

`scripts/tools/phase-deepthink.sh` prepares the gap analysis context by querying the SQLite findings database:

```
bash $HOME/swarm/scripts/tools/phase-deepthink.sh <engagement_id> <domain>
```

**Output**: `$RECON_BASE/<domain>/deepthink/gap_analysis.txt`

The gap context includes:
- **Findings DB stats** — counts of hosts, vulns, credentials, chains via `findings.sh stats`
- **Logged vulnerabilities** — list of all findings via `findings.sh list vulns`
- **Discovered hosts** — host inventory via `findings.sh list hosts`
- **Attack surface** — endpoint tiers from Phase 5 surface analysis
- **Gaps & questions** — 5 standard investigative questions
- **Coverage gaps** — which HUNT agents returned 0 findings or failed
- **Chain opportunities** — guidance to run `find_chains()`

---

## Workflow

### Step 1 — Load State

```
read_agent_notes(engagement_id="<eid>", agent_id="deepthink")
```

Check what knowledge is available:
- `ls knowledge/wstg/` — which WSTG categories exist
- `ls knowledge/payloads/` — which payload libraries exist
- `get_wstg_test("WSTG-...")` — specific test methodology
- `get_waf_bypass(vendor, class)` — WAF bypass payloads

### Step 2 — Check Tool Availability

```
which <tool> 2>/dev/null && echo "INSTALLED" || echo "MISSING"
```

If required tool is missing:
1. Log in state as `"status": "missing"`
2. Create issue doc at `engagements/<eid>/issues/tool-missing-<name>.md`
3. Suggest install command

### Step 3 — Analyze Knowledge Gaps

| If task needs... | Check... |
|-----------------|----------|
| SQL injection payloads | `knowledge/payloads/SQL Injection/` |
| XSS techniques | `knowledge/payloads/XSS Injection/` |
| WAF bypass for Cloudflare | `get_waf_bypass("cloudflare", "xss")` |
| Specific WSTG test | `get_wstg_test("WSTG-INPV-01")` |
| Attack technique guide | `search_wstg("SSRF technique")` |

If gap is confirmed:
1. Log the gap in state
2. Create `engagements/<eid>/issues/static-data-gap-<topic>.md`
3. Attempt first-principles reasoning

### Step 4 — First-Principles Reasoning

**For unknown vulnerability classes:**
1. Decompose the endpoint: what does it accept? (input type, format, encoding)
2. What does it return? (reflected, stored, transformed)
3. What primitive does the input control? (query, file path, command, template, redirect)
4. Map each primitive to its potential injection class
5. Build a custom test matrix

**For chain dead-ends:**
1. List all findings: `get_findings(engagement_id="<eid>")`
2. Graph the data flow: which endpoints send data to which other endpoints?
3. Look for adjacency: does finding A's output become finding B's input?
4. Check auth boundaries: can an unauthenticated finding bypass auth?
5. Check asset boundaries: does finding on domain A affect domain B?

**For WAF bypass exhaustion:**
1. Identify WAF: `identify_waf()` with response headers
2. Analyze blocking: regex? behavioral? rate-limit?
3. Regex: try encoding variations (unicode, double URL, mixed case)
4. Behavioral: reduce request rate, split payload across parameters
5. Rate-limit: add delays, rotate IPs if available

### Step 5 — Document & Persist

After each reasoning attempt:
1. `write_agent_notes(engagement_id, agent_id="deepthink", notes="...")` with updated state
2. If issue resolved (found chain, built bypass), document the solution
3. If issue persists, append to issue.md with new attempts

### Step 6 — Surface Results

Return structured summary:

```
## Issues Found
- tool-missing-nmap.md — nmap not installed, needed for port scanning
- static-data-gap-custom-protocol.md — no WSTG match

## Chains Discovered
- FINDING-001 (XSS) → FINDING-003 (cookie theft) — severity upgrade to Critical

## Recommended Actions
1. Install nmap: sudo apt-get install nmap
2. Manual review needed: custom protocol analysis
```

---

## Issue Tracking Format

Issues are saved as markdown files in `engagements/<eid>/issues/`:

```markdown
# Issue: <title>

**Detected:** 2026-06-12T02:30:00Z
**Severity:** high
**Category:** missing_tool | static_data_gap | script_error | analysis_blocked

## Description
What went wrong and under what circumstances.

## What Was Tried
- [2026-06-12 02:30] Tried approach A — failed because X

## Relevant Context
- Static data consulted: knowledge/wstg/..., knowledge/payloads/...
- Tools checked: nmap (missing), curl (ok)

## Suggested Fix
What the user can do to resolve this.
```

---

## Fallback Chain

```
@hunt-* → stuck → task(@deepthink)
                  ├── resolved → update state, return results
                  └── unresolved → create issue doc, return partially

@deepthink → needs data → task(@search)
                  ├── found → incorporate, resolve
                  └── not found → create static-data-gap issue
```

---

## Related Files

- `.opencode/agents/deepthink.md` — Agent: first-principles reasoning engine
- `scripts/tools/phase-deepthink.sh` — Script: creates gap analysis context from SQLite DB
- `server/server_data.py:820` — PHASE_NAMES entry for Phase 7
- `server/server.py:3180` — Gate check warns if phase>=7 and no findings
- `.opencode/agents/autopilot.md:163-184` — Trigger logic and invocation flow
