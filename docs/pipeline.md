# Pipeline — How Swarm Runs

## What Swarm Is

Swarm is a **script-driven** security testing pipeline. Bash scripts run each phase in strict order. The AI (LLM) is called **only for analysis** within each phase — it never decides what phase to run next.

Two interfaces work together:

1. **Pipeline Scripts** (`scripts/pipeline.sh` + `scripts/tools/phase-*.sh`) — automate the 12-phase pipeline: scope → auth → intel → recon → surface → hunt → exploit → validate → report
2. **Swarm Agents** — provide per-class bug hunting tradecraft, enterprise platform attack chains, and analysis *within* each phase via `@agent-name`

Together they turn an LLM into a methodical bug hunter: the pipeline tells it *what order to do things in*, the agents tell it *what to look for and how*, and Burp Suite provides *HTTP request execution*.

---

## Working Principle

```mermaid
graph TB
    classDef pipeline fill:#cce5ff,stroke:#333,stroke-width:2px,color:#000
    classDef phase fill:#e0f2f1,stroke:#333,stroke-width:2px,color:#000
    classDef ai fill:#e6ccff,stroke:#333,stroke-width:2px,color:#000
    classDef tool fill:#ffcccc,stroke:#333,stroke-width:2px,color:#000
    classDef mcp fill:#ffe5cc,stroke:#333,stroke-width:2px,color:#000

    Pipeline["`**pipeline.sh** runs phases in order
    (script-driven — AI never decides what's next)`"]:::pipeline

    Phase["`**Phase scripts** 
    scripts/tools/phase-*.sh
    each scripts runs its automated tools`"]:::phase

    AI["`**AI Agent** called for analysis
    @pintel / @recon / @surface / @hunt
    analyzes output, guides next actions`"]:::ai

    Burp["`**Burp Suite MCP Server**
    executes HTTP requests
    sends payloads, parses responses`"]:::tool

    MCP["`**WSTG MCP Server**
    get_wstg_test · identify_waf
    log_finding · track_test`"]:::mcp

    Pipeline --> Phase
    Phase --> AI
    AI --> MCP
    AI --> Burp
```

The loop: **pipeline.sh → phase script runs tools → AI analyzes results → log finding → next phase**

Each phase has its own script at `scripts/tools/phase-<name>.sh`. Run them individually or use `pipeline.sh` to run them in order.

> **Path note:** the examples below use `$HOME/swarm` as the repo location. Replace it with
> wherever you cloned Swarm (the scripts resolve their own root via `$SWARM_ROOT`/git, so running
> them from inside the repo works regardless of path).

**Two modes:**
- **Automatic** — `bash $HOME/swarm/scripts/pipeline.sh target.com` runs all 12 phases in strict order
- **Selective** — `bash $HOME/swarm/scripts/pipeline.sh target.com 3-6` runs phases 3 through 6
- **Manual** — `bash $HOME/swarm/scripts/tools/phase-recon.sh target.com` runs a single phase

---

## The Pipeline (12 Phases + conditional sub-phases)

```
Phase 1:   SCOPE       → register domains, load config, create task tree
Phase 2:   AUTH        → test credentials, detect WAF, save auth deliverable
Phase 3:   INTEL       → passive OSINT: WHOIS, M365, cloud, spoof check
Phase 4:   RECON       → subdomain enum, crawl, params, secrets
Phase 5:   SURFACE     → load recon, classify tiers + functional groups, prioritize endpoints
Phase 6:   HUNT        → test all bug classes via 57 hunt-* sub-agents
                        ├── group-based testing (1-2 reps per functional group)
                        ├── Ralph Wiggum loop: every endpoint must be covered before gate
                        └── (parallel) credential-attack → wordlist-gen → breach-check → osint-employees → spray
Phase 7:   DEEPTHINK  → (conditional) first-principles gap analysis when HUNT yields zero
Phase 8:   EXPLOIT     → deepen confirmed findings, escalate impact
                        ├── multi-auth-context probing (replay every finding with all sessions)
                        └── exhaustive exploitation gate (no finding skipped)
Phase 9:   SEARCH → (conditional) 13-resource retrieval when EXPLOIT stalls
Phase 10:  CAPTURE     → evidence collection, screenshots, redaction
Phase 11:  VALIDATE    → re-validate PoCs, 7-Question Gate
Phase 12:  REPORT      → coverage check, generate final report
```

```mermaid
flowchart LR
    classDef phase fill:#cce5ff,stroke:#333,stroke-width:2px,color:#000
    classDef conditional fill:#ffe5cc,stroke:#333,stroke-width:2px,color:#000
    classDef gate fill:#e0f2f1,stroke:#333,stroke-width:2px,color:#000
    classDef tracking fill:#e6ccff,stroke:#333,stroke-width:2px,color:#000

    SCOPE:::phase --> AUTH:::phase --> INTEL:::phase --> RECON:::phase --> SURFACE:::phase --> HUNT:::phase --> DEEPTHINK:::conditional --> EXPLOIT:::phase --> SEARCH:::conditional --> CAPTURE:::phase --> VALIDATE:::phase --> REPORT:::phase
    HUNT -->|"Ralph Wiggum: untested endpoints?"| HUNT
    EXPLOIT -->|"Exhaustive gate: un-exploited findings?"| EXPLOIT
    HUNT -.->|"zero findings"| DEEPTHINK
    EXPLOIT -.->|"WAF/CVE gaps"| SEARCH["SEARCH (research)"]:::conditional
    SEARCH -->|"payloads found"| EXPLOIT
    VALIDATE -->|PASS| REPORT
    VALIDATE -->|KILL| DISCARD["Discard"]:::conditional
    VALIDATE -->|DOWNGRADE| REPORT
    VALIDATE -->|CHAIN| HUNT

    subgraph Gate["7-Question Gate"]
        Q1["Q1: Real HTTP request?"]
        Q2["Q2: Accepted impact?"]
        Q3["Q3: Asset in scope?"]
        Q4["Q4: Without privileged access?"]
        Q5["Q5: Not known behavior?"]
        Q6["Q6: Provable impact?"]
        Q7["Q7: Not on never-submit list?"]
    end

    subgraph Tracking["MCP tracks everything"]
        direction LR
        R1["register_scope()"] --> T1["track_test()"] --> L1["log_finding()"]
        L1 --> T2["track_tool()"] --> C1["get_coverage()"] --> R2["generate_report()"]
    end
```

---

### Phase 1: SCOPE

| Step | Action | Script |
|------|--------|--------|
| 1 | Register target domain | `scripts/tools/phase-scope.sh <domain>` |
| 2 | Scaffold output directories | auto creates `$RECON_BASE/<domain>/{scope,intel,recon,...}` |
| 3 | Check target reachability | curl connectivity test |
| 4 | Write target metadata | `scope/target.txt`, `scope/started.txt` |
| 5 | Gate check | `scripts/tools/phase_gate.sh 1 <domain>` |

**Output:** `$RECON_BASE/<domain>/scope/` — scaffolded engagement.

---

### Phase 2: AUTH

| Step | Action | Script |
|------|--------|--------|
| 1 | Provide credentials / session tokens | manual, or `swarm-browser auth <url> --field ... --cookies save session.json` for login forms |
| 2 | WAF fingerprint check | `scripts/tools/phase-auth.sh <domain>` |
| 3 | Save auth context | output in `$RECON_BASE/<domain>/auth/waf_detection.txt` |
| 4 | Configure API key (AI agent features) | `bash $HOME/swarm/scripts/setup/setup.sh` Phase 0 — auto-detects provider: `sk-or-`→OpenRouter, `sk-ant-`→Anthropic, `sk-`→OpenAI |
| 5 | Gate check | `scripts/tools/phase_gate.sh 2 <domain>` |

**CRITICAL:** If Cloudflare detected, redirect 80% effort to API subdomain; use the headed browser for CF pages. Check WAF fingerprints at `knowledge/waf/`.

**Browser auth:** Use `swarm-browser auth <url> --field login=user --field password=pass --cookies save session.json` for login forms, or `swarm-browser auth --cookies load session.json` to reuse saved sessions across phases.

**Output:** `$RECON_BASE/<domain>/auth/` — WAF info + auth notes.

---

### Phase 3: Intel (passive)

| Step | Action | Script |
|------|--------|--------|
| 1 | WHOIS lookup, M365/Azure tenant discovery | `scripts/tools/phase-intel.sh <domain>` |
| 2 | SPF/DMARC spoofability check | auto (Spoofy — not auto-installed) |
| 3 | Cloud storage bucket enumeration | auto (manual — not auto-installed) |
| 4 | Gate check | `scripts/tools/phase_gate.sh 3 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-intel.sh <domain>`

**Output:** `$RECON_BASE/<domain>/intel/` — WHOIS, cloud, spoof data.

---

### Phase 4: RECON

| Step | Action | Script |
|------|--------|--------|
| 1 | Subdomain enumeration + DNS bruteforce | `scripts/tools/subdomain_enum.sh <domain>` → `scripts/tools/dns_bruteforce.sh <domain>` |
| 2 | URL crawl (waymore → gospider → katana) + param extraction | `scripts/tools/web_waymore.sh`, `web_gospider.sh`, `web_katana.sh`, `param_extract.sh` |
| 3 | Secrets / info disclosure scan | `scripts/tools/cariddi_scan.sh <domain>` |
| 4 | 403 bypass + vhost fuzzing | `scripts/tools/bypass_403.sh <domain>` + `scripts/tools/vhost_fuzz.sh <domain>` |
| 5 | Zone transfer + subdomain takeover | `scripts/tools/zone_transfer.sh <domain>` + `scripts/tools/takeover_scanner.sh <domain>` |
| 6 | Cloud recon + secrets validation + S3 buckets | `scripts/tools/cloud_recon.sh`, `auto_secrets.sh`, `s3_buckets.sh` |

**CRITICAL:** Never invoke tool binaries directly or install tools. All tools pre-installed.

**Output:** `$RECON_BASE/<domain>/` — subdomains/, crawl/, params/, secrets/, directories/, vhost/

**Full doc:** `docs/phases/recon.md`

---

### Phase 5: SURFACE

| Step | Action | Script |
|------|--------|--------|
| 1 | Collect all discovered URLs | `scripts/tools/phase-surface.sh <domain>` |
| 2 | Classify into Tiers | Tier 0 (public+input), Tier 1 (auth+input), Tier 2 (infra) |
| 3 | Count endpoints per tier | auto |
| 4 | Save ranked endpoint map | `surface/endpoint_map_ranked.txt` |
| 5 | Gate check | `scripts/tools/phase_gate.sh 5 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-surface.sh <domain>`

**Output:** `$RECON_BASE/<domain>/surface/endpoint_map_ranked.txt`

---

### Phase 6: HUNT

| Step | Action | Script |
|------|--------|--------|
| 1 | Parameter extraction + fuzzing | `scripts/tools/param_extract.sh` |
| 2 | Secrets hunting | `scripts/tools/secrets_hunter.sh <domain>` |
| 3 | SQLi automation | `scripts/tools/auto_sqli.sh <domain>` |
| 4 | XSS automation | `scripts/tools/auto_xss.sh <domain>` |
| 5 | Directory bruteforce | `AI-driven — see docs/directory-bruteforce.md` |
| 6 | VHost fuzzing | `scripts/tools/vhost_fuzz.sh <domain>` |
| 7 | 403 bypass checks | `scripts/tools/bypass_403.sh <domain> --quick` |
| 8 | **AI-led testing** — call `@hunt` agent | analyzes results, guides per-class testing |
| 9 | Gate check | `scripts/tools/phase_gate.sh 6 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-hunt.sh <domain>` (runs steps 1-7 automatically, dirbust excluded — AI-driven)

**For AI-driven analysis (step 8):** Call `@hunt` agent with the surface map. It loads the per-class tradecraft automatically. For automated browser-based testing (SPA flows, DOM XSS, OAuth), use `swarm-browser agent "<task>"` — describes what to do in natural language.

**OOB (Out-of-Band) detection:** For blind XSS, SSRF, and XXE, start the OOB listener before testing: `bash $HOME/swarm/scripts/tools/oob_listener.sh start`. Inject the returned callback URL into payloads, then poll with `bash $HOME/swarm/scripts/tools/oob_listener.sh stop` after testing.

| Class | Load with… |

| Class | Load with… |
|-------|-----------|
| XSS | `@hunt-xss` |
| SQLi | `@hunt-sqli` |
| SSRF | `@hunt-ssrf` |
| IDOR | `@hunt-idor` |
| SSTI | `@hunt-ssti` |
| CMDI/RCE | `@hunt-rce` |
| Auth bypass | `@hunt-auth-bypass` |
| ATO | `@hunt-ato` |
| GraphQL | `@hunt-graphql` |
| File upload | `@hunt-file-upload` |
| Race condition | `@hunt-race-condition` |
| OAuth | `@hunt-oauth` |
| CORS | `@hunt-cors` |
| XXE | `@hunt-xxe` |
| CSRF | `@hunt-csrf` |
| NoSQLi | `@hunt-nosqli` |
| LDAP | `@hunt-ldap` |
| Open redirect | `@hunt-open-redirect` |
| HTTP smuggling | `@hunt-http-smuggling` |
| Deserialization | `@hunt-deserialization` |
| Subdomain takeover | `@hunt-subdomain` |
| Cloud IAM | `@cloud-iam-deep` |
| M365/Entra | `@m365-entra-attack` |
| Android APK | `@apk-redteam-pipeline` |
| Smart contract | `web3-audit` (skill) |
| K8s | `@hunt-k8s` |
| Next.js | `@hunt-nextjs` |

**If WAF detected in Phase 2:** Pass to AI agent which applies vendor-specific bypasses from `knowledge/waf/`.

**Output:** `$RECON_BASE/<domain>/` — params/, secrets/, sqli/, xss/, directories/, vhost/

---

### Phase 7: DEEPTHINK (conditional)

| Step | Action | Script |
|------|--------|--------|
| 1 | Prepare gap analysis context | `scripts/tools/phase-deepthink.sh <domain>` |
| 2 | Call `@deepthink` agent | AI performs first-principles gap analysis |
| 3 | Gate check | `scripts/tools/phase_gate.sh 7 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-deepthink.sh <domain>`
**Agent:** `@deepthink` — reads gap context, identifies blind spots

---

### Phase 8: EXPLOIT

| Step | Action | Script |
|------|--------|--------|
| 1 | Compile all findings | `scripts/tools/phase-exploit.sh <domain>` |
| 2 | Call `@exploit` agent | AI deepens findings, chains, escalates |
| 3 | Multi-auth-context probing | AI replays findings with all sessions |
| 4 | Exploitation gate | Every finding must have PoC or bypass exhaustion |
| 5 | Gate check | `scripts/tools/phase_gate.sh 8 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-exploit.sh <domain>`
**Agent:** `@exploit` — loads compiled findings, attempts PoC exploitation

---

### Phase 9: SEARCH (conditional)

| Step | Action | Script |
|------|--------|--------|
| 1 | Prepare research context | `scripts/tools/phase-search.sh <domain>` |
| 2 | Call `@search` agent | AI researches payloads, CVEs, bypasses |
| 3 | Feed results back to EXPLOIT | Findings from research → new exploit attempts |

**Script:** `bash $HOME/swarm/scripts/tools/phase-search.sh <domain>`
**Agent:** `@search` — researches stale payloads, missing CVEs, WAF bypasses

---

### Phase 10: CAPTURE

| Step | Action | Script |
|------|--------|--------|
| 1 | Prepare evidence structure | `scripts/tools/phase-capture.sh <domain>` |
| 2 | Call `@capture` + `@evidence-hygiene` | AI captures screenshots, redacts PII |
| 3 | Save sanitized evidence | `$RECON_BASE/<domain>/evidence/<finding-id>/` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-capture.sh <domain>`
**Browser rules:** Use `swarm-browser screenshot <url> -o <file>` for visual evidence. For blind XSS/SSRF/XXE, use the OOB listener: `bash $HOME/swarm/scripts/tools/oob_listener.sh start` → inject callback URL → `bash $HOME/swarm/scripts/tools/oob_listener.sh stop` to collect interactions.

---

### Phase 11: VALIDATE

| Step | Action | Script |
|------|--------|--------|
| 1 | Prepare findings for validation | `scripts/tools/phase-validate.sh <domain>` |
| 2 | Call `@validate` + `@triage-validation` | AI runs 7-Question Gate on each finding |
| 3 | Assign verdict | PASS / KILL / DOWNGRADE / CHAIN REQUIRED |

**Script:** `bash $HOME/swarm/scripts/tools/phase-validate.sh <domain>`

**The 7-Question Gate** (run by AI agent):
```
Q1: Real HTTP request?
Q2: Accepted impact?
Q3: In scope?
Q4: Without privileged access?
Q5: Not known behavior?
Q6: Provable impact?
Q7: Not on never-submit list?
```

**Never-submit list:** Missing headers, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

---

### Phase 12: REPORT

| Step | Action | Script |
|------|--------|--------|
| 1 | Compile report context | `scripts/tools/phase-report.sh <engagement_id> <domain>` |
| 2 | Call `@report-writing` agent | AI generates submission-ready report |
| 3 | Choose platform | HackerOne (`@report-writing`) / Bugcrowd (`@bugcrowd-reporting`) / Client (`@redteam-report-template`) |
| 4 | Final gate | `scripts/tools/phase_gate.sh 12 <domain>` |

**Script:** `bash $HOME/swarm/scripts/tools/phase-report.sh <engagement_id> <domain>`
**Output:** `$RECON_BASE/<domain>/report/report_context.txt` → AI generates final report.

**CVSS scoring:** The PoC report generator (`generate_poc_report.sh`) auto-computes CVSS 3.1 scores. It maps severity (Info/Low/Medium/High/Critical) to a CVSS vector string using the `cvss` Python library via `compute_cvss()`.

---

## How Pipeline Scripts + Agents Interact

```mermaid
graph TB
    classDef orchestrator fill:#cce5ff,stroke:#333,stroke-width:2px,color:#000
    classDef user fill:#ffe5cc,stroke:#333,stroke-width:2px,color:#000
    classDef agent fill:#e6ccff,stroke:#333,stroke-width:2px,color:#000
    classDef tool fill:#ffcccc,stroke:#333,stroke-width:2px,color:#000
    classDef refs fill:#e0f2f1,stroke:#333,stroke-width:2px,color:#000

    Pipeline["pipeline.sh (or manual phase-*.sh)"]:::orchestrator
    Agent["Swarm Agent - reads script output, loads tradecraft"]:::agent
    User["User reviews results, calls agent: @pintel / @recon / @hunt"]:::user
    MCP["MCP Server - get_wstg_test, log_finding, track_test"]:::tool
    Burp["Burp Suite MCP Server - sends HTTP requests"]:::tool
    Refs["Reference Libraries - skills/, knowledge/waf/, payloads/"]:::refs

    Pipeline --> User
    User --> Agent
    Agent --> Refs
    Agent --> Burp
    Agent --> MCP
```

**At every phase, the pattern is the same:**

1. Run the phase script: `bash $HOME/swarm/scripts/tools/phase-<name>.sh <domain>`
2. Script runs automated tools, saves output
3. Call the appropriate AI agent: `@pintel`, `@recon`, `@surface`, `@hunt`, etc.
4. Agent reads the output, loads tradecraft from reference libraries
5. Agent guides further testing via Burp MCP
6. Findings are logged via MCP server

---

## Quickstart

```bash
# Run all 12 phases in order
bash $HOME/swarm/scripts/pipeline.sh target.com

# Run phases 3-6 only
bash $HOME/swarm/scripts/pipeline.sh target.com 3-6

# Run a single phase
bash $HOME/swarm/scripts/tools/phase-recon.sh target.com

# Call AI agent to analyze results
# In Swarm: @recon analyze the recon output for target.com
```

---

## Key Design Principles

1. **Script-driven, not agent-driven** — `pipeline.sh` runs phases in order; the AI never decides "what's next"
2. **AI for analysis only** — agents analyze results and guide testing, they don't orchestrate phases
3. **Phase gates enforce ordering** — `phase_gate.sh` tracks completed phases and warns on skips
4. **Each phase has one script** — `scripts/tools/phase-<name>.sh` — run it or call it via pipeline.sh
5. **Validate before drafting** — the 7-Question Gate prevents wasted effort on N/A findings
6. **MCP tracks everything** — findings, tests, tools, coverage — nothing gets lost
7. **Evidence hygiene by default** — redact before capture, not after
8. **Burp is optional** — curl + browser works fine for most testing
9. **References guide technique** — real H1 reports, WAF KBs, and payload libs inform every test
10. **Browser close after every op** — close browser between operations to prevent context leaks
