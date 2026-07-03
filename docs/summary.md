# Swarm Project — Complete Summary

## Overview

Swarm is a self-contained OpenCode agent bundle + WSTG MCP server for offensive security: bug hunting, external red-team engagements, and authorized penetration tests. It provides the complete OWASP Web Security Testing Guide methodology as an MCP server with 88 tools, paired with 118 autonomous agents covering vulnerability hunting, enterprise platform attacks, WAF bypass, and full engagement lifecycle management.

**Goal:** Turn an LLM into an autonomous, methodical, reference-informed bug hunter that can run a full penetration test from scope to report — discovering subdomains, crawling endpoints, fingerprinting WAFs, dispatching per-class exploit agents, validating PoCs, capturing redacted evidence, and generating a submission-ready report — without human intervention between phases. The pipeline is modeled on real bug bounty workflows: triage by attack surface, read disclosed reports for technique guidance, bypass WAFs before exploiting, and run every finding through a 7-Question Gate before drafting.

**Two operational modes:**
- **`@autopilot`** — fully autonomous: runs all 12 phases via `pipeline.sh` (bash scripts) + dispatches AI analysis agents via `task()`. Best for unattended full engagements.
- **`@consult`** — interactive: same pipeline but pauses at every phase transition with approval, calls `pipeline.sh` per-phase, dispatches AI analysis. Best for learning or guided testing.

**Stats:**
- 88 MCP tools · 118 agents (57 hunt-* + 18 pipeline + 43 specialty)
- 12 WSTG categories · 109 test cases
- 46 CLI tool wrapper scripts · 20 GF patterns for parameter discovery
- 12-phase autonomous pipeline (autopilot)
- Burp Suite MCP integration · headed browser automation (Playwright)

---

## Architecture

### Four Layers

```
Layer 1: Methodology + Agents        — how to think (12-phase pipeline, critical thinking)
Layer 2: 57 hunt-* agents            — what to look for (per-class detection + bypass)
Layer 3: Enterprise attack chains    — what to hit on the perimeter (M365, Okta, K8s, VPN, IAM)
Layer 4: Validation + Reporting      — how to ship it (7-Question Gate, VRT, redaction)
```

### System Layout

```
~/swarm/
├── server/                     MCP server (Python + FastMCP)
│   ├── server.py               88 tool definitions (6443 lines)
│   ├── waf_evasion.py          WAF identification + bypass engine
│   ├── waf_vendors.json        144 vendor fingerprints
│   ├── waf_bypasses.json       20 vendor bypass payload files
│   ├── findings_db.py          SQLite findings database
│   ├── knowledge_graph.py      Attack path chaining engine
│   ├── endpoint_priority.py    Risk-scoring endpoint prioritization
│   ├── context_compression.py  Phase context summarization
│   ├── task_tree.py            Hierarchical task tree management
│   ├── server_data.py          WSTG data, payloads, constants, slot types
│   ├── crypto_utils.py         Secret encryption/decryption
│   ├── tool_parsers.py         CLI tool output parsers
│   ├── tool_verification.py    Tool output quality verification
│   └── data/                   WSTG test cases, technique guides
├── .swarm/
│   ├── agents/                 118 agent definition files
│   ├── commands-bughunt/       7 CLI entry points
│   └── rules/                  Agent permission rules
├── .mcp.json                   MCP server config (wstg via server/venv/bin/python3, burp via uv run)
├── knowledge/                  Consolidated reference data
│   ├── wstg/                   WSTG v4.2 (12 categories, 110+ files)
│   ├── payloads/               64 PAT reference categories
│   ├── waf/                    144 vendor fingerprints, evasion, bypasses, skills
│   └── portswigger/            (future)
├── wordlists/                  Wordlists + 20 GF patterns
├── Workflow.md                 Agent workflow guide
├── docs/
│   ├── pipeline.md             12-phase pipeline reference
│   ├── (reports moved to ~/swarm-reports/)
│   ├── verification/           Verification artifacts
│   ├── architecture.md         Server architecture
│   └── ...                     ENGAGEMENTS, deep-testing, agent-reference
├── scripts/
│   ├── payloads/               PAT test harnesses (deploy, lib, hunt, 12 test.sh)
│   ├── pipeline.sh             12-phase pipeline orchestrator
│   └── tools/                  46 CLI tool wrapper scripts (+12 phase-*.sh)
├── prompts/                    13 per-category prompt templates
├── templates/                  Report templates, quality gates, guides
├── skills/                     70+ Swarm tradecraft skills
├── engagements/                Active engagement directories (gitignored)
│   └── runtime/                Runtime data (findings, evidence cache)
└── configs/                    Config examples (anthropic, router, schema)
```

---

## Pipeline (Autopilot)

12-phase autonomous pipeline orchestrated by `autopilot.md`. Each phase has gate checks via `phase_gate_check()`.

| Phase | Agent | Description | Gate |
|-------|-------|-------------|------|
| 1  SCOPE     | scope.md      | Register target, scope, credentials, task tree | phase_completed=0 |
| 2  AUTH      | (inline)      | Auth flow test, WAF detection, token capture | phase_completed=2 |
| 3  INTEL     | phase-intel.sh | WHOIS, M365/Azure, spoof check, cloud bucket enum | — |
| 4  RECON     | recon.md      | Subdomain enum, DNS, crawl, params, secrets | phase_completed=4 |
| 5  SURFACE   | surface.md    | Prioritize endpoints, rank attack surface | phase_completed=5 |
| 6  HUNT      | hunt.md       | Dispatch 57 hunt-* sub-agents, test all bug classes | phase_completed=6 |
| 7  DEEPTHINK | deepthink.md | (conditional) First-principles gap analysis when HUNT yields zero | — |
| 8  EXPLOIT   | exploit.md    | Second-wave exploitation: PoC all findings, WAF bypass, chaining | — |
| 9  SEARCH    | search.md     | (conditional) 13-resource retrieval when EXPLOIT stalls | — |
| 10 CAPTURE   | capture.md    | Evidence collection, screenshots, redaction | — |
| 11 VALIDATE  | validate.md   | Re-validate PoCs, 7-Question Gate, severity | phase_completed=5 |
| 12 REPORT    | report.md     | Coverage check, generate report | phase_completed=5 |

Autopilot is a thin orchestrator (248 lines) — phases 4-12 are dispatched via `task()` to specialized sub-agents to avoid context exhaustion.

---

## MCP Server (88 Tools)

### WSTG Knowledge Base
- `get_wstg_test(test_id)` — Full WSTG test case content
- `search_wstg(query)` — Search across all WSTG test cases
- `list_tests_in_category(category_code)` — Tests by category
- `list_wstg_categories()` — All WSTG categories
- `get_test_payloads(test_id)` — Extract payloads from test case
- `search_wstg(query)` — Search WSTG tests and technique references
- `get_slot_types(category)` — Sink classification reference
- `get_witness_payloads(sink_context)` — Context-aware witness payloads

### Engagement Management
- `findings_init(engagement_id, client, ...)` — Create engagement
- `findings_add_vuln(engagement_id, title, severity, ...)` — Add finding
- `findings_add_host(engagement_id, ...)` — Add discovered host
- `findings_add_service(engagement_id, ...)` — Add service
- `findings_add_credential(engagement_id, ...)` — Add credential
- `findings_add_chain(engagement_id, ...)` — Record attack chain
- `findings_list_vulns(engagement_id, ...)` — List vulnerabilities
- `findings_list_hosts(engagement_id)` — List hosts
- `findings_export(engagement_id)` — Export all data
- `findings_handoff(engagement_id)` — Generate handoff report
- `findings_stats(engagement_id)` — Engagement statistics
- `findings_log_action(engagement_id, ...)` — Log activity
- `update_finding(engagement_id, finding_id, ...)` — Update finding

### WAF Detection & Evasion
- `identify_waf(response_headers, response_body, status_code)` — Identify WAF vendor
- `get_waf_bypass(waf_vendor, vuln_class, bypass_level)` — Tailored bypass payloads
- `list_waf_vendors()` — All supported WAFs
- `identify_waf(response_headers, ...)` — MCP tool wrapper (171 vendors)

### Knowledge Graph
- `add_graph_node(engagement_id, node_id, node_type, label, ...)` — Add entity
- `add_graph_edge(engagement_id, source, target, edge_type, ...)` — Add relationship
- `query_graph(engagement_id, ...)` — Query nodes/edges
- `find_chains(engagement_id, ...)` — Find attack paths
- `get_graph_summary(engagement_id)` — Graph statistics

### Endpoint Priority
- `prioritize_endpoints(engagement_id, endpoints_json)` — Risk-score endpoints
- `get_priority_queue(engagement_id, limit)` — Get prioritized list

### Task Tree
- `create_task_tree(engagement_id)` — Initialize
- `add_task_node(engagement_id, parent_id, label, ...)` — Add task
- `update_task_node(engagement_id, node_id, ...)` — Update status
- `get_task_tree(engagement_id, max_depth)` — View tree
- `get_subtree(engagement_id, node_id)` — View subtree
- `get_task_summary(engagement_id)` — Progress summary

### Tool Integration
- `parse_tool_output(tool_name, raw_output, verbosity)` — Parse CLI output
- `ingest_tool_file(engagement_id, tool_name, file_path, verbosity)` — Parse file
- `verify_tool_result(tool_name, command, raw_output)` — Validate output
- `track_tool(engagement_id, tool_name, status, ...)` — Track tool execution

### Phase Management
- `phase_gate_check(engagement_id, phase_completed)` — Quality gate
- `save_checkpoint(engagement_id, description)` — Save state
- `resume_engagement(engagement_id)` — Resume from checkpoint
- `list_checkpoints(engagement_id)` — Available checkpoints
- `git_checkpoint(engagement_id, description)` — Git commit
- `git_rollback(engagement_id, reason)` — Roll back
- `compress_phase_context(engagement_id, phase)` — Summarize phase
- `get_engagement_summary(engagement_id)` — Full engagement summary
- `get_engagement_status(engagement_id)` — Dashboard view
- `get_engagement_config(engagement_id)` — Config retrieval
- `get_engagement_rules(engagement_id)` — Focus/avoid rules

### Validation & Reporting
- `validate_poc(engagement_id, command, ...)` — Execute + validate PoC
- `validate_finding_poc(engagement_id, finding_id)` — Re-validate finding
- `get_evidence_checklist(vuln_class)` — Evidence requirements
- `register_scope(engagement_id, domain, ...)` — Register domain
- `register_scope_batch(engagement_id, entries)` — Batch register
- `get_scope(engagement_id)` — Get scope
- `parse_scope_table(engagement_id, table_text)` — Parse bug bounty table
- `load_engagement_config(engagement_id, config_yaml)` — Load config
- `track_test(engagement_id, test_id, status, ...)` — Track WSTG test
- `get_coverage(engagement_id)` — WSTG coverage report
- `get_tool_coverage(engagement_id)` — Tool coverage report
- `generate_report(engagement_id, target, tester)` — Full pentest report
- `get_judge_data(engagement_id)` — Final Judge review packet
- `track_judge_review(engagement_id, verdict, ...)` — Record review
- `track_qa_review(engagement_id, phase, ...)` — Record QA review

### Exploitation
- `create_exploitation_queue(engagement_id, vuln_class, ...)` — Queue vulns
- `get_exploitation_queue(engagement_id, vuln_class)` — Get queue
- `validate_exploitation_queue(engagement_id, vuln_class)` — Validate
- `mark_exploited(engagement_id, vuln_class, vuln_id, result, ...)` — Mark outcome

### Browser Profile
- `get_browser_profile(engagement_id, agent_id)` — Isolated browser profile

### Deliverables
- `save_deliverable(engagement_id, deliverable_type, content, ...)` — Save
- `get_deliverable(engagement_id, deliverable_type)` — Retrieve
- `list_deliverables(engagement_id)` — List all

### Audit
- `get_audit_log(engagement_id, last_n)` — Event log

---

## Agents (118)

### Pipeline Agents (18)
auth, autopilot, browser-auth, bug-bounty, capture, consult, deepthink, exploit, hunt, osint, pintel, recon, report, scope, search, surface, validate, web2-vuln-classes

### Bug Class Agents (57 hunt-*)
api-misconfig, aspnet, ato, auth-bypass, brute-force, business-logic, cache-poison, cicd, clickjacking, cloud-misconfig, cors, crlf, csrf, dependency-confusion, deserialization, dispatch, dom, file-upload, graphql, grpc, host-header, http-param-pollution, http-smuggling, idor, jwt-confusion, k8s, laravel, ldap, lfi, llm-ai, mass-assignment, mfa-bypass, misc, nextjs, nodejs, nosqli, ntlm-info, oauth, open-redirect, prototype-pollution, race-condition, rce, saml, session, sharepoint, source-leak, springboot, sqli, ssrf, ssrf-cloud, ssti, subdomain, tls-network, websocket, xss, xxe

### Specialty Agents (43)
apk-redteam-pipeline, bb-local-toolkit, bb-methodology, bugcrowd-reporting, cloud-iam-deep, credential-attack, enterprise-vpn-attack, evidence-hygiene, m365-entra-attack, meme-coin-audit, mid-engagement-ir-detection, offensive-osint, okta-attack, osint-methodology, redteam-mindset, redteam-report-template, report-writing, security-arsenal, supply-chain-attack-recon, triage-validation, vmware-vcenter-attack, waf-bypass-akamai, waf-bypass-aws, waf-bypass-cloudflare, waf-bypass-f5, waf-bypass-fastly, waf-bypass-imperva, waf-bypass-modsecurity, waf-bypass-signalsciences, waf-bypass-sucuri, waf-encoding-obfuscation, waf-evasion-rce, waf-evasion-sqli, waf-evasion-xss, waf-fingerprinting, waf-header-spoofing, waf-hpp-hpf, waf-protocol-evasion, waf-regex-reversing, web2-recon, web3-audit

### Agent Reference Sections
Every hunt agent includes:
1. **WSTG methodology reference** — Relevant test IDs
2. **Deep testing workflow** — Mutation, fuzzing, entry point techniques
3. **BurpSuite pro workflow** — Per-class Burp MCP tool guidance
4. **PayloadsAllTheThings reference** — PAT README path
5. **Disclosed reports reference** — H1 per-class file + top 5 reports
6. **WAF fingerprint reference** — identify_waf(), vendor KB, bypass files
7. **Code analysis findings** — Source code patterns when available

---

## Reference Libraries

### PayloadsAllTheThings (knowledge/payloads/)
- 64 categories (unlinked from GitHub)
- 12 extracted with test.sh wrappers in scripts/payloads/
- ~25K total payloads
- pat_ref() maps 32 agent class names to PAT README paths
- 17 test.sh + 12 payloads.txt + lib.sh + hunt.sh + deploy.sh

### WAF Reference (knowledge/waf/)
- 144 vendor fingerprints with detection methodology
- 21 evasion technique files (WAF-EVASION-01 through 21)
- 24 known bypass vendor files
- 12 research papers + 11 presentations extracted to markdown
- 18 skills (fingerprinting, vendor-specific bypasses, encoding, HPP, regex reversing)
- obfu.py payload obfuscation script
- waf_evasion.py loads via JSON at runtime (171 total vendors)

### Wordlists
- raft-medium-dirs.txt, api-endpoints.txt, params.txt, common.txt
- 20 GF patterns for parameter discovery

---

## Server Components

### waf_evasion.py
- `WAF_SIGNATURES`: 27 built-in vendor fingerprints
- `_load_external_vendors()`: Loads 144 vendors from waf_vendors.json at runtime
- `_get_all_signatures()`: Merged 171 vendors total
- `WAF_BYPASSES`: 15 built-in (vendors + encoding strategies)
- `_load_external_bypasses()`: Loads 20 vendor files from waf_bypasses.json
- `_get_all_bypasses()`: Merged bypass data
- identify_waf(), get_waf_bypass(), list_waf_vendors()

### findings_db.py
SQLite-backed findings database with tables for:
- engagements, findings, hosts, services, credentials, chains, sessions

### knowledge_graph.py
- Nodes: endpoints, parameters, technologies, findings, user roles, cookies, domains, headers, files, secrets
- Edges: authenticates_to, has_parameter, reflects_in, redirects_to, trusts_origin, shares_session, uses_technology, has_finding, bypasses, chains_to, sends_to, reads_file, exposes, includes, manages, owned_by, injects_into

### endpoint_priority.py
Risk-scoring algorithm based on: parameter count, tech risk, taint chains, tool convergence, auth requirements, HTTP method, injectable parameter names

### tool_parsers.py
Parsers for: nmap, sqlmap, ffuf, httpx, whatweb, testssl, nikto, dalfox, katana, gau, wapiti, commix, sstimap, crlfuzz, smuggler, corscanner, generics

### context_compression.py
Phase-level summarization for inter-agent handoff; combines findings, tools, tests, and WAF data into compressed phase context

### server_data.py
Constants: CATEGORIES (WSTG categories), TOOL_REGISTRY (CLI tool metadata), WITNESS_PAYLOADS (context-aware PoC payloads), SLOT_TYPES (sink classification), EVIDENCE_CHECKLISTS, EXHAUSTION_THRESHOLDS, PHASE_NAMES, PHASE_TEST_REQUIREMENTS, PHASE_TOOL_REQUIREMENTS, DELIVERABLE_TYPES

---

## Scripts (48 CLI Tools)

Located in `scripts/tools/`: wrappers for subdomain enum, DNS bruteforce, web crawling, parameter extraction, directory bruteforce, vhost fuzzing, zone transfer, takeover scanning, cloud recon, secret discovery, cariddi scanning, bypass 403, OSINT (whois, Spoofy, cloud_enum), S3/cloud bucket scanning (cloud_enum + s3scanner + trufflehog), and more.

All domain-mode: accept domain as $1, auto-discover recon output, output to `$SWARM_ROOT/engagements/recon/<domain>/`. ENGAGEMENT_ID is now optional.

---

## Browser Automation (browser-use / MCP)

Browser automation uses **browser-use** `Browser` class imported directly in `server/browser_tools.py`. The browser persists across MCP calls via CDP port 9222.

### MCP Tools (7)
- `browser_analyze(eid, url)` — Page screenshot + text + interactive elements (LLM-driven)
- `browser_act(eid, action, index, text, url, code)` — navigate, click, type, js, state, cookies, html, close
- `browser_auto_auth(eid, url, email, headless)` — Autonomous signup → email verification → login
- `browser_login(eid, agent_id, url, username, password)` — Login form automation
- `browser_screenshot(eid, agent_id, url)` — Evidence screenshot capture
- `browser_crawl(eid, start_url, depth)` — SPA route discovery
- `browser_extract_storage(eid, agent_id, url)` — Cookies + localStorage + sessionStorage

### Subagents for Browser Auth
- `analyze` — Read-only page analysis: auth page discovery, redirect chain tracking, tech fingerprinting, storage analysis
- `browser-auth` — Uses analyze output to drive signup/login, MFA handling, session capture

### CLI Backend
- `server/venv/bin/python3 server/browser_use_backend.py navigate|state|click|type|screenshot|js|cookies|close`
- `.venv/bin/python scripts/browser_driver.py` (legacy, being phased out)
- Chrome runs independently on port 9222, survives between invocations

## OOB (Out-of-Band) Detection

- `scripts/tools/oob_listener.sh` — interactsh-client wrapper
- `bash $HOME/swarm/scripts/tools/oob_listener.sh start` → returns callback URL for blind XSS/SSRF/XXE payloads

- `bash $HOME/swarm/scripts/tools/oob_listener.sh stop` → collects received interactions
## CVSS Scoring

- `generate_poc_report.sh` auto-computes CVSS 3.1 scores via `compute_cvss()`
- Maps severity (Info/Low/Medium/High/Critical) to CVSS vector string using `cvss==3.6`

---

## Prompts

13 per-category prompt files in `prompts/`: api-testing, authentication, authorization, business-logic, client-side, configuration, cryptography, error-handling, exploitation, identity-management, info-gathering, input-validation, session-management

---

## Engagement Lifecycle

1. **Init**: findings_init() + create_task_tree()
2. **Scope**: Register domains, parse scope tables, load config
3. **Auth**: Test credentials, detect WAF, capture tokens
4. **OSINT**: WHOIS, M365/Azure tenant, spoof check, cloud bucket enum
5. **Recon**: Enumerate subdomains, crawl, discover endpoints
6. **Surface**: Prioritize endpoints by risk score
6. **Hunt**: Test all applicable bug classes with per-class agents
7. **Capture**: Collect evidence with redaction
8. **Validate**: Re-verify PoCs, 7-Question Gate
9. **Report**: Generate final report with coverage statistics

---

## Key Design Decisions

- **Autopilot as orchestrator, not monolith**: 248-line dispatcher; phases 2-12 via task()
- **Output to $SWARM_ROOT/engagements/recon/<domain>/**: Flat recon directory, no default-engagement layer, ENGAGEMENT_ID optional
- **Never install tools**: All tools pre-installed at `scripts/tools/`. Agents have explicit HARD RULES prohibiting `pip install`/`go install`/`apt install` — use wrapper scripts only
- **No raw tool binaries**: Every tool accessed via `bash $HOME/swarm/scripts/tools/<name>.sh <target>`, never invoked directly
- **WAF as JSON at runtime**: 144 vendors loaded from JSON, avoids Python syntax issues
- **Skills drive per-agent methodology**: Load relevant skill via `skill()` MCP tool for each vulnerability class
- **Browser cleanup**: Browser closed after every operation to prevent context leaks
- **Burp proxy auto-detection**: Headed browser routes through Burp on port 8080 when detected
- **consult.md frontmatter added**: Was missing entirely, now loads correctly
- **12 pipeline agents frontmatter fixed**: Added mode + permission blocks
- **deepthink + search added**: Conditional intelligence fallback phases (7, 9)
- **pipeline updated**: Re-exploitation loop after search finds new payloads
- **Deliverable-based data flow**: auth_analysis → Phase 6, endpoint_map_raw → Phase 5 → endpoint_map_ranked → Phase 6
- **Agent hardening**: All pipeline agents (autopilot, consult, recon, surface, hunt, pintel) now include HARD RULES: no tool installation, no raw binary invocations, phase gates mandatory. Fixes third-party models skipping steps or running `pip install`/`go install`/`apt install` instead of using `scripts/tools/` wrappers.

---

## Appendix A: Agent Roster (118)

### Pipeline & Dispatch (14)
`autopilot` `consult` `scope` `auth` `pintel` `recon` `surface` `hunt` `deepthink` `exploit` `search` `capture` `validate` `report`

### Auth-Session (3)
`browser-auth` `analyze` `credential-attack`

### Recon & OSINT (6)
`offensive-osint` `web2-recon` `osint-methodology` `osint` `dirbrute` `hunt-subdomain`

### `@hunt-*` Vulnerability Agents (57)
`hunt-api-misconfig` `hunt-aspnet` `hunt-ato` `hunt-auth-bypass` `hunt-brute-force` `hunt-business-logic` `hunt-cache-poison` `hunt-cicd` `hunt-clickjacking` `hunt-cloud-misconfig` `hunt-cors` `hunt-crlf` `hunt-csrf` `hunt-dependency-confusion` `hunt-deserialization` `hunt-dispatch` `hunt-dom` `hunt-file-upload` `hunt-graphql` `hunt-grpc` `hunt-host-header` `hunt-http-param-pollution` `hunt-http-smuggling` `hunt-idor` `hunt-jwt-confusion` `hunt-k8s` `hunt-laravel` `hunt-ldap` `hunt-lfi` `hunt-llm-ai` `hunt-mass-assignment` `hunt-mfa-bypass` `hunt-misc` `hunt-nextjs` `hunt-nodejs` `hunt-nosqli` `hunt-ntlm-info` `hunt-oauth` `hunt-open-redirect` `hunt-prototype-pollution` `hunt-race-condition` `hunt-rce` `hunt-saml` `hunt-session` `hunt-sharepoint` `hunt-source-leak` `hunt-springboot` `hunt-sqli` `hunt-ssrf` `hunt-ssrf-cloud` `hunt-ssti` `hunt-subdomain` `hunt-tls-network` `hunt-websocket` `hunt-xss` `hunt-xxe`

### Enterprise Platform (7)
`m365-entra-attack` `okta-attack` `cloud-iam-deep` `enterprise-vpn-attack` `apk-redteam-pipeline` `supply-chain-attack-recon` `vmware-vcenter-attack`

### Red Team Tradecraft (1)
`redteam-mindset`

### Workflow & Validation (3)
`bug-bounty` `triage-validation` `mid-engagement-ir-detection`

### Reporting & Hygiene (7)
`report-writing` `bugcrowd-reporting` `evidence-hygiene` `redteam-report-template` `web2-vuln-classes` `waf-fingerprinting` `security-arsenal`

### WAF Evasion (17)
`waf-bypass-akamai` `waf-bypass-aws` `waf-bypass-cloudflare` `waf-bypass-f5` `waf-bypass-fastly` `waf-bypass-imperva` `waf-bypass-modsecurity` `waf-bypass-signalsciences` `waf-bypass-sucuri` `waf-encoding-obfuscation` `waf-evasion-rce` `waf-evasion-sqli` `waf-evasion-xss` `waf-header-spoofing` `waf-hpp-hpf` `waf-protocol-evasion` `waf-regex-reversing`

### Web3 & Meme (2)
`meme-coin-audit` `web3-audit`

### Specialized (2)
`bb-local-toolkit` `bb-methodology`

## Appendix B: MCP Tool Roster (93)

### Engagement Lifecycle (17)
`load_engagement_config` `get_engagement_config` `get_engagement_rules` `get_engagement_status` `register_scope` `register_scope_batch` `get_scope` `parse_scope_table` `track_test` `track_tool` `track_qa_review` `track_judge_review` `get_coverage` `get_tool_coverage` `generate_resume_prompt` `resume_engagement` `save_checkpoint`

### Findings & Evidence (17)
`findings_init` `findings_add_host` `findings_add_service` `findings_add_vuln` `findings_list_hosts` `findings_list_vulns` `update_finding` `log_finding` `get_findings` `findings_add_credential` `findings_add_chain` `findings_export` `findings_handoff` `findings_log_action` `findings_stats` `get_judge_data`

### WSTG Methodology (6)
`get_wstg_test` `get_test_payloads` `search_wstg` `list_wstg_categories` `list_tests_in_category`

### Technique References (3)
`search_wstg` `get_witness_payloads` `get_evidence_checklist`

### WAF Evasion (4)
`identify_waf` `get_waf_bypass` `list_waf_vendors` `get_slot_types`

### Exploitation (5)
`create_exploitation_queue` `get_exploitation_queue` `validate_exploitation_queue` `mark_exploited` `validate_poc`

### PoC Validation (2)
`validate_finding_poc` `verify_tool_result`

### Phase Gates & QA (2)
`phase_gate_check` `generate_report`

### Source Code Analysis (3)
`start_code_analysis` `save_code_analysis` `get_code_analysis`

### Session & Browser (2)
`get_browser_profile` `call_graphql_introspect`

### Networking & HTTP (2)
`burp_send_request`

### Deliverables (3)
`save_deliverable` `get_deliverable` `list_deliverables`

### Task Tree (6)
`create_task_tree` `add_task_node` `update_task_node` `get_task_tree` `get_subtree` `get_task_summary`

### Knowledge Graph (6)
`add_graph_node` `add_graph_edge` `query_graph` `find_chains` `get_graph_summary` `get_engagement_summary`

### Git Checkpoint (2)
`git_checkpoint` `git_rollback`

### Utility & Output (8)
`ingest_tool_file` `parse_tool_output` `prioritize_endpoints` `get_priority_queue` `get_audit_log` `compress_phase_context` `list_checkpoints` `list_deliverables`

### State Persistence (2)
`get_code_analysis` (shared) `resume_engagement` (shared)

---

## Known Issues

- Third-party models (GPT-4, Claude, etc.) previously skipped pipeline steps and installed tools instead of using `scripts/tools/`. **Mitigated**: All agents now have hardcoded HARD RULES at the top prohibiting installation and enforcing phase order.

---

## Frontmatter

- Repository: https://github.com/manojxshrestha/swarm
- License: Proprietary — All Rights Reserved
- Python: 3.10+
- WSTG: v4.2
