# Phase Commands Reference

Full-path commands for every phase script, sub-tool, agent, and external binary.

Base paths:
- **Phase scripts**: `$SWARM_HOME/scripts/tools/phase-<name>.sh`
- **Sub-tool scripts**: `$SWARM_HOME/scripts/tools/<tool>.sh`
- **Supporting scripts**: `$SWARM_HOME/scripts/<script>.sh`
- **Agents**: `$SWARM_HOME/.swarm/agents/<agent>.md`
- **Docs**: `$SWARM_HOME/docs/phases/<name>.md`
- **Output**: `$RECON_BASE/<domain>` (default: `$SWARM_HOME/engagements/recon/<domain>`)

---

## Table of Contents

1. [Phase 0: Orchestrator](#phase-0-orchestrator)
2. [Phase 1: Scope](#phase-1-scope)
3. [Phase 2: Auth](#phase-2-auth)
4. [Phase 3: Intel](#phase-3-intel)
5. [Phase 3b: OSINT (standalone)](#phase-3b-osint-standalone)
6. [Phase 4: Recon](#phase-4-recon)
7. [Phase 5: Surface](#phase-5-surface)
8. [Phase 6: Hunt](#phase-6-hunt)
9. [Phase 7: Deepthink](#phase-7-deepthink)
10. [Phase 8: Exploit](#phase-8-exploit)
11. [Phase 9: Search](#phase-9-search)
12. [Phase 10: Capture](#phase-10-capture)
13. [Phase 11: Validate](#phase-11-validate)
14. [Phase 12: Report](#phase-12-report)

---

## Phase 0: Orchestrator

**Script:** `$SWARM_HOME/scripts/tools/phase-orchestrator.sh`
**Agent:** *(none)*
**Doc:** `$SWARM_HOME/docs/pipeline.md`

### Sub-tool scripts called
None — pure shell scaffolding.

### External binaries invoked
- `mkdir`, `echo`, `date`

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-orchestrator.sh <domain> [output_dir]
```

### What it does
Creates engagement directory tree (`scope/`, `intel/`, `recon/`, `crawl/`, `subdomains/`, `secrets/`, `directories/`, `vhost/`, `evidence/`, `screenshots/`). Writes `target.txt` and `started.txt`.

---

## Phase 1: Scope

**Script:** `$SWARM_HOME/scripts/tools/phase-scope.sh`
**Agent:** `@scope` — `$SWARM_HOME/.swarm/agents/scope.md`
**Doc:** `$SWARM_HOME/docs/phases/scope.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/tools/phase_gate.sh` (called by pipeline.sh after phase)

### External binaries invoked
- `curl` (connectivity check to `https://<domain>`)
- `mkdir`, `echo`, `date`

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-scope.sh <domain> [output_dir]
```

### What it does
Scaffolds engagement dirs, checks target HTTPS reachability, writes target metadata.

### MCP calls (via @scope agent)
```python
register_scope(engagement_id, domain, domain_type, eligibility)
load_engagement_config(engagement_id, config_yaml)
create_task_tree(engagement_id)
findings_init(engagement_id, client, etype, scope)
findings_add_host(engagement_id, hostname, role)
phase_gate_check(engagement_id, phase_completed=0)
```

---

## Phase 2: Auth

**Script:** `$SWARM_HOME/scripts/tools/phase-auth.sh`
**Agent:** `@auth` — `$SWARM_HOME/.swarm/agents/auth.md`
**Doc:** `$SWARM_HOME/docs/phases/auth.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/tools/auto_auth.py` — Playwright browser auth (signup→verify→login→cookie capture)

### External binaries invoked
- `curl -sI` (WAF header detection)
- `python3` (runs auto_auth.py)
- `playwright` / `selenium-wire` (via auto_auth.py)

### Command
```bash
# Standard
bash $SWARM_HOME/scripts/tools/phase-auth.sh <domain> [output_dir]

# With pre-set credentials (skips auto-auth)
BBHUNT_COOKIE="session=abc123" bash $SWARM_HOME/scripts/tools/phase-auth.sh <domain>
BBHUNT_BEARER="eyJ..." bash $SWARM_HOME/scripts/tools/phase-auth.sh <domain>
BBHUNT_AUTH_HEADERS="X-Api-Key: xxx" bash $SWARM_HOME/scripts/tools/phase-auth.sh <domain>
```

### Alternate manual auth approach
```bash
# Browser login with explicit fields
python3 -c "
from scripts.tools.auth_session import browser_login
browser_login(engagement_id, agent_id='auth-agent', url='https://<domain>/login',
              username='user', password='pass')
"
```

### MCP calls (via @auth agent)
```python
identify_waf(response_headers, response_body, status_code)
browser_login(engagement_id, agent_id, url, username, password)
browser_extract_storage(engagement_id, agent_id, url)
get_waf_bypass(waf_vendor, vuln_class, bypass_level)
phase_gate_check(engagement_id, phase_completed=1)
```

### What it does
Fingerprints WAF vendor from response headers. Launches background browser auto-auth (signup→email verify→login→cookie capture). Saves `auth/waf_detection.txt` and `auth/session.json`.

### Wrapper expansion (Phase 2)
**Replaced:** `run_bg "auto_auth" "$AUTH_DIR/auto_auth.log" "python3 'auto_auth.py' '$TARGET' --output-dir '$OUT_DIR'"`
**Expanded:**
```bash
nohup bash -c "python3 '<phase-script-dir>/auto_auth.py' '$TARGET' --output-dir '$OUT_DIR'" \
  > "$OUT_DIR/auth/auto_auth.log" 2>&1 &
```

---

## Phase 3: Intel

**Script:** `$SWARM_HOME/scripts/tools/phase-intel.sh`
**Agent:** `@pintel` — `$SWARM_HOME/.swarm/agents/pintel.md`
**Doc:** `$SWARM_HOME/docs/phases/pintel.md`

### Sub-tool scripts called
- `/home/pwn/.local/bin/msftrecon/msftrecon/msftrecon.py` (via venv) — M365/Azure tenant discovery
- `/home/pwn/.local/bin/Scopify/scopify.py` (via venv) — scope domain analysis
- `/home/pwn/.local/bin/Spoofy/spoofy.py` (via venv) — SPF/DMARC spoof check
- `/home/pwn/.local/bin/cloud_enum/cloud_enum.py` (via venv) — multi-cloud bucket enumeration

### External binaries invoked
- `whois` (WHOIS lookup)
- `unfurl` (company name extraction for Scopify/cloud_enum)
- `python3` (runs all tool venvs)

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-intel.sh <domain> [output_dir]
```

### Output files
| File | Location | Content |
|------|----------|---------|
| domain_info_general.txt | `intel/` | WHOIS data + msftrecon output |
| azure_tenant_domains.txt | `intel/` | M365/Azure tenant findings |
| scopify.txt | `intel/` | Scopify scope analysis |
| spoof.txt | `intel/` | SPF/DMARC spoofability |
| cloud_enum.txt | `intel/` | Cloud storage buckets |

### MCP calls (via @pintel agent)
```python
save_deliverable(engagement_id, 'osint_analysis', content, 'pintel')
track_tool(tool_name='pintel', status='run', notes='WHOIS + Spoofy + cloud_enum')
phase_gate_check(engagement_id, phase_completed=2)
```

### What it does
Three modules: `run_domain_info` (WHOIS + M365/Azure + Scopify), `run_spoof` (SPF/DMARC), `run_cloud_enum` (AWS/Azure/GCP/DO bucket scan).

### Wrapper expansion (Phase 3 — Intel)

#### WHOIS lookup
**Replaced:** `_run_tool "$INTEL_DIR/domain_info_general.txt" "whois '$TARGET' 2>/dev/null"`
**Expanded:**
```bash
whois "$TARGET" 2>/dev/null | tee -a "$INTEL_DIR/domain_info_general.txt"
```

#### msftrecon (M365/Azure tenant discovery)
**Replaced:** `_run_tool_venv msftrecon "python3 '$msftrecon_script' -d '$TARGET'"`
**Expanded:**
```bash
source "$HOME/.local/bin/msftrecon/venv/bin/activate"
python3 "$HOME/.local/bin/msftrecon/msftrecon/msftrecon.py" -d "$TARGET"
```

#### Scopify (scope analysis)
**Replaced:** `_run_tool_venv Scopify "python3 '$TOOLS_DIR/Scopify/scopify.py' -c '$company_name'"`
**Expanded:**
```bash
source "$HOME/.local/bin/Scopify/venv/bin/activate"
python3 "$HOME/.local/bin/Scopify/scopify.py" -c "$company_name"
```

#### Spoofy (SPF/DMARC)
**Replaced:** `_run_tool_venv Spoofy "cd '$TOOLS_DIR/Spoofy' && python3 '$spoofy_script' -d '$TARGET'"`
**Expanded:**
```bash
source "$HOME/.local/bin/Spoofy/venv/bin/activate"
cd "$HOME/.local/bin/Spoofy"
python3 "$HOME/.local/bin/Spoofy/spoofy.py" -d "$TARGET"
```

#### cloud_enum (multi-cloud bucket scan)
**Replaced:** `_run_tool_venv cloud_enum "PYTHONWARNINGS=ignore python3 '$cloud_enum_script' -k '$company_name' ..."`
**Expanded:**
```bash
source "$HOME/.local/bin/cloud_enum/venv/bin/activate"
PYTHONWARNINGS=ignore python3 "$HOME/.local/bin/cloud_enum/cloud_enum.py" \
    -k "$company_name" -k "$TARGET" -k "${TARGET%%.*}" \
    -t 50 -m "$fuzz_file" -b "$fuzz_file" -qs 2>/dev/null
```

---

## Phase 3b: OSINT (standalone)

**Script:** `$SWARM_HOME/scripts/tools/phase-osint.sh`
**Agent:** `@osint` — `$SWARM_HOME/.swarm/agents/osint.md`
**Doc:** `$SWARM_HOME/docs/phases/osint.md`

### Sub-tool scripts called
None — uses theHarvester directly.

### External binaries invoked
- `theHarvester` (via `$HOME/theHarvester/.venv/bin/theHarvester`)

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-osint.sh <domain> [output_dir]
```

### What it does
Runs theHarvester with two source sets:
- **Subdomains**: `crtsh,rapiddns,subdomaincenter,hackertarget,otx,urlscan,dnsdumpster,bevigil,certspotter,bufferoverun,threatcrowd,virustotal,waybackarchive,commoncrawl,securityTrails,chaos,fullhunt,projectdiscovery,robtex`
- **Emails**: `yahoo,duckduckgo,hunter,intelx,haveibeenpwned,hudsonrock,leakix,leaklookup,mojeek,tomba`

---

## Phase 4: Recon

**Script:** `$SWARM_HOME/scripts/tools/phase-recon.sh`
**Agent:** `@recon` — `$SWARM_HOME/.swarm/agents/recon.md`
**Doc:** `$SWARM_HOME/docs/phases/recon.md`

### Sub-tool scripts called (all via `nohup` in parallel)

| Script | Full Path |
|--------|-----------|
| subdomain_enum.sh | `$SWARM_HOME/scripts/tools/subdomain_enum.sh` |
| web_gospider.sh | `$SWARM_HOME/scripts/tools/web_gospider.sh` |
| web_katana.sh | `$SWARM_HOME/scripts/tools/web_katana.sh` |
| web_waymore.sh | `$SWARM_HOME/scripts/tools/web_waymore.sh` |
| extracturls.sh | `$SWARM_HOME/scripts/tools/extracturls.sh` |
| dns_bruteforce.sh | `$SWARM_HOME/scripts/tools/dns_bruteforce.sh` |
| param_extract.sh | `$SWARM_HOME/scripts/tools/param_extract.sh` |
| cariddi_scan.sh | `$SWARM_HOME/scripts/tools/cariddi_scan.sh` |
| vhost_fuzz.sh | `$SWARM_HOME/scripts/tools/vhost_fuzz.sh` |
| zone_transfer.sh | `$SWARM_HOME/scripts/tools/zone_transfer.sh` |
| github_dork.sh | `$SWARM_HOME/scripts/tools/github_dork.sh` |
| s3_buckets.sh | `$SWARM_HOME/scripts/tools/s3_buckets.sh` |

### External binaries invoked (by sub-tools)

| Binary | Called By |
|--------|-----------|
| `subfinder` | subdomain_enum.sh |
| `assetfinder` | subdomain_enum.sh |
| `findomain` | subdomain_enum.sh |
| `dnsx` | subdomain_enum.sh |
| `httpx` | subdomain_enum.sh |
| `gospider` | web_gospider.sh |
| `katana` | web_katana.sh |
| `waymore` | web_waymore.sh |
| `uro` | web_waymore.sh |
| `httpx` | extracturls.sh |
| `puredns` / `massdns` | dns_bruteforce.sh |
| `gf` | param_extract.sh |
| `cariddi` | cariddi_scan.sh |
| `ffuf` | vhost_fuzz.sh |
| `dig` | zone_transfer.sh |
| `gh` | github_dork.sh |
| `s3scanner` | s3_buckets.sh |
| `trufflehog` | s3_buckets.sh |
| `anew` | sub-tool dedup |
| `cloud_enum` (venv) | s3_buckets.sh, cloud_recon.sh |

### Command
```bash
# Full recon (all sub-tools in parallel)
bash $SWARM_HOME/scripts/tools/phase-recon.sh <domain> [output_dir]

# Root-only mode (skip subdomain enumeration)
bash $SWARM_HOME/scripts/tools/phase-recon.sh <domain> --root-only

# Skip specific tools
SKIP_LIST="gospider,katana" bash $SWARM_HOME/scripts/tools/phase-recon.sh <domain>
```

### Standalone sub-tool commands (run individually)
```bash
bash $SWARM_HOME/scripts/tools/subdomain_enum.sh <domain>
bash $SWARM_HOME/scripts/tools/dns_bruteforce.sh <domain>
bash $SWARM_HOME/scripts/tools/web_waymore.sh <domain>
bash $SWARM_HOME/scripts/tools/web_gospider.sh <domain>
bash $SWARM_HOME/scripts/tools/web_katana.sh <domain>
bash $SWARM_HOME/scripts/tools/extracturls.sh -f /path/to/crawl -d <domain>
bash $SWARM_HOME/scripts/tools/param_extract.sh <domain>
bash $SWARM_HOME/scripts/tools/cariddi_scan.sh <domain>
bash $SWARM_HOME/scripts/tools/bypass_403.sh <domain>
bash $SWARM_HOME/scripts/tools/vhost_fuzz.sh <domain>
bash $SWARM_HOME/scripts/tools/zone_transfer.sh <domain>
bash $SWARM_HOME/scripts/tools/github_dork.sh <domain>
bash $SWARM_HOME/scripts/tools/s3_buckets.sh <domain>
bash $SWARM_HOME/scripts/tools/cloud_recon.sh --keyword <company>
```

### What it does
Orchestrates 12 recon sub-tools (8 parallel + sequential sub-phases). Passive subdomain enum, active crawling, URL extraction/filtering, DNS bruteforce, parameter extraction with GF patterns, secrets scanning, vhost fuzzing, zone transfer, GitHub dorking, S3 bucket scanning.

### Wrapper expansion (Phase 4 — Recon)

All sub-tool calls follow the same pattern:

**Replaced:** `run_bg "<name>" "<logfile>" "bash '<script>.sh' '$TARGET'"`
**Expanded:**
```bash
nohup bash -c "bash '<phase-script-dir>/<script>.sh' '$TARGET'" > "<logfile>" 2>&1 &
```

| Sub-tool | Log file |
|----------|----------|
| `subdomain_enum.sh` | `$OUT_DIR/subdomains/subdomain_enum.log` |
| `web_gospider.sh` | `$CRAWL_DIR/gospider.log` |
| `web_katana.sh` | `$CRAWL_DIR/katana.log` |
| `web_waymore.sh` | `$CRAWL_DIR/waymore.log` |
| `extracturls.sh` | `$CRAWL_DIR/extracturls.log` |
| `dns_bruteforce.sh` | `$OUT_DIR/dns_bruteforce.log` |
| `param_extract.sh` | `$OUT_DIR/param_extract.log` |
| `cariddi_scan.sh` | `$OUT_DIR/cariddi_scan.log` |
| `vhost_fuzz.sh` | `$OUT_DIR/vhost_fuzz.log` |
| `zone_transfer.sh` | `$OUT_DIR/zone_transfer.log` |
| `github_dork.sh` | `$OUT_DIR/github_dork.log` |
| `s3_buckets.sh` | `$OUT_DIR/s3_buckets.log` |

---

## Phase 5: Surface

**Script:** `$SWARM_HOME/scripts/tools/phase-surface.sh`
**Agent:** `@surface` — `$SWARM_HOME/.swarm/agents/surface.md`
**Doc:** `$SWARM_HOME/docs/phases/surface.md`

### Sub-tool scripts called
None — pure shell text processing.

### External binaries invoked
- `cat`, `sort`, `grep`

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-surface.sh <domain> [output_dir]
```

### MCP calls (via @surface agent)
```python
get_deliverable(engagement_id, 'endpoint_map')
prioritize_endpoints(engagement_id, endpoints_json)
save_deliverable(engagement_id, 'endpoint_map', content, 'surface')
phase_gate_check(engagement_id, phase_completed=5)
```

### Scoring engine
`$SWARM_HOME/server/endpoint_priority.py:64-164` — 7-factor risk scoring

### What it does
Collects all URLs from 7 recon sources, deduplicates, classifies into Tier 0 (public+input), Tier 1 (auth+input), Tier 2 (infrastructure). Produces `surface/endpoint_map_ranked.txt`.

---

## Phase 6: Hunt

**Script:** `$SWARM_HOME/scripts/tools/phase-hunt.sh`
**Agent:** `@hunt` — `$SWARM_HOME/.swarm/agents/hunt.md`
**Sub-agents:** 56 `@hunt-*` agents + `@hunt-dispatch`
**Doc:** `$SWARM_HOME/docs/phases/hunt.md`

### Layer A — Sub-tool scripts called (via `nohup` in parallel)

| Script | Full Path |
|--------|-----------|
| param_extract.sh | `$SWARM_HOME/scripts/tools/param_extract.sh` |
| param-x8.sh | `$SWARM_HOME/scripts/tools/param-x8.sh` |
| secrets_hunter.sh | `$SWARM_HOME/scripts/tools/secrets_hunter.sh` |
| auto_secrets.sh | `$SWARM_HOME/scripts/tools/auto_secrets.sh` |
| vhost_fuzz.sh | `$SWARM_HOME/scripts/tools/vhost_fuzz.sh` |
| bypass_403.sh | `$SWARM_HOME/scripts/tools/bypass_403.sh` |

### External binaries invoked (by sub-tools)

| Binary | Called By |
|--------|-----------|
| `gf` | param_extract.sh |
| `x8` | param-x8.sh |
| `trufflehog` / `noseyparker` / `gitleaks` | secrets_hunter.sh |
| `curl` | auto_secrets.sh, bypass_403.sh |
| `ffuf` | vhost_fuzz.sh |
| `byp4xx` | bypass_403.sh (if installed) |

### Layer B — Batch test script
```bash
bash $SWARM_HOME/scripts/payloads/hunt.sh <engagement-id>
bash $SWARM_HOME/scripts/payloads/hunt.sh <engagement-id> --deep
```

### Command
```bash
# Standard — passive param extraction + secrets + vhost + 403
bash $SWARM_HOME/scripts/tools/phase-hunt.sh <domain> [output_dir]

# With active parameter discovery (slower)
bash $SWARM_HOME/scripts/tools/phase-hunt.sh <domain> --active-param

# Root-only mode
bash $SWARM_HOME/scripts/tools/phase-hunt.sh <domain> --root-only

# Skip specific checks
bash $SWARM_HOME/scripts/tools/phase-hunt.sh <domain> --skip vhost
```

### Wrapper expansion (Phase 6 — Hunt)

All 7 sub-tool calls use the same pattern:

**Replaced:** `run_bg "<name>" "<logfile>" "bash '<script>.sh' <args>"`
**Expanded:**
```bash
nohup bash -c "bash '<phase-script-dir>/<script>.sh' <args>" > "<logfile>" 2>&1 &
```

| Sub-tool | Arguments | Log file |
|----------|-----------|----------|
| `param_extract.sh` | `$TARGET` | `$HUNT_DIR/param_extract.log` |
| `param-x8.sh` | `-l $CRAWLED -o $OUT_DIR/params` | `$HUNT_DIR/param-x8.log` |
| `secrets_hunter.sh` | `--js-bundle $OUT_DIR` or `--filesystem $CRAWL_DIR` | `$HUNT_DIR/secrets_hunter.log` |
| `auto_secrets.sh` | `$TARGET` | `$HUNT_DIR/auto_secrets.log` |
| `vhost_fuzz.sh` | `$TARGET` | `$HUNT_DIR/vhost_fuzz.log` |
| `bypass_403.sh` | `$TARGET --quick` | `$HUNT_DIR/bypass_403.log` |

### Agent dispatch (@hunt-dispatch — 4 tiers)

**Tier 4 — Always-on agents (wapt mode, 56 agents):**
```
@hunt-xss  @hunt-sqli  @hunt-ssrf  @hunt-idor  @hunt-csrf  @hunt-xxe
@hunt-rce  @hunt-graphql  @hunt-oauth  @hunt-saml  @hunt-mfa-bypass
@hunt-auth-bypass  @hunt-ato  @hunt-file-upload  @hunt-business-logic
@hunt-race-condition  @hunt-llm-ai  @hunt-api-misconfig  @hunt-ssti
@hunt-cache-poison  @hunt-http-smuggling  @hunt-subdomain
@hunt-cloud-misconfig  @hunt-misc  @hunt-aspnet  @hunt-sharepoint
@hunt-ntlm-info  @hunt-lfi  @hunt-nosqli  @hunt-deserialization
@hunt-cors  @hunt-host-header  @hunt-open-redirect  @hunt-brute-force
@hunt-session  @hunt-ldap  @hunt-nextjs  @hunt-nodejs  @hunt-dom
@hunt-websocket  @hunt-grpc  @hunt-laravel  @hunt-soap  @hunt-springboot
@hunt-k8s  @hunt-cicd  @hunt-source-leak  @hunt-tls-network
@hunt-clickjacking  @hunt-crlf  @hunt-dependency-confusion
@hunt-http-param-pollution  @hunt-mass-assignment  @hunt-prototype-pollution
@hunt-jwt-confusion  @hunt-ssrf-cloud
```

### Standalone sub-tool commands
```bash
# OOB listener (start before blind testing)
bash $SWARM_HOME/scripts/tools/oob_listener.sh start

# Automated SQLi
bash $SWARM_HOME/scripts/tools/auto_sqli.sh <domain>

# Automated XSS
bash $SWARM_HOME/scripts/tools/auto_xss.sh <domain>

# AI-driven directory bruteforce
bash $SWARM_HOME/scripts/tools/dir_bruteforce.sh --url https://<domain> --intent api

# VHost fuzzing (standalone)
bash $SWARM_HOME/scripts/tools/vhost_fuzz.sh <domain>

# 403 bypass (standalone)
bash $SWARM_HOME/scripts/tools/bypass_403.sh <domain> --quick

# Stop OOB listener
bash $SWARM_HOME/scripts/tools/oob_listener.sh stop
```

### MCP calls (via @hunt agent)
```python
get_deliverable(engagement_id, 'endpoint_map')
get_witness_payloads(sink_context)
get_waf_bypass(waf_vendor, vuln_class, bypass_level)
validate_poc(engagement_id, command, expected_status, expected_match)
log_finding(engagement_id, test_id, title, severity, ...)
track_test(engagement_id, test_id, status, notes)
create_exploitation_queue(engagement_id, vuln_class, vulnerabilities)
findings_add_chain(engagement_id, name, steps)
phase_gate_check(engagement_id, phase_completed=6)
```

---

## Phase 7: Deepthink

**Script:** `$SWARM_HOME/scripts/tools/phase-deepthink.sh`
**Agent:** `@deepthink` — `$SWARM_HOME/.swarm/agents/deepthink.md`
**Doc:** `$SWARM_HOME/docs/phases/deepthink.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/findings.sh` — SQLite findings CLI

### External binaries invoked
- `python3` (embedded queries)
- `findings.sh` (bash CLI to SQLite)

### Command
```bash
# New signature (with engagement ID)
bash $SWARM_HOME/scripts/tools/phase-deepthink.sh <engagement_id> <domain> [output_dir]

# Old signature (no engagement ID)
bash $SWARM_HOME/scripts/tools/phase-deepthink.sh <domain> [output_dir]
```

### MCP calls (via @deepthink agent)
```python
read_agent_notes(engagement_id, agent_id='deepthink')
get_wstg_test(test_id)
get_waf_bypass(vendor, class)
search_wstg(query)
find_chains(engagement_id)
get_findings(engagement_id)
write_agent_notes(engagement_id, agent_id='deepthink', notes)
phase_gate_check(engagement_id, phase_completed=7)
```

### What it does
Conditional phase — only runs when HUNT yields zero findings or tools fail. Queries SQLite findings DB, compiles gap analysis context to `deepthink/gap_analysis.txt`.

---

## Phase 8: Exploit

**Script:** `$SWARM_HOME/scripts/tools/phase-exploit.sh`
**Agent:** `@exploit` — `$SWARM_HOME/.swarm/agents/exploit.md`
**Doc:** `$SWARM_HOME/docs/phases/exploit.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/findings.sh` — SQLite findings CLI

### External binaries invoked
- `python3` (embedded queries)

### Command
```bash
# New signature (with engagement ID)
bash $SWARM_HOME/scripts/tools/phase-exploit.sh <engagement_id> <domain> [output_dir]

# Old signature
bash $SWARM_HOME/scripts/tools/phase-exploit.sh <domain> [output_dir]
```

### MCP calls (via @exploit agent)
```python
findings_list_vulns(engagement_id)
get_witness_payloads(sink_context)
get_waf_bypass(vendor, vuln_class, bypass_level)
get_evidence_checklist(vuln_class)
validate_poc(engagement_id, command, ...)
update_finding(engagement_id, finding_id, severity, evidence, poc_output)
findings_add_chain(engagement_id, name, score, steps)
burp_generate_collaborator_payload()
burp_get_collaborator_interactions()
find_chains(engagement_id)
phase_gate_check(engagement_id, phase_completed=8)
```

### 5-Tier exploitation methodology
1. **Tier 1** — Confirm reflection/execution (witness payloads)
2. **Tier 2** — Demonstrate impact (data extraction, command execution)
3. **Tier 3** — OOB/Collaborator (blind findings)
4. **Tier 4** — WAF bypass escalation (basic→intermediate→advanced)
5. **Tier 5** — Cross-class chaining (e.g., XSS→session hijack, SSRF→IAM key theft)

---

## Phase 9: Search

**Script:** `$SWARM_HOME/scripts/tools/phase-search.sh`
**Agent:** `@search` — `$SWARM_HOME/.swarm/agents/search.md`
**Doc:** `$SWARM_HOME/docs/phases/search.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/findings.sh` — SQLite findings CLI

### External binaries invoked
- `python3` (embedded queries)

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-search.sh <domain> [output_dir]
# or
bash $SWARM_HOME/scripts/tools/phase-search.sh <engagement_id> <domain> [output_dir]
```

### MCP calls (via @search agent)
```python
search_wstg(query)
get_waf_bypass(vendor, vuln_class, bypass_level)
websearch(query)
webfetch(url)
validate_poc(engagement_id, command, ...)
```

### Research resources (4 tiers)
1. **Tier 1** — HackTricks, PayloadsAllTheThings, PortSwigger Academy
2. **Tier 2** — Exploit-DB, CISA KEV, NVD, Rapid7 DB
3. **Tier 3** — HackerOne Hacktivity, BugBoard, Bounty Radar
4. **Tier 4** — Payload Playground, PayloadForge, BypassBurrito

---

## Phase 10: Capture

**Script:** `$SWARM_HOME/scripts/tools/phase-capture.sh`
**Agent:** `@capture` + `@evidence-hygiene`
**Doc:** `$SWARM_HOME/docs/phases/capture.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/generate_poc_report.sh <engagement_id> all --domain <domain>`
- `$SWARM_HOME/scripts/findings.sh` (via embedded Python DB query)

### External binaries invoked
- `python3` (summary generation, DB queries)

### Command
```bash
# New signature (engagement_id + domain)
bash $SWARM_HOME/scripts/tools/phase-capture.sh <engagement_id> <domain> [output_dir]

# Old signature (domain only)
bash $SWARM_HOME/scripts/tools/phase-capture.sh <domain> [output_dir] [--engagement-id X]
```

### MCP calls (via @capture agent)
```python
findings_list_vulns(engagement_id)
browser_screenshot(engagement_id, agent_id, url, label)
browser_act(engagement_id, "close")
burp_get_collaborator_interactions()
```

### Output structure
```
<output_dir>/evidence/
├── SUMMARY.md
├── VERIFICATION.md
└── finding-<ref>-<slug>/
    ├── evidence.md
    ├── request.txt
    ├── collaborator.txt (if OOB)
    └── poc-report.md
```

---

## Phase 11: Validate

**Script:** `$SWARM_HOME/scripts/tools/phase-validate.sh`
**Agent:** `@validate` + `@triage-validation`
**Doc:** `$SWARM_HOME/docs/phases/validate.md`

### Sub-tool scripts called
None — pure shell text assembly.

### External binaries invoked
- `cat`, `find`

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-validate.sh <domain> [output_dir]
```

### MCP calls (via @validate agent)
```python
get_findings(engagement_id)
validate_poc(engagement_id, command, ...)
validate_finding_poc(engagement_id, finding_id)
update_finding(engagement_id, finding_id, severity, description)
generate_poc_report.sh <eid> <finding-id> --domain <domain>
```

### 7-Question Gate
```
Q1: Real HTTP request?
Q2: On accepted-impact list?
Q3: Asset in scope?
Q4: Without privileged access?
Q5: Not known behavior?
Q6: Provable impact?
Q7: Not on never-submit list?
```

### Never-submit list
Missing headers, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

---

## Phase 12: Report

**Script:** `$SWARM_HOME/scripts/tools/phase-report.sh`
**Agent:** `@report` + `@report-writing` / `@bugcrowd-reporting` / `@redteam-report-template`
**Doc:** `$SWARM_HOME/docs/phases/report.md`

### Sub-tool scripts called
- `$SWARM_HOME/scripts/findings.sh` — SQLite findings CLI

### External binaries invoked
- `cat`, `find`

### Command
```bash
bash $SWARM_HOME/scripts/tools/phase-report.sh <domain> [output_dir]
# or
bash $SWARM_HOME/scripts/tools/phase-report.sh <engagement_id> <domain> [output_dir]
```

### MCP calls (via @report agent)
```python
get_coverage()
get_tool_coverage()
phase_gate_check(engagement_id, phase_completed=12)
generate_report(engagement_id, target, tester, platform)
```

---

## Supporting Scripts

### Pipeline orchestrator
```bash
# Run all 12 phases
bash $SWARM_HOME/scripts/pipeline.sh <domain>

# Run phases 3-6
bash $SWARM_HOME/scripts/pipeline.sh <domain> 3-6

# Run single phase
bash $SWARM_HOME/scripts/pipeline.sh <domain> 4

# Resume from last checkpoint
bash $SWARM_HOME/scripts/pipeline.sh <domain> --resume

# Skip slow tools
SKIP_LIST=gospider,katana bash $SWARM_HOME/scripts/pipeline.sh <domain> 4

# Set per-phase timeout (seconds)
PIPELINE_TIMEOUT=1200 bash $SWARM_HOME/scripts/pipeline.sh <domain>
```

### Phase gate
```bash
bash $SWARM_HOME/scripts/tools/phase_gate.sh <phase-num> <domain>
```

### Environment validation
```bash
bash $SWARM_HOME/scripts/tools/validate-env.sh
```

### Findings database CLI
```bash
bash $SWARM_HOME/scripts/findings.sh init <engagement-id>
bash $SWARM_HOME/scripts/findings.sh add vuln <engagement-id> <title> --severity S
bash $SWARM_HOME/scripts/findings.sh list vulns <engagement-id>
bash $SWARM_HOME/scripts/findings.sh stats <engagement-id>
bash $SWARM_HOME/scripts/findings.sh export <engagement-id>
bash $SWARM_HOME/scripts/findings.sh handoff <engagement-id>
```

### Todo export
```bash
bash $SWARM_HOME/scripts/tools/todo-export.sh <domain>
```

### PoC report generator
```bash
bash $SWARM_HOME/scripts/generate_poc_report.sh <engagement-id> all --domain <domain>
bash $SWARM_HOME/scripts/generate_poc_report.sh <engagement-id> <finding-id> --domain <domain>
```

### Environment variables (pre-set)

| Variable | Purpose | Default |
|----------|---------|---------|
| `RECON_BASE` | Output directory base | `$SWARM_HOME/engagements/recon` |
| `SKIP_LIST` | Comma-separated tools to skip | *(empty)* |
| `PIPELINE_TIMEOUT` | Per-phase timeout (seconds) | *(none)* |
| `BBHUNT_COOKIE` | Pre-set session cookie | *(none)* |
| `BBHUNT_BEARER` | Pre-set bearer token | *(none)* |
| `BBHUNT_AUTH_HEADERS` | Pre-set auth headers | *(none)* |
| `ENGAGEMENT_ID` | Engagement ID for DB tracking | *(auto)* |

---

## Wrapper Expansion Reference

Complete audit of every wrapper function that has been removed from the project, along with its original definition and expansion.

### 1. `run_bg` — Background tool runner (removed)

**Was defined in:** `scripts/tools/_env.sh:85`
**Pattern:**
```bash
# Original:
run_bg <name> <logfile> <command>

# Equivalent expanded:
nohup bash -c "<command>" > "<logfile>" 2>&1 &
```
**Was used by:** `phase-auth.sh` (1 call), `phase-recon.sh` (5 calls + 7-module loop), `phase-hunt.sh` (7 calls) — all now expanded inline.

### 2. `run_scanner` — Python scanner with venv (removed)

**Was defined in:** `scripts/tools/_env.sh:161`
**Pattern:**
```bash
# Original:
run_scanner <tool_name> [args...]

# Equivalent expanded:
( source "$TOOLS_DIR/<tool>/venv/bin/activate" && python3 "$TOOLS_DIR/<tool>/<script>.py" [args...] )
```
**Supported tools:** sqlmap, commix, sstimap, corscanner, smuggler, msftrecon, Scopify, Spoofy, cloud_enum
**Note:** Never called from any script — all tools were invoked directly. Now removed.

### 3. `_run_tool` — Foreground nohup-piped runner (removed)

**Was defined in:** `scripts/tools/phase-intel.sh:34` (now removed)
**Pattern:**
```bash
# Original:
_run_tool <logfile> <command>

# Equivalent expanded:
<command> | tee -a "<logfile>"
```
**Was used by:** `phase-intel.sh` (1 call for whois) — now expanded inline.

### 4. `_run_tool_venv` — Foreground venv + nohup-piped runner (removed)

**Was defined in:** `scripts/tools/phase-intel.sh:43` (now removed)
**Pattern:**
```bash
# Original:
_run_tool_venv <logfile> <tool_name> <command>

# Equivalent expanded:
(
    source "<venv>/bin/activate"
    <command>
) > "<logfile>" 2>&1
```
**Was used by:** `phase-intel.sh` (4 calls: msftrecon, Scopify, Spoofy, cloud_enum) — now expanded inline.

### 5. `run_phase` — Phase script runner (removed)

**Was defined in:** `scripts/tools/auto_hunt.sh:53` (now removed), `scripts/pipeline.sh:106` (now inlined)
**Pattern:**
```bash
# Original:
run_phase <name> <script>

# Equivalent expanded:
bash "<script-path>" "$TARGET"
```
**Was used by:** `pipeline.sh` (1 call), `auto_hunt.sh` (4 calls) — all now expanded inline.

---

## Venv Tool Reference

Complete list of every tool in the project that depends on a Python virtual environment.

| # | Tool | Venv Path | Activation | Executable | Env Vars | `cd` | Used By |
|---|------|-----------|------------|------------|----------|------|---------|
| 1 | msftrecon | `$HOME/.local/bin/msftrecon/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../msftrecon/msftrecon.py -d $TARGET` | none | none | `phase-intel.sh` (formerly `_run_tool_venv`) |
| 2 | Scopify | `$HOME/.local/bin/Scopify/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../scopify.py -c $company` | none | none | `phase-intel.sh` (formerly `_run_tool_venv`) |
| 3 | Spoofy | `$HOME/.local/bin/Spoofy/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../spoofy.py -d $TARGET` | none | `$TOOLS_DIR/Spoofy` | `phase-intel.sh` (formerly `_run_tool_venv`) |
| 4 | cloud_enum | `$HOME/.local/bin/cloud_enum/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../cloud_enum.py -k $keyword -t 20` | `PYTHONWARNINGS=ignore` | none | `phase-intel.sh`, `s3_buckets.sh`, `cloud_recon.sh` |
| 5 | theHarvester | `$HOME/theHarvester/.venv/` | (direct binary) | `$venv/bin/theHarvester -d $TARGET -b $sources` | none | `$OSINT_DIR` | `phase-osint.sh` |
| 6 | waymore | `$REPO_DIR/tools/waymore/venv/` | (direct binary) | `$venv/bin/waymore -i $TARGET -mode U` | none | none | `web_waymore.sh` |
| 7 | Server Python | `$REPO_DIR/server/venv/` | `source "$venv/bin/activate"` | `$venv/bin/python3` (with `findings_db` module) | none | none | `findings.sh`, `handoff.sh`, `generate_poc_report.sh` |
| 8 | Swarm Python | `$REPO_DIR/.venv/` | `source "$venv/bin/activate"` | `$venv/bin/python` (with Playwright) | none | none | `auto_auth.py`, `browser_driver.py` |
| 9 | sqlmap | `$TOOLS_DIR/sqlmap/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../sqlmap.py [args]` | none | none | `auto_sqli.sh` (direct) |
| 10 | commix | `$TOOLS_DIR/commix/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../commix.py [args]` | none | none | (direct invocation) |
| 11 | sstimap | `$TOOLS_DIR/sstimap/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../sstimap.py [args]` | none | none | (direct invocation) |
| 12 | corscanner | `$TOOLS_DIR/corscanner/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../cors_scan.py [args]` | none | none | (direct invocation) |
| 13 | smuggler | `$TOOLS_DIR/smuggler/venv/` | `source "$venv/bin/activate"` | `python3 $venv/../smuggler.py [args]` | none | none | (direct invocation) |

### Example: Full venv expansion (cloud_enum in s3_buckets.sh)

```bash
# Original wrapper-free invocation (s3_buckets.sh:63-71):
env PYTHONWARNINGS=ignore "$TOOLS_DIR/cloud_enum/venv/bin/python" \
    "$TOOLS_DIR/cloud_enum/cloud_enum.py" \
    -k "$company_name" -k "$TARGET" -k "${TARGET%%.*}" \
    -t 20 -m "$mutations" -b "$brute" -qs \
    -f json -l "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null

# Equivalent with activate/deactivate:
(
    source "$TOOLS_DIR/cloud_enum/venv/bin/activate"
    PYTHONWARNINGS=ignore python3 "$TOOLS_DIR/cloud_enum/cloud_enum.py" \
        -k "$company_name" -k "$TARGET" -k "${TARGET%%.*}" \
        -t 20 -m "$mutations" -b "$brute" -qs \
        -f json -l "$CLOUD_DIR/cloud_enum_results.jsonl" 2>/dev/null
)
```

---

## Repository-Wide Tool Execution Inventory

Every script in `scripts/` and `scripts/tools/` and how it executes external tools.

| Script | Wrapper Calls | Direct Calls | Venv | Background | External Binaries |
|--------|-------------|-------------|------|------------|-------------------|
| `phase-orchestrator.sh` | 0 | 0 | 0 | 0 | `mkdir`, `echo`, `date` |
| `phase-scope.sh` | 0 | 0 | 0 | 0 | `curl`, `mkdir`, `date` |
| `phase-auth.sh` | 0 (replaced) | 0 | 0 | 1 (nohup &) | `curl` |
| `phase-intel.sh` | 0 (replaced) | 5 (whois, 4 venv) | **4** | 0 | `whois`, `python3`, `unfurl` |
| `phase-osint.sh` | 0 | 1 (theHarvester) | **1** | 0 | `theHarvester`, `python3` |
| `phase-recon.sh` | 0 (replaced) | 0 | 0 | **11** | (delegates to sub-tools) |
| `phase-surface.sh` | 0 | 0 | 0 | 0 | `cat`, `sort`, `grep` |
| `phase-hunt.sh` | 0 (replaced) | 0 | 0 | **7** | (delegates to sub-tools) |
| `phase-deepthink.sh` | 0 | `findings.sh` + `python3` | 0 | 0 | `python3` |
| `phase-exploit.sh` | 0 | `findings.sh` + `python3` | 0 | 0 | `python3` |
| `phase-search.sh` | 0 | `findings.sh` + `python3` | 0 | 0 | `python3` |
| `phase-capture.sh` | 0 | `generate_poc_report.sh` + `python3` | 0 | 0 | `python3` |
| `phase-validate.sh` | 0 | 0 | 0 | 0 | `cat`, `find` |
| `phase-report.sh` | 0 | `findings.sh` | 0 | 0 | `cat`, `find` |
| `auto_hunt.sh` | 0 (replaced) | 4 bash sub-scripts | 0 | 0 | (delegates) |
| `auto_xss.sh` | 0 | 2 | 0 | 0 | `dalfox`, `curl` |
| `auto_sqli.sh` | 0 | 2 | 0 | 0 | `sqlmap` (system pip) |
| `cloud_recon.sh` | 0 | 6 | **1** (cloud_enum) | 0 | `s3scanner`, `cloud_enum`, `cloudfail`, `curl`, `dig`, `python3` |
| `s3_buckets.sh` | 0 | 6 | **1** (cloud_enum venv) | 0 | `cloud_enum`, `s3scanner`, `trufflehog`, `jq` |
| `subdomain_enum.sh` | 0 | 5 | 0 | 0 | `subfinder`, `assetfinder`, `findomain`, `dnsx`, `httpx` |
| `dns_bruteforce.sh` | 0 | 1 | 0 | 0 | `puredns`/`massdns` |
| `web_gospider.sh` | 0 | 1 | 0 | 0 | `gospider` |
| `web_katana.sh` | 0 | 1 | 0 | 0 | `katana` |
| `web_waymore.sh` | 0 | 1 | **1** (waymore venv) | 0 | `waymore`, `uro` |
| `vhost_fuzz.sh` | 0 | 4 | 0 | 0 | `curl`, `parallel`, `ffuf`, `python3` |
| `bypass_403.sh` | 0 | 4 | 0 | 0 | `curl`, `byp4xx` |
| `param_extract.sh` | 0 | 1 | 0 | 0 | `gf` |
| `param-x8.sh` | 0 | 2 | 0 | 0 | `x8`, `python3` |
| `secrets_hunter.sh` | 0 | 5 | 0 | 0 | `trufflehog`, `noseyparker`, `gitleaks`, `curl` |
| `cariddi_scan.sh` | 0 | 2 | 0 | 0 | `cariddi` |
| `zone_transfer.sh` | 0 | 2 | 0 | 0 | `dig` |
| `github_dork.sh` | 0 | 2 | 0 | 0 | `gh` |
| `cicd_scanner.sh` | 0 | 1 | 0 | 0 | `sisakulint` |
| `takeover_scanner.sh` | 0 | 3 | 0 | 0 | `subjack`, `curl` |
| `vuln_scanner.sh` | 0 | 5+ | 0 | 0 | `curl`, `python3`, `dig` |
| `spray_orchestrator.sh` | 0 | 3 | 0 | 0 | `python3`, `trevorspray` |
| `oob_listener.sh` | 0 | 1 | 0 | **1** (&) | `interactsh-client` |
| `wordlist_engine.sh` | 0 | 2 | 0 | 0 | `cewler`, `hashcat` |
| `dir_bruteforce.sh` | 0 | 5+ | 0 | 0 | `ffuf`, `curl`, `python3` |
| `batch_subdomain_enum.sh` | 0 | 1 | 0 | **1** (&) | (delegates to subdomain_enum.sh) |
| `auto_secrets.sh` | 0 | 1 | 0 | 0 | `curl` |
| `extracturls.sh` | 0 | 2 | 0 | 0 | `httpx` |
| `breach_checker.py` | 0 | 0 (pure Python) | 0 | 0 | `urllib` (stdlib) |
| `token_scanner.py` | 0 | 0 (pure Python) | 0 | 0 | (none) |
| `zero_day_fuzzer.py` | 0 | many | 0 | 0 | `curl` (via subprocess) |
| `target_selector.py` | 0 | 2 | 0 | 0 | `curl` (via subprocess) |
| `findings.sh` | 0 | `$PYTHON` (venv-aware) | **1** (server venv) | 0 | `python3` |
| `handoff.sh` | 0 | `$PYTHON` (venv-aware) | **1** (server venv) | 0 | `python3` |
| `generate_poc_report.sh` | 0 | `$PYTHON` (venv-aware) | **1** (server venv) | 0 | `python3` |
| `pipeline.sh` | 0 | direct `bash` phase scripts | 0 | 0 | (delegates) |

**Note:** `run_scanner()` has been removed — all scripts call tools directly with venv activation.

---

## Full Phase Command Reference (Quick Copy)

```bash
# Phase 0: Orchestrator
bash $SWARM_HOME/scripts/tools/phase-orchestrator.sh <domain>

# Phase 1: Scope
bash $SWARM_HOME/scripts/tools/phase-scope.sh <domain>

# Phase 2: Auth
bash $SWARM_HOME/scripts/tools/phase-auth.sh <domain>

# Phase 3: Intel
bash $SWARM_HOME/scripts/tools/phase-intel.sh <domain>

# Phase 3b: OSINT (optional)
bash $SWARM_HOME/scripts/tools/phase-osint.sh <domain>

# Phase 4: Recon
bash $SWARM_HOME/scripts/tools/phase-recon.sh <domain>

# Phase 5: Surface
bash $SWARM_HOME/scripts/tools/phase-surface.sh <domain>

# Phase 6: Hunt
bash $SWARM_HOME/scripts/tools/phase-hunt.sh <domain>

# Phase 7: Deepthink
bash $SWARM_HOME/scripts/tools/phase-deepthink.sh <engagement_id> <domain>

# Phase 8: Exploit
bash $SWARM_HOME/scripts/tools/phase-exploit.sh <engagement_id> <domain>

# Phase 9: Search
bash $SWARM_HOME/scripts/tools/phase-search.sh <engagement_id> <domain>

# Phase 10: Capture
bash $SWARM_HOME/scripts/tools/phase-capture.sh <engagement_id> <domain>

# Phase 11: Validate
bash $SWARM_HOME/scripts/tools/phase-validate.sh <domain>

# Phase 12: Report
bash $SWARM_HOME/scripts/tools/phase-report.sh <engagement_id> <domain>
```
