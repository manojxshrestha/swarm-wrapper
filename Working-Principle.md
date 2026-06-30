# Swarm Working Principle

## Overview

Swarm runs 13 phases (0-12, with Phase 2b as an optional browser auth sub-phase) sequentially as standalone bash scripts under `scripts/tools/`. Each phase is invoked directly:

```bash
bash $HOME/swarm/scripts/tools/phase-<name>.sh target.com
```

No central orchestrator required. Each phase reads the output directory created by previous phases. The output base is `engagements/recon/<domain>/` (controlled by `$RECON_BASE`).

An optional orchestrator exists at `scripts/pipeline.sh` that runs phases sequentially with checkpoint/resume/skip support. Phase definitions (0-12, plus Phase 2b) are in `scripts/tools/_phase_defs.sh`.

---

## Common Environment (`scripts/tools/_env.sh`)

Sourced by every phase script. Provides:

- **Paths:** `SWARM_ROOT`, `RECON_BASE`, `TOOLS_DIR` (`$HOME/.local/bin`), `GO_BIN`
- **Logging:** `log_ok`, `log_err`, `log_warn`, `log_info`, `log_step`
- **Tool checks:** `_have <command>` — returns 0 if command exists
- **Skip support:** `_skip_check <name>` — returns 0 if tool name is in `$SKIP_LIST`
- **Platform detection:** WSL, Kali, Parrot, Debian, macOS auto-detection
- **Venv paths:** Python tools installed via `install.sh` live at `$HOME/.local/bin/<tool>/venv/`

Also sourced by `pipeline.sh`:

- **`scripts/tools/_phase_defs.sh`** — Defines the 12-phase array: names, descriptions, order
- **`scripts/findings.sh`** — SQLite findings database CLI: `init`, `add vuln`, `add host`, `list`, `stats`, `export`, `handoff`
- **`scripts/tools/phase_gate.sh`** — Quality gate called after each phase; enforces pipeline ordering and Phase 6 coverage threshold (≥90% agent dispatch)
- **`scripts/tools/validate-env.sh`** — Pre-flight check: verifies repo root, core tools, RECON_BASE, PATH
- **`scripts/tools/todo-export.sh`** — Exports completed phases from checkpoint file as JSON for AI todowrite integration

---

## Phase 0 — Orchestrator (`scripts/tools/phase-orchestrator.sh`)

**What it does:**
- Creates the full output directory scaffold
- Writes target.txt, scope.txt, started.txt metadata

**Commands it runs:**
```bash
mkdir -p "$OUT_DIR"/{scope,intel,recon,crawl,subdomains,secrets,directories,vhost,evidence,screenshots}
echo "$TARGET" > "$OUT_DIR/scope/target.txt"
: > "$OUT_DIR/scope/scope.txt"
date -I > "$OUT_DIR/scope/started.txt"
```

**Output:** `engagements/recon/<domain>/` scaffold directories + `scope/target.txt`, `scope/started.txt`

---

## Phase 1 — Scope (`scripts/tools/phase-scope.sh`)

**What it does:**
- Creates the output directory scaffold (same as Phase 0)
- Writes target.txt and started.txt
- Checks HTTPS connectivity via curl

**Commands it runs:**
```bash
mkdir -p "$OUT_DIR"/{scope,intel,recon,crawl,subdomains,secrets,directories,vhost,evidence,screenshots}
echo "$TARGET" > "$OUT_DIR/scope/target.txt"
date -I > "$OUT_DIR/scope/started.txt"
curl -sI "https://$TARGET" --connect-timeout 5
```

**Output:** `engagements/recon/<domain>/` scaffold directories

---

## Phase 2 — WAF Detection (`scripts/tools/phase-auth.sh`)

**What it does:**
- WAF fingerprinting via curl response headers (detects CloudFront, Cloudflare, Akamai, ModSecurity, Istio/Envoy, etc.)
- Captures full response headers for analysis
- Launches basic `auto_auth.py` in background as a lightweight auth attempt (signup → verify → login)
- Skips auto-auth if `BBHUNT_AUTH_HEADERS`, `BBHUNT_COOKIE`, `BBHUNT_BEARER` env vars are set, or if `auth/session.json` already exists
- **For full browser-based auth (OAuth, SSO, MFA, SPA login) → see Phase 2b below**

**Commands it runs:**
```bash
curl -sI "https://$TARGET" 2>&1 | grep -iE "server:|cf-ray|x-sucuri|x-iinfo|x-mod-security|x-waf|cloudflare|akamai|fastly" || true
curl -sI "https://$TARGET" 2>&1
nohup bash -c "python3 'auto_auth.py' '$TARGET' --output-dir '$OUT_DIR'" > auto_auth.log 2>&1 &
```

**Output:**
- `auth/waf_detection.txt` — WAF headers + full response headers
- `auth/auto_auth.log` — basic auth attempt log (if launched)
- `auth/session.json` — cookies/session from basic auto-auth (if successful)

---

## Phase 2b — Browser Auth (`@browser-auth` agent)

**What it does:**
- Browser-based authentication for flows that cannot be completed via simple API calls
- Form login, OAuth/SSO (Google, GitHub), SAML, auto signup, MFA (TOTP, email OTP)
- Anti-bot bypass for SPA/CAPTCHA/Cloudflare challenge pages
- Captures cookies, JWT tokens, localStorage for downstream phases

**How it works (no bash script — AI-driven via MCP browser tools):**
- Consumes `auth_analysis` deliverable from `@analyze` agent (auth mechanism classification)
- Auth methods, in priority order:

| Method | When | Credentials? |
|--------|------|-------------|
| `browser_login()` | Standard form login with known credentials | Yes |
| `browser_analyze()` + `browser_act()` loop | SPA/CSP/anti-bot pages where auto-detection fails | Yes |
| `browser_auto_auth()` | Autonomous signup → verify email → login | No (auto-generates via Guerrilla Mail) |
| Cookie/token injection | Have tokens from another source | No |

- Session verification: navigates to a protected endpoint after login
- Falls back with `captcha` status if CAPTCHA/SMS blocks automation

**Output:**
- `auth/session.json` — captured cookies and JWT tokens
- `auth/auth_storage.json` — localStorage/sessionStorage contents
- Browser screenshots as evidence (via `browser_screenshot`)

**When it runs:** Between Phase 2 (WAF detection) and Phase 3 (Intel), only if the target requires authenticated testing.

**References:**
- `docs/phases/browser-auth.md` — Phase 2b methodology
- `skills/browser-auth/SKILL.md` — Full browser auth methodology
- `.opencode/agents/browser-auth.md` — Agent orchestration prompt
- `prompts/browser-auth.md` — Subagent prompt

---

## Phase 3 — Passive Intel (`scripts/tools/phase-intel.sh`)

**What it does:**
- WHOIS lookup on the domain
- M365/Azure tenant discovery via msftrecon (venv subshell)
- Scope analysis via Scopify (venv subshell, requires unfurl)
- SPF/DMARC spoofability check via Spoofy (venv subshell)
- Cloud storage bucket enumeration via cloud_enum (venv subshell) — checks AWS S3, Azure Blob, GCP, DO Spaces

**Commands it runs:**
```bash
whois "$TARGET" 2>/dev/null | tee -a "$INTEL_DIR/domain_info_general.txt"
(source "$HOME/.local/bin/msftrecon/venv/bin/activate"; python3 "$TOOLS_DIR/msftrecon/msftrecon/msftrecon.py" -d "$TARGET")
(source "$HOME/.local/bin/Scopify/venv/bin/activate"; python3 "$TOOLS_DIR/Scopify/scopify.py" -c "$company_name")
(source "$HOME/.local/bin/Spoofy/venv/bin/activate"; cd "$TOOLS_DIR/Spoofy"; python3 "$TOOLS_DIR/Spoofy/spoofy.py" -d "$TARGET")
(source "$HOME/.local/bin/cloud_enum/venv/bin/activate"; PYTHONWARNINGS=ignore python3 "$TOOLS_DIR/cloud_enum/cloud_enum.py" -k "$company_name" -k "$TARGET" -k "${TARGET%%.*}" -t 50 -m "$mutations" -b "$brute" -qs 2>/dev/null) | anew -q "$INTEL_DIR/cloud_enum.txt"
```

**Output:**
- `intel/domain_info_general.txt` — WHOIS + msftrecon output
- `intel/azure_tenant_domains.txt` — Microsoft/Azure-related findings
- `intel/scopify.txt` — Scopify scope analysis
- `intel/spoof.txt` — SPF/DMARC spoofability report
- `intel/cloud_enum.txt` — Discovered cloud storage buckets

---

## Phase 3b — OSINT (optional) (`scripts/tools/phase-osint.sh`)

**What it does:**
- Email and subdomain enumeration via theHarvester (20+ search sources)
- Subdomain sources: crtsh, rapiddns, hackertarget, otx, urlscan, dnsdumpster, certspotter, bufferoverun, threatcrowd, virustotal, waybackarchive, commoncrawl, securityTrails, chaos, fullhunt, projectdiscovery, robtex
- Email sources: yahoo, duckduckgo, hunter, intelx, haveibeenpwned, hudsonrock, leakix, leaklookup, mojeek, tomba
- Extracts unique subdomains and emails from theHarvester JSON output

**Commands it runs:**
```bash
# Subdomain enumeration
"$HARVESTER_DIR/.venv/bin/theHarvester" -d "$TARGET" -b "crtsh,rapiddns,..." -n -r -f "theharvester_subdomains"

# Email enumeration
"$HARVESTER_DIR/.venv/bin/theHarvester" -d "$TARGET" -b "yahoo,duckduckgo,hunter,..." -n -r -f "theharvester_emails"

# Extract from JSON
python3 -c "import json; items = json.load(open('theharvester_subdomains.json'))['hosts']; ..."
python3 -c "import json; items = json.load(open('theharvester_emails.json'))['emails']; ..."
```

**Output:**
- `osint/theharvester_subdomains.json` — Raw theHarvester JSON (subdomain sources)
- `osint/theharvester_emails.json` — Raw theHarvester JSON (email sources)
- `osint/subdomains.txt` — Extracted unique subdomains
- `osint/emails.txt` — Extracted unique emails

---

## Phase 4 — Reconnaissance (`scripts/tools/phase-recon.sh`)

**Dependency chain:** subdomain_enum ─WAIT→ crawlers (parallel) ─WAIT→ merge ─→ modules (parallel) ─WAIT→ done

All jobs use `nohup` to survive session timeout; all stages use `wait` on captured PIDs to enforce ordering with zero polling.

### Sub-phase 4a: Subdomain Enumeration (`scripts/tools/subdomain_enum.sh`)

**What it does:**
- Passive subdomain discovery via subfinder + assetfinder + findomain
- DNS resolution via dnsx
- Live host probing via httpx (status code, title, tech detection, web server)
- **Runs sequentially** — crawlers depend on its output

**Commands it runs:**
```bash
subfinder -d "$TARGET" -all -silent | sort -u
assetfinder --subs-only "$TARGET" | sort -u
findomain -t "$TARGET" -q | sort -u
dnsx -l all_subdomains.txt -silent | sort -u
httpx -l resolved.txt -ports 80,443 -status-code -title -tech-detect -web-server -content-length -threads 100 -silent -o live_domains.txt
awk '{print $1}' live_domains.txt | sort -u > live_urls.txt
awk -F/ '{print $3}' live_urls.txt | cut -d: -f1 | sort -u > alive-domains.txt
grep "^https://" live_urls.txt > https-subs.txt
```

**Output (in `subdomains/`):**
- `all_subdomains.txt` — all unique subdomains from passive sources
- `live_domains.txt` — httpx raw output (status, tech, title, server)
- `live_urls.txt` — live HTTPS URLs (protocol+host)
- `alive-domains.txt` — clean domain names (resolved + alive)
- `https-subs.txt` — HTTPS-only URLs for downstream tools
- `subdomain_enum.log` — full run log

### Sub-phase 4b: Web Crawling (3 parallel, nohup + wait)

**gospider** (`scripts/tools/web_gospider.sh`):
```bash
gospider -S https-subs.txt -o gooutput -c 10 -d 3 -t 20 2>/dev/null || true
find gooutput -type f -exec cat {} + | grep -Eo 'https?://[^ ]+' | grep -i "$TARGET" | grep -viE "(woff|png|jpg|jpeg|gif|ico|bmp|webp|map)" | sort -u > alivesubsurls.txt
```

**katana** (`scripts/tools/web_katana.sh`):
```bash
katana -u https-subs.txt -d 5 -kf -jc -fx -ef woff,woff2,ttf,eot,otf,png,svg,jpg,jpeg,gif,ico,bmp,webp,mp4,mp3,pdf,css -o cleansubskatanaurls.txt
```

**waymore** (`scripts/tools/web_waymore.sh`):
```bash
waymore -i "$TARGET" -mode U -oU waygauurls.txt
```

All three launch in parallel via `nohup`. The orchestrator waits for **all three PIDs** to finish before proceeding — no polling loop, no partial data risk. Each crawler has a configurable timeout (`CRAWL_TIMEOUT`, default 300s); if exceeded, the process is killed and the script continues.

**Output (in `crawl/`):**
- `gooutput/` — gospider raw output directory
- `gospider.log`, `katana.log`, `waymore.log` — run logs

### Merge + Fallback (sequential, after crawlers finish)

```bash
find "$CRAWL_DIR/gooutput" -type f 2>/dev/null -exec cat {} + | \
  grep -hoE 'https?://[^"<> ]+' | sort -u > "$CRAWL_DIR/merged-crawl.txt"
```

The merge runs **only after** sub-phase 4b's `wait` completes, guaranteeing all crawl output is written before reading. No polling needed. If merge produces empty output, the root domain URL is written as fallback.

**Output:**
- `crawl/merged-crawl.txt` — merged URLs from all crawlers
- `crawl/crawledurls.txt` — final URL list (always populated, even if fallback to root domain)

### Sub-phase 4c: Recon Modules (7 parallel, nohup + wait)

```bash
for module in dns_bruteforce param_extract cariddi_scan vhost_fuzz zone_transfer github_dork s3_buckets; do
  nohup bash -c "bash '$SCRIPT_DIR/${module}.sh' '$TARGET'" > "${module}.log" 2>&1 &
done
```

All seven launch in parallel. The orchestrator waits for **every PID** before printing "Phase 4 complete" — no orphan background processes, no race conditions with Phase 5.

Each module:

**`dns_bruteforce.sh` — DNS brute-force enumeration**
```bash
puredns resolve all_subdomains.txt -r resolvers.txt | sort -u > resolved.txt
puredns bruteforce wordlist.txt "$TARGET" | sort -u >> all_subdomains.txt
```
Probes thousands of DNS names via puredns + massdns with curated wordlists.

**`param_extract.sh` — GF-pattern parameter extraction**
```bash
cat crawledurls.txt | grep -E '\?' | sort -u > paramurls.txt
cat paramurls.txt | gf xss > gf_xss.txt
cat paramurls.txt | gf sqli > gf_sqli.txt
cat paramurls.txt | gf ssrf > gf_ssrf.txt
cat paramurls.txt | gf ssti > gf_ssti.txt
cat paramurls.txt | gf idor > gf_idor.txt
cat paramurls.txt | gf lfi > gf_lfi.txt
cat paramurls.txt | gf redirect > gf_redirect.txt
cat paramurls.txt | gf rce > gf_rce.txt
```
Filters crawled URLs through GF patterns to find potential vulnerability vectors.

**`cariddi_scan.sh` — Automated scanning (two-pass)**
```bash
# Pass 1: Full intensive
cat alive-domains.txt | cariddi -intensive -s -info -e -err -ext 1 -c 30 -d 1 -plain -oh pass1 -ot pass1
# Pass 2: High-value paths (.env, .git, config, wp-config, backup.sql, etc.)
cat alive-domains.txt | cariddi -intensive -e -ef high-value-paths.txt -c 30 -d 1 -plain -ot pass2
```
Scans for secrets, info disclosure, endpoints, errors, and juicy files across two passes.

**`vhost_fuzz.sh` — Virtual host fuzzing**
```bash
ffuf -w wordlist.txt -H "Host: FUZZ.$TARGET" -u "$base_url" -ac -t 50 -o vhost_results.json
```
Discovers hidden virtual hosts that respond to the right Host header but have no DNS record.

**`zone_transfer.sh` — DNS zone transfer (AXFR) check**
```bash
dig ns "$TARGET" | awk '{print $5}' | dig axfr "$TARGET" @"$ns"
```
Enumerates NS records and attempts full zone transfer against each nameserver.

**`github_dork.sh` — GitHub dorking**
```bash
gh search code "org:$TARGET password" --limit 100
gh search code "org:$TARGET secret" --limit 100
gh search code "org:$TARGET api_key" --limit 100
```
Searches GitHub via gh CLI for exposed secrets, credentials, and API keys.

**`s3_buckets.sh` — S3 / cloud bucket scanner**
```bash
# cloud_enum on discovered subdomains
python3 cloud_enum.py -k "$company" -k "$domain" -t 50 -qs
# s3scanner on subdomain list
s3scanner -bucket-file subdomains.txt | grep -v "not found"
# trufflehog on public buckets
trufflehog s3 --bucket="$bucket" --only-verified
```
Scans for open cloud storage buckets (AWS S3, Azure Blob, GCP, DO Spaces) and validates findings.

**Output:** `*.log` files in `engagements/recon/<domain>/` directory

---

## Phase 5 — Surface Analysis (`scripts/tools/phase-surface.sh`)

**What it does:**
- Collects ALL discovered URLs from Phase 4 crawl/subdomain output
- Classifies URLs into 3 tiers by path patterns
- Produces a ranked endpoint map for prioritization

**Commands it runs:**
```bash
# Collect from all crawl sources
for src in merged-crawl.txt live_urls.txt crawledurls.txt cleansubskatanaurls.txt waygauurls.txt alivesubsurls.txt; do
  cat "$src" >> all_urls.txt 2>/dev/null || true
done
sort -u all_urls.txt -o all_urls.txt

# Classify by tier based on path patterns
case "$url" in
  *login*|*signin*|*auth*|*oauth*|*saml*|*logout*|*register*|*signup*)  -> tier1_auth_input.txt
  *admin*|*api*|*graphql*|*swagger*|*v1/*|*v2/*|*rest/*)               -> tier1_auth_input.txt
  *.js|*.json|*.xml|*.yaml|*.conf|*.bak|*.old|*robots.txt|*sitemap.xml|*.git/*|*.env*) -> tier0_public_input.txt
  *)                                                                     -> tier2_infra.txt
esac
```

**Output (in `surface/`):**
- `all_urls.txt` — deduplicated collection of all discovered URLs
- `tier0_public_input.txt` — JS, JSON, XML, .env, .git, config files (test first)
- `tier1_auth_input.txt` — login, admin, API, GraphQL endpoints (auth + input)
- `tier2_infra.txt` — everything else (infrastructure / info)
- `endpoint_map_ranked.txt` — ranked summary with counts per tier

---

## Phase 6 — Vulnerability Hunting (`scripts/tools/phase-hunt.sh`)

**What it does:**
Part A — Bash tool scanning (runs automated scanners via nohup)
Part B — AI agent dispatch (generates dispatch list for 48+ hunt agents)

### Part A: Automated Scanning

**1. Parameter extraction:**
```bash
nohup bash -c "bash '$SCRIPT_DIR/param_extract.sh' '$TARGET'" > hunt/param_extract.log 2>&1 &
```

**2. Active parameter discovery (conditional, requires `--active-param`):**
```bash
nohup bash -c "bash '$SCRIPT_DIR/param-x8.sh' -l 'crawl/crawledurls.txt' -o '${OUT_DIR}/params'" > hunt/param-x8.log 2>&1 &
```

**3. Secrets hunting (on JS bundles or crawl filesystem):**
```bash
nohup bash -c "bash '$SCRIPT_DIR/secrets_hunter.sh' --js-bundle '$OUT_DIR'" > hunt/secrets_hunter.log 2>&1 &
# or
nohup bash -c "bash '$SCRIPT_DIR/secrets_hunter.sh' --filesystem '$CRAWL_DIR'" > hunt/secrets_hunter.log 2>&1 &
nohup bash -c "bash '$SCRIPT_DIR/auto_secrets.sh' '$TARGET'" > hunt/auto_secrets.log 2>&1 &
```

**4. Vhost fuzzing:**
```bash
nohup bash -c "bash '$SCRIPT_DIR/vhost_fuzz.sh' '$TARGET'" > hunt/vhost_fuzz.log 2>&1 &
```

**5. 403 bypass:**
```bash
nohup bash -c "bash '$SCRIPT_DIR/bypass_403.sh' '$TARGET' --quick" > hunt/bypass_403.log 2>&1 &
```

**Output:** `hunt/*.log` files, `params/gf_*.txt`, `secrets/`, `vhost/`

### Part B: AI Agent Dispatch

**What it does:**
- Reads `agents/registry.yaml` for all available hunt agents
- Filters by target tech stack (optional `--tech` flag)
- Generates dispatch list + coverage matrix for AI to consume

**Commands it runs:**
```bash
bash $HOME/swarm/scripts/dispatch_hunt.sh target.com --tech nextjs,wordpress,cloudfront,istio,aws
```

**Output (in `hunt/`):**
- `dispatch_list.json` — ordered list of 48+ hunt agents to dispatch
- `coverage_matrix.csv` — tracking CSV with agent category, priority, status
- `dispatch_hunt.log` — run log

### Part B Execution (AI Action)

The AI agent must iterate over `dispatch_list.json` and dispatch each hunt agent:
```
task(subagent_type="hunt-xss", ...)
task(subagent_type="hunt-sqli", ...)
task(subagent_type="hunt-ssrf", ...)
task(subagent_type="hunt-ssti", ...)
# ... 48 agents total
```

Each hunt agent:
1. Loads the WSTG test methodology for its bug class
2. Sends payloads via Burp/browser/cURL
3. Runs `validate_poc()` to confirm findings
4. Logs findings to the SQLite findings database via `findings_add_vuln()`
5. Marks coverage status in `coverage_matrix.csv`

---

## Phase 7 — DeepThink (conditional) (`scripts/tools/phase-deepthink.sh`)

**What it does:**
- Runs only if Phase 6 produced zero findings (gap analysis)
- Queries the SQLite findings database for stats
- Collects endpoint map and coverage gaps
- Prepares context for the @deepthink AI agent

**Commands it runs:**
```bash
$FINDINGS_CLI stats "$ENGAGEMENT_ID"  # query SQLite DB
$FINDINGS_CLI list vulns "$ENGAGEMENT_ID"
$FINDINGS_CLI list hosts "$ENGAGEMENT_ID"
```

**Output:** `deepthink/gap_analysis.txt`

---

## Phase 8 — Exploitation (`scripts/tools/phase-exploit.sh`)

**What it does:**
- Compiles all findings from the SQLite database
- Prepares context for the @exploit AI agent
- Structures findings for 5-tier exploitation methodology

**Commands it runs:**
```bash
$FINDINGS_CLI stats "$ENGAGEMENT_ID"
$FINDINGS_CLI list vulns "$ENGAGEMENT_ID"
```

**Output:** `exploit/all_findings.txt`

---

## Phase 9 — Search (conditional) (`scripts/tools/phase-search.sh`)

**What it does:**
- Runs only when exploitation stalls (blocked findings, WAF bypass needed)
- Queries the SQLite findings database for blocked/potential findings
- Prepares research context for the @search AI agent (payloads, CVEs, bypasses)

**Commands it runs:**
```bash
$FINDINGS_CLI list vulns "$ENGAGEMENT_ID" | python3 -c "import json,sys; data=json.load(sys.stdin); blocked=[v for v in data if v.get('status') in ('potential','blocked','open')]; ..."
```

**Output:** `search/research_context.txt`

---

## Phase 10 — Evidence Capture (`scripts/tools/phase-capture.sh`)

**What it does:**
- Reads all findings from the SQLite database
- Generates evidence directory structure per finding
- Writes SUMMARY.md and VERIFICATION.md

**Commands it runs:**
```bash
bash $HOME/swarm/scripts/generate_poc_report.sh "$ENGAGEMENT_ID" all --domain "$TARGET"
# Inline Python: reads SQLite DB, generates SUMMARY.md
```

**Output:** `evidence/finding-<ref>-<slug>/evidence.md`, `request.txt`, `poc-report.md`, `SUMMARY.md`, `VERIFICATION.md`

---

## Phase 11 — Validation (`scripts/tools/phase-validate.sh`)

**What it does:**
- Collects findings from all subdirectories
- Writes the 7-Question Gate reference for the @validate AI agent

**Commands it runs:**
```bash
for dir in secrets sqli xss params directories; do
  for f in "$OUT_DIR/$dir"/*.txt; do head -5 "$f"; done
done
```

**Output:** `validate/findings_for_validation.txt`

---

## Phase 12 — Report (`scripts/tools/phase-report.sh`)

**What it does:**
- Queries the SQLite findings database for all stats
- Compiles scope, findings, and validation into report context

**Commands it runs:**
```bash
$FINDINGS_CLI stats "$ENGAGEMENT_ID"
$FINDINGS_CLI list vulns "$ENGAGEMENT_ID"
```

**Output:** `report/report_context.txt`

---

## Data Flow Diagram

```
Phase 0/1 (Scope)   ──>   scaffold directories + target.txt
       │
Phase 2 (Auth)      ──>   waf_detection.txt + session.json (if auth succeeds)
       │
Phase 3 (Intel)     ──>   WHOIS, SPF/DMARC, cloud buckets, Azure tenant info
       │
Phase 4 (Recon)     ──>   subdomains (all/ alive/ live/ https-subs)
       │                   crawled URLs (merged-crawl, crawledurls)
       │                   7+ background modules (*.log)
       │
Phase 5 (Surface)   ──>   classified endpoint map (Tier 0/1/2)
       │
Phase 6 (Hunt)      ──>   Part A: tool scans -> params/ secrets/ vhost/
       │                   Part B: 48 AI agents -> findings in SQLite DB
       │
Phase 7 (DeepThink) ──>   (conditional) gap analysis if hunt found nothing
       │
Phase 8 (Exploit)   ──>   deepen findings -> chain -> escalate
       │
Phase 9 (Search)    ──>   (conditional) payload/CVE research
       │
Phase 10 (Capture)  ──>   evidence/ per-finding directories
       │
Phase 11 (Validate) ──>   7-Question Gate on each finding
       │
Phase 12 (Report)   ──>   final report context
```

## Key Conventions

- **Output base:** `$RECON_BASE` = `$SWARM_ROOT/engagements/recon/<domain>/`
- **Findings database:** `server/data/findings.db` (SQLite), managed via `scripts/findings.sh` CLI
- **Venv tools:** All Python tools use isolated venvs at `$HOME/.local/bin/<tool>/venv/`, activated via `()` subshells
- **Background execution:** All long-running tools use `nohup bash -c "bash 'script.sh' '$TARGET'" > log 2>&1 &`
- **Skip support:** Any sub-tool can be skipped via `SKIP_LIST=tool1,tool2 bash $HOME/swarm/scripts/tools/phase-<name>.sh`
- **Graceful degradation:** Missing input files never cause hard failures — tools fall back to root domain or skip gracefully

## Supporting Scripts

| Script | Purpose |
|--------|---------|
| `scripts/pipeline.sh` | Optional 12-phase orchestrator with checkpoint/resume/skip |
| `scripts/tools/_phase_defs.sh` | Phase 0-12 definitions (names, descriptions, order) |
| `scripts/tools/phase_gate.sh` | Post-phase quality gate (Phase 6 coverage ≥90%) |
| `scripts/tools/validate-env.sh` | Pre-flight environment validation (repo root, tools, PATH) |
| `scripts/tools/todo-export.sh` | Export completed phases as JSON for AI todo tracking |
| `scripts/findings.sh` | SQLite findings database CLI (init, add, list, stats, export, handoff) |
| `scripts/generate_poc_report.sh` | Generate evidence.md/request.txt/poc-report.md per finding |
| `scripts/dispatch_hunt.sh` | Generate Phase 6 AI agent dispatch list + coverage matrix |
| `scripts/coverage_matrix.sh` | Update coverage matrix from hunt agent output |
| `scripts/handoff.sh` | Generate session handoff report for resume between sessions |
| `scripts/auto_hunt.sh` | Legacy quick-start script: runs phase-recon + auto_xss + auto_sqli + auto_secrets |
| `scripts/tools/extracturls.sh` | Extract scoped URLs from gospider output folder + httpx probe |

## Pipeline Orchestration (optional)

For automated multi-phase runs, `scripts/pipeline.sh` provides:

```bash
bash $HOME/swarm/scripts/pipeline.sh target.com          # Run all 12 phases
bash $HOME/swarm/scripts/pipeline.sh target.com 1-4      # Run phases 1-4
bash $HOME/swarm/scripts/pipeline.sh target.com 3        # Run phase 3 only
SKIP_LIST=tool1,tool2 bash $HOME/swarm/scripts/pipeline.sh target.com 4
bash $HOME/swarm/scripts/pipeline.sh target.com --resume # Skip completed phases
```

Pipeline features: checkpoint file (`.pipeline_checkpoint`), phase gating, skip list, resume support, atomic checkpoint writes, and per-phase timeout.
