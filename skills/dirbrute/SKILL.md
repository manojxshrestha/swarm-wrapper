---
name: dirbrute
description: AI-driven directory bruteforcing — NOT an auto-scanner. Uses ffuf with intent-based wordlist selection (api, wordpress, java, oauth, iis, full), profiles with request budgets (light 5K, standard 50K, deep 150K), extension targeting, robots.txt parsing, response fingerprinting, and structured evidence output. The AI decides which hosts to scan, which intent to use, and when to stop. NO parallel bruteforcing, NO recursion, NO mega-wordlists.
sources: ffuf, dirbust_common
---

# DIRBRUTE — AI-Driven Directory Bruteforcing

## Pipeline Integration

Dirbrute is a **Recon & Surface Mapping** tool. It fits into two phases of the Swarm 12-phase pipeline:

### Phase 4 — Recon (Primary)

After subdomain enumeration, live host discovery, and URL crawling, the AI uses dirbrute to find **hidden paths not discovered by crawlers**. This fills gaps in the endpoint map before surface analysis.

**When to use in Phase 4:**
- A live host has a web server but crawl only found top-level pages
- Tech fingerprinting revealed a specific framework (IIS, WordPress, Java) — use the matching intent
- You need to find admin panels, API endpoints, config files, or backup archives

**What feeds into Phase 4:**
- Tech fingerprint from httpx (headers, status codes, SSL cert)
- Live host list from Phase 4 subdomain/recon

### Phase 5 — Surface Analysis (Secondary)

After initial recon, if a host scores highly in the attack surface ranking but the endpoint map is thin, the AI runs deeper dirbrute scans (standard/deep profile, with extension targeting) to discover more surface.

**When to use in Phase 5:**
- Host has high priority score but <10 endpoints known
- Need extension probing for specific tech (e.g., .aspx for IIS, .jsp for Java)
- `critical_exposure.txt` from Phase 4 scan had hits that need follow-up

### Phase 6 — Hunt (Tertiary)

During hunting, if a specific vulnerability class needs path discovery (e.g., finding upload endpoints for file upload testing, or actuator paths for Spring Boot), dirbrute is called on-demand by the hunt agent via `task(subagent_type="dirbrute")`.

---

## Core Philosophy

**The AI decides, not the pipeline.** This is NOT an auto-scan-everything tool. Pipeline scripts (`phase-hunt.sh`, `phase-recon.sh`) do NOT invoke dirbrute automatically. The AI must:

1. Decide WHICH hosts need bruteforcing (based on recon data, tech fingerprint, attack surface)
2. Decide WHAT intent to use (based on detected tech stack)
3. Decide WHAT profile (based on host criticality and remaining budget)
4. Read and interpret the results to inform your next actions
5. Feed discovered paths into the endpoint map for exploitation agents

**No parallel bruteforcing.** Scan one host at a time. If you need to scan multiple hosts, write a scan plan with entries in priority order — the tool processes them sequentially.

---

## Tool

`scripts/tools/dir_bruteforce.sh` — AI-driven ffuf wrapper

Two modes:
- `--url <url> [options]` — single host scan (quick ad-hoc)
- `--plan <file>` — execute a scan plan JSON (preferred for structured work)

The AI generates a scan plan JSON, passes it to `--plan`, and the tool executes each entry sequentially.

---

## End-to-End AI Workflow

```
Phase 4 Recon:
  1. Subdomain enumeration → live host discovery → tech fingerprint
  2. For each live host with a web server:
     a. Check: already scanned? surface already known? rate-limited?
     b. Match tech stack → intent (IIS→iis, WordPress→wordpress, etc.)
     c. Assess host criticality → profile (light/standard/deep)
     d. Write scan_plan.json with decision rationale
     e. Dry-run to confirm budget and wordlists
     f. Execute scan
     g. Read critical_exposure.txt + interesting_surface.txt
     h. Add discovered paths to endpoint map
     i. If critical finds → escalate priority, consider deep scan

Phase 5 Surface Analysis:
  3. If endpoint map is thin on high-priority hosts:
     a. Rerun dirbrute with standard/deep profile
     b. Use extension probing (ext-profile matching tech)
     c. Examine robots.txt evidence for hidden paths

Phase 6 Hunt:
  4. On-demand: task(subagent_type="dirbrute") for specific path discovery
     e.g., "find file upload endpoints" → intent=default, look for /upload /file /attachments
```

---

## Decision Tree: When to Dirbrute

```
After recon:
  Does the host have a web server?               No → skip
  Has it been scanned already?                    Yes → skip (unless --force)
  Is the surface known (all endpoints mapped)?    Yes → skip
  Need to find hidden surface?                    No → skip

If YES → pick intent from tech fingerprint, pick profile from criticality
```

### Do NOT dirbrute when:
- Target is a static marketing site (no attack surface to find)
- You already have full endpoint coverage from crawl/SPA/OpenAPI
- You're rate-limited or WAF-blocked (check first with `curl -sI`)
- You're on a time budget and higher-value tests exist

---

## Intents (Tech Stack → Wordlist Mapping)

| Intent | Tech Fingerprint | Wordlists |
|--------|-----------------|-----------|
| `default` | Unknown / generic / fallback | common.txt, admin-panels.txt, Sensitive-Dirs-Files.txt, backup.txt |
| `api` | REST API, GraphQL, JSON responses | default + api-endpoints.txt, graphql-paths.txt, swagger-paths.txt, swaggerAPI.txt, swagger-wordlist.txt |
| `wordpress` | WordPress / wp-content / wp-json | default + wp-fuzz.txt |
| `java` | Java, Tomcat, Spring Boot, JSP | default + Apache-Tomcat.txt |
| `oauth` | OAuth provider, SSO, login page | default + oauth.txt |
| `iis` | IIS, ASP.NET, .NET, Windows Server | default + cgi-bin.txt |
| `full` | High-value host, multiple techs | ALL wordlists (common, admin-panels, Sensitive-Dirs-Files, backup, api-endpoints, graphql-paths, swagger*, oauth, wp-fuzz, Apache-Tomcat, cgi-bin, business-logic-paths, signup-PATHS, endpoints, apac, xml, big, pl) |
| `custom` | Explicit --wordlist flags | Whatever you specify |

---

## Profiles (Request Budgets)

| Profile | Budget | When to Use | Est. Time |
|---------|--------|-------------|-----------|
| `light` | 5,000 reqs | Quick check — low-value host, early recon, unknown surface | ~30s at default rate |
| `standard` | 50,000 reqs | Normal — medium-value host with some attack surface | ~5min at default rate |
| `deep` | 150,000 reqs | High-value — critical host, post-auth, before exploitation | ~15min at default rate |

### Extension Profiles (deep only)

| Ext Profile | Extensions | Tech Match |
|-------------|------------|------------|
| `php` | .php, .php3, .php4, .phtml, .bak, .old, .zip, .tar.gz | PHP/Laravel/WordPress |
| `java` | .jsp, .jspx, .do, .action, .class, .bak, .old | Java/Tomcat/Spring |
| `dotnet` | .aspx, .ashx, .asmx, .config, .bak, .old | ASP.NET/IIS |
| `generic` | .bak, .old, .zip, .tar.gz, .txt, .sql, .json | Fallback |

Extension scans use `raft-medium-files.txt` (~8,000 paths) as base wordlist. Budget impact: ~8,000 reqs × number of extensions. Only use `deep` profile when the host justifies the cost.

---

## How to Invoke

### Preferred: Scan Plan Mode

The AI writes a JSON plan file:

```json
{
  "schema_version": "1.0",
  "plans": [
    {
      "host": "http://target.com",
      "intent": "iis",
      "profile": "light",
      "reason": "IIS fingerprint from httpx headers",
      "confidence": 0.85
    }
  ]
}
```

Then tells the main agent to execute:

```bash
# Dry run first
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh --plan /tmp/scan_plan.json --dry-run

# Execute
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh --plan /tmp/scan_plan.json
```

Multiple entries = sequential scanning, one at a time, in order. Use this when you have priority-ranked hosts.

### Ad-hoc: URL Mode

For a single host without writing a plan:

```bash
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh \
  --url http://target.com \
  --intent api \
  --profile standard \
  --engagement my-engagement-id
```

### Dry Run (always do this first)

Shows wordlist choices, request estimates, and budget without sending any requests.

---

## Reading Results

Output layout under `${RECON_BASE}/<domain>/directories/`:

```
directories/
├── critical_exposure.txt         ← HIGH priority — read first
├── interesting_surface.txt       ← Notable paths — read second
├── results_summary.md            ← Overview with hit counts
└── evidence/<domain>/
    ├── scan_meta.json            ← Run metadata (intent, profile, req count, stop reason)
    ├── robots.txt                ← robots.txt + sitemap.xml content
    ├── results.json              ← All results as JSON array
    ├── 200/entries.json          ← Results grouped by HTTP status
    ├── 301/entries.json
    ├── 403/entries.json
    └── ...
```

### Result Fields

Each entry in results.json has:
| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Full URL of discovered path |
| `status` | int | HTTP status code |
| `words` | int | Word count (response fingerprint) |
| `lines` | int | Line count (response fingerprint) |
| `length` | int | Bytes (response fingerprint) |
| `path` | string | The FUZZ value that produced the hit |

### Stop Conditions

In `scan_meta.json`, `stopped_reason` tells you why the scan ended:

| Value | Meaning | Next Action |
|-------|---------|-------------|
| `completed` | All wordlists scanned normally | Read results |
| `budget_exhausted` | Hit profile's request limit | Consider increasing profile or splitting scan |
| `rate_limited` | >30% of responses were 429 | Wait, retry with --rate <ms> delay, or skip host |

---

## Downstream Data Flow

Results from dirbrute feed into the rest of the pipeline:

```
dirbrute scan
     │
     ├── critical_exposure.txt    → Security finding (config leak, source exposure)
     │                              Log via log_finding() or findings_add_vuln()
     │
     ├── interesting_surface.txt  → Endpoint map enrichment
     │                              Add paths to endpoint list for Phase 6 hunters
     │                              e.g., /admin → auth bypass testing
     │                              e.g., /api/  → API misconfig testing
     │                              e.g., /graphql → GraphQL introspection
     │
     ├── evidence/scan_meta.json  → Run stats for engagement tracking
     │                              track_tool("dir_bruteforce", ...)
     │
     └── evidence/robots.txt      → Additional path hints
                                  Parse for Disallowed paths not yet discovered
```

### What to Do With Critical Findings

If `critical_exposure.txt` contains entries, those are **immediate findings** that should be:
1. Validated manually (curl the URL, confirm content)
2. Logged as a finding via `findings_add_vuln()` or `log_finding()`
3. Explored for data extraction (e.g., download .git/HEAD, check .env contents)

---

## Anti-Patterns (Do NOT Do)

- **NO `raft-large-*.txt`** — these are 100K+ lines and will exhaust budgets on a single wordlist
- **NO recursive depth scanning** — ffuf -recursion causes combinatorial explosion. Use intent+profile instead
- **NO blanket extension fuzzing** — don't append 83 extensions to 17K paths. Use `--ext-profile` (deep only) with targeted extensions
- **NO scanning every subdomain** — pick the ones with actual attack surface
- **NO parallel scanning** — one host at a time. Write a plan with priority order
- **NO auto-invocation from pipeline scripts** — the AI must explicitly decide
- **NO guessing extensions** — use the intent/profile system. The wordlists are already curated per tech stack

---

## Example: Full Phase 4 Recon with Dirbrute

```
1. httpx shows testaspnet.vulnweb.com → IIS 8.5, ASP.NET 2.0
2. AI decides:
   - This host needs dirbusting (unknown surface)
   - intent = iis (matches IIS fingerprint)
   - profile = light (quick surface check, Phase 4)
3. AI writes scan_plan.json:
   {
     "plans": [{
       "host": "http://testaspnet.vulnweb.com",
       "intent": "iis",
       "profile": "light",
       "reason": "IIS detected, checking admin+cgi-bin+common paths",
       "confidence": 0.85
     }]
   }
4. AI runs dry-run → confirms 5K budget with 5 wordlists
5. AI executes → 5,000 requests, 17 hits, budget_exhausted
6. AI reads results:
   - Found: /cgi-bin/, /Trace.axd, /aspnet_client, /images, /robots.txt
   - critical_exposure.txt: clean
   - interesting_surface.txt: /cgi-bin/, /Trace.axd
7. AI adds these paths to endpoint map
8. AI decides: /Trace.axd is interesting → hunt-aspnet can test ViewState/request validation
9. AI does NOT do deep scan (light was sufficient for Phase 4)
```

---

## Script Reference

```
Usage:
  dir_bruteforce.sh --plan <file>                    Execute scan plan
  dir_bruteforce.sh --url <url> [options]            Single host scan

Options (with --url):
  --intent <name>       default|api|wordpress|java|oauth|iis|full|custom
  --profile <name>      light|standard|deep (default: light)
  --ext-profile <name>  php|java|dotnet|generic (deep only)
  --wordlist <name>     Advanced: force specific wordlist (repeatable)
  --rate <ms>           Request delay in ms (default 0)
  --dry-run             Print plan without executing
  --force               Re-scan existing results
  --engagement <id>     Engagement ID for WSTG tracking
  --help|-h             Show help
```

Location: `scripts/tools/dir_bruteforce.sh`
Wordlists: `wordlists/dirbust/` (23 files)
Output base: `${RECON_BASE}/<domain>/directories/`

### Key Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RECON_BASE` | Yes | — | Base directory for all recon output. Must be set in `_env.sh` |
| `SWARM_ROOT` | No | auto-detected | Project root directory |

### Dependencies

- `ffuf` — directory bruteforcing engine
- `curl` — robots.txt/sitemap fetching, WAF probe
- `python3` — JSON parsing, fingerprinting, report generation
- `openssl` — run ID generation (fallback: hex timestamp)

### Wordlist Directory: `wordlists/dirbust/`

26 curated wordlist files:

| File | Lines | Intent | Purpose |
|------|-------|--------|---------|
| `common.txt` | 4,746 | all | General web paths |
| `admin-panels.txt` | 60 | default, full | Admin login panels |
| `admin-PATHS.txt` | 720 | default, full | Additional admin paths |
| `Sensitive-Dirs-Files.txt` | 75 | default, full | Sensitive file paths |
| `backup.txt` | 40 | default, full | Backup file patterns |
| `api-endpoints.txt` | 269 | api | REST API paths |
| `graphql-paths.txt` | 124 | api | GraphQL endpoints |
| `swagger-paths.txt` | 97 | api | Swagger/OpenAPI paths |
| `swaggerAPI.txt` | 97 | api | Swagger API paths |
| `swagger-wordlist.txt` | 243 | api | Swagger wordlist |
| `oauth.txt` | 10 | oauth | OAuth paths |
| `wp-fuzz.txt` | 6,571 | wordpress | WordPress paths |
| `Apache-Tomcat.txt` | 29 | java | Tomcat/Java paths |
| `cgi-bin.txt` | 91 | iis | CGI scripts |
| `raft-medium-files.txt` | 17,129 | deep, full | Extension scan base |
| `raft-medium-directories.txt` | 29,999 | deep, full | Directory patterns |
| `business-logic-paths.txt` | 70 | default | Business logic paths |
| `signup-PATHS.txt` | 187 | default | Registration paths |
| `endpoints.txt` | 40 | default | Config/endpoint patterns |
| `kibana.txt` | 614 | default | Kibana/ELK paths |
| `sensitivejs.txt` | 129 | default | JS files leaking secrets |
| `extensions.txt` | 83 | deep, full | Extension patterns |
| `apac.txt` | 13,233 | full | APAC-specific paths |
| `xml.txt` | 78 | full | XML paths |
| `big.txt` | 20,469 | full | Large general wordlist |
| `pl.txt` | 7,570 | full | Perl/CGI paths |

Additional wordlists available on request (`$HOME/wordlists/`): `iis.txt` (73K), `aspx.txt` (33K),
`jsp.txt` (92K), `jsf.txt` (36K), `fuzz.txt` (22K), `exposelist.txt` (17K),
`raft-large-*` (62K-120K), `httparchive_apiroutes_2026_01_27.txt`.
These are deep-only due to size — copy to `wordlists/dirbust/` and update `INTENT_WL` in the script to enable.
