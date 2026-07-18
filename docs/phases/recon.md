# Phase 4: RECON (Reconnaissance)

Full subdomain enumeration, URL crawling, parameter extraction, secrets discovery, and cloud asset scanning. Runs after INTEL (Phase 3), feeds SURFACE (Phase 5).

---

## Objectives

- Discover all subdomains (passive + DNS brute-force)
- Collect historical and live URLs (wayback, crawlers)
- Extract parameterized URLs and classify by bug class (GF patterns)
- Find exposed secrets, config files, debug endpoints
- Probe for 403 bypasses and virtual hosts
- Check zone transfer and subdomain takeover
- Scan cloud storage buckets (AWS/Azure/GCP)

---

## Pipeline Steps

Run each step in order. Every script uses the full path `"$HOME/swarm/scripts/tools/<script>.sh"`.

### Step 1: Subdomain Enumeration + DNS Bruteforce

```bash
# Passive enumeration (subfinder + assetfinder + amass + crt.sh)
bash "$HOME/swarm/scripts/tools/subdomain_enum.sh" <target>

# Multiple domains in parallel:
bash "$HOME/swarm/scripts/tools/batch_subdomain_enum.sh" -j 3 domain1.com domain2.com domain3.com

# DNS brute-force (puredns + massdns, MUST run after subdomain_enum)
bash "$HOME/swarm/scripts/tools/dns_bruteforce.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `subdomain_enum.sh` | subfinder + assetfinder + amass + crt.sh/curl | Passive subdomain discovery from multiple sources |
| `dns_bruteforce.sh` | puredns + massdns | Brute-force subdomains from wordlist (`wordlists/dns/subdomains-top1million-20000.txt`) |

**Wordlists:** pre-installed at `$HOME/swarm/wordlists/dns/`:
- `resolvers.txt` — DNS resolvers for puredns
- `subdomains-top1million-20000.txt` — top 20K subdomain wordlist

### Step 2: URL Crawling + Parameter Extraction

```bash
bash "$HOME/swarm/scripts/tools/web_waymore.sh" <target>
bash "$HOME/swarm/scripts/tools/web_gospider.sh" <target>
bash "$HOME/swarm/scripts/tools/web_katana.sh" <target>
bash "$HOME/swarm/scripts/tools/param_extract.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `web_waymore.sh` | waymore (venv) | Passive URLs from Wayback Machine + AlienVault |
| `web_gospider.sh` | gospider | Active crawl — spider finds links from live pages |
| `web_katana.sh` | katana | Active crawl — headless browser + URL extraction |
| `param_extract.sh` | gf + sort/uniq | Extracts URLs with query parameters, classified by GF patterns (xss, sqli, ssrf, etc.) |

**Output:** `crawl/` directory with merged URL lists, `params/` with GF-filtered candidates.

### Step 3: URL Extraction + Alive Probing

```bash
bash "$HOME/swarm/scripts/tools/extracturls.sh" -f "$RECON_BASE/<target>/crawl" -d <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `extracturls.sh` | grep + httpx (venv) | Strips static assets (fonts, images, sourcemaps) from crawl output; probes remaining URLs with httpx to confirm they're alive |

**Output:**
- `crawl/allsubsurls.txt` — deduplicated, scoped URLs with static assets filtered out
- `crawl/alivesubsurls.txt` — httpx-verified subset of `allsubsurls.txt` (only when httpx available)

**Note:** Run automatically by `phase-recon.sh` after all 3 crawlers finish. Also sets `EXTRACT_URLS_RAN=true` for downstream phases. Phase 5 (surface) prefers these filtered files over raw crawl output when available.

### Step 4: Secrets Scan + Directory Bruteforce

```bash
bash "$HOME/swarm/scripts/tools/cariddi_scan.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `cariddi_scan.sh` | cariddi | Secrets (.env, .git/config), info disclosure, interesting paths |

**Directory bruteforce** is AI-driven via `task(subagent_type="dirbrute")`. It is NOT auto-invoked — the AI decides per-host based on:

**Dispatch conditions (ALL must match):**
- httpx confirmed the host has a web server (200/401/403/301)
- Crawl found <10 unique endpoints for that host
- NOT a static marketing site (no login, no params, no forms)
- NOT rate-limited or WAF-blocked

**Intent selection** (matches tech fingerprint to wordlists):

| Tech Fingerprint | Intent | Key Wordlists |
|-----------------|--------|---------------|
| Unknown / generic | `default` | common.txt (4.7K), admin-PATHS.txt (720), sensitivejs.txt (129) |
| REST API, GraphQL | `api` | default + api-endpoints (269), graphql-paths (124), swagger (3 files) |
| WordPress | `wordpress` | default + wp-fuzz.txt (6.5K) |
| Java, Tomcat, Spring | `java` | default + Apache-Tomcat.txt (29) |
| OAuth, SSO, login page | `oauth` | default + oauth.txt (10) |
| IIS, ASP.NET, .NET | `iis` | default + cgi-bin.txt (91) |
| High-value, multiple techs | `full` | All 26 wordlists (~103K lines) |

**Profile selection** (request budget):

| Profile | Budget | When |
|---------|--------|------|
| `light` | 5K | Quick check, low-value host, early recon |
| `standard` | 50K | Normal host with attack surface |
| `deep` | 150K | Critical host. Enables `--ext-profile` (extension fuzzing) |

**Output:** `directories/` directory:
- `critical_exposure.txt` — HIGH priority paths (.git, .env, config leaks)
- `interesting_surface.txt` — Notable paths (admin, graphql, swagger, etc.)
- `results_summary.md` — Overview with hit counts
- `evidence/<host>/scan_meta.json` — Run metadata (stopped reason, WAF)

### Step 5: 403 Bypass + Vhost Fuzzing

```bash
bash "$HOME/swarm/scripts/tools/bypass_403.sh" <target>
bash "$HOME/swarm/scripts/tools/vhost_fuzz.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `bypass_403.sh` | curl + bypass matrix | Tests header/method/encoding tricks against 401/403 endpoints |
| `vhost_fuzz.sh` | ffuf | Discovers hidden virtual hosts via Host header fuzzing |

### Step 6: Zone Transfer + Takeover Scanner

```bash
bash "$HOME/swarm/scripts/tools/zone_transfer.sh" <target>
bash "$HOME/swarm/scripts/tools/takeover_scanner.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `zone_transfer.sh` | dig + host + nslookup | Tests DNS zone transfer on all name servers |
| `takeover_scanner.sh` | subjack + curl fingerprint | Detects dangling DNS — subdomain takeover candidates |

### Step 7: Cloud Recon + Secrets Validation + S3 Buckets

```bash
bash "$HOME/swarm/scripts/tools/cloud_recon.sh" --keyword <keyword>
bash "$HOME/swarm/scripts/tools/auto_secrets.sh" <target>
bash "$HOME/swarm/scripts/tools/s3_buckets.sh" <target>
```

| Script | Tool | What it finds |
|--------|------|---------------|
| `cloud_recon.sh` | cloud_enum (venv) + s3scanner + CloudFail | Cloud storage buckets (AWS/Azure/GCP) + Cloudflare origin IP |
| `auto_secrets.sh` | curl | Validates cariddi-discovered secrets (accessible .env, .git, config) |
| `s3_buckets.sh` | cloud_enum (venv) + s3scanner + trufflehog | S3 bucket enumeration with secret scanning |

---

## Virtual Environments

Tools installed as Python packages run in isolated venvs. Activation is handled automatically by each script:

| Tool | Venv Path | Activated By |
|------|-----------|--------------|
| `waymore` | `$REPO_DIR/tools/waymore/{venv,.venv}/` | `web_waymore.sh` (checks venv/ then .venv/) |
| `cloud_enum` | `$TOOLS_DIR/cloud_enum/{venv,.venv}/` | `cloud_recon.sh`, `phase-intel.sh`, `s3_buckets.sh` (check venv/ then .venv/) |

Go binaries (subfinder, assetfinder, httpx, dnsx, gospider, katana, cariddi, ffuf, puredns, subjack, s3scanner) need no venv — installed at `~/go/bin/`.

---

## Directory Structure

After a full RECON run on `<target>`:

```
$RECON_BASE/<target>/
├── subdomains/
│   ├── all_subdomains.txt         # merged passive results (subfinder + assetfinder + findomain)
│   ├── alive-domains.txt          # clean domain names (no protocol/port/path)
│   ├── https-subs.txt             # HTTPS-only URLs
│   ├── live_domains.txt           # httpx raw output (status + tech + title + server)
│   ├── live_urls.txt              # live URLs (protocol+host)
├── dns_bruteforce.txt             # puredns brute-force results
├── crawl/
│   ├── waygauurls.txt             # waymore + gau URLs
│   ├── gospider.txt               # gospider crawl
│   ├── katana.txt                 # katana crawl
│   ├── merged-crawl.txt           # deduplicated (uro)
│   ├── extracturls.log            # extracturls.sh run log
│   ├── allsubsurls.txt            # static-filtered scoped URLs (extracturls.sh)
│   └── alivesubsurls.txt          # httpx-verified alive URLs (extracturls.sh)
├── params/
│   ├── paramurls.txt              # URLs with query params
│   ├── gf_xss.txt                 # XSS candidates
│   ├── gf_sqli.txt                # SQLi candidates
│   └── gf_ssrf.txt                # SSRF candidates
├── cariddi/
│   └── cariddi.txt                # secrets + interesting paths
├── directories/
│   ├── critical_exposure.txt      # high-priority findings (.git, .env, config leaks)
│   ├── interesting_surface.txt    # notable paths (admin, swagger, graphql)
│   ├── results_summary.md         # overview with hit counts
│   └── evidence/<host>/
│       ├── scan_meta.json         # run metadata (stopped reason, WAF, request count)
│       ├── results.json           # all ffuf results
│       └── <status>/entries.json  # results per HTTP status code (200/, 403/, etc.)
├── bypass/
│   ├── accessible.txt             # bypassed endpoints
│   └── forbidden.txt              # still blocked
├── vhost/
│   └── vhost_results.txt          # discovered virtual hosts
├── takeover/
│   └── subjack.txt                # takeover candidates
├── cloud/
│   ├── cloud_enum_results.jsonl   # cloud_enum output
│   ├── s3buckets.txt              # s3scanner results
│   └── non_cf_ips.txt             # Cloudflare origin IP candidates
└── secrets/
    ├── accessible.txt             # verified accessible secrets
    └── high_value_confirmed.txt   # high-value confirmed paths
```

---

## Gate

```python
phase_gate_check(engagement_id, phase_completed=4)
```

Gate passes when:
- Subdomain enumeration + DNS bruteforce completed
- URL crawl + parameter extraction completed
- Secrets scan completed
- Track record for each tool submitted

---

## Script

```bash
# Full pipeline (sequential — prefer running individual scripts per step above)
bash "$HOME/swarm/scripts/tools/phase-recon.sh" <target>
```

**CRITICAL:** All tools are pre-installed. Never invoke tool binaries directly. Never run `go install`, `pip install`, or `apt install`.
