# Configuration Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="config")` — Configuration test cases (WSTG-CONF-*)
- `search_wstg("configuration")` — Find relevant config test procedures
- `get_witness_payloads("config")` — Config-specific test payloads
- `identify_waf(target)` — Detect WAF/proxy configuration

## Key Test Categories
1. Default credentials (admin:admin, root:root, etc.)
2. Directory listing enabled
3. Debug/stack trace endpoints exposed
4. Information disclosure (server headers, error pages)
5. Cloud storage misconfiguration (open S3 buckets)
6. .git/config exposure
7. Backup file disclosure (.bak, ~, .old)
8. Unnecessary HTTP methods (PUT, DELETE, TRACE)
9. Security headers audit (HSTS, CSP, X-Frame-Options, etc.)

## Tool Usage

```bash
# smuggler — HTTP request smuggling detection
( source "$TOOLS_DIR/smuggler/venv/bin/activate" && python3 "$TOOLS_DIR/smuggler/smuggler.py" -u "$URL" ) 2>&1 | tee /tmp/smuggler.log
# Validate: check_tool_output(engagement_id, tool_name="smuggler", file_path="/tmp/smuggler.log")

# wafw00f — WAF fingerprinting (if not using identify_waf MCP)
wafw00f "$URL" 2>&1 | tee /tmp/wafw00f.log

# trufflehog — secret scanning in repos/dirs
trufflehog filesystem "$REPO_PATH" 2>&1 | tee /tmp/trufflehog.log
```

## Burp Workflow
```bash
# Check HTTP response headers
burp_send_to_repeater(url, method="GET")

# Test default paths
burp_send_to_repeater("https://target.com/admin/", method="GET")
burp_send_to_repeater("https://target.com/.git/config", method="GET")
burp_send_to_repeater("https://target.com/debug", method="GET")
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-CONF-01 | Network infrastructure configuration — internal IP exposure in headers, load balancer info |
| WSTG-CONF-02 | Application platform configuration — server header information disclosure (nginx, Apache, IIS versions) |
| WSTG-CONF-03 | File extensions handling — test for handler misconfiguration (`.php` files served as text, `.config` accessible) |
| WSTG-CONF-04 | Backup and unreferenced files — `.bak`, `~`, `.old`, `.swp`, `test/`, `demo/`, `backup/` |
| WSTG-CONF-05 | Enumerate admin interfaces — `/admin`, `/console`, `/manager`, `/jenkins`, `/kibana` |
| WSTG-CONF-06 | HTTP methods and XST — test for `PUT`, `DELETE`, `TRACE`, `OPTIONS` methods |
| WSTG-CONF-07 | HTTP Strict Transport Security (HSTS) — missing or insufficient `max-age`, no `includeSubDomains` |
| WSTG-CONF-08 | RIA cross-domain policy — Flash `crossdomain.xml`, Silverlight `clientaccesspolicy.xml` |
| WSTG-CONF-09 | File permission — world-readable files, directory listing, sensitive file permissions |
| WSTG-CONF-10 | Subdomain takeover — dangling DNS CNAME records pointing to unclaimed cloud services |
| WSTG-CONF-11 | Cloud storage — open S3 buckets, Azure Blob, GCP storage |
| WSTG-CONF-12 | Content Security Policy (CSP) — missing or overly permissive `script-src`, `unsafe-inline` |
| WSTG-CONF-13 | Path confusion — URL parsing discrepancies between frameworks and reverse proxies |
| WSTG-CONF-14 | HTTP security header misconfigurations — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |

## Attack Playbook

### Information Disclosure (WSTG-CONF-01/02)
1. Send OPTIONS request → capture server header, allowed methods
2. Check response headers for: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, `Via`, `X-Cache`
3. Send request with invalid methods → capture error page (may disclose paths, versions)
4. Test debug endpoints: `/debug`, `/console`, `/actuator`, `/heapdump`, `/threaddump`
5. Chain: version disclosure → CVE lookup → targeted exploit

### Backup Files (WSTG-CONF-04)
1. Append to discovered paths: `.bak`, `~`, `.old`, `.backup`, `.swp`
2. Common patterns: `index.php.bak`, `config.php.old`, `.env.backup`, `db.~sql`
3. Test `.git` disclosure: `/.git/config`, `/.git/HEAD`, `/.git/logs/HEAD`
4. If `.git` exposed → reconstruct full repo via `git-dumper` or manual fetch
5. Chain: `.git` disclosure → source code → DB credentials in config → DB access

### Security Headers (WSTG-CONF-07/14)
1. Check each header and document its value
2. CSP analysis: extract `script-src`, `frame-ancestors`, `report-uri`
3. HSTS: check `max-age` ≥ 31536000, `includeSubDomains` present, `preload` in header
4. Chain: missing CSP → XSS becomes more impactful (no script restriction)

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Skipping security header audit on every page** | Headers can vary per endpoint; test login page AND API endpoint |
| **Only checking /.git/config** | Also check `/.git/HEAD`, `/.git/logs/HEAD`, `/.git/index` — config may be blocked but other paths exposed |
| **Assuming all backup files end in .bak** | Try `.old`, `~`, `.swp`, `.backup`, `.back`, `.save`, `.copy`, `backup_`, `_backup` |
| **Not testing PUT method on APIs** | If PUT is allowed and writable, you can upload shells or overwrite config |
| **Checking HSTS only on main domain** | Subdomains and CDN endpoints often lack HSTS even when the main domain has it |

## Evidence Requirements
- [ ] HTTP response headers screenshot
- [ ] Default credential test results
- [ ] Exposed file/directory paths
- [ ] WSTG CONF test ID
- [ ] Security header audit table (header → value → pass/fail)

## Phase Gates
- Phase 3 (INFO-GATHERING): Discover configuration surface
- Phase 6 (HUNT): Systematically test each configuration vector
