# Information Gathering — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="info")` — Information gathering test cases (WSTG-INFO-*)
- `search_wstg("information gathering")` — Find relevant info-gathering procedures
- `identify_waf(target)` — WAF/proxy identification
- `get_witness_payloads("discovery")` — Discovery test payloads

## Key Test Categories
1. Search engine discovery (Google dorks, SHODAN, Censys)
2. Web server fingerprinting (headers, favicon, error pages)
3. Directory enumeration (common paths, backup files)
4. Technology stack identification (Wappalyzer, whatweb)
5. Content Management System identification
6. Subdomain enumeration
7. API endpoint discovery
8. Source code repository disclosure (.git, .svn)

## Burp Workflow
```bash
# Fingerprint server
burp_send_to_repeater("https://target.com/", method="GET")

# Directory brute-force setup
burp_send_to_intruder(
    url="https://target.com/$path$",
    positions=["path"],
    payloads=["/admin", "/api", "/.git/config", "/backup", "/wp-admin"]
)

# Spider for endpoints
burp_send_to_repeater("https://target.com/robots.txt", method="GET")
burp_send_to_repeater("https://target.com/sitemap.xml", method="GET")
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-INFO-01 | Search engine discovery — Google dorks, SHODAN, Censys, Wayback Machine |
| WSTG-INFO-02 | Web server fingerprinting — headers, favicon hash, error pages, response ordering |
| WSTG-INFO-03 | Directory enumeration — common paths, backup files, admin interfaces |
| WSTG-INFO-04 | Technology stack identification — Wappalyzer, whatweb, BuiltWith |
| WSTG-INFO-05 | Content Management System identification — WordPress, Drupal, Joomla, SharePoint |
| WSTG-INFO-06 | Subdomain enumeration — passive (certificate logs, DNS) + active (brute-force) |
| WSTG-INFO-07 | API endpoint discovery — Swagger, GraphQL introspection, WSDL |
| WSTG-INFO-08 | Source code repository disclosure — .git, .svn, .hg, backup archives |
| WSTG-INFO-09 | Information leakage via response — internal IPs, paths, version numbers |
| WSTG-INFO-10 | WAF identification — detect WAF vendor and version via characteristic responses |

## Attack Playbook

### Passive Recon
1. Search engine dorking: `site:target.com intitle:"index of"`, `site:target.com filetype:env`, `site:target.com inurl:wp-admin`
2. Certificate transparency: `https://crt.sh/?q=%25.target.com` → get all subdomains from SSL certs
3. Wayback Machine: `https://web.archive.org/web/*/target.com/*` → find historical endpoints, JS files
4. SHODAN/Censys: search for target domain/IP for open ports, services, banners
5. GitHub: search for target domain in public repos → `git config`, `.env`, leaked keys

### Active Recon
1. Subdomain brute-force: use common wordlist against target.com
2. Directory brute-force: use `/admin`, `/api`, `/backup`, `/.git`, `/wp-admin` paths
3. Port scan: 80, 443, 8080, 8443, 3000, 5000, 9000, 27017, 6379, 5432
4. Technology fingerprint: check response headers, HTML comment tags, JS framework patterns
5. WAF detection: `identify_waf(target)` → returns WAF vendor if detected
6. Source map discovery: `https://target.com/static/js/main.js.map` → reverse to source code

### Endpoint Discovery
1. Robots.txt and sitemap.xml → parse for hidden paths
2. JS file analysis: fetch all JS files, search for API endpoints, routes, base URLs
3. Comment analysis: check HTML/JS comments for TODO, FIXME, removed endpoints
4. GraphQL introspection: `GET /graphql?query={__schema{types{name}}}` or POST to common endpoints
5. Chain: JS source map → full front-end source → API endpoints + auth logic

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Skipping passive recon, going straight to active scanning** | Passive recon (crt.sh, Wayback, Google dorks) identifies targets that active scanning misses |
| **Not checking robots.txt and sitemap.xml** | These are designed to tell you what's there (and what's hidden) |
| **Directory brute-forcing with a tiny wordlist** | Use at least 10k paths; common admin paths are in the first 500 but API endpoints are deeper |
| **Overlooking JavaScript source maps** | `.js.map` files reconstructed to source code reveal every front-end endpoint |
| **Stopping at subdomain enumeration without live host checking** | Found subdomains may be stale/redirecting; verify with HTTP probe |

## Evidence Requirements
- [ ] Technology stack list with versions
- [ ] Discovered endpoints/subdomains list
- [ ] WAF detection results
- [ ] WSTG INFO test ID
- [ ] Passive recon sources checked (crt.sh, Wayback, SHODAN, dorks)

## Phase Gates
- Phase 3 (INFO-GATHERING): Complete this phase before moving to recon
- Phase 5 (SURFACE): Tag discovered endpoints with priority
