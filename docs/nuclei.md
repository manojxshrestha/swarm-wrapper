# Nuclei Integration

Swarm uses [ProjectDiscovery's nuclei](https://github.com/projectdiscovery/nuclei) as an **independent PoC validation engine** for false-positive reduction. When Swarm's consensus oracles flag a vulnerability, nuclei provides a second-opinion scan using curated YAML templates — if nuclei also finds it, the confidence level upgrades to `confirmed` with `independent_engine=True`.

---

## How It Works

Nuclei is invoked through the `check_tool_output` MCP tool in **ACTIVE mode**:

```
check_tool_output(engagement_id, url, vuln_class)
```

This runs:

```
nuclei -u <url> -t <template_dir> -json -silent -timeout 10
```

The tool:
1. Looks up the vuln class → template subdirectory mapping
2. Runs nuclei with all `.yaml` templates in that directory
3. Parses the JSON output
4. If findings exist: generates a `poc_token`, saves evidence, returns **PASS**
5. If no findings: returns **NOT DETECTED**

---

## Installation

Nuclei is installed via `scripts/setup/install.sh` as a Go tool:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

The binary lands at `$HOME/go/bin/nuclei` (added to `PATH` by the install script). The bundled templates ship with the repo at `wordlists/nuclei-templates/` — no `nuclei -update` needed.

### Verify installation

```bash
nuclei -version
ls wordlists/nuclei-templates/   # 21 subdirectories
```

---

## Vuln Class → Template Mapping

Each vulnerability class maps to one or more template subdirectories. The full mapping from `server.py`:

| Vuln Class | Template Directory | Templates |
|------------|-------------------|-----------|
| `sqli` | `sqli/` | 1 |
| `xss`, `xss_reflected`, `xss_stored`, `xss_dom` | `xss/` | 8 |
| `ssrf` | `ssrf/` | 7 |
| `ssti` | `ssti/` | 2 |
| `cmdi` | `cmdi/` | 1 |
| `path_traversal`, `lfi` | `path-traversal/` | 3 |
| `open_redirect` | `open-redirect/` | 3 |
| `xxe` | `xxe/` | 1 |
| `nosqli` | `nosqli/` | 5 |
| `ldap_injection` | `ldap-injection/` | 2 |
| `graphql`, `graphql_abuse` | `graphql/` | 11 |
| `cors`, `cors_misconfiguration` | `cors/` | 2 |
| `csp` | `csp/` | 2 |
| `clickjacking` | `clickjacking/` | 1 |
| `csrf` | `csrf/` | 1 |
| `prototype_pollution` | `prototype-pollution/` | 2 |
| `host_header_injection` | `misc/` | 8 |

**Shared categories** (available but not directly mapped to a vuln class):

| Directory | Templates | Purpose |
|-----------|-----------|---------|
| `debug/` | 11 | Debug endpoint detection (actuator, info leaks) |
| `exposures/` | 28 | Exposed files, config leaks, .git, .env |
| `misc/` | 8 | Catch-all (host-header, redirects, etc.) |

**Total**: 21 directories, ~100 YAML templates.

---

## Template Directory Structure

```
wordlists/nuclei-templates/
├── clickjacking/       # X-Frame-Options / CSP frame-ancestors
├── cmdi/               # Command injection
├── cors/               # CORS misconfiguration
├── csp/                # Content Security Policy
├── csrf/               # Cross-site request forgery
├── debug/              # Debug/info endpoints (actuator, env, stacktraces)
├── exposures/          # File/config exposure (.git, .env, backups)
├── graphql/            # GraphQL introspection, abuse
├── ldap-injection/     # LDAP injection
├── misc/               # Miscellaneous (host-header, etc.)
├── nosqli/             # NoSQL injection
├── open-redirect/      # Open URL redirect
├── path-traversal/     # Path traversal / LFI
├── prototype-pollution/ # Prototype pollution
├── sqli/               # SQL injection
├── ssrf/               # Server-side request forgery
├── ssti/               # Server-side template injection
├── xss/                # Cross-site scripting
└── xxe/                # XML external entity
```

---

## Adding New Templates

1. Write a nuclei YAML template following the official [nuclei template guide](https://docs.projectdiscovery.io/templates/introduction)
2. Save it to the matching subdirectory under `wordlists/nuclei-templates/`
3. No configuration changes needed — `check_tool_output` auto-discovers templates

For a new vuln class not yet mapped, add an entry to `VULN_TO_NUCLEI_DIR` in `server/server.py`:

```python
VULN_TO_NUCLEI_DIR["my_class"] = "my-directory"
```

Then create `wordlists/nuclei-templates/my-directory/` with your `.yaml` templates.

---

## Output & Evidence

When nuclei finds a match, Swarm:

1. Generates a `poc_token` (32-char hex) via `secrets.token_hex(16)`
2. Saves the full nuclei JSON output to `engagements/<eid>/evidence/nuclei-<poc_token>.json`
3. Returns a structured PASS response with template IDs, names, severities, and matched URLs

The `poc_token` can be passed to `findings_add_vuln(independent_engine=True, poc_token=...)` to register the finding as independently confirmed.

---

## Example

```python
# Via MCP client:
check_tool_output(
    engagement_id="eng-001",
    url="https://target.com/search?q=test",
    vuln_class="sqli"
)

# Response:
# PASS ✅
# URL: https://target.com/search?q=test
# Tool: nuclei
# Templates: sqli/ (1 findings)
# PoC Token: a1b2c3d4e5f6g7h8
#
# Findings:
# - SQL Injection [medium] — https://target.com/search?q=test' (template: sqli-detect)
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `nuclei binary not found` | Not installed | `bash scripts/setup/install.sh` or `go install ...` |
| `No nuclei templates available` | Vuln class not in `VULN_TO_NUCLEI_DIR` | Add mapping in `server.py` |
| `Template directory is empty` | No `.yaml` files in the subdirectory | Add templates |
| `Nuclei did not complete within 120 seconds` | Timeout | Target may be slow or unresponsive |
