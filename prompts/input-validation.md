# Input Validation Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="input")` — Input validation test cases (WSTG-INPV-*)
- `search_wstg("input validation")` — Find relevant test procedures
- `get_witness_payloads("xss")` — XSS test payloads
- `get_witness_payloads("sqli")` — SQL injection test payloads
- `get_witness_payloads("ssti")` — SSTI test payloads
- `get_waf_bypass("xss")` — XSS WAF bypass techniques
- `get_waf_bypass("sqli")` — SQLi WAF bypass techniques
- `get_waf_bypass("rce")` — Command injection bypass techniques

## Key Test Categories
1. XSS (reflected, stored, DOM-based, mXSS)
2. SQL injection (classic, blind, time-based, second-order)
3. SSTI (Jinja2, Twig, Freemarker, Velocity, ERB)
4. Command injection (OS command, argument injection)
5. SSRF (cloud metadata, internal network, blind OOB)
6. LFI/RFI (directory traversal, PHP wrappers, log poisoning)
7. Prototype pollution (server-side and client-side)
8. NoSQL injection (MongoDB $where, $regex)
9. XXE (in-band, blind OOB, SVG, XInclude)
10. HTTP Parameter Pollution
11. LDAP injection
12. File upload bypass (Content-Type, extension, polyglot)

## Burp Workflow
```bash
# Send request with payload
burp_send_to_repeater(url, headers, body)

# Test multiple payload variations
burp_send_to_intruder(url, positions=["param1"], payloads=witness_payloads)

# Check for OOB interactions
burp_check_collaborator(poll_id)

# WAF bypass testing
# If blocked, request WAF bypass techniques:
get_waf_bypass("sqli")  # returns equivalent bypasses
```

## WSTG Test Map

| ID | Category | What It Covers |
|----|----------|----------------|
| WSTG-INPV-01 | Reflected XSS | Inject script into response via params/headers/body |
| WSTG-INPV-02 | Stored XSS | Inject script persisted in DB (comments, profiles) |
| WSTG-CLNT-01 | DOM XSS | Client-side sink execution (eval, innerHTML, document.write) |
| WSTG-INPV-03 | HTTP Verb Tampering | HTTP method override, verb-based access control bypass |
| WSTG-INPV-04 | HTTP Parameter Pollution | Duplicate params, array notation, HPP for WAF bypass |
| WSTG-INPV-05 | SQL Injection | Classic error-based, UNION-based, blind inference extraction |
| WSTG-INPV-06 | LDAP Injection | Modify LDAP filter syntax, anonymous binds, directory traversal |
| WSTG-INPV-07 | ORM Injection | HQL, JPQL, raw fragment injection in ORM queries |
| WSTG-INPV-08 | XML Injection | XML structure manipulation, XPath injection |
| WSTG-INPV-09 | SSI Injection | Server-side include directive injection |
| WSTG-INPV-10 | XPath Injection | Bypass auth or extract XML data via XPath queries |
| WSTG-INPV-11 | Code Injection | eval() injection, dynamic code execution, unsafe reflection |
| WSTG-INPV-12 | Command Injection | OS command execution via shell metacharacters |

## Tool Usage

Run scanner tools with their venv activated directly:

```bash
# sqlmap — SQLi confirmation (output dir for check_tool_output)
( source "$TOOLS_DIR/sqlmap/venv/bin/activate" && python3 "$TOOLS_DIR/sqlmap/sqlmap.py" -u "$URL" --batch --output-dir=/tmp/sqlmap-out ) 2>&1 | tee /tmp/sqlmap.log
# Then validate: check_tool_output(engagement_id, tool_name="sqlmap", file_path="/tmp/sqlmap.log")

# commix — command injection confirmation
( source "$TOOLS_DIR/commix/venv/bin/activate" && python3 "$TOOLS_DIR/commix/commix.py" --url="$URL" --batch ) 2>&1 | tee /tmp/commix.log

# sstimap — template injection confirmation
( source "$TOOLS_DIR/sstimap/venv/bin/activate" && python3 "$TOOLS_DIR/sstimap/sstimap.py" -u "$URL" --method POST --data "..." ) 2>&1 | tee /tmp/sstimap.log

# crlfuzz — CRLF / HTTP response splitting
crlfuzz -u "$URL" 2>&1 | tee /tmp/crlfuzz.log

# dalfox — XSS scanning (reflected + stored + DOM)
dalfox url "$URL" --depth 3 2>&1 | tee /tmp/dalfox.log
```

After running, call `check_tool_output()` MCP tool with the log file to get a `poc_token` + `independent_engine` signal.

## Attack Playbook

### XSS (WSTG-INPV-01/02, CLNT-01)
1. Test reflected in URL params, POST body, headers → if success, escalate to stored
2. Test stored in comment fields, profile fields, file upload metadata
3. If reflected/stored fails → test DOM sink via `extract_content("document.body.innerHTML")`
4. If headed browser available → `browser_screenshot()` to confirm alert()
5. If WAF blocks → iterate WAF bypass: encoding → case permutation → polyglot → mXSS
6. Chain: XSS → cookie steal → session replay → ATO

### SQLi (WSTG-INPV-05)
1. Time-based: `' OR SLEEP(5)--` → measure response >5s = vulnerable
2. Boolean-based: `' OR '1'='1` vs `' OR '1'='2` → diff responses = vulnerable
3. Error-based: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--` → error shows version
4. UNION extraction: `' UNION SELECT 1,@@version,3--` → response shows DB version
5. Run each probe 3x due to WAF jitter; report success rate (e.g., 3/3, 2/3)
6. Chain: SQLi → extract admin hash → crack → admin access
7. **Tool assist**: `( source "$TOOLS_DIR/sqlmap/venv/bin/activate" && python3 "$TOOLS_DIR/sqlmap/sqlmap.py" -u "$URL" --batch --level=3 )` → `check_tool_output()`

### SSTI (general)
1. Test with `{{7*7}}` → response shows `49` = Jinja2/Twig/ERB
2. Test with `${7*7}` → response shows `49` = Freemarker/Velocity
3. Test with `*{7*7}` → response shows `49` = Velocity
4. If SSTI confirmed → escalate to RCE: `{{config.__class__.__init__.__globals__['os'].popen('id')}}`
5. Run each template syntax probe 2x to confirm

### SSRF (WSTG-INPV-19)
1. Test with external collaborator URL → burp_generate_collaborator_payload()
2. Test with cloud metadata IP: `http://169.254.169.254/latest/meta-data/`
3. Test with internal IPs: `http://10.0.0.1`, `http://172.16.0.1`, `http://192.168.1.1`
4. Test protocol smuggling: `file:///etc/passwd`, `gopher://`, `dict://`
5. If WAF blocks IPs → try decimal/hex/dotted-hex IP variants, redirect-based bypass
6. Chain: SSRF → cloud metadata → IAM credentials → cloud account takeover

### LFI
1. Test with `../../etc/passwd` → if readable, try PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`
2. Try log poisoning if direct read fails: inject PHP into User-Agent, LFI to `/var/log/apache2/access.log`
3. Chain: LFI → source code read → find DB creds → pivot

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Blind fuzzing without XSS context** | Test params that actually render in the page (reflected/stored); don't fuzz blindly |
| **SQLi on integer params without `'` first** | Integer params need `+UNION+SELECT` not `' UNION SELECT` |
| **SSTI with {{7*7}} on non-template engines** | Check for template engine first (error page, tech stack) |
| **Time-based SQLi with 10s+ delays** | Use SLEEP(2) not SLEEP(10); 2s difference is enough to measure |
| **SSRF without collaborator** | Always use OOB detection for blind SSRF; don't rely on response body alone |
| **Re-running same payload unchanged after WAF block** | If blocked, request WAF bypass techniques first, then retry |
| **File upload test without SVG XSS test** | SVG XSS (WSTG-INPV-02 variant) is the most common file upload bypass |

## Evidence Requirements
- [ ] Full URL with payload (URL-decoded form)
- [ ] Response showing successful injection
- [ ] WAF bypass chain documentation (if applicable)
- [ ] WSTG INPV test ID
- [ ] CVSS 3.1 score
- [ ] Retry count (e.g., "3/3 attempts succeeded")

## Phase Gates
- Phase 6 (HUNT): Test all input vectors per endpoint
- Phase 8 (EXPLOIT): Deep exploitation of confirmed injections
- Phase 11 (VALIDATE): Re-run all PoCs against clean instances
