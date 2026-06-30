# Client-Side Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="client")` — Client-side test cases (WSTG-CLNT-*)
- `search_wstg("client side")` — Find relevant client-side test procedures
- `get_witness_payloads("xss")` — XSS payloads for client-side testing
- `get_waf_bypass("xss")` — WAF bypass techniques for XSS

## Key Test Categories
1. DOM-based XSS (document.write, innerHTML, eval sinks)
2. DOM clobbering (id/name attribute collision)
3. Prototype pollution (__proto__, constructor)
4. PostMessage origin validation
5. WebSocket origin bypass
6. Local storage / session storage sensitive data
7. CORS misconfiguration
8. Clickjacking (X-Frame-Options, CSP frame-ancestors)
9. Trusted Types bypass

## Tool Usage

```bash
# dalfox — automated XSS detection with DOM scanning
dalfox url "$URL" --depth 2 2>&1 | tee /tmp/dalfox.log
# Validate: check_tool_output(engagement_id, tool_name="dalfox", file_path="/tmp/dalfox.log")

# crlfuzz — CRLF injection testing (can affect client-side resource loading)
crlfuzz -u "$URL" 2>&1 | tee /tmp/crlfuzz.log
```

## Burp Workflow
```bash
# Capture response for DOM analysis
burp_send_to_repeater(url, headers, body)

# Test XSS vectors
burp_send_to_repeater(url, headers, body)  # with XSS payload in params

# Test CORS
burp_send_to_repeater(url, headers={"Origin": "https://evil.com"}, body)
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-CLNT-01 | DOM XSS — document.write, innerHTML, outerHTML, eval()-family sinks |
| WSTG-CLNT-02 | JavaScript execution — evaluating attacker-controlled JS in page context |
| WSTG-CLNT-03 | HTML injection — attacker HTML rendered in page (iframe, img, script) |
| WSTG-CLNT-04 | Client-side URL redirect — open redirect via `window.location`, anchor `href` |
| WSTG-CLNT-05 | CSS injection — exfiltrate data via CSS selectors and background-image |
| WSTG-CLNT-06 | Client-side resource manipulation — attacker controls script/src, iframe/src loading |
| WSTG-CLNT-07 | Cross-origin resource sharing (CORS) — overly permissive `Access-Control-Allow-Origin` |
| WSTG-CLNT-08 | Clickjacking — missing `X-Frame-Options` or CSP `frame-ancestors` |
| WSTG-CLNT-09 | WebSockets — CSWSH, missing origin validation, WS message injection |
| WSTG-CLNT-10 | Web Messaging (PostMessage) — missing origin validation in `addEventListener` |
| WSTG-CLNT-11 | Browser storage — sensitive data in localStorage/sessionStorage |
| WSTG-CLNT-12 | Third-party functionality — external scripts/iframes without SRI or integrity checks |
| WSTG-CLNT-13 | Reverse tabnabbing — `target="_blank"` without `rel="noopener noreferrer"` |
| WSTG-CLNT-14 | Client-side prototype pollution — `__proto__`, `constructor` gadget chains |

## Attack Playbook

### DOM XSS (WSTG-CLNT-01)
1. Identify sinks: search source code for `innerHTML`, `document.write`, `eval`, `setTimeout(string)`, `Function(string)`
2. Trace source to sink: which user-controlled input (URL hash, search params, postMessage) reaches the sink?
3. Test with `"><img src=x onerror=alert(1)>` in the identified source parameter
4. If headed browser available → `browser_screenshot(url)`, verify with `browser_crawl()`
5. If no sink found → test prototype pollution (see below)
6. Chain: DOM XSS → `document.cookie` exfil → session steal → ATO

### Prototype Pollution (WSTG-CLNT-14)
1. Test with `__proto__[test]=true` in JSON body, URL query, or web message
2. Check if response or client-side behavior changes (pollution propagates)
3. If client-side → find a gadget that reads the polluted property and triggers XSS
4. Common gadgets: jQuery `$.extend`, lodash `_.merge`, Dojo `mixin`, `Object.assign`
5. Chain: prototype pollution → gadget XSS → cookie theft

### CORS (WSTG-CLNT-07)
1. Send request with `Origin: https://evil.com` → check if `Access-Control-Allow-Origin: https://evil.com` is reflected
2. Test with `Origin: null` (iframe sandbox) → if reflected, any sandboxed page can read
3. Test with `Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` → sensitive data readable
4. Chain: CORS → read authenticated API response → extract user data

### Web Messaging (WSTG-CLNT-10)
1. Search for `addEventListener("message",` or `onmessage` in JS source
2. Test origin validation: `postMessage(payload, "*")` → check if receiver validates `event.origin`
3. If no origin check → craft an attacker page that sends arbitrary messages
4. Chain: postMessage XSS → DOM manipulation → cookie theft

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Testing XSS only in URL params (ignoring DOM sinks)** | DOM XSS via postMessage or hash fragment won't appear in server logs |
| **Skipping CSP analysis before XSS testing** | A strong CSP blocks even successful injection — check CSP header first |
| **Testing CORS without `withCredentials`** | CORS with wildcard origin + no credentials is not exploitable |
| **Not closing the browser session** | Run `browser_act(engagement_id, "close")` after testing to free resources |
| **Not checking localStorage after XSS** | If XSS succeeds but no cookies → check localStorage for tokens |

## Evidence Requirements
- [ ] Full URL with XSS payload (no base64/encoding obfuscation in PoC)
- [ ] Browser alert() or DOM modification screenshot
- [ ] CSP headers document
- [ ] WSTG CLNT test ID
- [ ] Sink-to-source trace (which input reaches which sink)

## Phase Gates
- Phase 3 (INFO-GATHERING): Identify client-side attack surface
- Phase 6 (HUNT): Test each client-side vector
- Phase 8 (EXPLOIT): Demonstrate impact (cookie theft, phishing)
