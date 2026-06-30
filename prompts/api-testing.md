# API Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="api")` — OWASP API Security Top 10 test procedures
- `search_wstg("api")` — Find relevant API test cases
- `get_witness_payloads("api")` — Witness-generated API test payloads
- `get_waf_bypass("api")` — API-specific WAF bypass techniques

## Tool Usage

```bash
# corscanner — CORS misconfiguration detection
( source "$TOOLS_DIR/corscanner/venv/bin/activate" && python3 "$TOOLS_DIR/corscanner/cors_scan.py" -u "$BASE_URL" ) 2>&1 | tee /tmp/corscanner.log
# Validate: check_tool_output(engagement_id, tool_name="corscanner", file_path="/tmp/corscanner.log")

# smuggler — HTTP request smuggling detection
( source "$TOOLS_DIR/smuggler/venv/bin/activate" && python3 "$TOOLS_DIR/smuggler/smuggler.py" -u "$URL" ) 2>&1 | tee /tmp/smuggler.log
# Validate: check_tool_output(engagement_id, tool_name="smuggler", file_path="/tmp/smuggler.log")
```

## Burp Workflow
```bash
# Send to Burp Repeater
burp_send_to_repeater(url, method, headers, body)
burp_send_to_intruder(url, positions=[...], payloads=[...])

# Check Burp Collaborator for OOB interactions
burp_check_collaborator(poll_id)  # returns any interactions
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-APIT-01 | GraphQL — introspection, batching attacks, alias abuse, depth-based DoS |
| WSTG-APIT-02 | REST APIs — auth bypass, method tampering, content-type manipulation, IDOR |
| WSTG-APIT-03 | SOAP/XML web services — WSDL discovery, XML injection, XXE via API |

## Attack Playbook

### API Discovery (WSTG-APIT-02)
1. Test common API doc paths: `/api/docs`, `/swagger.json`, `/openapi.json`, `/graphql?query={__schema{types{name}}}`, `/wsdl`, `/api/v1/`
2. Check response headers for `X-API-Endpoint`, `X-Swagger`, `X-GraphQL`
3. If GraphQL discovered → run introspection query for full schema
4. Brute-force API paths: use `/api`, `/v1`, `/v2`, `/internal`, `/private`
5. Document: all discovered endpoints, methods, auth requirements, content types

### API Authentication Testing (WSTG-APIT-02)
1. Call each discovered endpoint WITHOUT auth header → check for 200/403 (should be 401)
2. Test auth header variants: `Authorization: Bearer`, `X-API-Key`, `X-Auth-Token`, cookie
3. Test expired token → should be 401, not 200
4. Test revoked token → should be 401
5. Test with wrong format: `Authorization: Bearer invalid`
6. Chain: missing auth on internal API → access admin functions without credentials

### GraphQL (WSTG-APIT-01)
1. Introspection query: `{__schema{types{name,fields{name,args{name,type{name}}}}}}`
2. Test batching attack: send multiple queries in single request (rate limit bypass)
3. Test alias abuse: `{a:user(id:1){name} b:user(id:2){name} c:user(id:3){name}}`
4. Test depth-based DoS: nested queries that cause exponential response growth
5. Test auth bypass in resolvers: query data that requires auth without auth header

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Only testing REST, skipping GraphQL endpoints** | GraphQL often has different auth/rate-limit than REST on the same app |
| **Testing API endpoints without documenting methods first** | A POST-only endpoint will never respond to GET |
| **Not checking response size for data exposure** | Look for full user objects when only username was requested |
| **Skipping rate-limit testing on write endpoints** | Creation endpoints (POST/PUT) are where rate-limit abuse actually matters |
| **Overlooking API version headers** | Old API versions often have weaker auth |

## Evidence Requirements
- [ ] Full request/response pair (with redacted auth headers)
- [ ] Burp Repeater screenshot showing the exploit
- [ ] WSTG test ID and category documented
- [ ] CVSS 3.1 score with vector string
- [ ] API endpoint map (all discovered endpoints + methods)

## Phase Gates
- Phase 3 (INFO-GATHERING): Map all API endpoints, document auth mechanisms
- Phase 5 (SURFACE): Tag each endpoint with tested categories
- Phase 6 (HUNT): Execute per-endpoint test procedures
- Phase 8 (EXPLOIT): Reproduce and chain findings
- Phase 11 (VALIDATE): Re-run all PoCs
