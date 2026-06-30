# Error Handling Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="error")` — Error handling test cases (WSTG-ERRH-*)
- `search_wstg("error handling")` — Find relevant test procedures

## Key Test Categories
1. Error code disclosure (stack traces, SQL errors, path disclosure)
2. Custom error pages bypassing security controls
3. Information leakage in error responses (API keys, DB credentials)
4. HTTP error code analysis (404 vs 403 for resource enumeration)
5. Exception handling bypass

## Burp Workflow
```bash
# Trigger errors
burp_send_to_repeater("https://target.com/api/users/'", method="GET")
burp_send_to_repeater("https://target.com/api/users/999999", method="GET")
burp_send_to_repeater("https://target.com/nonexistent.path", method="GET")

# Test malformed input errors
burp_send_to_repeater(url, headers={"Content-Type": "application/json"}, body="{invalid json}")
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-ERRH-01 | Improper error handling — verbose error messages disclosing internal paths, SQL queries, file paths |
| WSTG-ERRH-02 | Stack traces — full exception stack trace discloses internal paths, library versions, DB queries |

## Attack Playbook

### Error Code Leakage (WSTG-ERRH-01)
1. Send malformed input: `'` in param → check for SQL error with path/query info
2. Send type confusion: string where int expected → check for type error with class/stack info
3. Send oversized input: 100KB+ param → check for buffer/overflow errors
4. Send path traversal: `../../` in param → check for file system errors with paths
5. Send invalid content type: `Content-Type: text/xml` where JSON expected → check for parser errors
6. Chain: error disclosure → find DB credentials in paths → connect to DB

### Resource Enumeration via Error Codes
1. Send request to known resource → capture status code (200)
2. Send request to `/api/user/1` → capture status code
3. Send request to `/api/user/9999999` → compare status code (404 vs 403) to confirm existence vs no-access
4. Use differing status codes to enumerate valid user IDs, file paths, API endpoints
5. Chain: 403/404 differentiation → enumerate valid admin accounts

### Debug Endpoints
1. Test common debug paths: `/debug`, `/actuator`, `/actuator/health`, `/trace`, `/env`, `/beans`, `/heapdump`
2. If Spring Boot Actuator → `/actuator/env` may leak DB passwords, API keys
3. Test `/phpinfo.php`, `/info.php`, `/test.php`
4. Check response for paths, passwords, env vars, API keys
5. Chain: `/actuator/env` → find AWS keys → cloud account takeover

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Only testing error handling on main pages** | APIs expose the most detailed errors; test every discovered endpoint |
| **Assuming all `500` responses are the same** | Capture the full response body — one 500 may contain a full stack trace, another just "Error" |
| **Not testing error handling with authenticated vs unauthenticated requests** | The same error may disclose more info when authenticated |
| **Skipping heapdump analysis** | Spring Boot `/heapdump` contains ALL in-memory data including credentials |
| **Not checking for verbose errors in JSON/XML APIs** | JSON APIs often return structured errors with field names, types, constraints |

## Evidence Requirements
- [ ] Full error response (redact secrets before capture)
- [ ] Stack trace or debug output screenshot
- [ ] Enumeration timing differences documented
- [ ] WSTG ERR test ID
- [ ] Error triggering input (malformed payload used)

## Phase Gates
- Phase 3 (INFO-GATHERING): Document error behavior
- Phase 6 (HUNT): Systematically trigger errors per endpoint
