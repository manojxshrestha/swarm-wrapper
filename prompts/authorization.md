# Authorization Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="authz")` — AuthZ test cases (WSTG-ATHZ-*)
- `search_wstg("authorization")` — Find relevant authz test procedures
- `get_witness_payloads("authz")` — AuthZ test payloads

## Key Test Categories
1. IDOR (Insecure Direct Object Reference) — sequential/UUID enumeration
2. Horizontal privilege escalation (UserA → UserB resources)
3. Vertical privilege escalation (user → admin endpoints)
4. Mass assignment / parameter tampering on roles
5. Multi-tenant data isolation breaches
6. HTTP method override for authz bypass

## Burp Workflow
```bash
# Capture authenticated session for each role
burp_send_to_repeater(url, headers={"Cookie": "session=userA"}, body)

# Test with modified object IDs
burp_send_to_repeater("https://api.example.com/users/1001/profile", headers)

# Test admin functions as regular user
burp_send_to_repeater("https://admin.example.com/console/users", headers)
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-ATHZ-01 | Insecure direct object references — sequential/UUID/hashed ID enumeration without ownership check |
| WSTG-ATHZ-02 | Bypassing authorization schema — forced browsing, direct page access, parameter manipulation |
| WSTG-ATHZ-03 | Privilege escalation — user accesses admin functions via role parameter manipulation |
| WSTG-ATHZ-04 | Insecure direct object references (API context) — IDOR across REST/GraphQL endpoints |
| WSTG-ATHZ-05 | OAuth and authorization weaknesses — token scope bypass, authorization code misuse |

## Attack Playbook

### IDOR (WSTG-ATHZ-01/04)
1. Create two accounts (UserA, UserB) with different data
2. Capture UserA's authenticated request to their resource → modify ID to UserB's resource
3. If sequential IDs → iterate IDs in burp Intruder
4. If UUID/hashed IDs → check if UUID is guessable (timestamp-based, sequential component)
5. Test in URL path, query param, POST body, header, cookie
6. Chain: IDOR → access PII → exfiltrate full user database

### Vertical Privilege Escalation (WSTG-ATHZ-03)
1. Create user + admin accounts; capture admin session cookie
2. Send user-level request → add admin-cookie or role parameter (`"admin":true`, `"group":"admin"`)
3. Test hidden admin parameters: `is_admin`, `access_level`, `group_id`, `role`
4. Test admin endpoint access with user cookie: `/admin/console`, `/api/v1/admin/users`
5. Test HTTP method smuggling: `GET /admin/users` → `PUT /admin/users` with user cookie
6. Chain: priv-esc → admin access → create backdoor admin account

### Mass Assignment
1. Register user → intercept registration POST → add `"is_admin": true` or `"role": "admin"`
2. Update profile → intercept PUT → add `"credits": 999999` or `"balance": 0`
3. Common parameters to test: `role`, `is_admin`, `admin`, `permissions`, `group`, `type`, `access_level`, `plan`, `tier`
4. Chain: mass assignment → admin role → full system access

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Testing IDOR with only one account** | You need two accounts (or one account + known victim ID) to prove true IDOR |
| **Only testing IDOR in URL params** | Also test in POST body, JSON body, headers, cookies, and custom headers (`X-User-ID`) |
| **Skipping UUID-based IDOR because "it's random"** | Many UUIDv1 implementations are time-sequenced and predictable within a window |
| **Not testing mass assignment on account creation** | It's more common during signup than profile update |
| **Overlooking multi-tenant boundaries** | Tenant ID in JWT claims, custom header, or subdomain — test all three |

## Evidence Requirements
- [ ] Two accounts (low+high privilege) request/response pairs
- [ ] Direct object reference manipulation proof
- [ ] WSTG AUTHZ test ID documented
- [ ] Role/privilege escalation payload shown

## Phase Gates
- Phase 6 (HUNT): Map all protected endpoints, test each role
- Phase 8 (EXPLOIT): Demonstrate data access/exfiltration
