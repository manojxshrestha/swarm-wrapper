# API Security Testing

Swarm has dedicated hunt agents for API security testing spanning OWASP WSTG (APIT-01 through APIT-03) and OWASP API Security Top 10. This doc is the master reference.

## Agent Index

| Agent | Focus | WSTG | OWASP API Top 10 |
|-------|-------|------|-------------------|
| `hunt-api-misconfig` | BOLA/BFLA, mass assignment, JWT, CORS, rate limiting, versioning, OData, Swagger | WSTG-APIT-01 | API1-API10 |
| `hunt-grpc` | gRPC — server reflection, auth bypass, proto leakage, Web proxy injection | WSTG-APIT-02 | API2, API5, API8 |
| `hunt-graphql` | GraphQL introspection, batching, depth DoS, auth bypass, IDOR | WSTG-APIT-01 | API1, API3, API5 |
| `hunt-soap` | SOAP/XML — WSDL, XXE, XML bomb, WS-Security, action spoofing, XPath injection | WSTG-APIT-03 | API4, API6 |
| `hunt-idor` | BOLA/IDOR — sequential IDs, UUIDs, batch, auth-header mismatch, mass listing | WSTG-ATHZ-01 | API1 |
| `hunt-brute-force` | Rate limit bypass, credential stuffing, OTP brute, ReDoS | WSTG-ATHN-03 | API4 |
| `hunt-http-param-pollution` | Duplicate params, JSON key duplication, Content-Type confusion, method override | WSTG-INPV-04 | API6 |
| `hunt-ssrf` | Server-side request forgery, cloud metadata SSRF | WSTG-INPV-19 | API8 |
| `hunt-sqli` | SQL injection (classic, blind, time-based) | WSTG-INPV-05 | API6 |
| `hunt-xss` | Reflected/stored/DOM XSS, CSP bypass | WSTG-INPV-01 | API6 |
| `hunt-ssti` | Template injection (Jinja2, Twig, Freemarker) | WSTG-INPV-18 | API6 |
| `hunt-xxe` | XML External Entities (in-band, blind OOB, SSRF) | WSTG-INPV-20 | API6 |
| `hunt-cors` | CORS — origin reflection, wildcard with credentials, preflight bypass, null origin | WSTG-CLNT-07 | API6, API8 |
| `hunt-csrf` | CSRF — token bypass, SameSite bypass, JSON Content-Type, multi-step | WSTG-SESS-05 | API6 |
| `hunt-websocket` | WebSocket — message injection, origin bypass, CSWSH, proxy misconfig | WSTG-CLNT-09 | API2, API5 |
| `hunt-mass-assignment` | Mass assignment — extra fields, admin flag escalation, framework-specific | WSTG-BUSL-01 | API3 |

## OWASP WSTG API Test Categories

### WSTG-APIT-01 — Web API Testing (General)

**Agents:** `hunt-api-misconfig`, `hunt-graphql`

General API security covering all protocol-agnostic vulnerabilities:

Key techniques:
- Introspection query: `{ __schema { types { name fields { name } } } }`
- Batching attacks: send N login mutations in 1 HTTP request to bypass rate limits
- Alias abuse: multiple copies of same query in one request to hit resolver limits
- Depth-based DoS: deeply nested query exhausts resolver stack
- Auth bypass: `node(id:)` Relay resolver that checks auth at top level but not on nested relations
- IDOR via GraphQL: substitute victim IDs in query variables

### WSTG-APIT-02 — REST / gRPC API Testing

**Agents:** `hunt-api-misconfig`, `hunt-grpc`

Covers all REST-specific misconfigurations including:
- BOLA (API1) — object ID substitution in paths, query params, headers, bodies
- BFLA (API5) — HTTP verb tampering, sibling-route pattern, admin function as regular user
- Mass assignment — extra fields in JSON body (`isAdmin`, `role`, `permissions`)
- Excessive data exposure (API3) — full model serialization leaks `password_hash`, `ssn`, `api_key`
- Rate limiting bypass (API4) — IP spoofing, Content-Type rotation, session cycling, GraphQL batching
- API versioning attacks — downgrade to `/v1/` to bypass auth/validation added in `/v2/`
- Server-side prototype pollution — `__proto__` injection in JSON body
- CORS misconfig — reflected origin + credentialed access

### WSTG-APIT-03 — SOAP/XML Testing

**Agent:** `hunt-soap`

Key techniques:
- WSDL discovery — `/service?wsdl`, `?singleWsdl`, `.asmx?wsdl`, `.svc?wsdl`
- XXE via SOAP — in-band file read, blind OOB exfil, SSRF to cloud metadata
- XML bomb (billion laughs) — entity expansion DoS
- WS-Security bypass — missing security header, expired timestamps, username token injection
- XML signature wrapping (XSW) — forged element before/after signed element
- SOAPAction spoofing — change operation without altering body
- XML injection — element injection, CDATA, namespace injection
- XPath injection — `' or 1=1 or 'a'='a` bypass

## OWASP API Security Top 10 — 2023

| # | Category | Swarm Agent | Detection Pattern |
|---|----------|-------------|-------------------|
| API1 | Broken Object Level Authorization | `hunt-api-misconfig`, `hunt-idor` | Substitute object ID across users/tenants |
| API2 | Broken Authentication | `hunt-brute-force`, `hunt-auth-bypass` | Weak JWT, no rate limit on login, enum |
| API3 | Broken Object Property Level Authorization | `hunt-api-misconfig` | Mass assignment, excessive data exposure |
| API4 | Unrestricted Resource Consumption | `hunt-brute-force`, `hunt-api-misconfig` | No rate limiting, pagination abuse |
| API5 | Broken Function Level Authorization | `hunt-api-misconfig` | Admin function accessible as low-priv user |
| API6 | Unrestricted Access to Sensitive Business Flows | `hunt-http-param-pollution`, various | HPP, parameter tampering, flow bypass |
| API7 | Server-Side Request Forgery | `hunt-ssrf` | Cloud metadata, internal network access |
| API8 | Security Misconfiguration | `hunt-api-misconfig` | CORS, exposed Swagger, debug endpoints |
| API9 | Improper Inventory Management | `hunt-api-misconfig` | Deprecated API versions, ghost endpoints |
| API10 | Unsafe Consumption of APIs | `hunt-ssti`, `hunt-sqli`, various | Injection via third-party API responses |

## Methodology — Per Class

### BOLA / IDOR

1. Create two accounts (User A, User B) at same privilege level
2. Capture User A's object IDs from all API responses
3. Replay with User B's credentials, substituting User A's IDs
4. Test all parameter locations: path, query, body, headers, GraphQL variables
5. Test all HTTP verbs on each endpoint
6. Test batch endpoints with array of IDs

### BFLA

1. Map all endpoints from OpenAPI spec, JS bundles, or crawl
2. Identify admin/internal endpoints
3. Test each with a low-privilege token
4. Try all HTTP verbs: `GET` protected but `DELETE` exposed
5. Check sibling routes: `/api/admin/users` has middleware, `/api/admin/export` may not

### Mass Assignment

1. Read OpenAPI schema for field names: `components.schemas.*`
2. Craft JSON body with extra fields: `{"name": "test", "isAdmin": true, "role": "admin"}`
3. Test on signup, profile update, and team management endpoints
4. Target fields: `role`, `isAdmin`, `permissions`, `verified`, `accountType`, `credit`

### Rate Limiting Bypass

Ordered by likelihood of success:
1. **IP spoofing headers** — `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`
2. **Content-Type rotation** — JSON blocked, form-encoded allowed
3. **Session cycling** — discard and recreate session for fresh counter
4. **Endpoint aliasing** — `/login` vs `/api/login` vs `/api/v1/login`
5. **GraphQL batching** — N login mutations in 1 request
6. **HTTP method switching** — limit on POST, not on GET/HEAD
7. **User-Agent rotation** — limit keyed to IP+UA composite
8. **IPv6 vs IPv4** — dual-stack servers may have separate counters

### Excessive Data Exposure

1. Call API endpoint and compare response fields to what UI renders
2. Look for `password_hash`, `ssn`, `api_key`, `internal_id`, `credit_card`
3. Try field-fuzzing: `?fields=all`, `?include=internal`
4. GraphQL: request fields the UI never asks for
5. Common root cause: `SELECT *` ORM queries with generic serialization

### API Versioning Downgrade

1. Probe versioned paths: `/v1/`, `/v0/`, `/legacy/`, `/beta/`, `/deprecated/`
2. Check header-based versioning: `Accept: application/vnd.target.v1+json`
3. For each older version, retest auth, input validation, rate limiting
4. Check for ghost endpoints: removed from docs but still live on server

### HTTP Parameter Pollution

1. Send duplicate params with different values: `?amount=1&amount=10000`
2. Check framework-specific parsing (last-wins vs first-wins vs array-join)
3. Try array syntax: `?role[]=user&role[]=admin`
4. Test Content-Type cross-pollution: JSON body but form-urlencoded Content-Type
5. Try duplicate JSON keys (RFC 8259 doesn't mandate handler behavior):
   - Node.js/Go/Java: last key wins
   - Python/Flask: first key wins
6. HTTP method override pollution: `X-HTTP-Method-Override: POST` on a GET request
7. Auth bypass via HPP: `?id=own_id&id=victim_id` (WAF sees first, backend parses last)

### OData Exploitation

1. Discover: `/odata/`, `/_api/`, `/api/data/v9.0/`, `/sap/opu/odata/`
2. Anonymous `$metadata` disclosure reveals full schema
3. Boolean blind extraction via `$filter=startswith(column,'prefix')`
4. Column disclosure via `$orderby` on protected columns
5. WAF bypass via `$batch multipart/mixed` (inner operations not scanned)
6. Encoded operators: `%24filter` / `%2524filter` bypass keyword rules

### NSwag / Swagger / OpenAPI

1. Probe common paths: `/swagger`, `/swagger/v1/swagger.json`, `/api-docs`
2. Discover all endpoints: `jq '.paths | keys' swagger.json`
3. Read schema fields for mass assignment: `jq '.components.schemas'`
4. Test Swagger UI injection: `?configUrl=https://evil/spec.json`
5. Check version strings for known CVEs (CVE-2018-25031, DOM XSS in 3.14.1-3.38.0)
6. Feed spec to kiterunner or Autorize for mass testing

## Source Code Analysis Patterns

### Missing Authorization (BOLA root cause)

```javascript
// VULNERABLE
const invoice = await Invoice.findById(req.params.id);

// SECURE
const invoice = await Invoice.findOne({ _id: req.params.id, userId: req.user.id });
```

### Mass Assignment

```javascript
// VULNERABLE — accepts any body field
User.update(req.body);

// SECURE — whitelists allowed fields
User.update({ name: req.body.name, email: req.body.email });
```

### Excessive Data Exposure

```python
# VULNERABLE — returns full model
return User.objects.get(id=user_id).__dict__

# SECURE — explicit field selection
return {"name": user.name, "email": user.email}
```

### Missing Versioned Auth

```python
# VULNERABLE — v1 route registered before auth middleware
router_v1 = APIRouter(prefix="/api/v1")
router_v2 = APIRouter(prefix="/api/v2", dependencies=[Depends(auth_check)])

@router_v1.get("/users")  # NO AUTH
@router_v2.get("/users")  # WITH AUTH
```

## Discovery Wordlists

### WSDL paths
```
/service?wsdl, /service.asmx?wsdl, /Service.svc?wsdl, /ws/service.wsdl,
/axis2/services/listServices, /cxf/services, /_vti_bin/Lists.asmx?wsdl
```

### Swagger/OpenAPI paths
```
/swagger, /swagger/index.html, /swagger/v1/swagger.json,
/swagger-ui, /swagger-ui.html, /api-docs, /openapi.json,
/v2/api-docs, /v3/api-docs, /docs, /redoc
```

### OData paths
```
/odata, /odata/$metadata, /_api, /_api/web,
/api/data/v9.0, /sap/opu/odata/sap/
```

### API version paths
```
/api/v1, /api/v2, /api/v0, /api/v3, /api/beta,
/api/legacy, /api/deprecated, /api/internal
```

## See Also

- `agents/registry.yaml` — All hunt agent registrations
- `.opencode/agents/hunt-api-misconfig.md` — API misconfig agent
- `.opencode/agents/hunt-graphql.md` — GraphQL testing agent
- `.opencode/agents/hunt-grpc.md` — gRPC API security agent
- `.opencode/agents/hunt-soap.md` — SOAP/XML testing agent
- `.opencode/agents/hunt-idor.md` — IDOR/BOLA agent
- `.opencode/agents/hunt-brute-force.md` — Rate limiting/brute force agent
- `.opencode/agents/hunt-http-param-pollution.md` — HPP agent
- `.opencode/agents/hunt-cors.md` — CORS misconfiguration agent
- `.opencode/agents/hunt-csrf.md` — CSRF agent
- `.opencode/agents/hunt-websocket.md` — WebSocket security agent
- `.opencode/agents/hunt-mass-assignment.md` — Mass assignment agent
- `docs/pipeline.md` — Phase 6 (hunt) pipeline flow
- `docs/summary.md` — Anchored session summary
