# Cryptography Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="crypto")` — Cryptographic test cases (WSTG-CRYP-*)
- `search_wstg("cryptography")` — Find relevant crypto test procedures

## Key Test Categories
1. Weak TLS versions (SSLv3, TLS 1.0, TLS 1.1)
2. Weak cipher suites (RC4, 3DES, CBC-mode)
3. Certificate validation issues (self-signed, expired, hostname mismatch)
4. HSTS implementation (max-age, includeSubDomains, preload)
5. Weak password hashing (MD5, SHA1, unsalted)
6. Predictable session tokens (low entropy)
7. JWT weak signing (none alg, HS256 with leaked public key)
8. HTTP vs HTTPS mixed content

## Burp Workflow
```bash
# Check TLS via proxy
burp_send_to_repeater("https://target.com/", headers)

# Analyze JWT tokens
burp_send_to_repeater(url, headers={"Authorization": "Bearer <jwt>"}, body)

# The `jwt_tool` or manual analysis:
# 1. Decode JWT payload
# 2. Check algorithm
# 3. Test none/None/NONE alg bypass
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-CRYP-01 | Weak TLS/SSL — protocols below TLS 1.2 enabled, weak cipher suites (RC4, 3DES, CBC-mode) |
| WSTG-CRYP-02 | Padding oracle — CBC-mode padding error responses leak plaintext |
| WSTG-CRYP-03 | Sensitive data sent over unencrypted channel — login form over HTTP, mixed content |
| WSTG-CRYP-04 | Weak encryption — weak password hashing (MD5, SHA1, unsalted), predictable tokens |

## Attack Playbook

### TLS Weakness (WSTG-CRYP-01)
1. Run external: `nmap --script ssl-enum-ciphers -p 443 target.com`
2. Check protocol support: TLS 1.0, 1.1 should be disabled; TLS 1.2 minimum
3. Check cipher suites: no RC4, 3DES, CBC-mode ciphers; prefer ECDHE+AES-GCM
4. Check certificate: expiration >30 days? SHA256 not SHA1? SAN covers all subdomains?
5. Chain: weak TLS → credential interception (MITM on same network)

### JWT Weakness
1. Decode JWT → check header `"alg":"none"` → modify payload → send with `alg:none`
2. Check header `"kid":"..."` → test SQLi in kid parameter, path traversal to known file
3. Check header `"jku":"..."` or `"jwk":"..."` → attacker provides own public key
4. If HS256 → brute-force secret with weakpasswords/rockyou
5. If RS256 → get public key from `/jwks.json`, `/.well-known/jwks.json` → sign HS256 with public key as secret
6. Chain: JWT bypass → impersonate any user → admin access

### Weak Hashing (WSTG-CRYP-04)
1. Extract password hash if found in config file, backup, or DB dump
2. Identify hash type by format/length: MD5 (32 hex), SHA1 (40 hex), bcrypt ($2a$...)
3. If MD5/SHA1 → feed to hashcat with rockyou.txt
4. Report cracking speed and whether password was recovered
5. Chain: weak hash → cracked password → credential reuse on other services

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Only testing TLS on port 443** | Subdomains, CDNs, API endpoints often have different TLS configs |
| **Skipping padding oracle test** | A working padding oracle decrypts any ciphertext — critical finding |
| **Testing JWT none-alg without checking if the library checks algorithm whitelist** | Many JWT libraries now default to rejecting `alg:none` |
| **Overlooking `kid` injection in JWT** | If kid is used to read a file, `../../etc/passwd` or SQLi in kid can lead to RCE |
| **Not checking for mixed content** | Page over HTTPS loading JS over HTTP = all security controls bypassed |

## Evidence Requirements
- [ ] TLS version and cipher suite (SSLabs or nmap output)
- [ ] Certificate chain (valid dates, issuer, SANs)
- [ ] HSTS header value
- [ ] JWT token decode (header+payload, redacted signature)
- [ ] WSTG CRYP test ID
- [ ] Padding oracle timing measurements (if applicable)

## Phase Gates
- Phase 3 (INFO-GATHERING): TLS/certificate audit
- Phase 6 (HUNT): Deep crypto analysis
