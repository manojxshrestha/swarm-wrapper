# Identity Management Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="identity")` — Identity test cases (WSTG-IDNT-*)
- `search_wstg("identity")` — Find relevant identity test procedures

## Key Test Categories
1. User registration (weak email verification, self-registration admin)
2. Account provisioning (role escalation on signup)
3. Username enumeration (timing, error messages)
4. Identity provider federation (SAML, OAuth, OIDC)
5. Account deactivation/recovery
6. Guest account access
7. Service account vs user account boundaries

## Burp Workflow
```bash
# Test registration
burp_send_to_repeater(url, headers, body={"role": "admin"})  # mass assignment test

# Test email verification bypass
burp_send_to_repeater(url, headers, body)  # directly access authenticated endpoints

# Test account enumeration
burp_send_to_repeater("https://target.com/api/users/exists", headers, body={"email": "existing@test.com"})
burp_send_to_repeater("https://target.com/api/users/exists", headers, body={"email": "nonexistent@test.com"})
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-IDNT-01 | Role definitions — are application roles properly defined and enforced (user vs admin)? |
| WSTG-IDNT-02 | User registration process — self-registration allows role manipulation or weak verification |
| WSTG-IDNT-03 | Account provisioning — user creation by admins has consistent privilege assignment |
| WSTG-IDNT-04 | Account enumeration and guessability — error messages and timing distinguish valid from invalid |
| WSTG-IDNT-05 | Weak or unenforced username policy — predictable patterns allow user enumeration |

## Attack Playbook

### Registration Weakness (WSTG-IDNT-02)
1. Start registration → intercept POST → add `"role": "admin"` or `"is_admin": true`
2. Complete registration → check if admin privileges were granted
3. Test email verification bypass: skip verification link, directly access authenticated pages
4. Test duplicate registration: register same email twice → second should fail
5. Test temporary email: register with `*@tempmail.com` → should be rejected or flagged
6. Chain: mass assignment in registration → all new accounts as admin → full system compromise

### Federation Weakness
**SAML:**
1. Capture SAML response → modify assertion attributes (Email, Role, NameID)
2. Test signature stripping: remove `<ds:Signature>` → if no signature required, impersonate any user
3. Test replay: use same SAML response twice → second login should fail (if no ReplayAttack protection)
4. Test recipient check: modify `Destination` URL → send SAML response to different endpoint
5. Chain: SAML signature bypass → impersonate admin user → full access

**OAuth/OIDC:**
1. Test CSRF in OAuth flow: no `state` parameter → attacker initiates flow, intercepts code
2. Test code replay: use same authorization code twice → second should fail
3. Test redirect URI: modify redirect from `https://app.com/callback` to `https://evil.com/callback`
4. Chain: OAuth CSRF → attacker links their social account to victim's account → permanent access

### Account Enumeration (WSTG-IDNT-04)
1. Register with existing email → compare error vs new email
2. Password reset for existing vs non-existing → compare response body and timing
3. Login for existing vs non-existing → compare error text, timing, status code
4. API endpoint: `GET /api/users/exists?email=test@test.com`
5. Chain: enumerate valid emails → password spray on confirmed users

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Testing only direct registration (ignoring social/OAuth signup)** | OAuth signup flow often bypasses application-level checks and grants immediate access |
| **Skipping SAML response signature verification** | SAML without signature verification = instant admin impersonation |
| **Not testing OAuth `state` parameter** | Missing `state` allows CSRF on account linking — attacker links their social account to your account |
| **Testing email verification but not testing direct URL access** | Email verification is useless if the API endpoint bypasses it |
| **Assuming service accounts can't be exploited** | Service accounts with user-level access can perform user actions without audit trail |

## Evidence Requirements
- [ ] Registration flow screenshots
- [ ] Role/privilege manipulation proof
- [ ] Enumeration timing differences
- [ ] WSTG IDNT test ID
- [ ] OAuth/SAML assertion intercept (if applicable)

## Phase Gates
- Phase 3 (INFO-GATHERING): Map identity providers and flows
- Phase 6 (HUNT): Test each identity management vector
