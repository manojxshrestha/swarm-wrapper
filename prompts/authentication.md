# Authentication Testing — Swarm Workflow

## MCP Tools
- `get_wstg_test(category="auth")` — AuthN test cases (WSTG-ATHN-*)
- `search_wstg("authentication")` — Find relevant auth test procedures
- `get_witness_payloads("auth")` — Auth-specific test payloads

## Key Test Categories
1. Credential transport (plaintext, weak TLS)
2. Account enumeration (timing, error messages)
3. Brute-force resistance (rate limiting, lockout)
4. Password quality policy
5. Remember-me / "stay logged in" token strength
6. Browser cache poisoning (credential caching)
7. Password reset / forgot password logic flaws
8. Multi-factor authentication bypass
9. OAuth/SSO integration weaknesses

## Burp Workflow
```bash
burp_send_to_repeater(url, headers, body)
burp_send_to_intruder(url, positions=["username", "password"], payloads=["/usr/share/wordlists/auth-usernames.txt", "/usr/share/wordlists/rockyou-10k.txt"])

# For OAuth flows, capture and replay tokens
burp_send_to_repeater("https://idp.example.com/oauth/token", headers, body)
```

## WSTG Test Map

| ID | What It Covers |
|----|----------------|
| WSTG-ATHN-01 | Credential transport over unencrypted channels |
| WSTG-ATHN-02 | Default credentials and common username/password pairs |
| WSTG-ATHN-03 | Weak lockout policy (no rate limit, no account lockout) |
| WSTG-ATHN-04 | Bypassing authentication schema (forced browsing, direct page access) |
| WSTG-ATHN-05 | Vulnerable remember-me / persistent auth tokens |
| WSTG-ATHN-06 | Browser cache weakness (cached auth pages) |
| WSTG-ATHN-07 | Weak password policy (min length, complexity, rotation) |
| WSTG-ATHN-08 | Weak security question/answer (guessable, no brute-force protection) |
| WSTG-ATHN-09 | Weak password change or reset functionality (predictable tokens, email-only validation) |
| WSTG-ATHN-10 | Weaker authentication in alternative channel (mobile vs web, API vs UI auth gaps) |
| WSTG-ATHN-11 | Multi-factor authentication testing (bypass, replay, brute-force OTP) |

## Attack Playbook

### Account Enumeration (WSTG-IDNT-04)
1. Send login with valid username + wrong password → check error message vs invalid username
2. Send password reset for valid vs invalid → check timing difference (use burp Intruder with `$` for variable positions)
3. Send registration for existing username → compare response to new username
4. Run each test 3x to filter jitter; consistent 50ms+ diff = enumeration

### Password Reset (WSTG-ATHN-09)
1. Request reset → capture reset token from email/URL/response body
2. Analyze token entropy: length, character set, timestamp correlation
3. Test token reuse: use token, then use same token again
4. Test token prediction: request 10+ tokens, look for pattern
5. Test direct manipulation: modify email/username in reset request body
6. Chain: password reset token prediction → reset any user's password → account takeover

### MFA Bypass (WSTG-ATHN-11)
1. Complete auth step 1 (password) → capture step 2 request
2. Skip step 2: directly access authenticated resources after step 1
3. Replay old MFA token: use previously captured valid token
4. Brute force MFA: try common codes (000000, 123456), rate-limit check
5. OAuth MFA bypass: initiate OAuth flow, complete auth without MFA prompt
6. Chain: MFA bypass → access to protected data without valid 2FA

### Credential Stuffing (WSTG-ATHN-03)
1. Use common breached credential pairs for identified email format
2. Rate limit: spray 1 attempt per account, wait, repeat (bypasses lockout)
3. Report success rate: e.g., "3/500 accounts had valid breached passwords"
4. Chain: valid credential → escalate via IDOR or privilege escalation

## Anti-Patterns

| Pitfall | Why It Wastes Time |
|---------|-------------------|
| **Brute-forcing passwords without rate-limit check first** | Test lockout policy first; if no lockout, then spray. |
| **Testing OAuth flows without Burp proxy** | OAuth redirects happen in browser; always capture with Burp or the headed browser. |
| **Overlooking response timing for enumeration** | Even identical error messages can differ by 20-100ms; measure with burp Intruder. |
| **Not testing password reset link expiry** | A predictable token is still a bug; test that expired tokens are invalidated. |
| **Skipping MFA force-enrollment bypass** | Test if MFA can be skipped during initial account setup. |

## Evidence Requirements
- [ ] Screenshots of login/registration/flows
- [ ] Rate limiting test results (X attempts in Y seconds)
- [ ] Password reset token analysis (if applicable)
- [ ] MFA bypass proof (with and without MFA)
- [ ] WSTG ATHN test ID
- [ ] Timing differential measurement (if applicable)

## Phase Gates
- Phase 3 (INFO-GATHERING): Identify all auth mechanisms
- Phase 6 (HUNT): Test each auth vector systematically
- Phase 8 (EXPLOIT): Chain auth bypass to privilege escalation
