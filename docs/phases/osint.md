# Phase 3b: OSINT (Offensive Intelligence)

Active OSINT gathering — identity fabric mapping, social enumeration, breached credential lookup, organizational footprint. Runs after INTEL (Phase 3), feeds additional context into RECON (Phase 4).

---

## Objectives

- Enumerate employee identities (emails, usernames, roles)
- Search breached credential databases for exposed passwords
- Map organizational tech stack via job postings, GitHub, social media
- Discover exposed internal tools, staging servers, and test environments

---

## Dependencies

| Tool | Purpose |
|------|---------|
| Web search | Employee enumeration, org footprint |
| Breach databases | Credential leaks |
| Social media | Tech stack, employee roles, internal tool names |
| GitHub / GitLab | Exposed secrets, internal tooling, CI/CD configs |

---

## Workflow

### 1. Identity Enumeration

- Search for `@domain.com` email patterns across web/social
- Identify naming convention: `first.last`, `firstl`, `f.last`
- Build a candidate email list for credential testing

### 2. Breached Credential Lookup

- Check candidate emails against known breach databases
- Document exposed credentials (password, hash, session token)
- Flag reused passwords across corporate and personal accounts

### 3. Organizational Footprint

- Job postings → tech stack, internal tools, versions
- GitHub orgs → exposed API keys, internal repos, CI/CD configs
- Social media → employee roles, security team size, VPN/SSO vendors
- Shodan/Censys → exposed internal services, staging servers

### 4. Supply Chain Recon

- Dependency confusion opportunities (private package names)
- GitHub Actions / CI/CD pipeline exposures
- Third-party vendor integrations and their attack surface

---

## Output

Findings feed into Phase 4 (RECON) as additional scope targets and into Phase 6 (HUNT) as credential/test-user candidates.
