# Phase 1: SCOPE

Target enrollment and engagement scaffolding. Must complete before any testing.

---

## Objectives

- Register target domain(s) and scope boundaries in the engagement database
- Load engagement configuration (target, credentials, auth flow, rules)
- Verify target reachability
- Create task tree for the full engagement lifecycle
- Scaffold output directory structure
- Save scope metadata deliverables for downstream phases

---

## Steps

### 1. Register Scope Domains

Use `register_scope()` (single) or `register_scope_batch()` (multiple) to enroll domains.

```python
register_scope(engagement_id, domain="try.discourse.org", domain_type="app", eligibility="eligible")
```

Domain types: `app`, `api`, `auth_provider`, `cdn`, `third_party`, `wildcard_domain`, `android_app`, `ios_app`

Eligibility: `eligible`, `ineligible`, `critical`, `high`, `medium`, `none`

For Android/iOS apps, provide `app_id` (e.g., `"com.truecaller"` / `"448142450"`) and `notes`.

### 2. Load Engagement Configuration

```python
load_engagement_config(engagement_id, config_yaml)
```

Config YAML defines:
- **target** — URL, description
- **credentials** — username, password, type (form/oauth/header/cookie)
- **auth_flow** — login_url, signup_url, verification_url, selectors
- **scope** — in_scope, out_of_scope
- **rules** — focus (prioritized features), avoid (do-not-test areas)
- **browser** — headless, user_agent, viewport

### 3. Verify Target Reachability

Simple connectivity test using `curl`:

```bash
curl -sI "https://<domain>" --connect-timeout 5
```

Check for HTTP response. If unreachable, investigate (offline, non-web, DNS, firewall).

### 4. Create Task Tree

```python
create_task_tree(engagement_id)
```

Creates the hierarchical task structure: Phase -1 (Code Analysis) → Phase 0 (Scope) → Phase 1 (Auth) → ... → Phase 12 (Report).

### 5. Scaffold Directory Structure

Created by `scripts/tools/phase-scope.sh`:

```
$RECON_BASE/<domain>/
├── scope/          # target.txt, started.txt
├── intel/          # WHOIS, cloud, spoof data
├── recon/          # subdomains, crawl, params
├── crawl/          # merged crawl output
├── subdomains/     # subdomain enumeration
├── secrets/        # secret discovery
├── directories/    # directory bruteforce
├── vhost/          # vhost fuzzing
├── evidence/       # PoC screenshots, HAR
└── screenshots/    # page screenshots
```

### 6. Write Target Metadata

```bash
echo "<domain>" > scope/target.txt
date -I > scope/started.txt
```

### 7. Register Scope in Findings Database

```python
findings_init(engagement_id, client, etype="web", scope)
findings_add_host(engagement_id, hostname=domain, role="target")
```

### 8. Save Scope Deliverables

```python
save_deliverable(engagement_id, "scope_config", content, "scope")
```

---

## Rules

### Focus Rules (PRIORITIZE)

Features or areas to test aggressively. Examples:
- SSRF to private IP ranges
- Stored XSS (public-facing)
- Privilege escalation
- Multi-tenant data access
- RCE
- Database access / backup exposure

### Avoid Rules (DO NOT test)

Paths, features, or endpoints to avoid. Examples:
- Other instances besides the target
- Rate-limited login endpoints (non-critical)
- Third-party services outside scope

---

## Gate

```python
phase_gate_check(engagement_id, phase_completed=0)
```

Gate passes when:
- At least one scope domain registered
- Engagement config loaded (if YAML provided)
- Task tree created
- Target reachable (or offline documented)

---

## Output

| Artifact | Location | Description |
|----------|----------|-------------|
| target.txt | `scope/target.txt` | Domain name |
| started.txt | `scope/started.txt` | ISO date of scope start |
| scope_config | deliverable | Structured scope data for downstream phases |

---

## Script

```bash
bash $HOME/swarm/scripts/tools/phase-scope.sh <domain>
```
