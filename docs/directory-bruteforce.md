---
title: Directory Bruteforce (dirbrute)
nav_order: 6
description: AI-driven directory bruteforcing — intent-based ffuf with decision-making, not auto-scanning.
---

# Directory Bruteforce — `dirbrute`

## Overview

Dirbrute is an **AI-driven directory bruteforcing system**, NOT an auto-scanner. The AI decides which hosts to scan, which intent to use, what profile, and when to stop. Pipeline scripts never invoke it automatically.

**Key principles:**
- AI decides host-by-host, one at a time
- No parallel bruteforcing
- No recursion, no mega-wordlists
- Tech-matched intents instead of blanket scanning
- Structured evidence output for downstream agents

---

## Pipeline Position

| Phase | Role | Trigger |
|-------|------|---------|
| **Phase 4 — Recon** | **Primary** | After live host discovery + tech fingerprint. For each host with unknown surface, AI decides whether to dirbrute. |
| **Phase 5 — Surface** | **Secondary** | High-priority host with thin endpoint map. Rerun with deeper profile + extension targeting. |
| **Phase 6 — Hunt** | **On-demand** | A specific hunter needs path discovery. `task(subagent_type="dirbrute")`. |

---

## How It Works

```
Phase 4:
  1. Subdomain enum → live host discovery → tech fingerprint (httpx)
  2. AI iterates hosts:
     a. Check: web server? already scanned? surface known? rate-limited?
     b. Match tech → intent (IIS→iis, WordPress→wordpress, etc.)
     c. Assess criticality → profile (light/standard/deep)
     d. Write scan_plan.json
     e. Dry-run to confirm budget
     f. Execute: bash dir_bruteforce.sh --plan <file>
     g. Read critical_exposure.txt + interesting_surface.txt
     h. Add paths to endpoint map
     i. Critical finds? → log finding, consider deep scan

Phase 5:
  3. If endpoint map thin on high-priority host → rerun deeper

Phase 6:
  4. task(subagent_type="dirbrute") → targeted path discovery
```

Results feed into the endpoint map for Phase 6 hunters and into findings for critical exposures (`.git`, `.env`, `backup.zip`, etc.).

---

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| **Script** | `scripts/tools/dir_bruteforce.sh` | ffuf wrapper — scan plan execution, evidence, reports |
| **Skill** | `skills/dirbrute/SKILL.md` | Methodology documentation (source of truth) |
| **Agent** | `.opencode/agents/dirbrute.md` | Subagent — produces scan plans, instructs main agent |
| **Wordlists** | `wordlists/dirbust/` (23 files) | Curated wordlists per tech stack |
| **Registry** | `agents/registry.yaml` | Registered for Phase 6 dispatch |

---

## Intents

| Intent | Tech | Wordlists |
|--------|------|-----------|
| `default` | Unknown/generic | common, admin-panels, sensitive, backup |
| `api` | REST/GraphQL | default + api-endpoints, graphql, swagger |
| `wordpress` | WordPress | default + wp-fuzz |
| `java` | Java/Tomcat/Spring | default + Apache-Tomcat |
| `oauth` | OAuth/SSO | default + oauth |
| `iis` | IIS/ASP.NET | default + cgi-bin |
| `full` | High-value/multi-tech | ALL wordlists |
| `custom` | Explicit --wordlist flags | Whatever you specify |

## Profiles

| Profile | Budget | When |
|---------|--------|------|
| `light` | 5,000 reqs | Quick check, low-value host |
| `standard` | 50,000 reqs | Normal host with attack surface |
| `deep` | 150,000 reqs + ext scan | Critical host, before exploitation |

---

## Output

All output under `${RECON_BASE}/<domain>/directories/`:

| File | What it contains |
|------|-----------------|
| `critical_exposure.txt` | `.git/`, `.env`, `heapdump`, `backup.zip`, config leaks |
| `interesting_surface.txt` | `/admin`, `/graphql`, `/api/`, `/actuator`, etc. |
| `results_summary.md` | Human-readable overview |
| `evidence/<domain>/results.json` | All hits as JSON |
| `evidence/<domain>/scan_meta.json` | Run metadata |
| `evidence/<domain>/robots.txt` | robots.txt + sitemap |

---

## Reference

```bash
# Scan plan mode (preferred)
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh --plan /tmp/scan_plan.json

# Single host mode
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh --url http://target.com --intent api --profile standard

# Always dry-run first
bash $HOME/swarm/scripts/tools/dir_bruteforce.sh --plan /tmp/scan_plan.json --dry-run
```

## Anti-Patterns

- **No raft-large wordlists** — 100K+ lines exhaust budgets immediately
- **No recursive depth scanning** — combinatorial explosion
- **No blanket extension fuzzing** — use `--ext-profile` (deep only)
- **No scan every subdomain** — pick hosts with attack surface
- **No parallel scanning** — one host at a time
- **No auto-invocation** — AI decides explicitly
