---
description: "Pipeline Phase 3b — OSINT: email & subdomain enumeration via theHarvester"
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# OSINT — Phase 3b

Run theHarvester for email and subdomain OSINT against the target domain.

## HARD RULES — DO NOT VIOLATE

1. **NEVER install tools.** theHarvester is pre-installed at `~/theHarvester/`. Never run `pip install`, `go install`, or any package manager.
2. **ALWAYS use `"$HOME/swarm/scripts/tools/phase-osint.sh"`.** Run `bash "$HOME/swarm/scripts/tools/phase-osint.sh" <domain>` — not raw tool binaries.

## Workflow

### Step 1: Run OSINT script

```bash
bash "$HOME/swarm/scripts/tools/phase-osint.sh" <domain>
```

Runs theHarvester with two source sets:
- **Subdomains**: crtsh, rapiddns, subdomaincenter, hackertarget, otx, urlscan, dnsdumpster, bevigil, certspotter, bufferoverun, threatcrowd, virustotal, waybackarchive, commoncrawl, securityTrails, chaos, fullhunt, projectdiscovery, robtex
- **Emails**: yahoo, duckduckgo, hunter, intelx, haveibeenpwned, hudsonrock, leakix, leaklookup, mojeek, tomba

Output goes to `$HOME/swarm/engagements/recon/<domain>/osint/`.

### Step 2: Parse results

| File | Content |
|------|---------|
| `osint/theharvester_subdomains.json` | Raw theHarvester JSON (subdomain sources) |
| `osint/theharvester_emails.json` | Raw theHarvester JSON (email sources) |
| `osint/subdomains.txt` | Deduplicated unique subdomains |
| `osint/emails.txt` | Deduplicated unique emails |

### Step 3: Save deliverable

```
save_deliverable(
  engagement_id='<eid>',
  deliverable_type='osint_analysis',
  content=<json or markdown summary of emails + subdomains>,
  producer_agent='osint'
)
```

### Step 4: Track

```
track_tool(tool_name='osint', status='run', notes='theHarvester — emails + subdomains')
```

## Output

- Files in `$HOME/swarm/engagements/recon/<domain>/osint/`
- Subdomains feed into Phase 4 (RECON)
- Emails feed into credential-attack pipeline

## Notes

- theHarvester is installed via `scripts/setup/install.sh` at `~/theHarvester/`
- Runs via `uv run` — no manual venv activation needed
- 0 results is normal for security-mature targets
