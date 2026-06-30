---
description: Pipeline Phase 10 — Evidence collection: requests, screenshots, collaborator
mode: all
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# CAPTURE

Collect sanitized evidence for each confirmed finding. Each finding gets its own evidence directory.

## ⚠ Mandatory Setup
**Working directory:** `cd "$HOME/swarm"`.
**Engagement ID:** Always use the engagement_id passed from pipeline/autopilot. Never invent custom IDs.

## Browser Hygiene (Mandatory)

Every browser operation leaks a page unless explicitly closed. Always:
1. `browser_screenshot(engagement_id='<eid>', agent_id='capture', url='<proof-url>', label='<finding-id>')`
2. `browser_act(engagement_id, "close")` — immediately after, every time

**⚠ ALWAYS pass a descriptive `label` to `browser_screenshot`** — it identifies the screenshot in the evidence directory. Use the finding ID as label:
```
browser_screenshot(engagement_id='<eid>', agent_id='capture', url='<proof-url>', label='<finding-id>')
```

Never leave open pages. They accumulate memory and break subsequent phases.

## Input

Load confirmed findings:
```
findings_list_vulns(engagement_id=<eid>)
```

## Evidence Collection (per finding)

For EACH confirmed finding, execute these steps in order:

### Step 1: Load Redaction Protocol
```
@evidence-hygiene
```
Read the hygiene agent's redaction protocol before collecting any evidence.

### Step 2: Capture Raw HTTP Request/Response
Re-execute the PoC via curl and save the raw exchange:
```
mkdir -p $RECON_BASE/<domain>/evidence/<finding-id>/
curl -sv <poc-command> 2>&1 > $RECON_BASE/<domain>/evidence/<finding-id>/request.txt
```

### Step 3: Screenshot via headed browser (ALL findings — mandatory)

Every finding gets browser evidence. Use the headed browser, not curl screenshots:

```python
EVIDENCE_DIR="$RECON_BASE/<domain>/evidence/<finding-id>"
mkdir -p "$EVIDENCE_DIR"

# Screenshot showing visible evidence (URL bar, payload reflection, alert box)
browser_screenshot(
    engagement_id='<eid>',
    agent_id='capture',
    url='<proof-url>',
    label='evidence'
)

# Capture network requests for HAR-style evidence
browser_screenshot(
    engagement_id='<eid>',
    agent_id='capture',
    url='<proof-url>',
    label='network-har'
)
```

Also capture the raw HTTP exchange as backup:
```bash
curl -sv <poc-command> 2>&1 > "$EVIDENCE_DIR/request.txt"
```

### Step 4: Check OOB Interactions (if applicable)
For blind SSRF, blind XXE, blind SQLi, log4shell — check Burp Collaborator:
```
burp_get_collaborator_interactions(payloadId=<id>)
```
Save any interaction evidence to `$RECON_BASE/<domain>/evidence/<finding-id>/collaborator.txt`

### Step 5: Apply Hygiene
- **Redact** cookies, auth headers, session tokens, API keys
- **Redact** PII: emails, names, IPs (unless target's own test data), other users' data
- **Strip** screenshot metadata (EXIF, GPS, device info)
- **Sanitize** HAR files if used

### Step 6: Save Sanitized Evidence
Store the clean evidence as engagement deliverables:
```
save_deliverable(engagement_id='<eid>', deliverable_type='tool_results', content=<clean-request+response>, producer_agent='capture')
```

### Step 7: Generate PoC Report
After all evidence is collected, generate the per-finding PoC report in the program-submission format:

```
bash $HOME/swarm/scripts/generate_poc_report.sh <engagement-id> all
```

This creates `$RECON_BASE/<domain>/evidence/<finding-id>/poc-report.md` for every finding, pre-filled with the finding title, description, affected URL, evidence file list, and PoC output. Sections marked `[add ...]` require manual input — fill these in before submission.

The PoC report follows the standard template at `templates/poc-report-template.md` with sections: Summary, Shops Used to Test, Relevant Request IDs, Steps To Reproduce, Supporting Material.

## Verification

- [ ] `@evidence-hygiene` loaded for redaction protocol
- [ ] Every confirmed finding has raw HTTP evidence captured
- [ ] Screenshot taken for DOM/visual bugs
- [ ] Collaborator interactions checked for OOB findings
- [ ] Redaction applied to all evidence (cookies, PII, tokens stripped)
- [ ] Evidence files exist at `$RECON_BASE/<domain>/evidence/<finding-id>/`
- [ ] Deliverable saved for Phase 11 consumption

Proceed to Phase 11 (`@validate`) when all findings have clean evidence.
