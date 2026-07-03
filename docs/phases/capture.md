# Phase 10: CAPTURE (Evidence Collection)

Collects sanitized evidence for every confirmed finding from Phase 6 HUNT. Each finding gets its own evidence directory with raw HTTP exchange, screenshot, collaborator interactions (if OOB), and a PoC report. Runs after EXPLOIT (Phase 8) / SEARCH (Phase 9), feeds VALIDATE (Phase 11).

---

## Objectives

- Capture raw HTTP request/response for every confirmed finding
- Take browser screenshots for DOM/visual bugs
- Check collaborator interactions for OOB findings (SSRF, blind XXE, blind SQLi)
- Apply redaction (cookies, PII, tokens, auth headers)
- Generate structured PoC reports per finding
- Save sanitized deliverables for Phase 11

---

## Input

```
findings_list_vulns(engagement_id=<eid>)
```

---

## Evidence Structure

```
$RECON_BASE/<domain>/evidence/<finding-id>/
├── evidence.md           — vulnerability description + impact + PoC
├── request.txt           — raw HTTP request/response
├── collaborator.txt      — OOB interaction proof (if applicable)
└── poc-report.md         — structured bug-bounty style report
```

Also generated at the root:
```
$RECON_BASE/<domain>/evidence/
├── SUMMARY.md            — table of all findings with severity/cvss/tool
└── VERIFICATION.md       — checklist with redaction warnings
```

---

## Workflow

### Step 1: Load Redaction Protocol
Call `@evidence-hygiene` before collecting any evidence. Redact: cookies, auth headers, session tokens, API keys, PII (emails, names, IPs), other users' data.

### Step 2: Capture Raw HTTP
Re-execute the PoC via curl and save the raw exchange to `request.txt`.

### Step 3: Browser Screenshots (ALL findings)
Every finding gets headed browser evidence:
- `browser_screenshot()` with descriptive `label=<finding-id>`
- `browser_act("close")` — immediately after, every time

### Step 4: Check OOB Interactions
For blind SSRF, blind XXE, blind SQLi: `burp_get_collaborator_interactions()` → save to `collaborator.txt`.

### Step 5: Generate PoC Report
`phase-capture.sh` automatically calls `generate_poc_report.sh` for every finding. Each `poc-report.md` is pre-filled with finding data from the DB.

---

## Browser Hygiene (Mandatory)

Every browser operation leaks a page unless explicitly closed:

1. `browser_screenshot(engagement_id='<eid>', agent_id='capture', url='<proof-url>', label='<finding-id>')`
2. `browser_act(engagement_id, "close")` — immediately after

Never leave open pages. They accumulate memory and break subsequent phases.

---

## Dependencies

| Upstream | Produces |
|----------|----------|
| Phase 6 HUNT | Confirmed findings in SQLite DB |
| Phase 8 EXPLOIT | PoC evidence per finding |
| This phase | request.txt, screenshots, collaborator.txt, poc-report.md |

## Related

- `.swarm/agents/capture.md` — Agent for evidence collection
- `scripts/tools/phase-capture.sh` — Pipeline script with dual-signature support (positional and `--engagement-id`)
