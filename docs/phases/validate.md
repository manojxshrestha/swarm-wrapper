# Phase 11: VALIDATE (PoC Re-validation & 7-Question Gate)

Re-runs each finding's PoC, then filters through the 7-Question Gate before reporting. Runs after CAPTURE (Phase 10), gates to REPORT (Phase 12).

---

## Objectives

- Re-run every finding's PoC to confirm reproducibility
- Apply the 7-Question Gate to each finding
- Classify: PASS / DOWNGRADE / CHAIN REQUIRED / KILL
- Update finding records with verdicts
- Regenerate PoC reports with validated evidence

---

## Input

All captured findings from the SQLite findings database:
```
get_findings(engagement_id=<eid>)
```

---

## Workflow

### Step 1: Re-run PoC

- `validate_poc()` for each finding
- Confirm the finding is still reproducible
- If FAIL, log and skip (may be patched or intermittent)

### Step 2: 7-Question Gate

| # | Question |
|---|----------|
| Q1 | Can an attacker use this RIGHT NOW with a real HTTP request? |
| Q2 | Is the impact on the program's accepted-impact list? |
| Q3 | Is the vulnerable asset in scope? |
| Q4 | Does it work without privileged access an attacker can't get? |
| Q5 | Is this not already known or documented behavior? |
| Q6 | Can impact be proved beyond "technically possible"? |
| Q7 | Is this NOT on the never-submit list? |

**Never-submit list:** Missing headers, introspection alone, clickjacking alone, self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, rate limits on non-critical forms, cookie flags alone.

### Step 3: Assign Verdict

- **PASS** (all 7 ✓) — keep for report
- **DOWNGRADE** (Q2 or Q5 fails) — lower severity, still report
- **CHAIN REQUIRED** (Q4 or Q6 fails) — route back to `@hunt` for chain piece
- **KILL** (Q7 true or unfixable Q1/Q3 fail) — discard, do not report

### Step 4: Update Finding & Regenerate PoC Report

- `update_finding()` with verdict and adjusted severity
- `generate_poc_report.sh <eid> <finding-id> --domain <domain>` — regenerates with validated data

---

## Output

```
$RECON_BASE/<domain>/validate/
└── findings_for_validation.txt    — compiled context for AI agent

$RECON_BASE/<domain>/evidence/<finding-id>/
└── poc-report.md                  — validated PoC report
```
