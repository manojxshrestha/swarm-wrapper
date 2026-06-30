# Phase 12: REPORT (Coverage Check & Report Generation)

Final phase — verifies test coverage, validates phase gates, and generates the submission-ready report. Runs after VALIDATE (Phase 11).

---

## Objectives

- Verify WSTG and tool coverage via `get_coverage()` / `get_tool_coverage()`
- Validate all phase gates via `phase_gate_check()`
- Generate final report via `generate_report()`
- Present findings by severity, domains tested, and evidence

---

## Input

All validated findings from the SQLite findings database:
```
findings_list_vulns(engagement_id=<eid>)
```

---

## Workflow

### Step 1: Coverage Check

- `get_coverage()` — WSTG test coverage summary
- `get_tool_coverage()` — CLI tool coverage summary
- Warn if coverage below 60%

### Step 2: Phase Gate Validation

- `phase_gate_check()` for each completed phase
- Fix any blockers before proceeding

### Step 3: Generate Report

- `generate_report()` via MCP
- Choose platform: HackerOne (`@report-writing`) / Bugcrowd (`@bugcrowd-reporting`) / Client (`@redteam-report-template`)

### Step 4: Present to User

- Findings summary by severity
- Full report text
- PoC evidence per finding
- Walk through each `poc-report.md` to fill remaining `[add ...]` placeholders

---

## Output

```
$RECON_BASE/<domain>/report/
├── report_context.txt    — compiled summary for AI agent
└── report.md            — final generated report
```

Each finding's evidence at:
```
$RECON_BASE/<domain>/evidence/<finding-id>/poc-report.md
```
