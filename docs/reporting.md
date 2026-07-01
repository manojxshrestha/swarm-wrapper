# Reporting Pipeline

Phase 12 of Swarm's 12-phase methodology. All data collected across Phases 0-11 (findings, test coverage, tool tracking, gate results, judge review) is assembled into a structured markdown report.

---

## Tool Call Sequence

```
  1. get_coverage()              — Check WSTG test coverage (≥40% required)
  2. get_tool_coverage()         — Check tool tracking coverage
  3. get_judge_data()            — Compile engagement data for Final Judge
  4. track_judge_review()        — Record Judge verdict
  5. generate_report()           — Generate the final report
```

---

## Pre-Flight Gates

`generate_report()` enforces these checks (all must pass unless `force=True`):

| Gate | Check | Requirement |
|------|-------|-------------|
| Phase gates | All phases must have passed `phase_gate_check()` | No missing or failed gates |
| Category coverage | 8 required categories (INFO, CONF, ATHN, ATHZ, SESS, INPV, ERRH, CLNT) | Each >0% coverage, ≥1 completed test |
| Overall coverage | All WSTG tests | ≥40% attempted |
| Core INPV tests | 6 core input-validation tests (INPV-01 through INPV-06) | ≥2 completed, ≥4 attempted |
| Tool coverage | Mandatory unconditional tools | All must be tracked |

---

## Finding Processing

### Confidence Tiers

Only findings with `confidence=confirmed` AND a valid `poc_token` appear in the main report. Unverified findings go to "Additional Candidates" with capped severity.

| Confidence | CVSS Cap | Severity Cap | Source |
|------------|----------|--------------|--------|
| `confirmed` | 10.0 | — | Validated PoC with token |
| `version_based` | 6.0 | Medium | Version/CVE match only |
| `speculative` | 3.9 | Low | Indirect evidence |

### Deduplication

Findings are deduplicated by `(affected_url.rstrip("/"), test_id, title.strip().lower())`. Duplicates are merged — evidence concatenated, highest severity kept.

### Sorting

Findings sorted by severity: **Critical → High → Medium → Low → Informational**.

### Splitting

- **Confirmed Findings** — full severity, full report section
- **Additional Candidates** — version-based and speculative findings with capped severities appended after confirmed findings

---

## Report Structure

```
# Penetration Test Report

| Field | Value |
|-------|-------|
| Target | {target} |
| Engagement ID | {engagement_id} |
| Tester | {tester} |
| Date | {date} |
| Methodology | OWASP WSTG v4.2, OWASP API Security Top 10, CWE, MITRE ATT&CK |

[Disclaimer if force=True]

## Executive Summary
  - Total findings, dedup count, confirmed vs additional breakdown
  - Finding Summary Table: Critical / High / Medium / Low / Informational counts

### Target Scope & Domain Architecture
  | Domain | Type | Notes |

## Detailed Findings

### Confirmed Findings
  Per finding:
  - ID, Title
  - Severity, Confidence, WSTG Reference, Affected URL, Parameter, PoC Link
  - Description
  - Evidence (code-fenced HTTP request/response)
  - Remediation

### Additional Candidates (Version-Based / Speculative)
  Same format, severities capped

## Test Coverage
  | Category | Code | Completed | Skipped | N/A | Not Attempted | Coverage |

### Skipped Tests (with reasons)

### Tests Not Attempted

## Tool Coverage
  | Tool | Phase | Tier | Status | Findings | Notes |

## Exploitation Results
  | Vuln Class | Queued | Exploited | Failed | Pending |

## Final Judge Review
  Verdict, critical actions, recommended actions, notes
```

---

## Platform-Specific Agents

After `generate_report()` produces the base markdown, the user routes through a platform agent:

| Platform | Agent | What it adds |
|----------|-------|-------------|
| HackerOne / Generic | `@report-writing` | Title formula, H1 template, CVSS 3.1/4.0 scoring, 5-question severity self-assessment, 12-point pre-submit checklist, tone guidelines |
| Bugcrowd | `@bugcrowd-reporting` | VRT category mapping, manual severity override, severity-request paragraph, OOS-clause rebuttals (4+ templates), chained findings strategy |
| Red Team | `@redteam-report-template` | Client-facing DOCX deliverable, Subject/Observations/Impact/Recommendation/PoC per finding |
| Immunefi | `@report-writing` | Smart-contract format: contract, function, bug class, severity, root cause, PoC (Solidity), impact, fix |

---

## Templates

| Template | Used By | Purpose |
|----------|---------|---------|
| `templates/report-template.md` | `generate_report()` | Base markdown report structure |
| `templates/poc-report-template.md` | `validate_poc()` / `_save_poc_evidence()` | Per-finding PoC evidence report (JSON + MD) |
| `templates/quality-gates.md` | `@triage-validation` / `phase_gate_check()` | 23 anti-patterns, per-phase checklists, Final Judge criteria |
| `templates/testing-strategies.md` | `@hunt` / `@surface` | Per-endpoint test matrices, chaining, cross-domain |
| `templates/source-code-analysis.md` | `start_code_analysis()` | Source code review template |

---

## Evidence Storage

```
engagements/runtime/<engagement_id>/
├── report.md                         # Generated report
├── evidence/
│   ├── <timestamp>_<label>_<cmd>_<token>.json   # PoC evidence (JSON)
│   └── <timestamp>_<label>_<cmd>_<token>.md     # PoC evidence (markdown)
├── logs.txt                           # Live MCP tool call log
└── poc-audit.log                      # PoC validation audit trail
```

---

## Quality Enforcement

| Mechanism | Enforced By | Blocking? |
|-----------|-------------|-----------|
| Confidence tiers | `generate_report()` | Yes — unverified findings excluded unless `force=True` |
| PoC token system | `validate_poc()` | Yes — `add_vuln(independent_engine=True)` requires token |
| Phase gate timing (60s) | `phase_gate_check()` | Yes — prevents rushing |
| Inter-gate work verification | `phase_gate_check()` | Yes — events log checked between gates |
| Required category coverage | `generate_report()` | Yes — 8 categories must have >0% |
| Core INPV test minimum | `generate_report()` | Yes — 2 completed, 4 attempted |
| Mandatory tool tracking | `generate_report()` | Yes — all required tools tracked |
| Deduplication | `generate_report()` | Non-blocking — auto-merged |
| 23 anti-patterns | `quality-gates.md` / `@triage-validation` | Non-blocking — review guide |
| Final Judge review | `track_judge_review()` | Non-blocking — recorded in report |
| Force disclaimer | `generate_report()` | Warning — disclaimer added to report if `force=True` |
