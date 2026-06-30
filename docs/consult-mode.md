# Consult Mode

Interactive Phase1–Phase12 pipeline — same as autopilot but with human approval at every phase transition. The assistant suggests what to do next, offers alternatives, and asks "Ready?" before each phase.

---

## When to Use

| Scenario | Recommendation |
|----------|---------------|
| Learning a new target iteratively | **Consult** — pause after each phase to assess results |
| Stealth / low-and-slow approach | **Consult** — approve each step, adapt as you go |
| Complex auth flows | **Consult** — verify session capture before proceeding to recon |
| Business logic heavy target | **Consult** — inspect HUNT findings before moving to exploit |
| Training / mentoring | **Consult** — see each phase's output and understand the flow |

---

## How It Works

1. **Assistant suggests** the recommended next phase with reasoning
2. **Shows alternatives** — e.g., "Skip intel, go straight to recon"
3. **Updates todo list** — shows completed (✓), current (→), and remaining phases
4. **Asks "Ready?"** — waits for user approval before executing
5. **Runs pipeline.sh** — executes the phase script
6. **Summarizes results** — shows what was found
7. **Repeats** — suggest next phase, show alternatives, ask approval

---

## Phase Flow

```
Phase 1 (SCOPE)       → suggest next → ask user → advance on approval
Phase 2 (AUTH)        → suggest next → ask user → advance on approval
Phase 2b (BROWSER)    → suggest next → ask user → advance on approval
Phase 3 (INTEL)       → suggest next → ask user → advance on approval
Phase 4 (RECON)       → suggest next → ask user → advance on approval
Phase 5 (SURFACE)     → suggest next → ask user → advance on approval
Phase 6 (HUNT)        → suggest next → ask user → advance on approval
Phase 7 (DEEPTHINK)   → suggest next → ask user → advance on approval (conditional)
Phase 8 (EXPLOIT)     → suggest next → ask user → advance on approval
Phase 9 (SEARCH)      → suggest next → ask user → advance on approval (conditional)
Phase 10 (CAPTURE)    → suggest next → ask user → advance on approval
Phase 11 (VALIDATE)   → suggest next → ask user → advance on approval
Phase 12 (REPORT)     → suggest next → ask user → advance on approval
```

## What The Assistant Suggests

| Phase | Summary shown | Suggested next | Alternatives |
|-------|---------------|----------------|--------------|
| SCOPE | Domains registered, scope confirmed | "Get credentials for authenticated testing" | "Skip auth, go unauthenticated" |
| AUTH | Auth method documented, token saved | "Run passive intel (OSINT)" | "Skip intel, go straight to recon" |
| INTEL | WHOIS, cloud buckets, spoof check | "Run full recon — 17 tools" | "Quick recon or skip to surface" |
| RECON | Live hosts, endpoints, secrets found | "Rank attack surface into tiers" | "Start hunting Tier 0 immediately" |
| SURFACE | Tier 0/1/2 list built | "Start hunting — recommend class order" | "Focus on specific class, or run all" |
| HUNT | Findings by severity | "Run gap analysis if zero findings" | "Skip to exploitation" |
| DEEPTHINK | Gaps identified, chains analyzed | "Re-run Phase 6 for under-tested classes" | "Skip to exploitation" |
| EXPLOIT | Findings exploited or blocked | "Run research if blocked by WAF/CVEs" | "Proceed to capture" |
| SEARCH | CVEs, payloads, bypasses found | "Re-run exploitation with new techniques" | "Skip to capture" |
| CAPTURE | Evidence saved, redacted | "Validate through 7-Question Gate" | "Skip validation, go straight to report" |
| VALIDATE | PASS/DOWNGRADE/KILL counts | "Draft final report" | "Review findings before reporting" |

---

## Invocation

```
/consult target.com              # full interactive pipeline
/consult target.com --quick      # faster, fewer deep tests
/consult target.com --deep       # exhaustive testing
/consult targets.txt             # multi-target from file
```

---

## Safety

- Every URL checked against scope allowlist
- Every request logged to engagement audit
- Reports NEVER auto-submitted
- PUT/DELETE/PATCH require explicit approval

---

## Related

- Pipeline: `docs/pipeline.md`
- Phase methodology: `docs/phases/`
- Command: `.opencode/commands/consult.md`
- Agent: `.opencode/agents/consult.md`
