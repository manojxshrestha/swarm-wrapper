# Autopilot Mode

Full 12-phase autonomous pipeline — no approval stops. Runs end-to-end: scope → auth → intel → recon → surface → hunt → deepthink → exploit → search → capture → validate → report.

---

## When to Use

| Scenario | Recommendation |
|----------|---------------|
| New target, full assessment | **`--paranoid`** — stops at every signal, safe for unfamiliar targets |
| Systematic coverage run | **`--normal`** — batch checkpoint after validation |
| Experienced hunter, known surface | **`--yolo`** — minimal stops, still requires report approval |
| Quick first pass | **`--quick`** — ~40% fewer tokens, skips deep fuzzing |

---

## How It Works

1. **Phase 1-5** — `pipeline.sh` handles all bash tool execution (scope, auth, intel, recon, surface)
2. **Phase 6** — `pipeline.sh` runs param extraction + secrets + vhost + 403 bypass, then dispatches ALL 57 `@hunt-*` agents via `task()`
3. **Phase 7** — Conditional: deepthink triggers if coverage < 90% or zero findings
4. **Phase 8** — `pipeline.sh` compiles findings, then `@exploit` agent deepens each one through 5 tiers
5. **Phase 9** — Conditional: search triggers if WAF dead-ends, missing CVEs, payload rate < 20%
6. **Phase 10** — `@capture` agent collects screenshots and evidence
7. **Phase 11** — `@validate` runs 7-Question Gate on every finding
8. **Phase 12** — `@report` agent generates the final report

---

## Invocation

```
/autopilot target.com              # default: --paranoid
/autopilot target.com --normal     # batch checkpoint after validation
/autopilot target.com --yolo       # minimal checkpoints
/autopilot target.com --quick      # fast surface scan, fewer checks
/autopilot targets.txt             # multi-target from file
```

---

## Checkpoint Modes

| Mode | When it stops | Best for |
|------|---------------|----------|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

---

## Safety

- Every URL checked against scope allowlist
- Every request logged to engagement audit
- Reports NEVER auto-submitted
- PUT/DELETE/PATCH require human approval in `--yolo` mode
- Circuit breaker: stops after 5 consecutive 403/429/timeout on same host
- Rate limited: 1 req/sec (testing), 10 req/sec (recon)
- One target per session — no cross-contamination

---

## Related

- Pipeline: `docs/pipeline.md`
- Phase methodology: `docs/phases/`
- Command: `.opencode/commands/autopilot.md`
- Agent: `.opencode/agents/autopilot.md`
- CLI: `bughunt autopilot [target]` — same pipeline from terminal
