---
name: bug-bounty
description: Bug bounty orchestrator — routes to the right hunt-* sub-agent based on vulnerability class. Provides orientation, dispatch logic, and phase overview. Full methodology at docs/methodology.md.
---

# Bug Bounty Master Workflow

Full pipeline: Recon -> Learn -> Hunt -> Validate -> Report. This skill defines the **orchestration and dispatch logic**. The full methodology reference has been extracted to `docs/methodology.md`.

## THE ONLY QUESTION THAT MATTERS

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions -- and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"**
>
> If the answer is NO -- **STOP. Do not write. Do not explore further. Move on.**

## CRITICAL RULES

1. **READ FULL SCOPE FIRST** -- verify every asset/domain is owned by the target org
2. **NO THEORETICAL BUGS** -- "Can an attacker steal funds, leak PII, takeover account, or execute code RIGHT NOW?" If no, STOP.
3. **KILL WEAK FINDINGS FAST** -- run the 7-Question Gate BEFORE writing any report
4. **Validate before writing** -- check CHANGELOG, design docs, deployment scripts FIRST
5. **One bug class at a time** -- go deep, don't spray
6. **Verify data isn't already public** -- check web UI in incognito before reporting API "leaks"
7. **5-MINUTE RULE** -- if a target shows nothing after 5 min probing (all 401/403/404), MOVE ON
8. **IMPACT-FIRST HUNTING** -- ask "what's the worst thing if auth was broken?" If nothing valuable, skip target
9. **CREDENTIAL LEAKS need exploitation proof** -- finding keys isn't enough, must PROVE what they access
10. **STOP SHALLOW RECON SPIRALS** -- don't probe 403s, don't grep for analytics keys, don't check staging domains that lead nowhere
11. **BUSINESS IMPACT over vuln class** -- severity depends on CONTEXT, not just vuln type
12. **UNDERSTAND THE TARGET DEEPLY** -- before hunting, learn the app like a real user
13. **DON'T OVER-RELY ON AUTOMATION** -- automated scans hit WAFs, trigger rate limits, find the same bugs everyone else finds
14. **HUNT LESS-SATURATED VULN CLASSES** -- XSS/SSRF/XXE have the most competition. Expand into: cache poisoning, Android/mobile vulns, business logic, race conditions, OAuth/OIDC chains, CI/CD pipeline attacks
15. **ONE-HOUR RULE** -- stuck on one target for an hour with no progress? SWITCH CONTEXT
16. **TWO-EYE APPROACH** -- combine systematic testing (checklist) with anomaly detection (watch for unexpected behavior)
17. **T-SHAPED KNOWLEDGE** -- go DEEP in one area and BROAD across everything else

## Reference Index

| Resource | Location |
|----------|----------|
| Bug bounty methodology (full) | `docs/methodology.md` |
| VRT-categorized vulnerability specs | `web2-vuln-classes` agent |
| Tool install & usage | `docs/summary.md`, `docs/bughunt-cli.md` |
| 12-phase pipeline deep-dive | `docs/pipeline.md` |
| WSTG methodology (OWASP) | WSTG MCP `get_wstg_test(test_id)` |

## Sub-Agent Dispatch Table

When a user asks about a specific vulnerability class or phase, dispatch to the appropriate `hunt-*` sub-agent:

| Topic | Dispatch to |
|-------|-------------|
| Recon (subdomain, crawl, tech detect) | `web2-recon` |
| IDOR / BOLA | `hunt-idor` |
| XSS (reflected/stored/DOM) | `hunt-xss` |
| SSRF (including cloud metadata) | `hunt-ssrf` + `hunt-ssrf-cloud` |
| SQL injection | `hunt-sqli` |
| SSTI | `hunt-ssti` |
| Command injection / RCE | `hunt-rce` + `hunt-lfi` |
| CSRF | `hunt-csrf` |
| CORS misconfiguration | `hunt-cors` |
| Open redirect | `hunt-open-redirect` |
| OAuth / OIDC | `hunt-oauth` |
| JWT alg confusion | `hunt-jwt-confusion` |
| GraphQL | `hunt-graphql` |
| File upload | `hunt-file-upload` |
| Race conditions | `hunt-race-condition` |
| Business logic | `hunt-business-logic` |
| Authentication bypass | `hunt-auth-bypass` + `hunt-ato` |
| Session management | `hunt-session` + `hunt-mfa-bypass` |
| HTTP request smuggling | `hunt-http-smuggling` |
| Host header injection | `hunt-host-header` |
| Cache poisoning/deception | `hunt-cache-poison` |
| WebSocket | `hunt-websocket` |
| XXE | `hunt-xxe` |
| Prototype pollution | `hunt-prototype-pollution` |
| Deserialization | `hunt-deserialization` |
| Mass assignment | `hunt-mass-assignment` |
| Subdomain takeover | `hunt-subdomain` |
| Cloud misconfig (S3, Firebase, K8s) | `hunt-cloud-misconfig` |
| CI/CD pipeline (GitHub Actions) | `hunt-cicd` |
| LLM / AI / prompt injection | `hunt-llm-ai` |
| Next.js / Node.js / Laravel / Spring | respective `hunt-*` agents |
| Android / Mobile | `hunt-source-leak` + `hunt-cloud-misconfig` |
| SOAP / XML services | `hunt-soap` |
| LDAP injection | `hunt-ldap` |
| SAML SSO | `hunt-saml` |
| NTLM / info disclosure | `hunt-ntlm-info` |
| gRPC | `hunt-grpc` |
| Source code leak (.git, .env) | `hunt-source-leak` |
| Dependency confusion | `hunt-dependency-confusion` |
| ATO (account takeover) | `hunt-ato` |
| Credential attack / password spray | `credential-attack` |
| Offensive OSINT / employee enum | `offensive-osint` |

## Phase Overview (12-Pipeline)

| Phase | Name | What happens | Dispatch |
|-------|------|-------------|----------|
| 1 | SCOPE | Register domains, load config, init findings DB | `scope` |
| 2 | AUTH | Obtain credentials, WAF fingerprint | `auth` / `browser-auth` |
| 3 | INTEL | WHOIS, M365/SPF, cloud buckets | `pintel` / `osint` |
| 4 | RECON | Subdomain enum, crawl, param discovery | `recon` / `web2-recon` / `dirbrute` |
| 5 | SURFACE | Classify endpoints, prioritize, rank | `surface` |
| 6 | HUNT | Per-class vuln testing via hunt-* agents | See dispatch table above |
| 7 | DEEPTHINK | Gap analysis when hunt yields zero | `deepthink` |
| 8 | EXPLOIT | Deepen findings, chain analysis, WAF bypass | `exploit` |
| 9 | SEARCH | Research payloads, CVEs, bypass techniques | `search` |
| 10 | CAPTURE | Sanitized evidence (screenshots, HTTP, redaction) | `capture` |
| 11 | VALIDATE | Re-validate PoCs, 7-Question Gate, verdict | `validate` / `triage-validation` |
| 12 | REPORT | Coverage check, generate final report | `report` / `report-writing` |

## When to Use This Skill vs Direct Hunt-* Agent

- **Use this skill**: When you don't know what to hunt yet — "I have a target, what should I test?" — it provides orientation and dispatches to the right sub-agent.
- **Use hunt-* directly**: When you already know the vuln class — "this endpoint reflects my Host header into a JS src URL, that's cache poisoning."
- **Close the orchestrator after routing**: Don't keep this skill loaded all session — it occupies context that could hold actual probe results.

## Engagement Scaffolding

```
targets/<target>/scope.md         — declared scope
targets/<target>/findings/        — one MD per validated finding
targets/<target>/evidence/        — HARs, screenshots, redacted curl transcripts
targets/<target>/submissions.txt  — submitted-report URLs + states
$RECON_BASE/<target>/             — subfinder | dnsx | httpx | katana outputs
```

## Related Skills & Chains

- **`bb-methodology`** — The 12-phase pipeline that this orchestrator runs against. Load FIRST, then this skill names the topic-matched hunt-* skills.
- **`hunt-dispatch`** — Routes by engagement mode (red-team vs bug-bounty). Composes with this skill: mode first, then topic.
- **`triage-validation`** — 7-Question Gate + kill signals. Run before writing any report.
- **`report-writing`** — Platform-specific report templates (HackerOne/Bugcrowd/Intigriti).
- **`web2-recon`** — Recon sub-pipeline (subdomain -> HTTP probe -> tech detect).
- **`credential-attack`** — Parallel password spray pipeline.
- **`bb-local-toolkit`** — Local tool locations and install paths.
- **`evidence-hygiene`** — Cookie/PII redaction, evidence chain of custody.

## Operator Notes

> Engagement-derived additions from real authorized engagements + Phase 2 verification across 31+ skill-area live tests.

### Common Misuse: Loading Every Hunt-* Simultaneously

There are 50+ hunt-* agents in this repo. The orchestrator's job is to pick 2-3 by topic match, not dump the entire library. If the user says "hunt this SaaS app", load `web2-recon` + `hunt-idor` + `hunt-api-misconfig` (SaaS-typical trio) and stop. Add more only when recon suggests a specific additional class (e.g., GraphQL found → add `hunt-graphql`).

### When the Orchestrator Gets It Wrong

If the orchestrator misroutes (loads the wrong hunt-* for the topic), fix the `description:` frontmatter field on the target hunt-* agent to include the missing trigger word. Don't add another dispatch layer.

### Context Discipline

- Start with this skill on any new target
- Let it route to the right hunt-* agent
- Close this skill once the hunt-* agent is loaded
- Don't keep the orchestrator open all session