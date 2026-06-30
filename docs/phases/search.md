# Phase 9: SEARCH (Real-Time Intelligence Retrieval)

Conditional meta-phase for external research when static `knowledge/` data is stale, incomplete, or missing. Retrieves current CVEs, payloads, WAF bypasses, and disclosed reports. Runs after EXPLOIT (Phase 8), feeds findings back into Phase 8 for re-exploitation.

---

## When It Activates

Phase 9 is **conditional** — it only runs when EXPLOIT (Phase 8) encounters one or more of these triggers.

| Trigger | Description |
|---------|-------------|
| Unknown technology | Tech stack identified but no CVEs checked |
| WAF dead-end | All bypass techniques exhausted for any vulnerability class |
| Payload rate < 20% | >80% of injected payloads returned no reflection/error/timing change |
| Missing CVEs | Critical/High findings lack disclosed report reference for severity justification |
| Stale payloads | Payloads in `knowledge/payloads/` or WAF profiles fail against the target |
| No technique match | `search_wstg()` returns nothing useful for the target tech |

If **no triggers** are true → skip Phase 9 entirely.

---

## 4-Tier Research Priority

Research resources in priority order. Stop once the gap is filled.

### Tier 1 — General Technique & Payload References

| Priority | Resource | Best for |
|----------|----------|----------|
| 1 | **HackTricks** | Pentesting methodology, per-class technique guides, cloud/AD/network |
| 2 | **PayloadsAllTheThings** | 64 categories of copy-ready payloads, bypasses, cheatsheets |
| 3 | **PortSwigger Academy** | 211 labs, authoritative technique explanations (SQLi, XSS, SSRF, JWT) |

### Tier 2 — CVE & Exploit Research

| Priority | Resource | Best for |
|----------|----------|----------|
| 4 | **Exploit-DB** | 46K+ public exploits/PoCs with CVE mapping |
| 5 | **CISA KEV** | Known exploited vulns in the wild |
| 6 | **NVD** | Official CVE details with CVSS scores |
| 7 | **Rapid7 DB** | 340K+ CVEs with Metasploit module mapping |

### Tier 3 — Disclosed Reports & Severity Precedent

| Priority | Resource | Best for |
|----------|----------|----------|
| 8 | **HackerOne Hacktivity** | 12K+ disclosed reports, searchable by severity/type/program |
| 9 | **BugBoard** | H1 report search by keyword — 10K+ reports |
| 10 | **Bounty Radar** | Aggregated 4,700+ H1 + 279 Immunefi programs |

### Tier 4 — WAF Bypass & Payload Generation

| Priority | Resource | Best for |
|----------|----------|----------|
| 11 | **Payload Playground** | 32 generators, 43 cheat sheets, encoding pipeline |
| 12 | **PayloadForge** | 204 curated payloads, 13 mutation techniques, 7 WAF profiles |
| 13 | **BypassBurrito** | LLM-powered WAF bypass generation — 13 supported WAFs |

---

## Workflow

### Step 1: Check Static Data First

Before searching the web, verify the gap genuinely exists:
- `search_wstg("<technique>")` — WSTG methodology reference
- `get_waf_bypass("<vendor>", "<class>")` — existing WAF bypass profiles
- `ls knowledge/payloads/<category>/` — payload library check

Only proceed to search if static data genuinely lacks the answer.

### Step 2: Execute Research

Use `websearch()` or `webfetch()` to query resources in priority order (Tier 1 → Tier 4). Formulate targeted queries:

| Gap | Example Query |
|-----|---------------|
| General technique | `hacktricks.wiki <vuln-class> bypass technique` |
| Payloads | `PayloadsAllTheThings <category> payloads` |
| CVE | `CVE <product> <version> RCE` |
| WAF bypass | `Cloudflare WAF bypass XSS 2026 technique` |
| Report precedent | `site:hackerone.com "account takeover" "$2000"` |

### Step 3: Synthesize & Verify

- Cross-reference community sources (Payload Playground, BypassBurrito) against established ones (HackTricks, PortSwigger)
- Verify payloads via `validate_poc()` before logging findings or re-attempting exploitation
- Check source credibility and applicability to the target's version/config

### Step 4: Feed Back to Phase 8

If research found new techniques or payloads:
1. Document findings with source citations
2. Create issue files for dead-ends (gaps that couldn't be filled)
3. Re-run Phase 8 (EXPLOIT) with the newly discovered techniques

---

## Dependencies

| Upstream | Produces |
|----------|----------|
| Phase 8 EXPLOIT | Blocked/potential findings, WAF bypass exhaustion, tech stack details |
| This phase | Research results, issue files for dead-ends, re-exploitation payloads |

## Related

- `.opencode/agents/search.md` — Agent with 4-tier research priority
- `scripts/tools/phase-search.sh` — Pipeline script (researches gaps from SQLite DB)
- `server/server_data.py:822` — PHASE_NAMES entry
