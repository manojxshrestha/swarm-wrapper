# Architecture

Swarm is a dual-interface security testing platform: an **MCP server** (88 tools for methodology, tracking, findings management, browser automation) and an **OpenCode agent bundle** (118 auto-loading agents for bug hunting tradecraft, enterprise attack, and WAF bypass).

```
┌─────────────────────────────────────────────────────────┐
│                    USER (OpenCode / LLM)                 │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐    ┌──────────────────────────┐
│  Swarm MCP      │    │  OpenCode Agents (117)   │
│  Server (88 tools)│    │                         │
│  ──────────────── │    │  ──────────────────────  │
│  • WSTG v4.2 · OWASP Top 10 · OWASP API Top 10 · OWASP ASI · WAF/CRS · CWE · MITRE ATT&CK · NIST · CVSS · PortSwigger · Payload libraries     │    │  • hunt-xss, hunt-sqli   │
│  • WAF bypass    │    │  • triage-validation     │
│  • Findings DB    │    │  • offensive-osint       │
│  • Engagement     │    │  • m365-entra-attack     │
│    management     │    │  • ... 80 more           │
│  • Phase gates    │    │  • dirbrute              │
│  • Reporting      │    │  • deepthink            │
│  • Reporting      │    │  • search               │
│  • Knowledge      │    └──────────┬───────────────┘
│    graph          │               │ triggers
└────────┬──────────┘               ▼
         │              ┌──────────────────────────┐
         │              │  Burp Suite MCP Server   │
         │              │  (HTTP request execution) │
         │              └──────────────────────────┘
         ▼
┌─────────────────────────────────────────────────────┐
│              Storage (server/data/)                   │
│  runtime/findings/ tracking/ scope/ checkpoints/ events/     │
│  exploitation-queues/ deliverables/ configs/         │
│  task-trees/ priority-queues/ waf-data/              │
│  knowledge-graphs/ gate-tracking/ qa-tracking/       │
│  code-analysis/                                       │
└─────────────────────────────────────────────────────┘
```

## Components

### 1. MCP Server (`server/server.py`)

The core methodology engine. 88 tools organized into:

| Category | Tools | Purpose |
|----------|-------|---------|
| Knowledge Base | 5 | WSTG test cases, search, payloads |
| Technique Guides | 3 | PortSwigger Academy, WAF bypass |
| Engagement Management | 4 | Scope, config, YAML parsing |
| Findings & Evidence | 6 | Log, update, query findings |
| Test Coverage | 4 | Track tests and tools |
| Phase Gates & QA | 4 | Gate checks, QA/judge reviews |
| Report Generation | 1 | Auto-generate markdown reports |
| Exploitation | 6 | Queue, classify, mark exploited |
| Code Analysis | 3 | Source code review pipeline |
| Checkpoint & Resume | 4 | Save/restore engagement state |
| Task Tree | 6 | Hierarchical planning |
| Browser Automation | 7 | browser_analyze, browser_act, browser_login, browser_auto_auth, browser_screenshot, browser_crawl, browser_extract_storage |
| Git Checkpointing | 2 | Git snapshots |
| WAF Evasion | 3 | Fingerprint + bypass payloads |
| Knowledge Graph | 5 | Node/edge graph + chaining |
| Findings Database | 13 | SQLite-backed CRUD + graph |
| Utility | 9 | Status, audit, prioritize, verify |

### 2. OpenCode Agents (118)

Agents auto-load when you describe what you're testing. Each is a flat `.md` file at `.opencode/agents/<name>.md` with YAML frontmatter and markdown body.

| Domain | Count | Agent names |
|--------|-------|-------------|
| Pipeline & Dispatch | 14 | `autopilot`, `consult`, `scope`, `auth`, `pintel`, `recon`, `surface`, `hunt`, `deepthink`, `exploit`, `search`, `capture`, `validate`, `report` |
| Auth-Session | 3 | `browser-auth`, `analyze`, `credential-attack` |
| Recon & OSINT | 6 | `offensive-osint`, `web2-recon`, `osint-methodology`, `osint`, `dirbrute`, `hunt-subdomain` |
| Web App Hunting | 57 | `hunt-api-misconfig`, `hunt-aspnet`, `hunt-ato`, `hunt-auth-bypass`, `hunt-brute-force`, `hunt-business-logic`, `hunt-cache-poison`, `hunt-cicd`, `hunt-clickjacking`, `hunt-cloud-misconfig`, `hunt-cors`, `hunt-crlf`, `hunt-csrf`, `hunt-dependency-confusion`, `hunt-deserialization`, `hunt-dispatch`, `hunt-dom`, `hunt-file-upload`, `hunt-graphql`, `hunt-grpc`, `hunt-host-header`, `hunt-http-param-pollution`, `hunt-http-smuggling`, `hunt-idor`, `hunt-jwt-confusion`, `hunt-k8s`, `hunt-laravel`, `hunt-ldap`, `hunt-lfi`, `hunt-llm-ai`, `hunt-mass-assignment`, `hunt-mfa-bypass`, `hunt-misc`, `hunt-nextjs`, `hunt-nodejs`, `hunt-nosqli`, `hunt-ntlm-info`, `hunt-oauth`, `hunt-open-redirect`, `hunt-prototype-pollution`, `hunt-race-condition`, `hunt-rce`, `hunt-saml`, `hunt-session`, `hunt-sharepoint`, `hunt-source-leak`, `hunt-springboot`, `hunt-sqli`, `hunt-ssrf`, `hunt-ssrf-cloud`, `hunt-ssti`, `hunt-subdomain`, `hunt-tls-network`, `hunt-websocket`, `hunt-xss`, `hunt-xxe` |
| Enterprise Platform | 7 | `m365-entra-attack`, `okta-attack`, `cloud-iam-deep`, `enterprise-vpn-attack`, `vmware-vcenter-attack`, `apk-redteam-pipeline`, `supply-chain-attack-recon` |
| Red Team Tradecraft | 1 | `redteam-mindset` |
| Workflow & Validation | 3 | `bug-bounty`, `triage-validation`, `mid-engagement-ir-detection` |
| Reporting & Hygiene | 7 | `report-writing`, `bugcrowd-reporting`, `evidence-hygiene`, `redteam-report-template`, `web2-vuln-classes`, `waf-fingerprinting`, `security-arsenal` |
| WAF Evasion | 17 | `waf-bypass-aws`, `waf-bypass-cloudflare`, `waf-bypass-f5`, `waf-bypass-imperva`, `waf-bypass-modsecurity`, `waf-bypass-sucuri`, `waf-bypass-akamai`, `waf-bypass-fastly`, `waf-bypass-signalsciences`, `waf-encoding-obfuscation`, `waf-evasion-rce`, `waf-evasion-sqli`, `waf-evasion-xss`, `waf-hpp-hpf`, `waf-protocol-evasion`, `waf-regex-reversing`, `waf-header-spoofing` |
| Web3 & Meme | 2 | `meme-coin-audit`, `web3-audit` |
| Specialized | 2 | `bb-local-toolkit`, `bb-methodology` |

### 3. Commands (14)

Slash commands in `.opencode/commands/` that route to specific agents:

| Command | Routes to | Purpose |
|---------|-----------|---------|
| `/auth <target>` | auth | Authenticate to target — capture tokens, cookies, session state |
| `/autopilot <target>` | autopilot | Autonomous hunt loop with configurable checkpoints |
| `/capture <finding-id>` | capture | Evidence collection — screenshots, requests, collabs |
| `/consult <target>` | consult | Interactive Phase1–Phase12 pipeline with human approval gates |
| `/deepthink <finding-id>` | deepthink | First-principles gap analysis on stuck findings |
| `/exploit <vuln-class>` | exploit | Deep-research exploitation with WAF bypass |
| `/hunt <target>` | hunt | Two-track active vulnerability dispatcher |
| `/osint <target>` | osint | Passive intel — WHOIS, M365, cloud buckets, SPF |
| `/recon <target>` | recon | Subdomain enum, live host discovery, URL crawl |
| `/report <finding-id>` | report | Generate submission-ready bug bounty report |
| `/scope <asset>` | scope | Register target domain, scope, credentials |
| `/search <vuln-class>` | search | RAG-powered re-dispatch for uncovered classes |
| `/surface <target>` | surface | Ranked P1/P2/Kill-List attack surface |
| `/validate <finding-id>` | validate | 7-Question Gate — kills weak findings |

### 4. Scripts & Tools (`scripts/`)

| Path | Purpose |
|------|---------|
| `scripts/bughunt.py` | Terminal-native CLI runner |
| `scripts/hunt.sh` | Engagement-folder scaffolder |
| `scripts/install.sh` | Installer |
| `scripts/convert_skills.py` | Skill-to-agent converter |
| `scripts/convert_commands.py` | Command converter |
| `scripts/connect-burp.sh` | Burp MCP connection |
| `scripts/dork_runner.py` | Google dork automation |
| `scripts/tools/` (48 files) | Scanners, testers, helpers |
| `scripts/browser_driver.py` | Legacy headed Chromium driver (replaced by browser-use MCP tools) |
| `server/browser_tools.py` | browser-use Browser class — MCP tools for browser_analyze, browser_act, browser_login, browser_auto_auth, browser_screenshot, browser_crawl, browser_extract_storage |
| `server/venv/` | MCP server venv — contains browser-use, playwright, all MCP deps |
| `scripts/tools/oob_listener.sh` | OOB listener wrapper — interactsh-client start/stop/url for blind XSS/SSRF/XXE |

### 5. Wordlists (`wordlists/`)

Supplementary wordlists for recon and fuzzing: API endpoints, common paths, parameters, sensitive files.

### 6. Skills Reference (`skills/`)

Reference copies of all agent SKILL.md files (102 total). The active versions are in `.opencode/agents/`.

### 7. MCP Configuration (`.mcp.json`)

The project `.mcp.json` registers 2 MCP servers for OpenCode integration:

| Server | Tools | Purpose |
|--------|-------|---------|
| `wstg` | 93 | Methodology, findings database, engagement management, reporting, browser automation |
| `burp` | 35 | Burp Suite proxy integration, repeater, scanner, collaborator |

Browser automation is provided via MCP tools (`browser_analyze`, `browser_act`, `browser_auto_auth`, `browser_login`, `browser_screenshot`, `browser_crawl`, `browser_extract_storage`) using **browser-use** imported directly in `server/browser_tools.py`. See `docs/browser-flow.md`.

These are relative-path servers — no installation needed beyond the project clone.

---

## How agents auto-trigger

1. You describe what you're testing in plain English
2. OpenCode scans the `description` field in each agent's YAML frontmatter
3. Matching agents load into context
4. The LLM uses the agent's content to guide testing

Example: *"I see a `?url=` parameter on this endpoint"* → `hunt-ssrf` loads automatically. You don't invoke it by name.

---

## Agent-loading mechanics

- **Auto-trigger**: Agents load when their `description` matches your prompt
- **Progressive disclosure**: Large agents keep SKILL.md lean, put detailed content in subfolders
- **Commands**: Explicit invocations (`/triage`, `/report`, etc.) force-load specific agents

---

## What's NOT in the bundle

- **No automated exploitation** — guides hunting, doesn't fire payloads automatically
- **No CI/CD integration** — designed for individual researchers, not scanning pipelines
- **iOS testing not covered** — Android only via `apk-redteam-pipeline`
