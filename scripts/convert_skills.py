#!/usr/bin/env python3
"""Convert BH skills to OpenCode agents for Swarm.

Usage:
    python3 convert_skills.py <phase> [--dry-run]

Phases:
    1 = Core Web Hunters (29)
    2 = Enterprise Platform (11)
    3 = Support & Methodology (14)
    4 = Framework-Specific (7)
    5 = Specialized (10)
    6 = WAF Bypass & Evasion (15)
    all = all of the above

Output: .swarm/agents/<agent-dir>/SKILL.md
"""

import re
import sys
import yaml
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
HOME = Path.home()
BH_SKILLS = SCRIPT_DIR / "skills"
AGENTS_DIR = SCRIPT_DIR / ".swarm/agents"

# ── Phase 1: Core Web Hunters ───────────────────────────────────────────────
PHASE_1 = {
    "hunt-xss": {
        "agent": "xss-hunter",
        "description": "Cross-Site Scripting hunter. Reflected, stored, and DOM-based XSS, CSP bypass, mXSS, sanitizer evasion, polyglot payloads, cache-poison XSS chains, and postMessage gadgets.",
        "wstg": "INPV-01 (Reflected XSS), INPV-02 (Stored XSS), CLNT-01 (DOM XSS)",
        "swarm_prompt": "input-validation.md, client-side.md",
    },
    "hunt-sqli": {
        "agent": "sqli-hunter",
        "description": "SQL injection and NoSQL injection hunter. Classic SQLi, blind/time-based, second-order, ORM raw-fragment SQLi, MongoDB $regex/$where injection, CouchDB JavaScript injection, DynamoDB expression injection.",
        "wstg": "INPV-05 (SQL Injection)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-ssrf": {
        "agent": "ssrf-hunter",
        "description": "Server-Side Request Forgery hunter. Cloud metadata SSRF, blind OOB SSRF, URL parser bypass, redirect-based SSRF, and chain paths to RCE.",
        "wstg": "INPV-19 (SSRF)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-ssti": {
        "agent": "ssti-hunter",
        "description": "Server-Side Template Injection hunter. Jinja2, Twig, Freemarker, Velocity, Jade/Pug, ERB. Detection, context identification, RCE chains.",
        "wstg": "INPV-18 (Template Injection)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-lfi": {
        "agent": "lfi-hunter",
        "description": "Local File Inclusion / Path Traversal hunter. Directory traversal, RFI, PHP wrappers, log poisoning, and chain to RCE.",
        "wstg": "ATHZ-01 (Path Traversal/IDOR)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-xxe": {
        "agent": "xxe-hunter",
        "description": "XML External Entity hunter. In-band XXE, blind OOB XXE, SVG XXE, XInclude attacks, docx/pptx XXE, SOAP XXE.",
        "wstg": "INPV-20 (XXE)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-idor": {
        "agent": "idor-hunter",
        "description": "Insecure Direct Object Reference hunter. UUID enumeration, sequential IDs, GraphQL IDOR, multi-tenant data access, mass assignment chaining, and parameter-based object reference bypass.",
        "wstg": "ATHZ-01 (IDOR)",
        "swarm_prompt": "authorization.md",
    },
    "hunt-csrf": {
        "agent": "csrf-hunter",
        "description": "Cross-Site Request Forgery hunter. Anti-CSRF token bypass, SameSite bypass, JSON Content-Type CSRF, multi-step CSRF, and chaining to ATO.",
        "wstg": "SESS-05 (CSRF)",
        "swarm_prompt": "session-management.md",
    },
    "hunt-cors": {
        "agent": "cors-hunter",
        "description": "CORS misconfiguration hunter. Origin reflection, wildcard origin with credentials, preflight bypass, null origin, and intranet CORS exploitation.",
        "wstg": "CLNT-07 (CORS)",
        "swarm_prompt": "client-side.md",
    },
    "hunt-oauth": {
        "agent": "oauth-hunter",
        "description": "OAuth 2.0 / OpenID Connect hunter. Redirect URI bypass, state nonce leakage, CSRF on OAuth flow, token leakage via Referer, implicit flow weaknesses.",
        "wstg": "ATHZ-05 (OAuth/OIDC)",
        "swarm_prompt": "authentication.md",
    },
    "hunt-graphql": {
        "agent": "graphql-hunter",
        "description": "GraphQL API hunter. Introspection, batching attacks, alias abuse, depth-based DoS, auth bypass, IDOR in GraphQL resolvers, custom scalar injection.",
        "wstg": "APIT-01 (GraphQL)",
        "swarm_prompt": "api-testing.md",
    },
    "hunt-file-upload": {
        "agent": "file-upload-hunter",
        "description": "File upload vulnerability hunter. Unrestricted file upload, SVG XSS, polyglot files, Content-Type bypass, zip slip, race condition on upload.",
        "wstg": "BUSL-08 (File Upload), BUSL-09 (Malicious Files)",
        "swarm_prompt": "business-logic.md, input-validation.md",
    },
    "hunt-host-header": {
        "agent": "host-header-hunter",
        "description": "Host header injection hunter. Password reset poisoning, cache poisoning, SSRF via Host header, routing-based SSRF, absolute URL injection.",
        "wstg": "INPV-17 (Host Header Injection)",
        "swarm_prompt": "configuration.md, input-validation.md",
    },
    "hunt-http-smuggling": {
        "agent": "http-smuggler",
        "description": "HTTP request smuggling hunter. CL.TE, TE.CL, TE.TE variations, connection reuse poisoning, cache poisoning via smuggling, WAF bypass.",
        "wstg": "INPV-15 (HTTP Smuggling)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-open-redirect": {
        "agent": "open-redirect-hunter",
        "description": "Open redirect hunter. URL parser bypass, protocol confusion, CRLF injection in redirect, chaining to phishing/XSS, OAuth redirect abuse.",
        "wstg": "CLNT-04 (Open Redirect)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-brute-force": {
        "agent": "brute-force-hunter",
        "description": "Brute force and credential stuffing hunter. Rate limiting bypass, JWT brute force, 2FA bypass via brute force, password policy bypass.",
        "wstg": "ATHN-03 (Lockout/Brute Force), ATHN-07 (Weak Password Policy)",
        "swarm_prompt": "authentication.md",
    },
    "hunt-session": {
        "agent": "session-hunter",
        "description": "Session management flaw hunter. Session fixation, predictable tokens, weak cookie attributes, concurrent session handling, JWT session weaknesses.",
        "wstg": "SESS-01 through SESS-11 (Session Management)",
        "swarm_prompt": "session-management.md",
    },
    "hunt-auth-bypass": {
        "agent": "auth-bypass-hunter",
        "description": "Authentication bypass hunter. Forced browsing, HTTP method override, parameter pollution, direct endpoint access, role-based bypass.",
        "wstg": "ATHZ-02 (Authorization Bypass)",
        "swarm_prompt": "authorization.md",
    },
    "hunt-ato": {
        "agent": "ato-hunter",
        "description": "Account Takeover hunter. Password reset logic flaws, email takeover, OAuth token theft, 2FA bypass, session hijack, SSO bypass chains.",
        "wstg": "IDNT-04 (Account Enumeration), ATHN-01 (Credential Transport)",
        "swarm_prompt": "authentication.md",
    },
    "hunt-subdomain": {
        "agent": "subdomain-hunter",
        "description": "Subdomain takeover hunter. CNAME dangling, NS delegation, Azure/DNS/CloudFront/S3 takeover, expired DNS, dead link hijacking.",
        "wstg": "CONF-10 (Subdomain Takeover)",
        "swarm_prompt": "info-gathering.md",
    },
    "hunt-api-misconfig": {
        "agent": "api-misconfig-hunter",
        "description": "API security misconfiguration hunter. Mass assignment, rate limiting gaps, excessive data exposure, improper asset management, auth on non-production APIs.",
        "wstg": "APIT-02 (REST), APIT-03 (SOAP)",
        "swarm_prompt": "api-testing.md",
    },
    "hunt-mfa-bypass": {
        "agent": "mfa-bypass-hunter",
        "description": "MFA bypass hunter. Push fatigue, backup code reuse, token reuse, biometric bypass, SIM swap chaining, rate limiting, social engineering vectors.",
        "wstg": "ATHN-11 (MFA Testing)",
        "swarm_prompt": "authentication.md",
    },
    "hunt-race-condition": {
        "agent": "race-condition-hunter",
        "description": "Race condition hunter. TOCTOU, payment race conditions, coupon/loyalty race, rate limit race, async race, database contention.",
        "wstg": "BUSL-04 (Race Conditions)",
        "swarm_prompt": "business-logic.md",
    },
    "hunt-cache-poison": {
        "agent": "cache-poison-hunter",
        "description": "Web cache poisoning hunter. Unkeyed inputs, CDN-specific poisoning (Cloudflare, Akamai, Fastly), cache deception, cache key injection.",
        "wstg": "",
        "swarm_prompt": "client-side.md, configuration.md",
    },
    "hunt-deserialization": {
        "agent": "deserialization-hunter",
        "description": "Insecure deserialization hunter. PHP unserialize, Java deserialization (ysoserial), .NET ViewState, pickle, Ruby MARSHAL, Node.js unserialize.",
        "wstg": "",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-dom": {
        "agent": "dom-hunter",
        "description": "DOM-based vulnerability hunter. DOM XSS, DOM clobbering, DOM injection, prototype pollution, trusted types bypass, client-side template injection.",
        "wstg": "CLNT-01 (DOM XSS)",
        "swarm_prompt": "client-side.md",
    },
    "hunt-websocket": {
        "agent": "websocket-hunter",
        "description": "WebSocket security hunter. WS message injection, origin bypass, CSWSH, WS proxy misconfig, cross-origin WebSocket hijacking, WS tunneling.",
        "wstg": "CLNT-09 (WebSocket)",
        "swarm_prompt": "client-side.md",
    },
    "hunt-llm-ai": {
        "agent": "llm-hunter",
        "description": "LLM/AI security hunter. Prompt injection, RAG poisoning, model data extraction, jailbreak detection, indirect prompt injection via tools, MCP server abuse.",
        "wstg": "OWASP LLM Top 10",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-rce": {
        "agent": "rce-hunter",
        "description": "Remote Code Execution hunter. Command injection (OS), eval() injection, SSTI chained to RCE, file write to RCE, dependency RCE, library injection.",
        "wstg": "INPV-12 (Command Injection), INPV-11 (Code Injection)",
        "swarm_prompt": "input-validation.md",
    },

    "hunt-ssrf-cloud": {
        "agent": "ssrf-cloud-hunter",
        "description": "Cloud metadata SSRF & IAM credential theft hunter. AWS IMDSv1/v2, GCP metadata, Azure IMDS, K8s SA token exfil, ECS task credentials, Lambda env vars, DigitalOcean, Linode.",
        "wstg": "INPV-19 (SSRF), CONF-11 (Cloud Storage)",
        "swarm_prompt": "input-validation.md, configuration.md",
    },}

# ── Phase 2: Enterprise Platform ────────────────────────────────────────────
PHASE_2 = {
    "cloud-iam-deep": {
        "agent": "cloud-iam-auditor",
        "description": "Cloud IAM privilege escalation auditor. AWS IAM priv-esc (24+ patterns), Azure RBAC abuse, GCP IAM misconfig, cross-account role trust, managed policy exploitation.",
        "wstg": "CONF-11 (Cloud Storage)",
        "swarm_prompt": "configuration.md",
    },
    "m365-entra-attack": {
        "agent": "m365-attacker",
        "description": "Microsoft 365 / Entra ID attack chains. AADSTS error analysis, Smart Lockout math, Conditional Access bypass, token theft, device registration abuse, hybrid identity.",
        "wstg": "ATHZ-05 (OAuth/OIDC), IDNT-04 (Federation)",
        "swarm_prompt": "authentication.md, identity-management.md",
    },
    "okta-attack": {
        "agent": "okta-attacker",
        "description": "Okta identity platform attack chains. Okta-as-IdP misconfig, SWA injection, delegated authentication flaws, API token abuse, event hook manipulation.",
        "wstg": "ATHZ-05 (SAML/OIDC), IDNT-04 (Federation)",
        "swarm_prompt": "authentication.md, identity-management.md",
    },
    "vmware-vcenter-attack": {
        "agent": "vcenter-attacker",
        "description": "VMware vCenter exploitation chains. CVE-2021-21972 through CVE-2024-37085, vCenter to ESXI lateral movement, vCenter SSO bypass, vulnerable appliance exploitation.",
        "wstg": "CONF-03 (Infrastructure Config)",
        "swarm_prompt": "configuration.md",
    },
    "enterprise-vpn-attack": {
        "agent": "vpn-attacker",
        "description": "Enterprise VPN exploitation. Cisco ASA/FTD, Fortinet FortiGate, Citrix ADC/Gateway, Palo Alto PAN-OS, Pulse Secure, SonicWall, F5 Big-IP CVEs and config weaknesses.",
        "wstg": "CONF-03 (Infrastructure Config)",
        "swarm_prompt": "configuration.md",
    },
    "hunt-k8s": {
        "agent": "k8s-hunter",
        "description": "Kubernetes security hunter. RBAC abuse, pod escape, secrets exposure, kubelet API, etcd access, admission controller bypass, container breakout chains.",
        "wstg": "CONF-10 (Container Security)",
        "swarm_prompt": "configuration.md",
    },
    "hunt-cicd": {
        "agent": "cicd-hunter",
        "description": "CI/CD pipeline hunter. GitHub Actions injection, GitLab CI abuse, Jenkins pipeline groovy, self-hosted runner compromise, artifact poisoning, secret exposure.",
        "wstg": "CONF-11 (CI/CD Security)",
        "swarm_prompt": "configuration.md",
    },
    "hunt-cloud-misconfig": {
        "agent": "cloud-misconfig-hunter",
        "description": "Cloud storage misconfiguration hunter. Open S3/Azure Blob/GCP buckets, public AMIs, unsecured databases, cloud metadata exposure, snapshot sharing.",
        "wstg": "CONF-10 (Cloud Config)",
        "swarm_prompt": "configuration.md",
    },
    "apk-redteam-pipeline": {
        "agent": "apk-analyzer",
        "description": "Android APK red team pipeline. APK acquisition, decompile (jadx/apktool), secret grep, Frida instrumentation, certificate pinning bypass, intent analysis.",
        "wstg": "MOB-01 through MOB-09 (Mobile Security)",
        "swarm_prompt": "client-side.md",
    },
    "supply-chain-attack-recon": {
        "agent": "supply-chain-hunter",
        "description": "Supply chain attack recon. Dependency confusion, package squatting, typosquatting, GH Actions dependency injection, SBOM mining, mirror/pypi/gem/npm registry poisoning.",
        "wstg": "CONF-12 (Supply Chain Security)",
        "swarm_prompt": "configuration.md",
    },
    "hunt-sharepoint": {
        "agent": "sharepoint-hunter",
        "description": "SharePoint security hunter. SharePoint on-prem/online misconfiguration, privilege escalation, exposed web parts, workflow abuse, viewstate deserialization.",
        "wstg": "CONF-04 (SharePoint), ATHZ-02 (Privilege Escalation)",
        "swarm_prompt": "configuration.md, authorization.md",
    },
    "hunt-ntlm-info": {
        "agent": "ntlm-hunter",
        "description": "NTLM information disclosure hunter. NTLM challenge capture, relay primitives, coercion, NetNTLMv2 interception, HTTP NTLM auth exposure.",
        "wstg": "INFO-09 (NTLM Leak), CONF-08 (Auth Headers)",
        "swarm_prompt": "info-gathering.md, configuration.md",
    },
}

# ── Phase 3: Support & Methodology ──────────────────────────────────────────
PHASE_3 = {
    "bb-methodology": {
        "agent": "bb-methodology",
        "description": "Bug bounty methodology orchestrator. 5-phase nonlinear workflow, mode selection (bounty/redteam/pentest/audit), scope confirmation, throttle management, payout optimization.",
        "wstg": "All phases (Workflow Orchestration)",
        "swarm_prompt": "",
    },
    "hunt-dispatch": {
        "agent": "hunt-dispatcher",
        "description": "Hunt dispatcher — routes to the correct hunting agent based on target fingerprinting. Mode selection, technology stack identification, agent delegation.",
        "wstg": "INFO-01 (Fingerprinting), INFO-02 (Technology Detection)",
        "swarm_prompt": "info-gathering.md",
    },
    "report-writing": {
        "agent": "report-writing",
        "description": "Security report writer. HackerOne/Bugcrowd/Intigriti/Immunefi templates, impact quantification, CVSS 3.1 scoring, remediation guidance, executive summaries.",
        "wstg": "All phases (Report Generation)",
        "swarm_prompt": "templates/report-template.md",
    },
    "triage-validation": {
        "agent": "triage-validation",
        "description": "Finding triage and validation. 7-Question Gate: real request? accepted impact? in-scope? not admin-only? concrete? not on never-submit? Verdicts: PASS/KILL/DOWNGRADE/CHAIN-REQUIRED.",
        "wstg": "All phases (Validation Gate)",
        "swarm_prompt": "templates/quality-gates.md",
    },
    "evidence-hygiene": {
        "agent": "evidence-hygiene",
        "description": "Evidence hygiene specialist. Cookie/PII redaction, HAR sanitization, screenshot metadata stripping, evidence chain of custody, submission proof pack.",
        "wstg": "All phases (Evidence Handling)",
        "swarm_prompt": "templates/testing-strategies.md",
    },
    "offensive-osint": {
        "agent": "offensive-osint",
        "description": "Offensive OSINT gatherer. Identity fabric mapping, breached credential lookup, email/phone/social enumeration, dark web intel, organizational footprint.",
        "wstg": "INFO-01 (Search Engine Recon), INFO-02 (OSINT), INFO-06 (Information Leak)",
        "swarm_prompt": "info-gathering.md",
    },
    "web2-recon": {
        "agent": "web2-recon",
        "description": "Web recon specialist. Subdomain enumeration, technology fingerprinting, endpoint discovery, directory brute force, parameter fuzzing, WAF detection.",
        "wstg": "INFO-03 through INFO-10 (Recon Techniques)",
        "swarm_prompt": "info-gathering.md",
    },
    "osint-methodology": {
        "agent": "osint-methodology",
        "description": "OSINT methodology guide. Source verification, data correlation, persona tracking, geolocation, temporal analysis, OSINT tool selection framework.",
        "wstg": "INFO-01, INFO-02, INFO-06",
        "swarm_prompt": "info-gathering.md",
    },
    "redteam-mindset": {
        "agent": "redteam-mindset",
        "description": "Red team operator mindset. Primary directive, anti-patterns, operational discipline, burnout avoidance, documentation hygiene, engagement closure discipline.",
        "wstg": "All phases (Operator Guidance)",
        "swarm_prompt": "",
    },
    "mid-engagement-ir-detection": {
        "agent": "ir-detector",
        "description": "Mid-engagement IR/defender detection awareness. SOC detection patterns, blue team tooling, EDR telemetry, defender response playbooks, operational stealth.",
        "wstg": "All phases (OPSEC)",
        "swarm_prompt": "templates/testing-strategies.md",
    },
    "redteam-report-template": {
        "agent": "redteam-reporter",
        "description": "Red team report template generator. Client-facing DOCX deliverables, Subject/Observations/Impact/Recommendation/PoC sections, embedded screenshots, executive summary.",
        "wstg": "All phases (Red Team Reporting)",
        "swarm_prompt": "templates/report-template.md",
    },
    "bugcrowd-reporting": {
        "agent": "bugcrowd-reporter",
        "description": "Bugcrowd-specific reporter. VRT category mapping, severity justification, OOS rebuttal templates, Bugcrowdninja alias hygiene, friendly-tester posture guidelines.",
        "wstg": "All phases (Bugcrowd Reporting)",
        "swarm_prompt": "templates/report-template.md",
    },
    "bug-bounty": {
        "agent": "bug-bounty",
        "description": "Bug bounty generalist orchestrator. Program selection, duplicate detection, payout optimization, VRT mapping, responsible disclosure, bounty hunter workflow.",
        "wstg": "All phases (Bug Bounty)",
        "swarm_prompt": "",
    },
    "security-arsenal": {
        "agent": "security-arsenal",
        "description": "Security tool arsenal reference. Payload banks, wordlists, tool configuration profiles, one-liner collections, WAF bypass lists, encoding/decoding reference.",
        "wstg": "All phases (Tool Reference)",
        "swarm_prompt": "",
    },

    "bb-local-toolkit": {
        "agent": "bb-local-toolkit",
        "description": "Complete bug bounty local toolkit — recon, pre-hunt learning, vulnerability hunting, LLM/AI security testing, A-to-B bug chaining, bypass tables, language-specific grep, and reporting workflow.",
        "wstg": "All categories (BB Workflow)",
        "swarm_prompt": "",
    },
    "credential-attack": {
        "agent": "credential-attacker",
        "description": "Credential attack methodology — password spray, wordlist generation, breach checking, OSINT employee enumeration, rate-limit tactics, BBP legal guardrails.",
        "wstg": "ATHN-07 (Password Policy), ATHN-03 (Brute Force/Lockout)",
        "swarm_prompt": "authentication.md",
    },}

# ── Phase 4: Framework-Specific ─────────────────────────────────────────────
PHASE_4 = {
    "hunt-aspnet": {
        "agent": "aspnet-hunter",
        "description": "ASP.NET / .NET security hunter. ViewState validation bypass, machineKey disclosure, IIS misconfig, UnvalidatedRequestValues, request validation bypass (CVE-2024-22093).",
        "wstg": "CONF-04 (.NET Config), INPV-05 (ASP.NET Injection)",
        "swarm_prompt": "configuration.md, input-validation.md",
    },
    "hunt-springboot": {
        "agent": "springboot-hunter",
        "description": "Spring Boot security hunter. Actuator exposure, Spring4Shell, classpath RCE, property injection, Spring Cloud/Config vulnerabilities, SpEL injection.",
        "wstg": "CONF-05 (Admin Interfaces)",
        "swarm_prompt": "configuration.md, input-validation.md",
    },
    "hunt-laravel": {
        "agent": "laravel-hunter",
        "description": "Laravel security hunter. Debug mode exposure, APP_KEY decryption, serialization RCE, mass assignment, Blade template injection, Eloquent injection.",
        "wstg": "CONF-04 (PHP Config), INPV-05 (Eloquent Injection)",
        "swarm_prompt": "configuration.md, input-validation.md",
    },
    "hunt-nextjs": {
        "agent": "nextjs-hunter",
        "description": "Next.js security hunter. Vercel misconfig, SSG/SSR data leakage, API route auth bypass, middleware bypass, image optimization abuse, RSC injection.",
        "wstg": "CONF-04 (Node.js Config), APIT-02 (Next.js API)",
        "swarm_prompt": "configuration.md, api-testing.md",
    },
    "hunt-nodejs": {
        "agent": "nodejs-hunter",
        "description": "Node.js/Express security hunter. Prototype pollution, unsafe eval, deserialization, dependency vulnerability, misconfigured CORS, express-session flaws.",
        "wstg": "CLNT-14 (Prototype Pollution), INPV-11 (Code Injection)",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-tls-network": {
        "agent": "tls-hunter",
        "description": "TLS/SSL and network security hunter. Weak cipher suites, outdated TLS versions, certificate validation bypass, STARTTLS injection, HTTP/2 downgrade.",
        "wstg": "CRYP-01 (Weak TLS), CRYP-02 (Padding Oracle), CRYP-03 (Weak Crypto)",
        "swarm_prompt": "cryptography.md",
    },
}

# ── Phase 5: Specialized ────────────────────────────────────────────────────
PHASE_5 = {
    "hunt-nosqli": {
        "agent": "nosqli-hunter",
        "description": "NoSQL injection hunter. MongoDB $where/$regex injection, CouchDB JavaScript injection, Cassandra CQL injection, DynamoDB expression injection.",
        "wstg": "",
        "swarm_prompt": "input-validation.md",
    },
    "hunt-saml": {
        "agent": "saml-hunter",
        "description": "SAML SSO hunter. XML signature wrapping, assertion injection, Replay attack, recipient/audience confusion, IDP-initiated SSO abuse, certificate manipulation.",
        "wstg": "IDNT-04 (Federation)",
        "swarm_prompt": "authentication.md, identity-management.md",
    },
    "hunt-ldap": {
        "agent": "ldap-hunter",
        "description": "LDAP injection and security hunter. LDAP injection, anonymous binds, privilege escalation via LDAP, directory traversal, AD/LDAP misconfig.",
        "wstg": "INPV-06 (LDAP Injection), CONF-07 (Directory Services)",
        "swarm_prompt": "input-validation.md, configuration.md",
    },
    "hunt-source-leak": {
        "agent": "hunt-source-leak",
        "description": "Source code leak hunter. .git/config exposure, .env file access, backup file disclosure, source map/reverse source map analysis, debug endpoint exposure.",
        "wstg": "INFO-06 (Information Leak), CONF-02 (File Exposure)",
        "swarm_prompt": "info-gathering.md, configuration.md",
    },
    "hunt-business-logic": {
        "agent": "bizlogic-hunter",
        "description": "Business logic flaw hunter. Pricing manipulation, workflow bypass, multi-step process flaws, currency conversion exploits, loyalty/coupon abuse, KYC bypass.",
        "wstg": "BUSL-01 through BUSL-10 (Business Logic)",
        "swarm_prompt": "business-logic.md",
    },
    "hunt-misc": {
        "agent": "misc-hunter",
        "description": "General vulnerability hunter. Catch-all for uncovered classes, emerging threats, zero-day patterns, uncommon attack surfaces, and novel vulnerability types.",
        "wstg": "All categories (General)",
        "swarm_prompt": "",
    },
    "web3-audit": {
        "agent": "web3-audit",
        "description": "Web3/blockchain audit hunter. 10 DeFi bug classes: reentrancy, flash loan, oracle manipulation, sandwich attack, MEV extraction, access control, integer overflow, signature replay.",
        "wstg": "DeFi Security (10 Bug Classes)",
        "swarm_prompt": "input-validation.md, business-logic.md",
    },
    "meme-coin-audit": {
        "agent": "meme-coin-auditor",
        "description": "Meme coin / token audit hunter. Token rug-pull detection, honeypot analysis, liquidity lock verification, ownership renounce, proxy contract risks.",
        "wstg": "DeFi Security (Token Risks)",
        "swarm_prompt": "business-logic.md",
    },

    "hunt-grpc": {
        "agent": "grpc-hunter",
        "description": "gRPC API vulnerability hunter. Server reflection, missing auth on internal endpoints, plaintext gRPC over HTTP/2, internal endpoint disclosure, proto file leakage, gRPC-Web proxy injection, HTTP/2 rapid reset DoS.",
        "wstg": "APIT-03 (SOAP/XML-RPC)",
        "swarm_prompt": "api-testing.md, input-validation.md",
    },}


# ── Phase 6: WAF Bypass & Evasion ─────────────────────────────────────────
PHASE_6 = {
    "waf-fingerprinting": {
        "agent": "waf-fingerprinter",
        "description": "WAF fingerprinting and identification. Detect Cloudflare, AWS WAF, ModSecurity, F5 ASM, Imperva, Sucuri, Akamai, and 15+ other WAFs from response headers, error pages, and blocking behavior.",
        "wstg": "INFO-08 (Fingerprinting)",
        "swarm_prompt": "info-gathering.md",
    },
    "waf-bypass-cloudflare": {
        "agent": "waf-bypass-cloudflare",
        "description": "Cloudflare WAF bypass techniques. Known origin IP discovery (Censys/Shodan, favicon hash, SSL cert, FZDS), header spoofing (X-Forwarded-For, CF-Connecting-IP), path normalization bypass, and rate-limit evasion.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-aws": {
        "agent": "waf-bypass-aws",
        "description": "AWS WAF (WAF/Shield) bypass techniques. IP allowlist rules, rate-based rules bypass, SQLi/XSS rule evasion via encoding, size constraint bypass, regional WAF enumeration.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-f5": {
        "agent": "waf-bypass-f5",
        "description": "F5 BIG-IP ASM WAF bypass techniques. Attack signature evasion, policy bypass via parameter obfuscation, HTTP protocol compliance bypass, iRule misconfiguration.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-imperva": {
        "agent": "waf-bypass-imperva",
        "description": "Imperva WAF (Incapsula) bypass techniques. Known origin IP discovery, header spoofing, client classification bypass, challenge-solving automation.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-modsecurity": {
        "agent": "waf-bypass-modsecurity",
        "description": "ModSecurity WAF bypass techniques. CRS rule evasion, false positive abuse, request smuggling before WAF, protocol anomaly bypass, SecRuleEngine misconfig.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-sucuri": {
        "agent": "waf-bypass-sucuri",
        "description": "Sucuri WAF bypass techniques. Known origin IP via leaked DNS, header spoofing, cache-based bypass, CloudProxy misconfiguration.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-akamai": {
        "agent": "waf-bypass-akamai",
        "description": "Akamai Kona WAF bypass techniques. CVE-2025-30143 variable chaining, JSON escape unicode normalization, tagged template literals, redirect-based SSRF, origin IP discovery.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-fastly": {
        "agent": "waf-bypass-fastly",
        "description": "Fastly Next-Gen WAF bypass techniques. Parameter cloaking for cache poisoning, origin IP bypass, startup probe fail-open, content-type confusion, HTTP/2 frame delay.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-bypass-signalsciences": {
        "agent": "waf-bypass-signalsciences",
        "description": "Signal Sciences (Fastly NGWAF) bypass techniques. JSON/HTML encoding bypass, chunked transfer encoding smuggling, payload padding, content-type confusion, null byte injection.",
        "wstg": "CONF-02 (Bypass WAF)",
        "swarm_prompt": "configuration.md",
    },
    "waf-encoding-obfuscation": {
        "agent": "waf-encoding-evader",
        "description": "WAF encoding and obfuscation bypass. Double URL encoding, Unicode normalization, mixed case, comment insertion, null bytes, UTF-8 overlong sequences, base64 padding tricks.",
        "wstg": "",
        "swarm_prompt": "input-validation.md",
    },
    "waf-evasion-xss": {
        "agent": "waf-evasion-xss",
        "description": "WAF XSS evasion techniques. Polyglot payloads, event handler variants, SVG bypass, mutation XSS (mXSS), DOMPurify bypass, trusted types bypass, CSP bypass via JSONP/gadgets.",
        "wstg": "INPV-01 (XSS), CLNT-01 (DOM XSS)",
        "swarm_prompt": "input-validation.md, client-side.md",
    },
    "waf-evasion-sqli": {
        "agent": "waf-evasion-sqli",
        "description": "WAF SQLi evasion techniques. Heavy comment insertion, case variation, scientific notation, chunked encoding, HTTP parameter pollution, unicode encoding, CRLF+padding.",
        "wstg": "INPV-05 (SQLi)",
        "swarm_prompt": "input-validation.md",
    },
    "waf-evasion-rce": {
        "agent": "waf-evasion-rce",
        "description": "WAF RCE/command injection evasion techniques. Backtick/pipe substitution, environment variable obfuscation, hex/octal encoding, wildcard expansion, newline injection, parameter splitting.",
        "wstg": "INPV-12 (Command Injection)",
        "swarm_prompt": "input-validation.md",
    },
    "waf-header-spoofing": {
        "agent": "waf-header-spoofer",
        "description": "WAF header spoofing techniques. X-Forwarded-For, True-Client-IP, X-Real-IP, CF-Connecting-IP, X-Originating-IP, X-Remote-IP, X-Client-IP, Forwarded, Via, X-Forwarded-Host, X-Forwarded-Proto.",
        "wstg": "CONF-05 (Header Spoofing)",
        "swarm_prompt": "configuration.md",
    },
    "waf-hpp-hpf": {
        "agent": "waf-hpp-specialist",
        "description": "HTTP Parameter Pollution and HPF evasion. Duplicate parameter injection, array notation, parameter separation, HPP for WAF bypass, HPP for auth bypass, parameter clustering.",
        "wstg": "INPV-04 (HPP)",
        "swarm_prompt": "input-validation.md",
    },
    "waf-protocol-evasion": {
        "agent": "waf-protocol-evader",
        "description": "WAF protocol-level evasion techniques. HTTP/0.9 fallback, chunked transfer encoding smuggling, Content-Type confusion, method override (X-HTTP-Method-Override, X-HTTP-Method), HTTP/2 → HTTP/1.1 downgrade.",
        "wstg": "INPV-15 (HTTP Smuggling)",
        "swarm_prompt": "input-validation.md",
    },
    "waf-regex-reversing": {
        "agent": "waf-regex-reverser",
        "description": "WAF regex reversing and rule inference. Blind rule mapping via binary search on payload length, character class probing, alternation testing, ReDoS against the WAF itself, rule timing side-channels.",
        "wstg": "",
        "swarm_prompt": "input-validation.md",
    },
}

# ── WSTG cross-reference by agent name ──────────────────────────────────────
WSTG_TESTS = {
    "xss-hunter": "WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01",
    "sqli-hunter": "WSTG-INPV-05, WSTG-INPV-06",
    "ssrf-hunter": "WSTG-INPV-19",
    "ssti-hunter": "WSTG-INPV-18",
    "lfi-hunter": "WSTG-ATHZ-01",
    "xxe-hunter": "WSTG-INPV-20",
    "idor-hunter": "WSTG-ATHZ-01",
    "csrf-hunter": "WSTG-SESS-05",
    "cors-hunter": "WSTG-CLNT-07",
    "oauth-hunter": "WSTG-ATHZ-05",
    "graphql-hunter": "WSTG-APIT-01",
    "file-upload-hunter": "WSTG-BUSL-07",
    "host-header-hunter": "WSTG-INPV-17",
    "http-smuggler": "WSTG-INPV-15",
    "open-redirect-hunter": "WSTG-CLNT-04",
    "brute-force-hunter": "WSTG-ATHN-03",
    "session-hunter": "WSTG-SESS-*",
    "auth-bypass-hunter": "WSTG-ATHZ-02",
    "ato-hunter": "",
    "subdomain-hunter": "WSTG-INFO-03",
    "api-misconfig-hunter": "WSTG-APIT-02",
    "mfa-bypass-hunter": "WSTG-ATHN-11",
    "race-condition-hunter": "WSTG-BUSL-04",
    "cache-poison-hunter": "",
    "deserialization-hunter": "WSTG-INPV-10",
    "dom-hunter": "WSTG-CLNT-01",
    "websocket-hunter": "WSTG-CLNT-09",
    "llm-hunter": "",
    "rce-hunter": "WSTG-INPV-12",

    "ssrf-cloud-hunter": "WSTG-INPV-19",
    "grpc-hunter": "WSTG-APIT-02",
    "bb-local-toolkit": "All categories",
    "credential-attacker": "WSTG-ATHN-07",
    "waf-fingerprinter": "WSTG-INFO-08",
    "waf-bypass-cloudflare": "WSTG-CONF-02",
    "waf-bypass-aws": "WSTG-CONF-02",
    "waf-bypass-f5": "WSTG-CONF-02",
    "waf-bypass-imperva": "WSTG-CONF-02",
    "waf-bypass-modsecurity": "WSTG-CONF-02",
    "waf-bypass-sucuri": "WSTG-CONF-02",
    "waf-encoding-evader": "WSTG-INPV-16",
    "waf-evasion-xss": "WSTG-INPV-01",
    "waf-evasion-sqli": "WSTG-INPV-05",
    "waf-evasion-rce": "WSTG-INPV-03",
    "waf-header-spoofer": "WSTG-CONF-05",
    "waf-hpp-specialist": "WSTG-INPV-04",
    "waf-protocol-evader": "WSTG-INPV-17",
    "waf-regex-reverser": "WSTG-INPV-16",
}


def _fix_acronyms(text: str) -> str:
    """Fix acronym casing: Xss -> XSS, Sqli -> SQLi, etc."""
    fixes = {
        "Xss": "XSS",
        "Sqli": "SQLi",
        "Ssrf": "SSRF",
        "Ssti": "SSTI",
        "Lfi": "LFI",
        "Xxe": "XXE",
        "Idor": "IDOR",
        "Csrf": "CSRF",
        "Cors": "CORS",
        "Oauth": "OAuth",
        "Graphql": "GraphQL",
        "Ato": "ATO",
        "Mfa": "MFA",
        "Dom": "DOM",
        "Rce": "RCE",
        "Nosqli": "NoSQLi",
        "Hpp": "HPP",
        "Hpf": "HPF",
        "Tls": "TLS",
        "Ntlm": "NTLM",
        "Saml": "SAML",
        "Ldap": "LDAP",
        "Spel": "SpEL",
        "AspNet": "ASP.NET",
        "K8S": "K8s",
        "Cicd": "CI/CD",
        "Llm": "LLM",
        "Ai": "AI",
        "Api": "API",
        "Cdn": "CDN",
        "Dns": "DNS",
        "Url": "URL",
        "Waf": "WAF",
        "Jwt": "JWT",
        "Csp": "CSP",
        "Mxss": "mXSS",
        "Svg": "SVG",
        "Ssl": "SSL",
        "Sso": "SSO",
        "Rbac": "RBAC",
        "Cve": "CVE",
        "Cvss": "CVSS",
        "Poc": "PoC",
        "Oob": "OOB",
        "Or Ntl": "or NTLM",
    }
    for wrong, correct in fixes.items():
        text = text.replace(wrong, correct)
    return text

# Maps old BH skill references to Swarm equivalents
BH_TO_SWARM = {
    "hunt-xss": "xss-hunter",
    "hunt-sqli": "sqli-hunter",
    "hunt-ssrf": "ssrf-hunter",
    "hunt-ssti": "ssti-hunter",
    "hunt-lfi": "lfi-hunter",
    "hunt-xxe": "xxe-hunter",
    "hunt-idor": "idor-hunter",
    "hunt-csrf": "csrf-hunter",
    "hunt-cors": "cors-hunter",
    "hunt-oauth": "oauth-hunter",
    "hunt-graphql": "graphql-hunter",
    "hunt-file-upload": "file-upload-hunter",
    "hunt-host-header": "host-header-hunter",
    "hunt-http-smuggling": "http-smuggler",
    "hunt-open-redirect": "open-redirect-hunter",
    "hunt-brute-force": "brute-force-hunter",
    "hunt-session": "session-hunter",
    "hunt-auth-bypass": "auth-bypass-hunter",
    "hunt-ato": "ato-hunter",
    "hunt-subdomain": "subdomain-hunter",
    "hunt-api-misconfig": "api-misconfig-hunter",
    "hunt-mfa-bypass": "mfa-bypass-hunter",
    "hunt-race-condition": "race-condition-hunter",
    "hunt-cache-poison": "cache-poison-hunter",
    "hunt-deserialization": "deserialization-hunter",
    "hunt-dom": "dom-hunter",
    "hunt-websocket": "websocket-hunter",
    "hunt-llm-ai": "llm-hunter",
    "hunt-rce": "rce-hunter",
    "hunt-k8s": "k8s-hunter",
    "hunt-cicd": "cicd-hunter",
    "hunt-cloud-misconfig": "cloud-misconfig-hunter",
    "hunt-nosqli": "nosqli-hunter",
    "hunt-saml": "saml-hunter",
    "hunt-ldap": "ldap-hunter",
    "source-leak-hunter": "hunt-source-leak",
    "hunt-business-logic": "bizlogic-hunter",
    "hunt-misc": "misc-hunter",
    "hunt-sharepoint": "sharepoint-hunter",
    "hunt-ntlm-info": "ntlm-hunter",
    "hunt-aspnet": "aspnet-hunter",
    "hunt-springboot": "springboot-hunter",
    "hunt-laravel": "laravel-hunter",
    "hunt-nextjs": "nextjs-hunter",
    "hunt-nodejs": "nodejs-hunter",
    "hunt-tls-network": "tls-hunter",
    "security-arsenal": "security-arsenal",
    "triage-validator": "triage-validation",
    "report-writer": "report-writing",
    "evidence-hygiene": "evidence-hygiene",
    "osint-gatherer": "offensive-osint",
    "web-recon": "web2-recon",
    "osint-methodology": "osint-methodology",
    "bb-methodology": "bb-methodology",
    "bug-bounty": "bug-bounty",
    "bugcrowd-reporting": "bugcrowd-reporter",
    "redteam-mindset": "redteam-mindset",
    "mid-engagement-ir-detection": "ir-detector",
    "redteam-report-template": "redteam-reporter",
    "cloud-iam-deep": "cloud-iam-auditor",
    "m365-entra-attack": "m365-attacker",
    "okta-attack": "okta-attacker",
    "vmware-vcenter-attack": "vcenter-attacker",
    "enterprise-vpn-attack": "vpn-attacker",
    "supply-chain-attack-recon": "supply-chain-hunter",
    "apk-redteam-pipeline": "apk-analyzer",
    "web3-auditor": "web3-audit",
    "meme-coin-audit": "meme-coin-auditor",
    "hunt-dispatch": "hunt-dispatcher",

    "hunt-ssrf-cloud": "ssrf-cloud-hunter",
    "hunt-grpc": "grpc-hunter",
    "bb-local-toolkit": "bb-local-toolkit",
    "credential-attack": "credential-attacker",
    "waf-fingerprinting": "waf-fingerprinter",
    "waf-bypass-cloudflare": "waf-bypass-cloudflare",
    "waf-bypass-aws": "waf-bypass-aws",
    "waf-bypass-f5": "waf-bypass-f5",
    "waf-bypass-imperva": "waf-bypass-imperva",
    "waf-bypass-modsecurity": "waf-bypass-modsecurity",
    "waf-bypass-sucuri": "waf-bypass-sucuri",
    "waf-encoding-obfuscation": "waf-encoding-evader",
    "waf-evasion-xss": "waf-evasion-xss",
    "waf-evasion-sqli": "waf-evasion-sqli",
    "waf-evasion-rce": "waf-evasion-rce",
    "waf-header-spoofing": "waf-header-spoofer",
    "waf-hpp-hpf": "waf-hpp-specialist",
    "waf-protocol-evasion": "waf-protocol-evader",
    "waf-regex-reversing": "waf-regex-reverser",
}


HEADER_TEMPLATE = """\
---
description: {description}
mode: subagent
permission:
  read: allow
  bash: deny
  edit: deny
  grep: allow
  glob: allow
---

You are an expert {short_name} for penetration testing.

## Workflow Integration with Swarm

This agent works alongside the Swarm MCP server and WSTG methodology:

1. **Read the methodology** → `get_wstg_test("{wstg_test_id}")` for baseline technique guidance
{swarm_prompt_line}3. **Browser automation** — Use browser tools for auth flows, screenshots, crawling, and client-side testing:
   - `browser_login(engagement_id, agent_id, url, username, password)` — login form automation with cookie persistence
   - `browser_screenshot(engagement_id, agent_id, url)` — capture evidence screenshots
   - `browser_crawl(engagement_id, start_url, depth)` — discover pages and endpoints via link crawling
   - `browser_extract_storage(engagement_id, agent_id, url)` — extract cookies, localStorage, sessionStorage
   - `_run_driver("navigate", url)` — navigate to a URL (low-level, reuses persistent browser)
   - `_run_driver("state")` — get page state including interactive elements
   - `_run_driver("click", index)` — click element by index
   - `_run_driver("type", index, text)` — type into element
   - `_run_driver("js", code)` — execute JavaScript in page context

   **Auth helper**: Use `browser_login()` for login form automation with auto-detected form fields.

4. **BurpSuite pro workflow** — Use Burp MCP tools at every stage like a professional bug hunter. All HTTP requests flow through Burp (NOT raw curl). The workflow mirrors real Burp usage:

   a) **Proxy** — Intercept and review all traffic:
      - `burp_set_proxy_intercept_state(True/False)` — toggle intercept to pause/resume requests in-flight
      - `burp_get_proxy_http_history()` — review discovered endpoints, params, and auth tokens in history
      - `burp_get_active_editor_contents()` — read the current request in the editor
      - `burp_set_active_editor_contents(text)` — modify a request in the editor before forwarding

   b) **Repeater** — Manual testing on interesting endpoints:
      - `burp_send_http1_request(content, targetHostname, targetPort, usesHttps)` — fire a single HTTP/1.1 request
      - `burp_send_http2_request(headers, pseudoHeaders, requestBody, ...)` — fire a single HTTP/2 request
      - `burp_create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName)` — save request/response to a named Repeater tab for review
      - `burp_create_repeater_tab_http2(headers, pseudoHeaders, requestBody, targetHostname, targetPort, usesHttps, tabName)` — save HTTP/2 finding to Repeater

   c) **Intruder** — Automated fuzzing and enumeration:
      - `burp_send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName)` — send request to Intruder for parameter fuzzing, brute force, or ID enumeration

   d) **Collaborator** — Out-of-band detection:
      - `burp_generate_collaborator_payload()` — get a unique collaborator URL for OOB testing (blind XSS, SSRF, XXE, SQLi)
      - `burp_get_collaborator_interactions(payloadId)` — poll for DNS/HTTP/SMTP callbacks from the target
      - Also available: `swarm-oob start` / `swarm-oob stop` for standalone OOB listener (scripts/tools/oob_listener.sh)

   e) **Scanner** — Automated vulnerability scanning:
      - `burp_get_scanner_issues()` — retrieve scan findings (filter by severity)

   f) **Organizer** — Evidence storage for reporting:
      - `burp_get_organizer_items(count, offset)` — retrieve saved items from Organizer
      - `burp_get_organizer_items_regex(count, offset, regex)` — search Organizer by pattern
5. **Find vulnerabilities** → `log_finding()` or `findings_add_vuln()` to persist to SQLite
6. **Log findings** → `findings_add_vuln(engagement_id, title, severity, ..., test_id="{wstg_test_id}")`
7. **Track coverage** → `track_test(engagement_id, test_id="{wstg_test_id}", status="completed", notes=...)`
8. **Chain findings** → `findings_add_chain()` to record multi-step attack paths
9. **Generate report** → `findings_handoff()` for cross-session handoff or `generate_report()` for final output

**Documentation**: See `docs/browser-flow.md` for browser automation reference, `docs/pipeline.md` for OOB detection workflow.

## Scope Notice

- **Advisory mode** (default): You provide methodology, payloads, and analysis. The user executes commands.
- **Execution mode**: If the user has a declared scope in Swarm (`findings_init()`), you may compose commands for the user to run.

---

## {title}

"""


def convert_skill(skill_dir: str, config: dict, dry_run: bool = False) -> str:
    """Convert a single BH skill to OpenCode agent."""
    skill_path = BH_SKILLS / skill_dir / "SKILL.md"
    if not skill_path.exists():
        print(f"  [SKIP] {skill_path} not found")
        return ""

    content = skill_path.read_text(encoding="utf-8")

    # Parse YAML frontmatter - handle problematic descriptions with colons
    parts = content.split("---", 2)
    frontmatter = {}
    try:
        frontmatter = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        # Fallback: extract fields manually using regex
        fm_text = parts[1]
        name_m = re.search(r'^name:\s*(.+)$', fm_text, re.MULTILINE)
        desc_m = re.search(r'^description:\s*(.+)$', fm_text, re.MULTILINE)
        if name_m:
            frontmatter['name'] = name_m.group(1).strip()
        if desc_m:
            frontmatter['description'] = desc_m.group(1).strip()
    body = parts[2].strip()

    agent_name = config["agent"]
    description = config["description"]
    wstg = config.get("wstg", "")
    swarm_prompt = config.get("swarm_prompt", "")

    # Get a human-readable title from the skill name
    title_parts = skill_dir.replace("hunt-", "").replace("-", " ").title()
    if title_parts.startswith("Hunt "):
        title_parts = title_parts[5:]
    title_parts = _fix_acronyms(title_parts)
    title = title_parts + " Testing"

    short_name = agent_name.replace("-hunter", "").replace("-auditor", "").replace("-analyzer", "").replace("-attacker", "").replace("-reporter", "").replace("-detector", "").replace("-gatherer", "").replace("-recon", "").replace("-dispatcher", "").replace("-validator", "").replace("-writer", "").replace("-smuggler", "").replace("-methodology", "")

    # Build WSTG test ID reference
    wstg_first = wstg.split(",")[0].strip() if wstg else "WSTG"
    wstg_test_id = WSTG_TESTS.get(agent_name, wstg_first)

    # Build header
    prompt_line = f"2. **Check related prompt** → read `prompts/{swarm_prompt}` for Swarm-specific workflow\n" if swarm_prompt else ""
    header = HEADER_TEMPLATE.format(
        description=description,
        short_name=short_name,
        wstg_test_id=wstg_test_id,
        swarm_prompt_line=prompt_line,
        title=title,
    )

    # Rewrite cross-references in the body
    body = _rewrite_refs(body)

    # Fix Swarm MCP tool references
    body = _fix_tool_refs(body)

    # Fix outdated browser tool references
    body = _fix_browser_refs(body)

    agent_content = header + body

    if dry_run:
        print(f"  [OK] {agent_name} (would write to {AGENTS_DIR}/{skill_dir}.md)")
        return ""

    # Write to flat file using skill directory name
    agent_path = AGENTS_DIR / f"{skill_dir}.md"
    agent_path.write_text(agent_content, encoding="utf-8")
    lines = len(agent_content.splitlines())
    print(f"  [OK] {agent_name} -> {skill_dir}.md ({lines} lines)")
    return agent_name


def _rewrite_refs(body: str) -> str:
    """Rewrite BH cross-references to Swarm agent names."""
    for old_ref, new_ref in sorted(BH_TO_SWARM.items(), key=lambda x: -len(x[0])):
        body = body.replace(f"`{old_ref}`", f"`{new_ref}`")
        body = body.replace(f"[{old_ref}]", f"[{new_ref}]")
    body = body.replace("Claude-BugHunter", "Swarm")
    body = body.replace("triage-validation", "triage-validator")
    body = body.replace("hunt-dispatch", "hunt-dispatcher")
    body = body.replace("bb-methodology", "bb-methodology")
    return body


def _fix_tool_refs(body: str) -> str:
    """Replace old tool refs with Swarm MCP equivalents."""
    body = body.replace("`claude`", "`opencode`")
    body = body.replace("Claude Code", "OpenCode")
    return body


def _fix_browser_refs(body: str) -> str:
    """Replace outdated browser tool refs with current Swarm browser tools."""
    body = body.replace("playwright_browser_navigate(", "_run_driver(\"navigate\", ")
    body = body.replace("playwright_browser_click(", "_run_driver(\"click\", ")
    body = body.replace("playwright_browser_type(", "_run_driver(\"type\", ")
    body = body.replace("playwright_browser_fill_form(", "_run_driver(\"type\", ")
    body = body.replace("playwright_browser_snapshot(", "browser_screenshot(")
    body = body.replace("playwright_browser_take_screenshot(", "browser_screenshot(")
    body = body.replace("playwright_browser_evaluate(", "_run_driver(\"js\", ")
    body = body.replace("playwright_browser_network_requests(", "browser_crawl(")
    body = body.replace("playwright_browser_console_messages(", "_run_driver(\"state\", ")
    body = body.replace("playwright_browser_close(", "# browser auto-closes on idle")
    body = body.replace("`playwright_browser_navigate`", "`_run_driver(\"navigate\", url)`")
    body = body.replace("`playwright_browser_click`", "`_run_driver(\"click\", index)`")
    body = body.replace("`playwright_browser_type`", "`_run_driver(\"type\", index, text)`")
    body = body.replace("`playwright_browser_fill_form`", "`_run_driver(\"type\", ...)`")
    body = body.replace("`playwright_browser_snapshot`", "`browser_screenshot()`")
    body = body.replace("`playwright_browser_take_screenshot`", "`browser_screenshot()`")
    body = body.replace("`playwright_browser_evaluate`", "`_run_driver(\"js\", code)`")
    body = body.replace("`playwright_browser_network_requests`", "`browser_crawl()`")
    body = body.replace("`playwright_browser_console_messages`", "`_run_driver(\"state\")`")
    body = body.replace("`playwright_browser_close`", "`# auto-close`")
    body = body.replace("`playwright_browser_*`", "`browser_login`, `browser_screenshot`, `browser_crawl`, `browser_extract_storage`, `_run_driver()`")
    body = body.replace("Playwright browser", "browser")
    body = body.replace("Playwright", "browser")
    body = body.replace("./scripts/browser-use-agent.sh", "python3 scripts/browser_driver.py")
    body = body.replace("../docs/browser-testing.md", "../docs/browser-flow.md")
    body = body.replace("`retry_with_browser_use_agent`", "`browser_login` or `browser_screenshot`")
    body = body.replace("retry_with_browser_use_agent", "browser_login")
    body = body.replace("browser-use", "browser")
    body = body.replace("browser_use", "browser")
    body = body.replace("Puppeteer, PhantomJS", "browser tools")
    body = body.replace("Puppeteer, wkhtmltopdf, Browsershot", "browser tools")
    body = body.replace("PhantomJS", "headless browser")
    body = body.replace("Puppeteer", "Playwright/Chromium")
    return body


def process_phase(phase_name: str, skills: dict, dry_run: bool = False) -> list:
    """Process all skills in a phase."""
    print(f"\n{'='*60}")
    print(f"Phase: {phase_name}")
    print(f"{'='*60}")
    converted = []
    for skill_dir, config in skills.items():
        result = convert_skill(skill_dir, config, dry_run)
        if result:
            converted.append(result)
    print(f"  Total: {len(converted)}/{len(skills)} converted")
    return converted


def main():
    dry_run = "--dry-run" in sys.argv

    phases_arg = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "--dry-run" else "all"

    AGENTS_DIR.mkdir(parents=True, exist_ok=True)

    phase_map = {
        "1": ("Core Web Hunters", PHASE_1),
        "2": ("Enterprise Platform", PHASE_2),
        "3": ("Support & Methodology", PHASE_3),
        "4": ("Framework-Specific", PHASE_4),
        "5": ("Specialized", PHASE_5),
        "6": ("WAF Bypass & Evasion", PHASE_6),
        "all": ("All Phases", {**PHASE_1, **PHASE_2, **PHASE_3, **PHASE_4, **PHASE_5, **PHASE_6}),
    }

    if phases_arg not in phase_map:
        print(f"Usage: {sys.argv[0]} <phase|all> [--dry-run]")
        print(f"  Phases: {', '.join(k for k in phase_map if k != 'all')}, all")
        sys.exit(1)

    name, skills = phase_map[phases_arg]
    if dry_run:
        print(f"[DRY RUN] Would convert {len(skills)} skills\n")

    total = 0
    result = process_phase(name, skills, dry_run)
    total += len(result)

    print(f"\n{'='*60}")
    print(f"Summary: {total}/{len(skills)} agents created in {AGENTS_DIR}")
    if dry_run:
        print("(dry run — no files written)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
