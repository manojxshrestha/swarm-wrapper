---
name: hunt-dispatch
description: Skill-set loader for /hunt orchestrator. Fingerprints the target, picks the right platform attack skills, and loads the Red Team or WAPT skill set. Use when /hunt has just received a mode answer (redteam or wapt + blackbox|greybox) and needs to load the appropriate skills and print the taxonomy. Not for direct user invocation.
---

# hunt-dispatch

skill-set loader for `/hunt`. one concept (which skills to load), one place.

invocation contract:

```
hunt-dispatch mode=redteam
hunt-dispatch mode=wapt box=blackbox
hunt-dispatch mode=wapt box=greybox
```

## step 1 — fingerprint (red team only)

run a one-shot fingerprint and parse `$RECON_BASE/<target>/live-hosts.txt` if present:

```bash
curl -sI "https://$TARGET" 2>/dev/null | tr -d '\r'
test -f "$RECON_BASE/$TARGET/live-hosts.txt" && cat "$RECON_BASE/$TARGET/live-hosts.txt"
```

look for the following signals → platform skill mapping:

```
okta.com | auth0.com | pingidentity         →  okta-attack
login.microsoftonline.com | outlook | sts   →  m365-entra-attack
pulse | fortinet | ivanti | citrix          →  enterprise-vpn-attack
vsphere | vcenter | :9443                   →  vmware-vcenter-attack
amazonaws | azure | googleapis | gcp        →  cloud-iam-deep
github.com/<org>/                           →  supply-chain-attack-recon
.apk | play.google.com                      →  apk-redteam-pipeline
MongoDB | mongoose | CouchDB | Redis        →  hunt-nosqli
?page= | ?file= | ?path= | php wrapper      →  hunt-lfi
rO0A | VIEWSTATE | rememberMe cookie        →  hunt-deserialization
Access-Control-Allow-Origin header          →  hunt-cors
/forgot-password | /reset | X-Forwarded    →  hunt-host-header
?redirect= | ?next= | ?return= | ?url=     →  hunt-open-redirect
OTP | /verify | /2fa | no-rate-limit        →  hunt-brute-force
Set-Cookie session | PHPSESSID              →  hunt-session
Active Directory | LDAP | OpenLDAP | ADFS  →  hunt-ldap
__NEXT_DATA__ | /_next/ | buildId           →  hunt-nextjs
X-Powered-By: Express | Node.js | .js stack →  hunt-nodejs
postMessage | dangerouslySetInnerHTML        →  hunt-dom
WebSocket | ws:// | socket.io               →  hunt-websocket
gRPC | :50051 | application/grpc            →  hunt-grpc
laravel_session | Ignition | Telescope       →  hunt-laravel
X-Application-Context | Whitelabel | /actuator → hunt-springboot
:6443 | :10250 | :2379 | kubectl            →  hunt-k8s
.github/workflows | Jenkins | GitLab CI     →  hunt-cicd
.js.map | swagger.json | /.env              →  hunt-source-leak
HSTS missing | SPF | DMARC | AXFR           →  hunt-tls-network
cf-ray | server: cloudflare              →  waf-bypass-cloudflare
x-amzn-RequestId | x-amzn-trace-id     →  waf-bypass-aws
BIG-IP | ASM | TS19e6e1                →  waf-bypass-f5
X-Iinfo | Incapsula | Imperva           →  waf-bypass-imperva
ModSecurity | OWASP_CRS | NYOB          →  waf-bypass-modsecurity
X-Sucuri-ID | F5-Traffic-Shield         →  waf-bypass-sucuri
X-Akamai-* | AkamaiGHost               →  waf-bypass-akamai
X-Fastly-* | X-Sigsci-*                →  waf-bypass-fastly
X-Sigsci-Tags | sigsci block page      →  waf-bypass-signalsciences

```

multiple matches → load all matching platform skills.

## step 2 — load skill set

invoke each skill in order via the Skill tool.

### mode=redteam

always-on (load first):

```
redteam-mindset
mid-engagement-ir-detection
waf-fingerprinting
```

platform (load second, conditional on fingerprint matches from step 1):

```
okta-attack
m365-entra-attack
enterprise-vpn-attack
vmware-vcenter-attack
cloud-iam-deep
supply-chain-attack-recon
apk-redteam-pipeline
```
### waf bypass (conditional on WAF fingerprint from step 1)

when a WAF is detected, also load the corresponding bypass skill plus all evasion skills
(since the vuln class to test is not known until the user picks a target):

```
{waf-bypass-cloudflare | waf-bypass-aws | waf-bypass-f5 | waf-bypass-imperva | waf-bypass-modsecurity | waf-bypass-sucuri | waf-bypass-akamai | waf-bypass-fastly | waf-bypass-signalsciences}
waf-evasion-xss
waf-evasion-sqli
waf-evasion-rce
waf-encoding-obfuscation
waf-header-spoofing
waf-hpp-hpf
waf-protocol-evasion
waf-regex-reversing
```

high-impact hunt-* set (load third):

```
hunt-rce
hunt-sqli
hunt-ssrf
hunt-ato
hunt-auth-bypass
hunt-saml
hunt-oauth
hunt-mfa-bypass
hunt-file-upload
hunt-http-smuggling
hunt-cloud-misconfig
hunt-sharepoint
hunt-aspnet
```

report format: `redteam-report-template` (subject / observations / description / impact / recommendation / poc).

### mode=wapt

always-on:

```
bb-methodology
security-arsenal
triage-validation
waf-fingerprinting
```


### waf bypass (conditional on WAF fingerprint from step 1)

when a WAF is detected, also load the corresponding bypass skill plus all evasion skills:

```
{waf-bypass-cloudflare | waf-bypass-aws | waf-bypass-f5 | waf-bypass-imperva | waf-bypass-modsecurity | waf-bypass-sucuri | waf-bypass-akamai | waf-bypass-fastly | waf-bypass-signalsciences}
waf-evasion-xss
waf-evasion-sqli
waf-evasion-rce
waf-encoding-obfuscation
waf-header-spoofing
waf-hpp-hpf
waf-protocol-evasion
waf-regex-reversing
```

full hunt-* set (all OWASP-relevant):

```
hunt-xss             hunt-sqli            hunt-ssrf            hunt-idor
hunt-csrf            hunt-xxe             hunt-rce             hunt-graphql
hunt-oauth           hunt-saml            hunt-mfa-bypass      hunt-auth-bypass
hunt-ato             hunt-file-upload     hunt-business-logic  hunt-race-condition
hunt-llm-ai          hunt-api-misconfig   hunt-ssti            hunt-cache-poison
hunt-http-smuggling  hunt-subdomain       hunt-cloud-misconfig hunt-misc
hunt-aspnet          hunt-sharepoint      hunt-ntlm-info
hunt-lfi             hunt-nosqli          hunt-deserialization
hunt-cors            hunt-host-header     hunt-open-redirect
hunt-brute-force     hunt-session         hunt-ldap
hunt-nextjs          hunt-nodejs          hunt-dom
hunt-websocket       hunt-grpc            hunt-laravel
hunt-springboot      hunt-k8s             hunt-cicd
hunt-source-leak     hunt-tls-network
```

report format: `report-writing` (`bugcrowd-reporting` if the target is on bugcrowd).

box=greybox: creds already captured by `/hunt`, available in session memory. apply them to every authenticated test.

## step 3 — taxonomy print (once, at session start)

emit a deterministic block. plain text, lowercase, colon-delimited, no decoration.

### mode=redteam

```
loaded for red team: {N} skills
  mindset:    redteam-mindset
  platform:   {fingerprint-matched skills, or "none detected"}
  auth:       hunt-ato, hunt-auth-bypass, hunt-saml, hunt-oauth, hunt-mfa-bypass
  inj:        hunt-rce, hunt-sqli, hunt-ssrf, hunt-file-upload
  infra:      hunt-http-smuggling, hunt-cloud-misconfig
  stack:      hunt-sharepoint, hunt-aspnet
  ir:         mid-engagement-ir-detection
  waf:        waf-fingerprinting, {detected-waf-bypass-skills, or "none detected"}

```

### mode=wapt

```
loaded for wapt ({blackbox|greybox}): {N} skills
  inj:        hunt-xss, hunt-sqli, hunt-ssrf, hunt-rce, hunt-xxe, hunt-ssti, hunt-file-upload
  authz:      hunt-idor, hunt-auth-bypass, hunt-ato
  auth:       hunt-oauth, hunt-saml, hunt-mfa-bypass
  api:        hunt-graphql, hunt-api-misconfig
  logic:      hunt-business-logic, hunt-race-condition
  infra:      hunt-http-smuggling, hunt-cache-poison
  recon:      hunt-subdomain
  cloud:      hunt-cloud-misconfig
  ai:         hunt-llm-ai
  stack:      hunt-aspnet, hunt-sharepoint, hunt-ntlm-info
  misc:       hunt-misc, hunt-csrf
  waf:        waf-fingerprinting, {detected-waf-bypass-skills, or "none detected"}
  reporting:  bb-methodology, security-arsenal, triage-validation
```

## step 4 — return control to /hunt

after taxonomy print, hand control back to `/hunt` for step 3 (sibling delegation) and step 4 (active testing). do not run probes here — this skill only loads context.

## privacy

never echo back, log, or persist:
- SOW / scope-of-work / engagement-letter content
- grey box credentials (kept in session memory by `/hunt`, never written to disk)
- client identifiers in user-level memory

---

## Validation Subagent

Before logging a finding, spawn a dedicated subagent to independently confirm exploitability:

1. Pass all evidence (URL, parameters, request/response, payload) to the subagent.
2. The subagent must independently reproduce the PoC — not just restate the hypothesis.
3. If blind/OOB is required, the subagent must start an interactsh listener and demonstrate out-of-band callback before the finding is logged.
4. Only after validation succeeds, capture evidence, assign severity, and log the finding.

This gate prevents false positives, hallucinated impact, and non-reproducible findings from entering the report.

## Related Skills & Chains

- **`bb-methodology`** — When PART 0 mode confirmation completes. Workflow primitive: `bb-methodology` confirms engagement type (red team vs WAPT vs bug bounty); the answer feeds directly into this skill's `mode=redteam` / `mode=wapt` invocation.
- **`redteam-mindset`** + **`mid-engagement-ir-detection`** — When `mode=redteam` is loaded. Workflow primitive: these are the always-on skills loaded first by step 2 of the redteam flow before any platform skill or hunt-* skill.
- **`okta-attack`** / **`m365-entra-attack`** / **`enterprise-vpn-attack`** / **`vmware-vcenter-attack`** / **`cloud-iam-deep`** / **`supply-chain-attack-recon`** / **`apk-redteam-pipeline`** — When fingerprint signals match. Workflow primitive: step 1's curl fingerprint scan against `$RECON_BASE/<target>/live-hosts.txt` maps banner / domain signals to one or more of these platform skills.
- **`hunt-rce`** / **`hunt-sqli`** / **`hunt-ssrf`** / **`hunt-ato`** / **all other hunt-* skills`** — When the mode-specific skill set is being printed. Workflow primitive: this skill is the loader; it names the hunt-* skills but does not run probes — actual hunting happens after step 4 returns control to `/hunt`.
- **`report-writing`** vs **`redteam-report-template`** — When the taxonomy print specifies the report format. Workflow primitive: `mode=wapt` ends with `report-writing` as the deliverable format; `mode=redteam` ends with `redteam-report-template` instead.
