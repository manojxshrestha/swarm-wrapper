#!/usr/bin/env bash
# =============================================================================
# generate_poc_report.sh — Generate evidence, request, and PoC report per finding
#
# Reads a finding from the SQLite database + evidence files, and writes:
#   engagements/recon/<domain>/evidence/finding-<ref>-<slug>/
#     evidence.md    — full vulnerability description from DB data
#     request.txt    — raw HTTP request/response evidence
#     poc-report.md  — bug-bounty style PoC report template
#
# Usage:
#   generate_poc_report.sh <engagement-id> <finding-id> --domain <domain>
#   generate_poc_report.sh <engagement-id> all --domain <domain>
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

EID="${1:?Usage: $0 <engagement-id> <finding-id|all> --domain <domain>}"
FINDING_FILTER="${2:?Usage: $0 <engagement-id> <finding-id|all> --domain <domain>}"
shift 2

DOMAIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    *) log_err "Unknown option: $1"; exit 1 ;;
  esac
done

if [ -z "$DOMAIN" ]; then
  log_err "--domain is required"
  exit 1
fi

DB_PATH="${SWARM_ROOT:-.}/server/data/findings.db"

if [ ! -f "$DB_PATH" ]; then
  log_err "Findings database not found at $DB_PATH"
  exit 1
fi

generate_for_finding() {
  local FINDING_ID="$1"
  export GEN_EID="$EID"
  export GEN_FID="$FINDING_ID"
  export GEN_DB="$DB_PATH"
  export GEN_DOMAIN="$DOMAIN"
  export GEN_ROOT="${SWARM_ROOT:-.}"

  SWARM_VENV_PYTHON="$(dirname "$(dirname "$0")")/server/venv/bin/python3"
  PYTHON="${SWARM_VENV_PYTHON:-python3}"
  if [ ! -x "$PYTHON" ]; then
    PYTHON="python3"
  fi
  $PYTHON << 'PYEOF'
import sqlite3, json, os, glob, re
try:
    from cvss import CVSS3
    HAS_CVSS = True
except ImportError:
    HAS_CVSS = False

def compute_cvss(severity, title, affected_url):
    vectors = {
        "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "low":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "info":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }
    vec = vectors.get(severity.lower(), vectors["medium"])
    if not HAS_CVSS:
        return vec, None, None
    try:
        v = CVSS3(vec)
        return v.clean_vector(), v.scores()[0], v.severities()[0]
    except Exception:
        return vec, None, None

EID = os.environ['GEN_EID']
FINDING_REF = os.environ['GEN_FID']
DB_PATH = os.environ['GEN_DB']
DOMAIN = os.environ['GEN_DOMAIN']
SWARM_ROOT = os.environ['GEN_ROOT']

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Support both numeric id and finding_ref (e.g. "FINDING-001")
try:
    FINDING_ID = int(FINDING_REF)
    cursor = conn.execute(
        'SELECT id, engagement_id, title, severity, cvss, cve, mitre_id, test_id, '
        'tool_used, status, poc_output, affected_url, affected_parameter, '
        'description, evidence, remediation, domain, created_at, updated_at, finding_ref '
        'FROM vulns WHERE id = ? AND engagement_id = ?',
        (FINDING_ID, EID)
    )
except ValueError:
    cursor = conn.execute(
        'SELECT id, engagement_id, title, severity, cvss, cve, mitre_id, test_id, '
        'tool_used, status, poc_output, affected_url, affected_parameter, '
        'description, evidence, remediation, domain, created_at, updated_at, finding_ref '
        'FROM vulns WHERE finding_ref = ? AND engagement_id = ?',
        (FINDING_REF, EID)
    )
row = cursor.fetchone()
if not row:
    print(f"ERROR: Finding {FINDING_ID} not found", flush=True)
    exit(1)

finding = dict(row)
conn.close()

# -- Helpers --
finding_ref = finding.get("finding_ref") or f"FINDING-{finding['id']:03d}"
ref_num = finding['id']

def slugify(text, max_len=40):
    s = text.lower()
    s = re.sub(r'[^a-z0-9]+', '-', s)
    s = s.strip('-')
    return s[:max_len].rstrip('-')

title_slug = slugify(finding['title'])
slug = f"finding-{ref_num:03d}-{title_slug}"

EVIDENCE_DIR = f"{SWARM_ROOT}/engagements/recon/{DOMAIN}/evidence/{slug}"

os.makedirs(EVIDENCE_DIR, exist_ok=True)

# -- Collect evidence files --
screenshots = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "screenshot.*")))
request_logs = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "request.*")))
collab_files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "collaborator*.*")))

supporting = []
for f in screenshots:
    supporting.append(f"  * `{os.path.basename(f)}` — PoC screenshot")
for f in request_logs:
    supporting.append(f"  * `{os.path.basename(f)}` — HTTP request/response")
for f in collab_files:
    supporting.append(f"  * `{os.path.basename(f)}` — Collaborator interaction")

existing_evidence = os.path.join(EVIDENCE_DIR, "evidence.md")
existing_request = os.path.join(EVIDENCE_DIR, "request.txt")
has_existing_evidence = os.path.exists(existing_evidence)
has_existing_request = os.path.exists(existing_request)

# -- Parse evidence field --
raw_evidence = finding.get("evidence") or ""

# Extract HTTP requests from evidence text
request_lines = []
in_request = False
for line in raw_evidence.split('\n'):
    stripped = line.strip()
    if re.match(r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/', stripped):
        in_request = True
        request_lines.append(line)
    elif re.match(r'^[A-Z][a-z]+://', stripped):
        request_lines.append(f"$ {stripped}")
    elif in_request:
        request_lines.append(line)
        if stripped == '':
            in_request = False

# DNS/curl commands
dns_lines = []
for line in raw_evidence.split('\n'):
    if re.match(r'^\$?\s*(dig|host|nslookup|nmap|curl)', line.strip()):
        dns_lines.append(line)
    elif re.match(r'^→|\d+\.\d+\.\d+\.\d+', line.strip()):
        dns_lines.append(line)

# -- Format request.txt --
request_body = ""
if request_lines:
    request_body = "\n".join(request_lines)
elif dns_lines:
    request_body = "\n".join(dns_lines)
elif raw_evidence:
    request_body = raw_evidence[:2000]

if not has_existing_request:
    req_path = os.path.join(EVIDENCE_DIR, "request.txt")
    if request_body:
        header = f"# Evidence for {finding_ref}: {finding['title']}\n# URL: {finding.get('affected_url','')}\n# Tool: {finding.get('tool_used','')}\n\n"
        with open(req_path, "w") as f:
            f.write(header + request_body)
    else:
        with open(req_path, "w") as f:
            f.write(f"# {finding_ref}: {finding['title']}\n# Capture raw Burp HTTP request/response here\n# curl -sv '{finding.get('affected_url','')}' > request.txt\n")

# -- Format evidence.md --
severity = finding.get("severity", "Medium")
cvss = finding.get("cvss", 0.0)
title = finding.get("title", "Untitled Finding")
affected_url = finding.get("affected_url", "")
affected_param = finding.get("affected_parameter", "")
cve = finding.get("cve", "")
tool = finding.get("tool_used", "")
remediation = finding.get("remediation", "")
description = finding.get("description", "") or raw_evidence[:500]

# Parse reproduction steps
repro_steps = []
if finding.get("poc_output"):
    repro_steps.append(finding['poc_output'])
elif raw_evidence:
    lines = raw_evidence.split('\n')
    steps = [l for l in lines if l.strip() and not l.startswith('#') and not l.startswith('$')]
    if steps:
        for i, s in enumerate(steps[:5], 1):
            repro_steps.append(f"{i}. {s.strip()}")
if not repro_steps:
    repro_steps.append(f"1. Access {affected_url or 'the affected endpoint'}")
    if affected_param:
        repro_steps.append(f"2. Manipulate parameter: {affected_param}")
    repro_steps.append("3. Observe the vulnerability")

extra_lines = []
if affected_param:
    extra_lines.append(f"  - **Parameter**: {affected_param}")
if cve:
    extra_lines.append(f"  - **CVE**: {cve}")
if tool:
    extra_lines.append(f"  - **Tool**: {tool}")
extra_block = "\n".join(extra_lines)
cvss_str = f"(CVSS: {cvss})" if cvss > 0 else ""

evidence_body = f"""# {finding_ref}: {title} ({severity})

## Affected URL
- **URL**: {affected_url or 'N/A'}
{extra_block}
- **Severity**: {severity} {cvss_str}

## Description
{description}

## Impact
{severity} severity vulnerability discovered in {affected_url or 'the target application'}.{f' (CVE: {cve})' if cve else ''}

## Evidence
```
{raw_evidence[:1500]}
```

## Reproduction Steps
{chr(10).join(repro_steps)}

"""

if remediation:
    evidence_body += f"## Remediation\n{remediation}\n"

if not has_existing_evidence:
    with open(existing_evidence, "w") as f:
        f.write(evidence_body)

# -- Format poc-report.md --
shops = finding.get("domain") or affected_url or "[add affected domains]"

req_ids = []
for line in raw_evidence.split('\n'):
    m = re.search(r'[Xx]-[Rr]equest-[Ii][Dd][^:]*:\s*(\S+)', line)
    if m:
        req_ids.append(m.group(1))
    m2 = re.search(r'x-ms-request-id[^:]*:\s*(\S+)', line)
    if m2:
        req_ids.append(m2.group(1))
    m3 = re.search(r'cf-ray[^:]*:\s*(\S+)', line)
    if m3:
        req_ids.append(m3.group(1))

req_ids_text = ", ".join(req_ids) if req_ids else "[not captured -- raw HTTP in request.txt]"

poc_steps = []
if finding.get("poc_output"):
    poc_steps.append(finding['poc_output'])
elif raw_evidence:
    poc_steps.append(raw_evidence[:800])
else:
    poc_steps.append(f"Access the affected endpoint and observe the issue")

if poc_steps and not poc_steps[0].startswith("1."):
    poc_steps[0] = f"  1. {poc_steps[0]}"

supporting_text = "\n".join(supporting) if supporting else "  * `evidence.md` -- Full vulnerability documentation\n  * `request.txt` -- Raw HTTP request/response evidence"

# Compute CVSS
cvss_vec, cvss_score, cvss_sev = compute_cvss(severity, title, affected_url)
cvss_block = ""
if cvss_score is not None:
    cvss_block = f"""
## CVSS 3.1 Score
- **Score**: {cvss_score:.1f} ({cvss_sev})
- **Vector**: {cvss_vec}
"""
elif cvss_vec:
    cvss_block = f"""
## CVSS 3.1 Vector
{cvss_vec}
"""

poc_template = f"""{cvss_block}## Summary:
{title}

## Shops Used to Test:
{shops}

## Relevant Request IDs:
{req_ids_text}

## Steps To Reproduce:
{poc_steps[0] if poc_steps else '  1. [add reproduction steps]'}

## Supporting Material:
{supporting_text}
"""

with open(os.path.join(EVIDENCE_DIR, "poc-report.md"), "w") as f:
    f.write(poc_template)

print(f"  {finding_ref}: {finding['title']} [{finding['severity']}] -> {slug}/")
PYEOF
}

# -- Main --
if [ "$FINDING_FILTER" = "all" ]; then
  log_info "Generating evidence for all findings in $EID (domain: $DOMAIN)"
  FINDINGS=$(DB_PATH="$DB_PATH" EID="$EID" python3 -c '
import os, sqlite3
db_path = os.environ["DB_PATH"]
eid = os.environ["EID"]
conn = sqlite3.connect(db_path)
cursor = conn.execute("SELECT id FROM vulns WHERE engagement_id = ?", (eid,))
ids = [str(r[0]) for r in cursor.fetchall()]
conn.close()
print(" ".join(ids))
')
  if [ -z "$FINDINGS" ]; then
    log_warn "No findings found for engagement $EID"
    exit 0
  fi
  for fid in $FINDINGS; do
    generate_for_finding "$fid" || true
  done
  log_ok "Done. Evidence generated for all $EID findings."
else
  generate_for_finding "$FINDING_FILTER"
  log_ok "Evidence generated for finding $FINDING_FILTER"
fi
