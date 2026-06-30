# Phase 3: INTEL (Passive Intelligence)

Passive intelligence gathering — no API keys required. Runs after AUTH, before RECON. Output feeds target context to all later phases.

---

## Objectives

- WHOIS lookup for registrant org, name servers, dates
- M365/Azure tenant discovery and tenant ID verification
- Scopify scope-expansion domain analysis
- SPF/DMARC/DKIM spoofability assessment via Spoofy
- Cloud storage bucket enumeration (AWS S3, Azure Blob, GCP, DO Spaces)

---

## Steps

### 1. Run Intel Script

```bash
bash $HOME/swarm/scripts/tools/phase-intel.sh <domain>
```

Runs 3 modules sequentially with output visible in terminal:

| Module | Tool | Output | What it finds |
|--------|------|--------|---------------|
| domain_info | whois + msftrecon + Scopify | `intel/domain_info_general.txt`, `azure_tenant_domains.txt`, `scopify.txt` | WHOIS registrant, M365/Azure tenant, scope analysis |
| spoof | Spoofy | `intel/spoof.txt` | SPF/DMARC/DKIM spoofability |
| cloud_enum_scan | cloud_enum | `intel/cloud_enum.txt` | AWS S3, Azure Blob, GCP, DO Spaces buckets |

Skipped: `ip_info` (requires WHOISXML_API key).

Missing tools are gracefully skipped. Tools are pre-installed via `scripts/setup/install.sh`.

### 2. Parse Results

Read each output file and extract actionable intel:

- **WHOIS**: Registrant organization, name servers, creation/expiry dates
- **Azure/M365**: Verified tenant ID, authentication endpoints
- **Scopify**: Potential scope-expansion domains
- **Spoof**: SPF hard/soft fail, DMARC policy (`p=reject`/`quarantine`/`none`), DKIM signing status
- **Cloud enum**: Open storage buckets, bucket names for further testing

### 3. Save Intel Deliverable

```python
save_deliverable(
    engagement_id='<eid>',
    deliverable_type='osint_analysis',
    content=<json or markdown summary of all findings>,
    producer_agent='pintel'
)
```

### 4. Track

```python
track_tool(tool_name='pintel', status='run', notes='WHOIS + Spoofy + cloud_enum')
```

---

## Virtual Environments

Each tool runs in its own venv, created by `install.sh` at `$HOME/.local/bin/<tool>/venv/`. Activation is handled by sourcing the venv directly in `phase-intel.sh`.

---

## Gate

```python
phase_gate_check(engagement_id, phase_completed=2)
```

Gate passes when:
- Intel script completed (any results or documented skips)
- Intel deliverable saved (or documented as incomplete)

Intel results are informational, not blocking — proceed to Phase 4 (RECON) regardless.

---

## Output

| Artifact | Location | Description |
|----------|----------|-------------|
| domain_info_general.txt | `intel/domain_info_general.txt` | WHOIS data + msftrecon output |
| azure_tenant_domains.txt | `intel/azure_tenant_domains.txt` | M365/Azure-related findings |
| scopify.txt | `intel/scopify.txt` | Scopify scope analysis |
| spoof.txt | `intel/spoof.txt` | SPF/DMARC/DKIM spoofability report |
| cloud_enum.txt | `intel/cloud_enum.txt` | Discovered cloud storage buckets |
| osint_analysis | deliverable | Structured intel summary for Phase 6 |

---

## Script

```bash
bash $HOME/swarm/scripts/tools/phase-intel.sh <domain>
```
