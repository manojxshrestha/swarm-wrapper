---
name: osint
description: OSINT — email & subdomain enumeration via theHarvester
---

# /osint

Run theHarvester for email and subdomain OSINT against the target domain.

## Usage

```
/osint target.com
```

Runs `scripts/tools/phase-osint.sh <domain>` — theHarvester with subdomain and email source sets.

## Output

| File | Content |
|------|---------|
| `osint/subdomains.txt` | Unique subdomains |
| `osint/emails.txt` | Unique emails |
