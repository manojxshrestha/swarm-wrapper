---
name: waf-bypass-signalsciences
description: Skill for bypassing Signal Sciences (Fastly NGWAF) WAF using JSON/HTML encoding bypass, chunked transfer encoding smuggling, payload padding, content-type confusion, parameter pollution, and null byte injection.
sources: github
---

# Signal Sciences (Fastly NGWAF) WAF Bypass

## Crown Jewel Targets

- Endpoints protected by stand-alone Signal Sciences agent
- Legacy Signal Sciences deployments without Fastly NG WAF rules
- Endpoints using only default rule sets
- APIs where request body inspection is limited by size

## Attack Surface Signals

- `X-Sigsci-Tags` response header
- `X-Sigsci-RequestID` response header
- Block page content containing "sigsci"
- 403 responses with "Request blocked by WAF" and Signal Sciences branding

## Step-by-Step Methodology

1. Confirm Signal Sciences presence: check for `X-Sigsci-*` headers
2. Test basic XSS/SQLi to confirm active blocking
3. Test with JSON/HTML encoding: Signal Sciences has weaker coverage on encoded payloads
4. Test chunked transfer encoding smuggling: split payload across chunks with delay
5. Test content-type confusion: send JSON in form-data wrapper
6. Test parameter pollution: duplicate params with mixed encoding
7. Test null byte injection: `%00` before payload termination
8. Test payload padding with garbage prefix to exceed inspection buffer

## Bypass Techniques

- Encoding rotation: unicode -> HTML entities -> mixed encoding
- Chunked smuggling: split payload into 1-3 byte chunks
- Null byte prefix: `%00` before payload to truncate rule matching
- Content-type switching: JSON in form-data, form-data in JSON
- Parameter pollution with different encoding per param
- Payload padding: prepend garbage to exceed agent inspection buffer
