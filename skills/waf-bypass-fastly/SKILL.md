---
name: waf-bypass-fastly
description: Skill for bypassing Fastly Next-Gen WAF (Signal Sciences) using parameter cloaking for cache poisoning, origin IP bypass, startup probe fail-open, content-type confusion, and HTTP/2 frame delay.
sources: github
---

# Fastly Next-Gen WAF Bypass

## Crown Jewel Targets

- Fastly Compute@Edge + NGWAF endpoints
- Services with default NGWAF rule sets
- Endpoints where startup probe is enabled
- APIs behind Fastly CDN with WAF bypass via cache poisoning

## Attack Surface Signals

- `X-Sigsci-*` headers (X-Sigsci-Tags, X-Sigsci-RequestID)
- `X-Fastly-*` headers (X-Fastly-Request-ID, X-Cache)
- `X-Timer` header with Fastly timing
- `Server: Fastly` header

## Step-by-Step Methodology

1. Confirm Fastly/SigSci presence: check for `X-Sigsci-*` or `X-Fastly-*` headers
2. Test basic XSS/SQLi to confirm WAF is active
3. Test HTTP/2 frame delay: send headers first, delay DATA by 500ms+ to bypass streaming inspection
4. Test parameter cloaking for cache poisoning: add duplicate params where WAF inspects first, origin uses second
5. Test content-type confusion: send multipart/form-data to JSON parser mismatch
6. Test origin IP bypass: Fastly CDN origin may be directly reachable
7. Test payload padding >8KB to exceed buffer inspection depth

## Bypass Techniques

- Startup probe exploitation: send payloads during agent startup window
- HTTP/2 frame timing: delay DATA frames to bypass streaming WAF
- Parameter pollution: send same param twice, WAF sees one, origin sees other
- Content-type switching: multipart smuggled as JSON, or vice versa
- Payload padding: exceed WAF buffer size for partial/no inspection
- Origin IP discovery: find real origin via Censys/masscan
