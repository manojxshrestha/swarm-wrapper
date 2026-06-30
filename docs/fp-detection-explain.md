# FP Detection System — Explained

This document explains *why* the FP detection system exists, *how* it
works conceptually, and *what happens* when a finding flows through it.
Read this if you want to understand the reasoning, not just the API.

---

## The Problem

AI pentesting agents generate false positives. Lots of them. Here's why:

```
Agent sees 403 response    →  "Authentication bypass!"
Agent sees "login" text    →  "Session expired, try again!"
Agent sees WAF block page  →  "Access control vulnerability!"
Agent sees any 500 error   →  "Server-side crash, possible RCE!"
```

The core issue: an LLM is a pattern matcher, not a verifier. It sees
*surface-level similarity* between a response and a known vulnerability
pattern, but it can't reliably distinguish between:

- A real SQL error message vs. a fake one returned by a WAF
- A reflected XSS that actually executes vs. one that's HTML-escaped
- A rate limit page vs. an auth bypass success message

---

## The Solution: Six Deterministic Gates

Instead of asking the LLM to self-critique (which doesn't work — LLMs
confirm their own biases), we added six code-level gates that enforce
verification before any finding can be saved:

```
┌─ Gate 1 ───────────────────┐
│  validate_poc()             │  ← Must run first
│  "Can the PoC actually      │
│   produce the expected      │
│   response?"                │
└──────────┬──────────────────┘
           │ Pass + PoC Token
           ▼
┌─ Gate 2 ───────────────────┐
│  Payload Consensus          │  ← Optional, but recommended
│  "Do 3 different payloads   │
│   all produce the same      │
│   kind of result?"          │
└──────────┬──────────────────┘
           │ Pass
           ▼
┌─ Gate 3 ───────────────────┐
│  Response Diff              │  ← Optional, but powerful
│  "Is the attack response    │
│   actually different from   │
│   normal traffic?"          │
└──────────┬──────────────────┘
           │ Anomaly detected
           ▼
┌─ Gate 4 ───────────────────┐
│  Browser Verification       │  ← Required for XSS/CSRF
│  "Does the payload actually │
│   execute in a real         │
│   browser?"                 │
└──────────┬──────────────────┘
           │ Verified
           ▼
┌─ Gate 5 ───────────────────┐
│  add_vuln() gates           │  ← Automatic, inescapable
│  "Does the evidence meet    │
│   minimum quality bars?"    │
└──────────┬──────────────────┘
           │ Passed
           ▼
┌─ Gate 6 ───────────────────┐
│  Noise Filter               │  ← Automatic, inescapable
│  "Is this actually a CDN   │
│   error page, not a vuln?"  │
└─────────────────────────────┘
```

---

## Walkthrough: A Real Finding

Let's follow a reflected XSS finding from discovery to report.

### Step 1: Discovery

The agent finds a search endpoint that echoes user input back in the
response. It suspects XSS.

### Step 2: PoC Validation

The agent calls:

```
validate_poc(
    engagement_id="demo-001",
    command="curl -s 'https://target.com/search?q=<script>alert(1)</script>'",
    expected_match="<script>alert(1)</script>",
    require_consensus=True,
    vuln_class="xss",
    auto_retry=3,
)
```

**What happens internally:**

```
1. CONSENSUS CHECK ── runs 3 curl commands with different XSS payloads
   │  Payload 1: <script>alert(1)</script>  → 200, found in body  ✓
   │  Payload 2: <img src=x onerror=alert(1)> → 200, found in body  ✓
   │  Payload 3: javascript:alert(1)       → 200, NOT found in body ✗
   │
   │  Result: 2/3 passed (min_success=2) → CONSENSUS PASSED ✓

2. REPRODUCIBILITY CHECK ── runs the same command 3 times
   │  Run 1: exit=0, 142ms  ✓
   │  Run 2: exit=0, 138ms  ✓
   │  Run 3: exit=0, 145ms  ✓
   │
   │  Result: 3/3, avg=142ms, stddev=3ms → REPRODUCIBLE ✓

3. EXECUTION ── runs the actual command
   │  exit=0, HTTP 200, payload found in body → PASS

4. TOKEN GENERATION
   │  Token: sha256("demo-001" + "curl -s ..." + "<script>..." + "2024-...")
   │  Token: "a1b2c3d4..."
   │  Evidence saved to: engagements/runtime/demo-001/poc-evidence/a1b2c3d4.../
```

**Agent sees:**
```
## PoC Validation: PASS ✅
**Payload Consensus**: 2/3 passed ✅
**Reproducibility**: 3/3 runs successful (avg=142ms, stddev=3ms) ✅
**PoC Token**: `a1b2c3d4e5f6...`
```

### Step 3: Browser Verification (required for XSS)

Since XSS requires browser evidence for `confirmed` confidence, the
agent opens a browser:

```
browser_analyze(engagement_id="demo-001", url="https://target.com/search")
  → Loads the page, finds the search input field (index 3)

browser_act(engagement_id="demo-001", action="type", index=3, text="<script>alert(1)</script>")
  → Types the payload into the search box

browser_act(engagement_id="demo-001", action="click", index=4)
  → Clicks the search button

browser_screenshot(engagement_id="demo-001", url="...", agent_id="xss-agent")
  → Captures the alert box as evidence

mark_browser_verified(
    engagement_id="demo-001",
    url="https://target.com/search",
    payload="<script>alert(1)</script>",
    screenshot_taken=True,
)
```

### Step 4: Save Finding

```
findings_add_vuln(
    engagement_id="demo-001",
    title="Reflected XSS in search endpoint",
    severity="High",
    affected_url="https://target.com/search",
    confidence="confirmed",
    poc_token="a1b2c3d4e5f6...",
    evidence="HTTP 200, payload found in body at positions 156-179",
)
```

**What happens inside add_vuln():**

```
1. VERIFICATION GATE ── confidence="confirmed", poc_token="a1b2c3d4e5f6..."
   → poc_token is present, _verify_poc_token() checks evidence file → PASS

2. SEVERITY GATE ── severity="High", evidence length > 20 chars
   → PASS

3. BROWSER VALIDATION GATE ── vuln class inferred as "xss_reflected"
   → class is in BROWSER_REQUIRED_CLASSES
   → has_browser_evidence("demo-001", "https://target.com/search") → TRUE
   → PASS

4. NOISE FILTER ── evidence doesn't match any noise pattern
   → PASS (no noise detected)

5. AUTO CONFIDENCE SCORING ──
   → consensus_passed=True (+35), reproduced=True (+25),
     browser_confirmed=True (+20), poc_token exists (+5)
   → Total: 85 → confirmed ✓

6. SAVED TO DATABASE ── confidence="confirmed"
```

### Step 5: Report

The finding appears in `generate_report()` with `confidence="confirmed"`,
meaning it passes the report gate.

---

## Walkthrough: A False Positive Blocked

Now let's see what happens with a typical FP.

### Scenario

Agent sends a SQL injection payload and gets a 403 with "blocked" text.
It thinks this is a WAF bypass success (the request was processed).

### Step 2: PoC Validation

```
validate_poc(
    command="curl -s 'https://target.com/api?id=1'",
    require_consensus=True,
    vuln_class="sqli",
)
```

**Consensus check:**

```
Payload 1: '  → 403 WAF block  ✗
Payload 2: "  → 403 WAF block  ✗
Payload 3: OR 1=1  → 403 WAF block  ✗
```

Consensus fails: 0/3 passed. **The agent cannot save this as confirmed.**

### What the agent learns

The consensus failure tells the agent:

> "Your command doesn't actually work against this endpoint.
> All 3 SQLi payloads were blocked by WAF. Try:
> - Using WAF bypass techniques
> - A different parameter
> - A different injection point"

This saves the agent from logging a false "SQL injection found" finding
when it was really just hitting a WAF.

---

## Layering Explained

### Why multiple layers?

Each layer catches a different failure mode:

| Failure Mode | Caught By |
|-------------|-----------|
| Agent hallucinates a finding | Layer A (poc_token required) |
| A single payload got lucky | Layer B (consensus) |
| The response wasn't actually different | Layer C (diff engine) |
| Payload doesn't execute in a real browser | Layer E (browser gate) |
| The "evidence" is a WAF page | Layer F (noise filter) |
| Agent skips validation entirely | Layer A (hard gate in add_vuln) |

No single layer is sufficient. An agent could:
- Get lucky with one payload → caught by consensus
- Hit a real error that's still a WAF block → caught by noise filter
- Find an XSS without browser execution → caught by browser gate
- Save a finding without PoC → caught by verification gate

### Why deterministic (no LLM calls)?

Each FP detection layer uses **zero** LLM calls. Everything is regex,
hash comparison, subprocess execution, or statistical calculation.

**Reasoning:**

```
LLM-based FP detection loop:
  1. Agent finds candidate
  2. Agent asks "is this a real vuln?" (LLM call)
  3. LLM says yes (confirmation bias)
  4. Agent saves finding
  → Still a false positive

Deterministic FP detection:
  1. Agent finds candidate
  2. validate_poc() runs the actual command
  3. Checks if response matches expected content (exact string match)
  4. Compares against baseline (hash comparison)
  5. Checks for noise patterns (regex)
  6. If any check fails, finding is downgraded
  → Cannot be bypassed by agent reasoning
```

LLMs are used for *hunting* (finding candidates) but not for
*verification* (confirming candidates).

### Why downgrade instead of reject?

```
Scenario:
  - Real vulnerability
  - But no PoC token (validate_poc wasn't run)
  - But no browser evidence (browser test wasn't done)

If we REJECT:
  → Finding is lost. Human can't review it later.
  → Agent loses information about what it found.

If we DOWNGRADE:
  → Finding saved as version_based / speculative.
  → Still in the database, still in the report (at lower severity).
  → Human reviewer can investigate and upgrade.
  → Agent can revisit and add more evidence later.
```

Downgrading preserves information while still enforcing quality gates.

---

## How Agents Interact With the System

### Good Agent Flow

```
1. Find potential vuln
2. Run validate_poc(require_consensus=True, vuln_class="xss", auto_retry=3)
3. If PASS: run browser_analyze → browser_act → mark_browser_verified()
4. Call findings_add_vuln(confidence="confirmed", poc_token="...")
5. All gates pass → finding saved as confirmed
```

### Bad Agent Flow (what the gates prevent)

```
1. Find potential vuln
2. Call findings_add_vuln(confidence="confirmed", poc_token="")
   → Gate A rejects: "poc_token required for confirmed"

1. Find potential vuln
2. Call validate_poc(require_consensus=True, vuln_class="sqli")
   → All 3 payloads fail → consensus failed
   → Agent cannot save as confirmed without fixing the PoC

1. Find possible XSS
2. Run validate_poc() → PASS
3. Call findings_add_vuln(confidence="confirmed", poc_token="abc")
   → Browser gate: XSS class requires browser evidence
   → Confidence downgraded to version_based
```

### Agent Decision Tree

```
Found a potential vulnerability?
│
├── Can I run validate_poc()?
│   ├── YES → Run with require_consensus and auto_retry
│   │         ├── PASS → Continue
│   │         └── FAIL → Fix PoC, try different payload/parameter
│   └── NO → Save as speculative (no poc_token = can't be confirmed)
│
├── Is this XSS/CSRF/clickjacking?
│   ├── YES → Must run browser_analyze + mark_browser_verified()
│   │         before "confirmed" confidence
│   └── NO → Can skip browser gate
│
├── Is there a baseline for this URL?
│   ├── YES → Pass baseline_id to validate_poc for diff
│   ├── NO  → Run collect_baseline() first (10 samples, ~5 seconds)
│   └── Skip → Diff not available, confidence cap limits score
│
└── Save finding:
    ├── All gates pass  →  confidence="confirmed"
    ├── Some gates pass →  confidence="version_based"
    └── No gates pass   →  confidence="speculative"
```

---

## Scoring Examples

### What reaches "confirmed" (≥80)

| Scenario | consensus | repro | browser | baseline | chain | Score |
|----------|-----------|-------|---------|----------|-------|-------|
| Full PoC + 3 payloads + browser | 35 | 25 | 20 | 0 | 0 | **80** |
| Full PoC + 3 payloads + 3 retries | 35 | 25 | 0 | 10 | 5 | **80** |
| Consensus + repro + browser | 35 | 25 | 20 | 0 | 5 | **85** |

### What reaches "version_based" (50-79)

| Scenario | consensus | repro | browser | baseline | chain | Score |
|----------|-----------|-------|---------|----------|-------|-------|
| Only consensus + repro | 35 | 25 | 0 | 0 | 0 | 60 |
| Only consensus + browser | 35 | 0 | 20 | 0 | 0 | 55 |
| Only repro + browser | 0 | 25 | 20 | 10 | 0 | 55 |
| Consensus + chain | 35 | 0 | 0 | 0 | 5 | 40 → speculative |

### What stays "speculative" (<50)

| Scenario | consensus | repro | browser | baseline | chain | Score |
|----------|-----------|-------|---------|----------|-------|-------|
| No verification signals at all | 0 | 0 | 0 | 0 | 0 | **0** |
| Just poc_token (no consensus/repro/browser) | 0 | 0 | 0 | 0 | 0 | 5 |
| Just chain (indirect evidence) | 0 | 0 | 0 | 0 | 5 | 5 |
| Just browser | 0 | 0 | 20 | 0 | 0 | 20 |

---

## Common Questions

### "Can I skip validate_poc() and just save a finding?"

Yes, but:
- `confidence="confirmed"` requires a PoC token → you'll get rejected
- Without a token, confidence defaults to `version_based` or `speculative`
- Report generation filters out non-confirmed findings (or marks them lower)

### "Can I force a finding through as confirmed?"

No. The gates are in the code path:
- `add_vuln()` checks `poc_token` and `_verify_poc_token()` — no token = no confirmed
- `_verify_poc_token()` checks the actual evidence file on disk — must exist
- The evidence file is created by `validate_poc()` — only real command execution creates it

### "What if validate_poc() passes but the finding is still wrong?"

Possible, but reduced to nearly zero by the combination of:
1. **Consensus**: 3 different payloads must agree
2. **Reproducibility**: 3+ runs must all succeed consistently
3. **Browser**: Payload must execute in a real browser (for XSS classes)
4. **Diff**: Response must differ from baseline (not just match any response)

All four false positives require a systematic coincidence rather than
a single agent/hallucination error.

### "Can I re-run validate_poc() for an existing finding?"

Yes — `validate_finding_poc()` re-runs the stored PoC command and
regenerates the PoC token. This is useful for:
- Verifying findings are still reproducible after a retest
- Upgrading a finding from `version_based` to `confirmed` after adding
  browser verification

### "What happens to findings saved with the old JSON-based log_finding()?"

The old `log_finding()` (JSON-based, no SQLite) still works, but:
- It has a duplicate detection warning
- It doesn't enforce PoC token gating (backward compatible)
- New `findings_add_vuln()` (SQLite-based) has all the gates
- Migrate to `findings_add_vuln()` for FP protection

---

## Troubleshooting

### "I keep getting 'consensus failed'"

```
Possible causes:
1. The WAF is blocking all 3 payloads → try WAF bypass techniques
2. The endpoint doesn't accept the parameter you're targeting
3. The command syntax is wrong (test with curl directly first)
4. The vuln_class doesn't match the actual vulnerability

Fix: Start with require_consensus=False, get one payload working,
then enable consensus with vuln_class that fits.
```

### "My finding was downgraded from confirmed to version_based"

```
Check which gate triggered it:
1. poc_token missing → run validate_poc() and include the token
2. poc_token invalid → PoC evidence file was deleted; re-run validate_poc()
3. Browser evidence missing for XSS class → run browser_analyze + mark_browser_verified()
4. Noise filter matched → evidence contains CAPTCHA/WAF/rate limit text

Check the finding's confidence field in the database to see the final value.
```

### "I got a valid finding but it's stuck at version_based"

```
To upgrade to confirmed, you need:
- A valid poc_token from validate_poc() PASS
- At least 80 confidence points:
  - consensus_passed=True (35 pts) + reproduced=True (25 pts) = 60
  - Or consensus_passed=True (35) + browser_confirmed=True (20) = 55
  - Or reproduced=True (25) + browser_confirmed=True (20) + baseline_anomaly=True (10) = 55

Run validate_poc with require_consensus=True + auto_retry>=3 + vuln_class set.
If it's XSS, also run mark_browser_verified().
```

### "NoiseDetector incorrectly classified my legitimate finding"

```
The noise filter triggers on body text / header patterns. If your
legitimate finding contains words like "login", "session expired",
or "access denied" in the evidence text, it will be classified as noise.

Workaround: Make sure the evidence text you pass to add_vuln() contains
the actual request/response proving the vulnerability, not just the
summary text. If the actual vuln response is different from the noise
page, include that evidence instead.
```
