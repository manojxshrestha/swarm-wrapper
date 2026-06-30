# False Positive Detection System

Six deterministic validation layers that enforce verification in code. Agents cannot bypass any gate — enforcement is in the DB write path and PoC execution path, not in agent prompts.

---

## Architecture Overview

```
Agent Submission Path:

  log_finding() / findings_add_vuln()
           │
           ▼
  ┌─────────────────────────────────┐
  │  validate_poc()                 │
  │  ┌───────────────────────────┐  │
  │  │  B: Payload Consensus     │  │  require_consensus + vuln_class
  │  │  - Run N payload variants  │  │
  │  │  - Require min_success/N   │  │
  │  └───────────────────────────┘  │
  │  ┌───────────────────────────┐  │
  │  │  B2: Reproducibility      │  │  auto_retry >= 3
  │  │  - Run command N times     │  │
  │  │  - Return timing stats     │  │
  │  └───────────────────────────┘  │
  │  ┌───────────────────────────┐  │
  │  │  Execution + Validation   │  │
  │  │  - Run command             │  │
  │  │  - Check exit code         │  │
  │  │  - Parse HTTP status       │  │
  │  │  - Check expected_match    │  │
  │  │  - Check expected_no_match │  │
  │  └───────────────────────────┘  │
  │  ┌───────────────────────────┐  │
  │  │  C: Response Diff         │  │  baseline_id provided
  │  │  - Compare vs baseline     │  │
  │  │  - Dynamic value filter    │  │
  │  │  - Error sig detection     │  │
  │  │  - Reflection check        │  │
  │  └───────────────────────────┘  │
  │  ┌───────────────────────────┐  │
  │  │  PoC Token Generation     │  │  sha256(engagement+cmd+response+ts)
  │  └───────────────────────────┘  │
  └──────────┬──────────────────────┘
             │ PASS + poc_token
             ▼
  add_vuln() ──▶ SQLite vulns table
           │
           ├── A: Verification Gate (in add_vuln)
           │   ├── poc_token required for "confirmed"
           │   ├── Severity gating by evidence
           │   ├── Title/URL validation
           │   └── Browser validation gate
           │
           ├── F: Noise Filter (in add_vuln)
           │   └── NoiseDetector.classify(evidence)
           │       └── If matched: severity=Info, confidence=speculative
           │
           ├── D: Auto Confidence Scoring (in add_vuln)
           │   └── _compute_confidence(consensus, repro, browser, etc.)
           │       └── ≥80 confirmed, ≥50 version_based, else speculative
           │
           └── E: Browser Validation Gate (in add_vuln)
               └── BROWSER_REQUIRED_CLASSES + has_browser_evidence()
                   └── If missing: confidence=version_based
```

---

## Layer A: Verification Gate

**File:** `server/findings_db.py` — method `add_vuln()`, lines 427–535

**What it does:** Enforces minimum evidence quality at the moment a finding is persisted to SQLite. Every finding passes through this code path — no exceptions.

### Gate Logic (in execution order)

```
1. poc_token gate
   IF confidence == "confirmed" AND NOT poc_token
   THEN confidence = "version_based"
   └─ Rationale: "confirmed" requires reproducible PoC proof

2. Severity gate
   IF severity == "Critical" AND (poc_output is empty OR cvss < 7.0)
   THEN severity = "High"
   └─ Rationale: Critical needs high CVSS or actual PoC output

   IF severity == "High" AND len(evidence.strip()) < 20 AND poc_output is empty
   THEN severity = "Medium"
   └─ Rationale: High needs at least some evidence text or PoC

3. Browser validation gate
   vuln_classes = _infer_vuln_class(title, test_id, description)
   IF any(c in BROWSER_REQUIRED_CLASSES for c in vuln_classes)
      AND confidence == "confirmed"
      AND NOT has_browser_evidence(engagement_id, affected_url)
   THEN confidence = "version_based"
   └─ Rationale: browser-dependent vulns need in-browser confirmation

4. Noise filter
   noise_classes = NoiseDetector.classify(evidence, {})
   IF noise_classes
   THEN severity = "Informational", confidence = "speculative"
   └─ Rationale: CAPTCHA/WAF/CDN pages are not vulnerabilities

5. Auto confidence scoring
   IF confidence in ("version_based", "speculative")
   THEN computed = _compute_confidence(...)
        IF computed == "confirmed" THEN confidence = computed
   └─ Rationale: upgrade confidence if verification signals are strong

6. Hard validation
   IF len(title.strip()) < 5  →  raise ValueError
   IF not affected_url        →  raise ValueError
   └─ These raise exceptions that bubble up to the MCP tool caller
```

### Code Flow

```
findings_add_vuln() [MCP tool]                     # server.py:739
  │
  ├── Validate severity & confidence enums
  ├── Enforce poc_token for "confirmed"
  │   └── _verify_poc_token(engagement_id, poc_token)
  │       └── Reads evidence file from engagements/runtime/<eid>/poc-evidence/
  │           └── Checks sha256 hash matches
  ├── Apply CVSS cap based on confidence
  │
  └── _fdb.add_vuln(...)                            # findings_db.py:427
      │
      ├── Gate: poc_token + confirmed check
      ├── Gate: severity downgrade
      ├── Gate: browser validation (queries browser_verifications table)
      ├── Gate: noise filter (NoiseDetector.classify)
      ├── Auto confidence scoring (_compute_confidence)
      ├── Hard validation (title, url)
      ├── INSERT into vulns table
      └── Auto-chain detection
```

### Design Decisions

- **Why in add_vuln() and not in the MCP tool?** So that any code path that creates a vuln (log_finding, findings_add_vuln, future bulk import) goes through the same gates.
- **Why raise ValueError for title/url?** These are programmer errors, not FP issues. Agents must provide these.
- **Why downgrade instead of reject?** Downgrading preserves the finding for human review; rejecting would lose information.

---

## Layer B: Payload Consensus + Auto Retry

**File:** `server/server.py` — `validate_poc()`, lines 6445–6760

### Payload Consensus (`_check_consensus`, line 6388)

**How it works:**

```
1. Look up CONSENSUS_RULES[vuln_class]              # server.py:6321
   Each rule has:
     - payloads: list<string>  (3 payload variants)
     - min_success: int        (2, meaning 2/3 must pass)

2. For each payload:
     injected_command = _build_poc_command(command, payload)
                       └─ Injects payload into URL query param
                          or appends to command

     result = subprocess.run(shlex.split(injected_command), ...)
     success = (result.returncode == 0)

3. PASS if successes >= min_success
   FAIL otherwise
```

**Payload injection strategy** (`_build_poc_command`, line 6375):

```
IF command contains "curl":
   1. Extract the URL from the command
   2. Parse URL, add ?q=<payload> to query string
   3. Replace original URL with injected URL in command
ELSE:
   Append payload as shell-quoted argument
```

**Consensus rules table** (`server.py:6321`):

```python
CONSENSUS_RULES = {
    "sqli": {
        "payloads": ["'", '"', "OR 1=1"],
        "min_success": 2,
    },
    "xss": {
        "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "min_success": 2,
    },
    "ssti": {
        "payloads": ["{{7*7}}", "${7*7}", "#{7*7}"],
        "min_success": 2,
    },
    "cmdi": {
        "payloads": [";id", "|id", "`id`"],
        "min_success": 2,
    },
    "ssrf": {
        "payloads": ["http://169.254.169.254/", "http://localhost/", "file:///etc/passwd"],
        "min_success": 2,
    },
    "_default": {
        "payloads": [],
        "min_success": 1,
    },
}
```

### Auto Retry / Reproducibility (`_check_reproducibility`, line 6421)

**How it works:**

```
1. Run the EXACT same command N times (N = auto_retry param)
2. For each run, record: run_number, exit_code, elapsed_ms
3. After all runs:
     success_count = count of runs with exit_code == 0
     avg_timing_ms = mean of elapsed times
     timing_stddev = standard deviation of elapsed times
4. Return ReproducibilityResult dataclass
```

**ReproducibilityResult dataclass** (`server.py:6405`):

```python
@dataclass
class ReproducibilityResult:
    all_succeeded: bool         # True only if ALL runs passed
    success_count: int          # number of successful runs
    total_runs: int             # total runs attempted
    avg_timing_ms: float        # mean execution time
    timing_stddev: float        # stddev of execution time
    individual_results: list[tuple[int, int]]  # [(run_num, exit_code), ...]

    @property
    def success_rate(self) -> float: ...
    @property
    def is_consistent(self) -> bool:          # rate >= 0.8 AND stddev < 2000ms
```

**Why this exists:** A single successful run could be a fluke (race condition, cached response, transient state). Multiple runs with consistent timing suggest the behavior is real.

**Behavior at each auto_retry value:**

| auto_retry | Behavior |
|------------|----------|
| 1 (default) | Skip reproducibility check entirely |
| 2 | Run twice, all_succeeded must be True |
| 3+ | Run N times, return timing stats even on success |

### Main Execution + Validation (validate_poc core)

After consensus and reproducibility gates pass:

```
1. Parse command, check destructive command guard
   └─ _POC_DESTRUCTIVE_BINS: rm, dd, mkfs, fdisk, format, mv, reboot, halt, poweroff, shutdown

2. Execute command via subprocess.run (no shell=True)
   └─ Timeout: POC_VALIDATION_TIMEOUT (configurable, default 30s)

3. Parse HTTP status from curl output (if applicable)
   └─ Runs a separate curl -s -o /dev/null -w "%{http_code}" <url>
   └─ Only if command contains "curl"

4. Validate:
   - Exit code == 0?
   - HTTP status matches expected_status ("200", "403", "2xx", etc.)?
   - expected_match in stdout?
   - expected_no_match NOT in stdout?

5. If PASS:
   - Generate poc_token = sha256(engagement_id + command + stdout[0:100] + timestamp)
   - Save evidence to engagements/runtime/<eid>/poc-evidence/<token>/evidence.txt
   - Include consensus/reproducibility summary in output

6. Return formatted markdown (PASS + poc_token, or FAIL + reasons)
```

### PoC Token Lifecycle

```
1. GENERATED: validate_poc() PASS
   └─ sha256 hex digest of (engagement_id + command + stdout_preview + iso_timestamp)

2. STORED: engagements/runtime/<eid>/poc-evidence/<token>/
   └─ evidence.txt (full stdout)
   └─ meta.json (command, returncode, timing, label)

3. VERIFIED: findings_add_vuln() / log_finding()
   └─ _verify_poc_token() checks evidence file exists + token hash matches

4. EXPIRED: never (tokens are valid indefinitely once generated)
```

---

## Layer C: Response Diff Engine

**File:** `server/response_diff.py` (567 lines)

### Dynamic Value Filter (`DynamicValueFilter`, line 308)

**What it does:** Replaces known dynamic patterns with `{TYPE}` placeholders before comparison, so that CSRF token rotation, session ID changes, and timestamp updates don't trigger false diff signals.

**Patterns filtered (in order of application):**

| Pattern Name | Regex | Example |
|-------------|-------|---------|
| CSRF_TOKEN | `<input name="csrf_token" value="...">` | `<input name="csrf_token" value="abc123">` → `{CSRF_TOKEN}` |
| UUID | `[0-9a-f]{8}-...-{12}` | `550e8400-e29b-41d4-a716-446655440000` → `{UUID}` |
| SESSION_ID | `(session_id\|sid\|jsessionid)=[a-zA-Z0-9]{16,}` | `session_id=abc123def456ghi789` → `{SESSION_ID}` |
| TIMESTAMP | ISO 8601 timestamps | `2024-01-15T10:30:00` → `{TIMESTAMP}` |
| DATE | HTTP date format | `Mon, 15 Jan 2024` → `{DATE}` |
| LARGE_ID | `"id": 12345` (4+ digits) | `{"id": 12345}` → `{"id": {LARGE_ID}}` |
| ANALYTICS | GA/GTM/UTM tracking params | `?utm_source=twitter` → `?{ANALYTICS}` |
| NONCE | CSP nonces, 10+ base64 chars | `nonce="aB3DeFgHiJkLmNoPqRsTuV=="` → `{NONCE}` |
| CACHE_BUSTER | `?_=1234567890` | `?_=1712345678` → `{CACHE_BUSTER}` |
| FLOAT_NUMBER | Floats with 4+ decimal places | `0.12345678` → `{FLOAT_NUMBER}` |
| AUTH_HEADER | Authorization/Bearer/API key values | `Authorization: Bearer eyJhbGci...` → `{AUTH_HEADER}` |

**How normalize() works:**

```python
def normalize(text: str) -> tuple[str, int]:
    count = 0
    for name, pattern in DYNAMIC_PATTERNS:
        text, subs = pattern.subn(f"{{{name}}}", text)
        count += subs
    return text, count
```

Applied to both baseline samples and attack responses before comparison.

### Fingerprinting (`ResponseFingerprint`, line 60)

**What it does:** Transforms a raw HTTP response into a structured fingerprint for comparison.

**Fields produced:**

```python
@dataclass
class ResponseFingerprint:
    raw_status: int                          # HTTP status code
    raw_headers: dict[str, str]              # All response headers (lowercased keys)
    raw_body: str                            # Full response body
    body_length: int                         # len(raw_body)
    body_hash: str                           # sha256(normalized_body)
    timing_ms: float                         # Response time in milliseconds
    dom_skeleton: Optional[str]              # HTML tag structure (structural tags only)
    json_keys: Optional[str]                 # JSON key paths as sorted dot-separated string
    normalized_body: str                     # Body after DynamicValueFilter normalization
    normalized_length: int                   # len(normalized_body)
    entropy: float                           # Shannon entropy of raw body
```

**DOM Skeleton extraction:**

```
1. Check if body contains <html or <!doctype (HTML detection)
2. If not HTML: return None
3. Extract all HTML tags via regex <(\w+)[^>]*>
4. Filter to structural tags only:
     {html, head, body, div, span, form, table, tr, td, th,
      ul, ol, li, p, h1-h6, section, article, nav, header,
      footer, main, aside, script, style, select, input, button,
      a, img, iframe}
5. Join with ">" separator: "html>head>body>div>form>input"
```

**JSON Keys extraction:**

```
1. Check if body starts with { or [
2. Parse as JSON
3. Walk recursively, collecting key paths
   dict → recurse into values
   list → use first element's structure
4. Return sorted paths joined with " > "
   Example: "data > id > data > items[] > name"
```

### Baseline Profile (`BaselineProfile`, line 167)

**What it does:** Collects N normal responses from a URL and maintains a multi-sample profile.

**Data collected per sample:**

```python
@dataclass
class BaselineProfile:
    url: str
    method: str
    request_body: str
    sample_count: int                               # N samples collected
    status_codes: set[int]                          # All observed status codes
    body_lengths: list[int]                         # All body lengths
    normalized_bodies: list[str]                    # All normalized bodies
    normalized_hashes: set[str]                     # Unique normalized body hashes
    dom_skeletons: list[str | None]                 # DOM skeletons per sample
    json_keys: str | None                           # JSON keys (assumed stable)
    timings: list[float]                            # Timing per sample
    volatile_headers: set[str]                      # Headers that changed between samples
    dynamic_fields_found: dict[str, int]             # {pattern_name: count} across samples
```

**Stability check** (is_stable()):

```
Returns True when:
  - sample_count >= 3
  - len(status_codes) == 1 (all same status)
  - len(normalized_hashes) <= 2 (normalized body hashes are nearly identical)
```

**Collection process** (`collect_baseline`, line 536):

```
1. Send <samples> requests via curl to the URL (default 10)
2. For each response:
     a. Measure timing
     b. Parse into ResponseFingerprint
     c. Add sample to BaselineProfile
3. Return populated BaselineProfile
4. Server saves to SQLite baselines table via _fdb.save_baseline()
```

### Diff Comparison (`compare()`, line 390)

**What it does:** Compares an attack `ResponseFingerprint` against a `BaselineProfile`, producing a `DiffResult` with verdict and evidence.

**Signal collection:**

```
1. Status code: is attack status in baseline status_codes?
   Weight: 3 if changed

2. Body length: is attack length within normal range?
   Normal range: min(baseline_lengths) - padding  to  max(baseline_lengths) + padding
   Padding = (max-min) * 2 + 50
   Weight: 2 if outside range

3. Normalized similarity: max Levenshtein similarity of attack
   normalized body against all baseline normalized bodies
   Weight: 2 if similarity < 0.8

4. DOM structure: is attack DOM skeleton in baseline dom_skeletons?
   Weight: 3 if changed

5. JSON keys: do attack JSON keys match baseline?
   Weight: 3 if changed

6. Error signatures: regex matches for SQL errors, tracebacks, etc.
   Weight: 3 if found

7. Reflection: does payload string appear in response body?
   Weight: 2 if reflected (count > 0)
   Also checks URL-encoded version of payload

8. Timing anomaly: does attack timing exceed 2x baseline P95?
   Weight: 1 if anomalous

9. Entropy delta: Shannon entropy change from baseline mean
   (logged but not weighted in verdict)
```

**Verdict computation:**

```python
confidence = signal_count / total_weight

if confidence >= 0.75:   verdict = "DIFFERENT"
elif confidence >= 0.40: verdict = "SUSPICIOUS"
elif confidence >= 0.15: verdict = "LIKELY_SAME"
else:                     verdict = "MATCH"
```

**Error signatures detected** (`ERROR_SIGNATURES`, line 46):

```
- SQL: "SQL syntax", "mysql_error", "MariaDB", "PostgreSQL.*ERROR",
        "SQLite.*Error", "ORA-[0-9]{5}"
- PHP: "Division by zero", "unexpected T_STRING", "Parse error",
        "Fatal error", "Warning.*include"
- .NET: "System.Data.SqlClient.SqlException", "Microsoft OLE DB"
- Java: "java.sql.SQLException", "org.hibernate.exception"
- General: "FileNotFoundException", "No such file",
           "failed to open stream"
- Debug: "stack trace:", "Traceback (most recent call last)"
- HTTP: "not found", "404 Not Found", "403 Forbidden"
```

### Reflection Detection

```python
def _detect_reflections(body: str, payload: str) -> int:
    # Count exact payload occurrences
    count = body.count(payload)
    if count > 0:
        return count
    # Fallback: URL-encoded version
    import urllib.parse
    encoded = urllib.parse.quote(payload)
    return body.count(encoded)
```

---

## Layer D: Auto Confidence Scoring

**File:** `server/findings_db.py` — method `_compute_confidence()`, line 938

**What it does:** Computes a confidence level from verification signals, not from evidence quality or severity.

### Signal Weights

```python
SCORING_WEIGHTS = {
    "payload_consensus": 35,    # require_consensus=True passed all 3 payloads
    "reproduced": 25,           # auto_retry >= 3 and 100% success rate
    "browser_confirmed": 20,    # mark_browser_verified() was called for this URL
    "baseline_anomaly": 10,     # diff_response() returned DIFFERENT or SUSPICIOUS
    "independent_engine": 10,   # Phase G stub — ≥2 detection methods agreed
}
```

### Scoring Function

```python
def _compute_confidence(
    poc_token="",
    poc_output="",
    evidence="",
    cvss=0.0,
    chain_count=0,
    consensus_passed=False,
    reproduced=False,
    browser_confirmed=False,
    baseline_anomaly=False,
    independent_engine=False,
) -> str:
    score = 0
    if poc_token:        score += 5          # hard gate, token alone is weak signal
    if consensus_passed: score += 35         # strongest signal
    if reproduced:       score += 25         # second strongest
    if browser_confirmed: score += 20        # third
    if baseline_anomaly: score += 10         # supporting
    if independent_engine: score += 10       # future
    if chain_count > 0:  score += 5          # chain bonus

    if score >= 80:      return "confirmed"    # ~2 strong signals + 1 supporting
    elif score >= 50:    return "version_based" # 2 moderate signals
    else:                return "speculative"   # weak or no signals
```

### Example Scores

| Scenario | poc_token | consensus | repro | browser | baseline | chain | Total | Result |
|----------|-----------|-----------|-------|---------|----------|-------|-------|--------|
| Full PoC + consensus + repro | 5 | 35 | 25 | 0 | 0 | 0 | 65 | version_based |
| Full + browser | 5 | 35 | 25 | 20 | 0 | 0 | 85 | **confirmed** |
| Consensus only | 0 | 35 | 0 | 0 | 0 | 0 | 35 | speculative |
| Consensus + repro | 0 | 35 | 25 | 0 | 0 | 0 | 60 | version_based |
| Consensus + browser | 0 | 35 | 0 | 20 | 0 | 0 | 55 | version_based |
| Consensus + repro + browser + anomaly | 5 | 35 | 25 | 20 | 10 | 5 | 100 | **confirmed** |
| Nothing | 0 | 0 | 0 | 0 | 0 | 0 | 0 | speculative |

### When Scoring Runs

Scoring runs only when `confidence` is `version_based` or `speculative`:

```python
if confidence in ("version_based", "speculative"):
    browser_confirmed = self.has_browser_evidence(engagement_id, affected_url)
    computed = self._compute_confidence(
        poc_token=poc_token,
        chain_count=len(self.detect_chains(engagement_id)),
        consensus_passed=consensus_passed,
        reproduced=reproduced,
        browser_confirmed=browser_confirmed,
        baseline_anomaly=baseline_anomaly,
    )
    if computed == "confirmed":
        confidence = computed  # upgrade only, never downgrade
```

---

## Layer E: Browser Validation Gate

**File:** `server/findings_db.py` — `mark_browser_verified()` (line 903), `has_browser_evidence()` (line 921)

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS browser_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    payload TEXT DEFAULT '',
    screenshot_taken INTEGER DEFAULT 0,
    verified_at TEXT NOT NULL
);
```

### Required Classes

```python
BROWSER_REQUIRED_CLASSES: set = {
    "xss_reflected",    # needs DOM confirmation
    "xss_stored",       # needs DOM confirmation
    "xss_dom",          # inherently browser-only
    "clickjacking",     # needs visual confirmation
    "csrf",             # needs actual form submission
    "cors_misconfiguration",  # needs cross-origin test
    "prototype_pollution",     # needs browser-side verification
}
```

### Vulnerability Class Inference

`_infer_vuln_class()` (line 832) maps finding metadata to classes:

```python
@staticmethod
def _infer_vuln_class(title, test_id="", description=""):
    text = f"{title} {test_id} {description}".lower()
    classes = []
    for vuln_class, keywords in VULN_CLASS_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            classes.append(vuln_class)
    return classes
```

Keywords are matched against title + test_id + description. For example:
- "Reflected XSS in search" → contains "xss", "reflected xss" → `["xss_reflected"]`
- "SQL injection at /api/users" → contains "sql injection" → `["sqli"]`

### Gate Logic

```
1. vuln_classes = _infer_vuln_class(title, test_id, description or evidence)
2. IF any class in BROWSER_REQUIRED_CLASSES
      AND confidence == "confirmed"
      AND NOT has_browser_evidence(engagement_id, affected_url)
   THEN:
      confidence = "version_based"
```

### Workflow for Browser Verification

```
1. Agent identifies XSS candidate
2. Agent runs: browser_analyze(url)  →  loads the page
3. Agent runs: browser_act("type", index=..., text=payload)
4. Agent runs: browser_act("screenshot")  →  confirms alert/payload executed
5. Agent runs: mark_browser_verified(engagement_id, url, payload, screenshot_taken=True)
   └─ Inserts row into browser_verifications table
6. Agent runs: findings_add_vuln(..., confidence="confirmed")
   └─ add_vuln() checks has_browser_evidence() → True → allows "confirmed"
```

---

## Layer F: Noise Filter

**File:** `server/response_diff.py` — `NoiseDetector` class (line 567)

### Noise Categories

```python
NOISE_PATTERNS: list[tuple[str, list[re.Pattern], list[str]]] = [
    ("CAPTCHA",           [body_patterns],         [header_patterns]),
    ("RATE_LIMIT",        [body_patterns],         [header_patterns]),
    ("WAF_BLOCK",         [body_patterns],         [header_patterns]),
    ("MAINTENANCE",       [body_patterns],         []),
    ("CDN_ERROR",         [body_patterns],         [header_patterns]),
    ("LOGIN_REDIRECT",    [body_patterns],         [header_patterns]),
    ("ANTI_BOT",          [body_patterns],         [header_patterns]),
    ("SESSION_EXPIRED",   [body_patterns],         []),
    ("GENERIC_500",       [body_patterns],         []),
]
```

### Detection Algorithm

```python
@staticmethod
def classify(response_body: str, response_headers: dict) -> list[str]:
    if not response_body:
        return []

    body_lower = response_body.lower()
    header_lines = [f"{k}: {v}".lower() for k, v in response_headers.items()]

    found = []
    for label, body_patterns, header_patterns in NOISE_PATTERNS:
        body_match = any(p.search(body_lower) for p in body_patterns)
        header_match = (
            any(any(hpat in hl for hl in header_lines) for hpat in header_patterns)
            if header_patterns else False
        )
        if body_match or header_match:
            found.append(label)

    return found
```

### Body Patterns Per Category

| Category | Body Patterns (all case-insensitive) |
|----------|--------------------------------------|
| CAPTCHA | `captcha`, `recaptcha`, `cf-turnstile`, `hcaptcha` |
| RATE_LIMIT | `rate limit`, `too many requests`, `429`, `try again later` |
| WAF_BLOCK | `access denied`, `blocked`, `request rejected`, `please contact`, `you have been blocked`, `your request was blocked` |
| MAINTENANCE | `maintenance`, `under construction`, `temporarily unavailable`, `be right back` |
| CDN_ERROR | `502 bad gateway`, `503 service unavailable`, `504 gateway timeout`, `cloudflare.*error`, `fastly.*error`, `akamai.*error` |
| LOGIN_REDIRECT | `login`, `sign in`, `log in`, `authenticate`, `redirect_uri` |
| ANTI_BOT | `javascript.*enabled`, `browser check`, `verifying you`, `challenge`, `ddos protection`, `enable javascript` |
| SESSION_EXPIRED | `session expired`, `session timeout`, `please log in again`, `your session has` |
| GENERIC_500 | `500 internal server error`, `an error occurred` |

### Header Patterns Per Category

| Category | Header Substrings (header lines lowercased) |
|----------|---------------------------------------------|
| CAPTCHA | `cf-challenge` |
| RATE_LIMIT | `x-ratelimit-`, `retry-after` |
| WAF_BLOCK | `cf-ray`, `x-sucuri`, `x-waf` |
| CDN_ERROR | `x-cache`, `x-served-by`, `cf-cache-status` |
| LOGIN_REDIRECT | `location:.*login`, `location:.*auth` |
| ANTI_BOT | `server: cloudflare` |

### Integration in add_vuln()

```python
# -- Noise Filter (Phase F) --------------------------------------------
try:
    from server.response_diff import NoiseDetector
    noise_classes = NoiseDetector.classify(evidence or "", {})
    if noise_classes:
        severity = "Informational"
        confidence = "speculative"
except ImportError:
    pass
```

If the evidence text matches any noise category, the finding is automatically downgraded to Informational/speculative. This happens BEFORE confidence scoring, so the scoring can't override the noise downgrade.

---

## MCP Tools: Full Reference

### validate_poc()

```
validate_poc(
    engagement_id: str          │ REQUIRED - engagement identifier
    command: str                │ REQUIRED - PoC command (typically curl)
    expected_status: str        │ "200", "403", "2xx", "3xx", "4xx" (optional)
    expected_match: str         │ String that MUST appear in response body
    expected_no_match: str      │ String that MUST NOT appear in response body
    label: str                  │ Human-readable label for logging
    force: bool                 │ Allow destructive commands (rm, dd, etc.)
    require_consensus: bool     │ Run payload consensus check
    vuln_class: str             │ "sqli"|"xss"|"ssti"|"cmdi"|"ssrf"
    auto_retry: int             │ 1=no retry, 3+=retry with stats
) -> str                        │ Markdown result with PoC Token on PASS
```

**PASS output format:**
```
## PoC Validation [label]: PASS ✅

**Command**: `curl -s https://target.com/api?q=test`
**Duration**: 1.2s
**HTTP Status**: 200
**Payload Consensus**: 3/3 passed ✅
**Reproducibility**: 5/5 runs successful (avg=142ms, stddev=23ms) ✅

**✅ PoC verified — finding can be logged with confidence.**
**PoC Token**: `a1b2c3d4e5f6...`
```

**FAIL output format:**
```
## PoC Validation [label]: FAIL ❌

**Command**: `curl -s https://target.com/api?q=test`
**Duration**: 0.5s
**HTTP Status**: 404 (expected 200)

### ❌ Issues Found
- Expected status 200, got 404

### Response Preview
```
404 Not Found
```
```

### collect_baseline()

```
collect_baseline(
    engagement_id: str          │ REQUIRED
    url: str                    │ REQUIRED - URL to baseline
    method: str                 │ HTTP method (default: GET)
    headers: str                │ Raw headers, one per line
    body: str                   │ Request body for POST
    samples: int                │ Number of samples (default: 10)
    label: str                  │ Optional label
) -> str                        │ Markdown with baseline_id
```

### diff_response()

```
diff_response(
    engagement_id: str          │ REQUIRED
    baseline_id: str            │ REQUIRED - from collect_baseline()
    attack_command: str         │ REQUIRED - curl command with payload
    payload_string: str         │ Payload to check for reflection
) -> str                        │ Markdown diff report
```

### mark_browser_verified()

```
mark_browser_verified(
    engagement_id: str          │ REQUIRED
    url: str                    │ REQUIRED - verified URL
    payload: str                │ Payload that executed
    screenshot_taken: bool      │ Was screenshot captured?
) -> str                        │ Confirmation markdown
```

---

## Data Flow Diagrams

### Full Finding Lifecycle

```
1. DISCOVERY ── Agent identifies potential vulnerability
   │
2. VALIDATION ── Agent calls validate_poc()
   │  ├── Payload consensus (require_consensus=True)
   │  ├── Reproducibility check (auto_retry>=3)
   │  ├── Response diff (baseline_id provided)
   │  └── PoC Token generated on PASS
   │
3. BROWSER EVIDENCE ── For XSS/CSRF/clickjacking
   │  └── mark_browser_verified()
   │
4. PERSISTENCE ── Agent calls findings_add_vuln()
   │  ├── add_vuln() verification gate (A)
   │  ├── add_vuln() noise filter (F)
   │  ├── add_vuln() confidence scoring (D)
   │  └── add_vuln() browser gate (E)
   │
5. REPORTING ── Agent calls generate_report()
   └── Only findings with confidence="confirmed" appear
```

### SQLite Table Relationships

```
engagements
    │
    ├── hosts ── services
    │
    ├── vulns
    │   └── Fields: title, severity, cvss, confidence, poc_token,
    │                consensus_passed, reproduced, baseline_anomaly
    │
    ├── credentials
    │
    ├── chains
    │
    ├── baselines
    │   └── profile_json: serialized BaselineProfile.to_dict()
    │
    ├── browser_verifications
    │   └── url, payload, screenshot_taken, verified_at
    │
    └── session_log
```

### Evidence Storage

```
engagements/runtime/<engagement_id>/
    ├── findings.md              # Append-only human-readable finding log
    ├── logs.txt                 # Live tail-f logging of all MCP tool calls
    ├── progress.log             # Timestamped one-line progress entries
    └── poc-evidence/
        └── <poc_token>/
            ├── evidence.txt     # Full command stdout
            └── meta.json        # Command, returncode, timing, label
```

---

## Design Principles

1. **Enforcement in code, not prompts** — Every gate is in the DB write path or PoC execution path. No agent can opt out.

2. **Deterministic only** — No LLM calls in any FP detection layer. All logic is regex, comparison, or statistics.

3. **Downgrade don't reject** — Findings are preserved at lower severity/confidence rather than rejected. Human reviewers can always re-evaluate.

4. **Backward compatible** — All new params (`consensus_passed`, `reproduced`, `baseline_anomaly`) are optional with `False` defaults. Existing code works unchanged.

5. **Signals over substance** — Confidence scoring prefers verification signals (consensus, reproducibility, browser confirmation) over content signals (evidence length, CVSS score).

---

## File Reference

| File | Lines | Components |
|------|-------|------------|
| `server/findings_db.py` | 970 | Layer A (add_vuln gate), Layer D (_compute_confidence), Layer E (browser_verifications CRUD) |
| `server/server.py` | 7242 | Layer B (validate_poc, _check_consensus, _check_reproducibility, CONSENSUS_RULES), ReproducibilityResult |
| `server/response_diff.py` | 567 | Layer C (DynamicValueFilter, ResponseFingerprint, BaselineProfile, DiffResult, compare, collect_baseline, ERROR_SIGNATURES), Layer F (NoiseDetector, NOISE_PATTERNS) |
