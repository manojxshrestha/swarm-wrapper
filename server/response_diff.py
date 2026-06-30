"""Smart Response Diff Engine.

Parses HTTP responses into structured fingerprints, collects baselines
from normal requests, and computes diffs between baseline and attack
responses. Filters out dynamic values (CSRF tokens, UUIDs, dates, etc.)
so that only meaningful structural changes are reported.

All functions are deterministic — no AI calls.
"""

import hashlib
import json
import math
import re
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

# ── Dynamic Value Patterns ────────────────────────────────────────────────

DYNAMIC_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("CSRF_TOKEN", re.compile(r'<input[^>]*name=["\'](csrf_token|_token|authenticity_token|csrfmiddlewaretoken)["\'][^>]*value=["\']([^"\']+)')),
    ("UUID", re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)),
    ("SESSION_ID", re.compile(r"(session[_-]?id|sid|jsessionid|phpsessid|PHPSESSID)=[a-zA-Z0-9]{16,}")),
    ("TIMESTAMP", re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")),
    ("DATE", re.compile(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} " r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}")),
    ("LARGE_ID", re.compile(r'"id"\s*:\s*\d{4,}')),
    ("ANALYTICS", re.compile(r"(ga:|gtm-|utm_|fbq=)[a-zA-Z0-9_-]+")),
    ("NONCE", re.compile(r'nonce["\']?\s*[:=]\s*["\'][a-zA-Z0-9+/=]{10,}["\']')),
    ("CACHE_BUSTER", re.compile(r"[?&]_=\d{10,}")),
    ("FLOAT_NUMBER", re.compile(r"\b\d+\.\d{4,}\b")),
    ("AUTH_HEADER", re.compile(r"(Authorization|Bearer|ApiKey|X-API-Key):\s*[a-zA-Z0-9+/=._-]{10,}", re.I)),
]

ERROR_SIGNATURES: list[re.Pattern] = [
    re.compile(r"SQL syntax|mysql_error|MariaDB|PostgreSQL.*ERROR|SQLite.*Error|ORA-[0-9]{5}"),
    re.compile(r"Division by zero|unexpected T_STRING|Parse error|Fatal error|Warning.*include"),
    re.compile(r"System\.Data\.SqlClient\.SqlException|Microsoft OLE DB"),
    re.compile(r"java\.sql\.SQLException|org\.hibernate\.exception"),
    re.compile(r"FileNotFoundException|No such file|failed to open stream"),
    re.compile(r"stack trace:|Traceback \(most recent call last\)"),
    # NOTE: "404 Not Found"/"403 Forbidden"/bare "not found" were removed here —
    # they are ordinary HTTP responses, not injection error oracles, and caused
    # benign 404/403 pages to be scored as DIFFERENT/SUSPICIOUS (H5 false positive).
]


# ── Data Classes ──────────────────────────────────────────────────────────


@dataclass
class ResponseFingerprint:
    raw_status: int
    raw_headers: dict[str, str]
    raw_body: str
    body_length: int
    body_hash: str
    timing_ms: float
    dom_skeleton: str | None
    json_keys: str | None
    normalized_body: str
    normalized_length: int
    entropy: float

    @staticmethod
    def from_curl_output(stdout: str, timing_ms: float = 0) -> "ResponseFingerprint":
        """Parse curl -i output into a ResponseFingerprint."""
        status_code = 0
        headers = {}
        body = ""

        # Split headers from body on first blank line
        header_end = stdout.find("\r\n\r\n")
        if header_end == -1:
            header_end = stdout.find("\n\n")
        if header_end != -1:
            header_section = stdout[:header_end]
            body = stdout[header_end:].lstrip()
            # Parse status line
            first_line = header_section.split("\n")[0].strip()
            status_match = re.search(r"HTTP/[\d.]+\s+(\d+)", first_line)
            if status_match:
                status_code = int(status_match.group(1))
            # Parse headers
            for line in header_section.split("\n")[1:]:
                line = line.strip()
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()
        else:
            body = stdout

        normalized, _ = DynamicValueFilter.normalize(body)
        dom_skeleton = ResponseFingerprint._extract_dom_skeleton(body)
        json_keys = ResponseFingerprint._extract_json_keys(body)

        return ResponseFingerprint(
            raw_status=status_code,
            raw_headers=headers,
            raw_body=body,
            body_length=len(body),
            body_hash=hashlib_sha256(normalized),
            timing_ms=timing_ms,
            dom_skeleton=dom_skeleton,
            json_keys=json_keys,
            normalized_body=normalized,
            normalized_length=len(normalized),
            entropy=_shannon_entropy(body),
        )

    @staticmethod
    def _extract_dom_skeleton(html: str) -> str | None:
        """Extract HTML tag structure as a simplified skeleton."""
        # Look for HTML content
        if "<html" not in html.lower() and "<!doctype" not in html.lower():
            return None
        # Extract opening tags (keep only tag names)
        tags = re.findall(r"<(\w+)[^>]*>", html)
        if not tags:
            return None
        # Build skeleton: keep only structural tags, skip inline/text-level
        structural = {
            "html",
            "head",
            "body",
            "div",
            "span",
            "form",
            "table",
            "tr",
            "td",
            "th",
            "ul",
            "ol",
            "li",
            "p",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "section",
            "article",
            "nav",
            "header",
            "footer",
            "main",
            "aside",
            "script",
            "style",
            "select",
            "input",
            "button",
            "a",
            "img",
            "iframe",
        }
        skeleton = [t for t in tags if t.lower() in structural]
        return ">".join(skeleton) if skeleton else None

    @staticmethod
    def _extract_json_keys(body: str) -> str | None:
        """Extract JSON key paths as a dot-separated skeleton."""
        body_stripped = body.strip()
        if not (body_stripped.startswith("{") or body_stripped.startswith("[")):
            return None
        try:
            data = json.loads(body_stripped)
        except (json.JSONDecodeError, ValueError):
            return None

        keys = []

        def _walk(obj, path: str):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full = f"{path}.{k}" if path else k
                    keys.append(full)
                    _walk(v, full)
            elif isinstance(obj, list):
                # Use index 0's structure as representative
                if obj:
                    _walk(obj[0], f"{path}[]")

        _walk(data, "")
        return " > ".join(sorted(keys)) if keys else None


@dataclass
class BaselineProfile:
    url: str
    method: str
    request_body: str
    sample_count: int = 0
    status_codes: set = field(default_factory=set)
    body_lengths: list = field(default_factory=list)
    normalized_bodies: list = field(default_factory=list)
    normalized_hashes: set = field(default_factory=set)
    dom_skeletons: list = field(default_factory=list)
    json_keys: str | None = None
    timings: list = field(default_factory=list)
    volatile_headers: set = field(default_factory=set)
    dynamic_fields_found: dict = field(default_factory=dict)

    def add_sample(self, fp: ResponseFingerprint) -> None:
        self.sample_count += 1
        self.status_codes.add(fp.raw_status)
        self.body_lengths.append(fp.body_length)
        self.normalized_bodies.append(fp.normalized_body)
        self.normalized_hashes.add(fp.body_hash)
        if fp.dom_skeleton:
            self.dom_skeletons.append(fp.dom_skeleton)
        if fp.json_keys:
            self.json_keys = fp.json_keys
        self.timings.append(fp.timing_ms)

    def timing_p50(self) -> float:
        if not self.timings:
            return 0.0
        s = sorted(self.timings)
        return s[len(s) // 2]

    def timing_p95(self) -> float:
        if not self.timings:
            return 0.0
        s = sorted(self.timings)
        idx = min(int(len(s) * 0.95), len(s) - 1)
        return s[idx]

    def is_stable(self, max_hashes: int = 2) -> bool:
        if self.sample_count < 3:
            return False
        if len(self.status_codes) > 1:
            return False
        if len(self.normalized_hashes) > max_hashes:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "request_body": self.request_body,
            "sample_count": self.sample_count,
            "status_codes": list(self.status_codes),
            "body_lengths": self.body_lengths,
            "normalized_bodies": self.normalized_bodies,
            "normalized_hashes": list(self.normalized_hashes),
            "dom_skeletons": list(set(self.dom_skeletons)),
            "json_keys": self.json_keys,
            "timings": self.timings,
            "volatile_headers": list(self.volatile_headers),
            "dynamic_fields_found": self.dynamic_fields_found,
        }

    @staticmethod
    def from_dict(data: dict) -> "BaselineProfile":
        bp = BaselineProfile(
            url=data.get("url", ""),
            method=data.get("method", "GET"),
            request_body=data.get("request_body", ""),
            sample_count=data.get("sample_count", 0),
            status_codes=set(data.get("status_codes", [])),
            body_lengths=data.get("body_lengths", []),
            normalized_bodies=data.get("normalized_bodies", []),
            normalized_hashes=set(data.get("normalized_hashes", [])),
            dom_skeletons=data.get("dom_skeletons", []),
            json_keys=data.get("json_keys"),
            timings=data.get("timings", []),
            volatile_headers=set(data.get("volatile_headers", [])),
            dynamic_fields_found=data.get("dynamic_fields_found", {}),
        )
        return bp


@dataclass
class DiffResult:
    verdict: str  # "MATCH" | "LIKELY_SAME" | "SUSPICIOUS" | "DIFFERENT"
    confidence: float  # 0.0 - 1.0

    status_same: bool = True
    body_length_delta: int = 0
    body_length_delta_pct: float = 0.0
    body_length_within_normal: bool = True
    normalized_similarity: float = 1.0

    dom_changed: bool | None = None
    json_keys_changed: bool | None = None

    new_headers: list = field(default_factory=list)
    missing_headers: list = field(default_factory=list)

    timing_delta_ms: float = 0.0
    timing_anomaly: bool = False

    error_signatures_found: list = field(default_factory=list)
    reflection_count: int = 0
    reflection_positions: list = field(default_factory=list)
    entropy_delta: float = 0.0

    def to_markdown(self) -> str:
        lines = [f"### Response Diff — Verdict: {self.verdict} (confidence: {self.confidence:.0%})\n"]
        if self.status_same:
            lines.append("✅ Status: same")
        else:
            lines.append("❌ Status: changed")
        if not self.body_length_within_normal:
            delta_pct = f"{self.body_length_delta_pct:+.1%}"
            lines.append(f"⚠️  Body length: {self.body_length_delta:+d} ({delta_pct})")
        if self.dom_changed:
            lines.append("❌ DOM structure: changed")
        elif self.dom_changed is False:
            lines.append("✅ DOM structure: same")
        if self.json_keys_changed:
            lines.append("❌ JSON keys: changed")
        elif self.json_keys_changed is False:
            lines.append("✅ JSON keys: same")
        if self.error_signatures_found:
            lines.append(f"⚠️  Error signatures: {', '.join(self.error_signatures_found)}")
        if self.reflection_count > 0:
            lines.append(f"⚠️  Payload reflected {self.reflection_count} time(s)")
        if self.timing_anomaly:
            lines.append(f"⚠️  Timing anomaly: +{self.timing_delta_ms:.0f}ms")
        if abs(self.entropy_delta) >= 0.5:
            lines.append(f"ℹ️  Entropy delta: {self.entropy_delta:+.2f}")
        return "\n".join(lines)


# ── Dynamic Value Filter ──────────────────────────────────────────────────


class DynamicValueFilter:
    @staticmethod
    def normalize(text: str) -> tuple[str, int]:
        """Replace dynamic values with {TYPE} placeholders.
        Returns (normalized_text, number_of_replacements)."""
        count = 0
        for name, pattern in DYNAMIC_PATTERNS:
            text, subs = pattern.subn(f"{{{name}}}", text)
            count += subs
        return text, count


# ── Noise Detection (Phase F) ──────────────────────────────────────────────


NOISE_PATTERNS: list[tuple[str, list[re.Pattern], list[str]]] = [
    (
        "CAPTCHA",
        [
            re.compile(r"captcha|recaptcha|cf-turnstile|hcaptcha", re.I),
        ],
        ["cf-challenge"],
    ),
    (
        "RATE_LIMIT",
        [
            re.compile(r"rate limit|too many requests|429|try again later", re.I),
        ],
        ["x-ratelimit-", "retry-after"],
    ),
    (
        "WAF_BLOCK",
        [
            re.compile(r"access denied|blocked|request rejected|please contact|" r"you have been blocked|your request was blocked", re.I),
        ],
        ["cf-ray", "x-sucuri", "x-waf"],
    ),
    (
        "MAINTENANCE",
        [
            re.compile(r"maintenance|under construction|temporarily unavailable" r"|be right back", re.I),
        ],
        [],
    ),
    (
        "CDN_ERROR",
        [
            re.compile(r"502 bad gateway|503 service unavailable|504 gateway timeout" r"|cloudflare.*error|fastly.*error|akamai.*error", re.I),
        ],
        ["x-cache", "x-served-by", "cf-cache-status"],
    ),
    (
        "LOGIN_REDIRECT",
        [
            re.compile(r"login|sign in|log in|authenticate|redirect_uri", re.I),
        ],
        ["location:.*login", "location:.*auth"],
    ),
    (
        "ANTI_BOT",
        [
            re.compile(r"javascript.*enabled|browser check|verifying you", re.I),
            re.compile(r"challenge|ddos protection|enable javascript", re.I),
        ],
        ["server: cloudflare"],
    ),
    (
        "SESSION_EXPIRED",
        [
            re.compile(r"session expired|session timeout|please log in again" r"|your session has", re.I),
        ],
        [],
    ),
    (
        "GENERIC_500",
        [
            re.compile(r"500 internal server error|an error occurred", re.I),
        ],
        [],
    ),
]


class NoiseDetector:
    @staticmethod
    def classify(response_body: str, response_headers: dict) -> list[str]:
        """Classify a response into noise categories.

        Returns list of labels (e.g. ['CAPTCHA', 'WAF_BLOCK']).
        Determines whether a response is likely a security control,
        CDN error, rate limit, or other false positive source.
        """
        if not response_body:
            return []

        body_lower = response_body.lower()
        header_lines = [f"{k}: {v}".lower() for k, v in response_headers.items()]

        found: list[str] = []
        for label, body_patterns, header_patterns in NOISE_PATTERNS:
            body_match = any(p.search(body_lower) for p in body_patterns)
            header_match = any(any(hpat in hl for hl in header_lines) for hpat in header_patterns) if header_patterns else False
            if body_match or header_match:
                found.append(label)

        return found


# ── Helpers ────────────────────────────────────────────────────────────────


def hashlib_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of the text."""
    if not text:
        return 0.0
    text = text[:10000]  # limit for performance
    length = len(text)
    freq = Counter(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy, 4)


def _sample_head_tail(s: str, budget: int = 2000) -> str:
    """Bound a string to `budget` chars while preserving BOTH ends, so a
    difference appended at the tail (e.g. an error/leak at the bottom of a
    large page) is not lost to head-only truncation (M5)."""
    if len(s) <= budget:
        return s
    half = budget // 2
    return s[:half] + s[-half:]


def _levenshtein_similarity(a: str, b: str) -> float:
    """Compute similarity between two strings using normalized Levenshtein distance.
    Returns 1.0 for identical, 0.0 for completely different.
    Bounds cost by sampling the head AND tail of each string (M5) so that
    differences past the first 2000 chars are still detected."""
    a = _sample_head_tail(a)
    b = _sample_head_tail(b)
    if not a and not b:
        return 1.0
    # Compute Levenshtein distance
    m, n = len(a), len(b)
    # Use single row optimization
    prev = list(range(n + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * n
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    distance = prev[n]
    max_len = max(m, n)
    if max_len == 0:
        return 1.0
    return 1.0 - (distance / max_len)


def _detect_reflections(body: str, payload: str) -> int:
    """Count how many times the payload string appears in the response body."""
    if not payload or not body:
        return 0
    # Check for the raw payload first
    count = body.count(payload)
    if count > 0:
        return count
    # Fallback: check URL-encoded version
    encoded = urllib.parse.quote(payload)
    return body.count(encoded)


def _check_error_signatures(body: str) -> list[str]:
    """Check for error signatures in response body."""
    found = []
    for pattern in ERROR_SIGNATURES:
        if pattern.search(body):
            found.append(pattern.pattern[:50])
    return found


# ── Compare ────────────────────────────────────────────────────────────────


def compare(
    baseline: BaselineProfile | None,
    attack_fp: ResponseFingerprint,
    payload_string: str = "",
) -> DiffResult:
    """Compare an attack response against a baseline profile.
    Returns a structured DiffResult with verdict and evidence.

    Verdicts:
    - MATCH: Attack response is indistinguishable from baseline (no vulnerability detected)
    - LIKELY_SAME: Minor differences that are probably noise
    - SUSPICIOUS: Notable differences worth AI review
    - DIFFERENT: Significant structural change (likely a valid finding)
    """
    result = DiffResult(verdict="SUSPICIOUS", confidence=0.3)

    # No baseline, OR a baseline that collected no usable samples (e.g. every
    # request errored). Returning MATCH here would falsely read as "not a
    # vulnerability"; instead report UNKNOWN/SUSPICIOUS so the caller knows the
    # comparison could not be made (M5).
    if baseline is None or baseline.sample_count == 0 or not baseline.body_lengths:
        result.verdict = "SUSPICIOUS"
        result.confidence = 0.3
        result.status_same = True
        result.body_length_delta = 0
        result.body_length_within_normal = True
        return result

    # 1. Status code comparison
    result.status_same = attack_fp.raw_status in baseline.status_codes

    # 2. Body length comparison
    if baseline.body_lengths:
        mean_len = sum(baseline.body_lengths) / len(baseline.body_lengths)
        result.body_length_delta = attack_fp.body_length - int(mean_len)
        result.body_length_delta_pct = result.body_length_delta / mean_len if mean_len > 0 else 0.0
        # Within normal range?
        min_len = min(baseline.body_lengths)
        max_len = max(baseline.body_lengths)
        padding = (max_len - min_len) * 2 + 50  # Allow extra variance
        result.body_length_within_normal = min_len - padding <= attack_fp.body_length <= max_len + padding

    # 3. Normalized body similarity (after dynamic value filtering)
    if baseline.normalized_bodies:
        similarities = [_levenshtein_similarity(bn, attack_fp.normalized_body) for bn in baseline.normalized_bodies]
        result.normalized_similarity = max(similarities) if similarities else 0.0
    else:
        result.normalized_similarity = 1.0

    # 4. DOM structure comparison
    if attack_fp.dom_skeleton and baseline.dom_skeletons:
        if attack_fp.dom_skeleton in baseline.dom_skeletons:
            result.dom_changed = False
        else:
            result.dom_changed = True

    # 5. JSON keys comparison
    if attack_fp.json_keys and baseline.json_keys:
        result.json_keys_changed = attack_fp.json_keys != baseline.json_keys

    # 6. Timing anomaly
    if baseline.timings:
        p95 = baseline.timing_p95()
        if p95 > 0 and attack_fp.timing_ms > p95 * 2:
            result.timing_anomaly = True
            result.timing_delta_ms = attack_fp.timing_ms - baseline.timing_p50()

    # 7. Error signatures — only count signatures NEWLY introduced by the
    #    attack (i.e. not already present in the baseline). A signature the
    #    baseline already emits is normal behaviour, not evidence (H5).
    attack_sigs = _check_error_signatures(attack_fp.raw_body)
    baseline_sigs: set[str] = set()
    for bn in baseline.normalized_bodies:
        baseline_sigs.update(_check_error_signatures(bn))
    result.error_signatures_found = [s for s in attack_sigs if s not in baseline_sigs]

    # 8. Reflection detection
    if payload_string:
        result.reflection_count = _detect_reflections(attack_fp.raw_body, payload_string)

    # 9. Entropy delta
    if baseline.normalized_bodies:
        baseline_entropy = sum(_shannon_entropy(b) for b in baseline.normalized_bodies) / len(baseline.normalized_bodies)
        result.entropy_delta = attack_fp.entropy - baseline_entropy

    # ── Verdict ──────────────────────────────────────────────────────
    signal_count = 0
    total_weight = 0

    # Status change is a strong signal
    if not result.status_same:
        signal_count += 3
    total_weight += 3

    # Body length outside normal range
    if not result.body_length_within_normal:
        signal_count += 2
    total_weight += 2

    # DOM change
    if result.dom_changed:
        signal_count += 3
    total_weight += 3

    # JSON structure change
    if result.json_keys_changed:
        signal_count += 3
    total_weight += 3

    # Low normalized similarity
    if result.normalized_similarity < 0.8:
        signal_count += 2
    total_weight += 2

    # Error signatures
    if result.error_signatures_found:
        signal_count += 3
    total_weight += 3

    # Reflection
    if result.reflection_count > 0:
        signal_count += 2
    total_weight += 2

    # Timing anomaly
    if result.timing_anomaly:
        signal_count += 1
    total_weight += 1

    # Compute confidence
    result.confidence = signal_count / total_weight if total_weight > 0 else 0.0

    # Verdict mapping
    if result.confidence >= 0.75:
        result.verdict = "DIFFERENT"
    elif result.confidence >= 0.4:
        result.verdict = "SUSPICIOUS"
    elif result.confidence >= 0.15:
        result.verdict = "LIKELY_SAME"
    else:
        result.verdict = "MATCH"

    # H5: floor the verdict for two signals that are too important to be
    # dismissed as MATCH/LIKELY_SAME by the averaged score. A reflected payload
    # (canonical XSS indicator) or a NEWLY-appeared error signature warrants at
    # least manual review.
    if (result.reflection_count > 0 or result.error_signatures_found) and result.verdict in ("MATCH", "LIKELY_SAME"):
        result.verdict = "SUSPICIOUS"
        result.confidence = max(result.confidence, 0.4)

    return result


# ── Baseline Collection ──────────────────────────────────────────────────


def collect_baseline(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    samples: int = 10,
) -> BaselineProfile:
    """Send N normal requests to the URL and build a baseline profile."""
    import subprocess as _sp

    bp = BaselineProfile(url=url, method=method, request_body=body)

    for i in range(samples):
        try:
            start = time.time()
            cmd = ["curl", "-s", "-X", method, url, "-i", "-L", "--max-time", "15"]
            if headers:
                for line in headers.strip().split("\n"):
                    line = line.strip()
                    if ":" in line:
                        cmd.extend(["-H", line])
            if body:
                cmd.extend(["--data-raw", body])
            result = _sp.run(cmd, capture_output=True, text=True, timeout=20)
            elapsed = (time.time() - start) * 1000
            fp = ResponseFingerprint.from_curl_output(result.stdout, elapsed)
            bp.add_sample(fp)
        except Exception:
            continue

    return bp
