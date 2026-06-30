"""Labeled corpus for the FP/FN benchmark.

Each case feeds the real consensus oracle (`server._consensus_oracle`) a
vuln_class, payload, attack response, and benign control response, with the
ground-truth label of whether that response is genuine exploitation evidence.

`vulnerable=True`  → oracle SHOULD return True  (a real positive)
`vulnerable=False` → oracle SHOULD return False (a benign/safe response)

Precision/recall are computed from these in test_benchmark.py. Add cases here
as new FP/FN sources are found in the field — this file IS the benchmark.
"""

# resp/control are the dicts _run_curl produces: ok_conn, status, body, elapsed_ms
def _r(body="", status="200", elapsed_ms=50, ok=True):
    return {"ok_conn": ok, "status": status, "body": body, "elapsed_ms": elapsed_ms}


_BENIGN_CONTROL = _r(body="<html>normal page, query=swarmbenign42x</html>")

CASES = [
    # ── SQLi ───────────────────────────────────────────────────────────────
    {"name": "sqli_error_based", "vuln_class": "sqli", "payload": "' OR '1'='1",
     "resp": _r(body="You have an error in your SQL syntax near ''"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "sqli_time_based", "vuln_class": "sqli", "payload": "' AND SLEEP(5)--",
     "resp": _r(body="ok", elapsed_ms=5200), "control": _r(body="ok", elapsed_ms=60), "vulnerable": True},
    {"name": "sqli_safe_200", "vuln_class": "sqli", "payload": "' OR '1'='1",
     "resp": _r(body="<html>search results: none found</html>"), "control": _BENIGN_CONTROL, "vulnerable": False},
    {"name": "sqli_safe_404", "vuln_class": "sqli", "payload": "' OR '1'='1",
     "resp": _r(body="404 Not Found", status="404"), "control": _r(body="404 Not Found", status="404"), "vulnerable": False},
    {"name": "sqli_baseline_already_errors", "vuln_class": "sqli", "payload": "'",
     "resp": _r(body="mysql_fetch error"), "control": _r(body="mysql_fetch error"), "vulnerable": False},

    # ── XSS ──────────────────────────────────────────────────────────────────
    {"name": "xss_reflected", "vuln_class": "xss", "payload": "<img src=x onerror=alert(1)>",
     "resp": _r(body="<html>results: <img src=x onerror=alert(1)></html>"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "xss_not_reflected", "vuln_class": "xss", "payload": "<img src=x onerror=alert(1)>",
     "resp": _r(body="<html>results: none</html>"), "control": _BENIGN_CONTROL, "vulnerable": False},
    {"name": "xss_reflected_in_control_too", "vuln_class": "xss", "payload": "<x>",
     "resp": _r(body="echo <x>"), "control": _r(body="echo <x>"), "vulnerable": False},

    # ── SSTI ─────────────────────────────────────────────────────────────────
    {"name": "ssti_eval", "vuln_class": "ssti", "payload": "{{7*7}}",
     "resp": _r(body="49"), "control": _r(body="swarmbenign42x"), "vulnerable": True},
    {"name": "ssti_no_eval", "vuln_class": "ssti", "payload": "{{7*7}}",
     "resp": _r(body="{{7*7}}"), "control": _r(body="swarmbenign42x"), "vulnerable": False},

    # ── cmdi ─────────────────────────────────────────────────────────────────
    {"name": "cmdi_marker", "vuln_class": "cmdi", "payload": ";id",
     "resp": _r(body="uid=0(root) gid=0(root)"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "cmdi_no_marker", "vuln_class": "cmdi", "payload": ";id",
     "resp": _r(body="invalid input"), "control": _BENIGN_CONTROL, "vulnerable": False},

    # ── path traversal / xxe ───────────────────────────────────────────────
    {"name": "lfi_passwd", "vuln_class": "path_traversal", "payload": "../../etc/passwd",
     "resp": _r(body="root:x:0:0:root:/root:/bin/bash"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "lfi_no_leak", "vuln_class": "path_traversal", "payload": "../../etc/passwd",
     "resp": _r(body="file not found"), "control": _BENIGN_CONTROL, "vulnerable": False},
    {"name": "xxe_passwd", "vuln_class": "xxe", "payload": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
     "resp": _r(body="root:x:0:0:root"), "control": _BENIGN_CONTROL, "vulnerable": True},

    # ── open redirect ──────────────────────────────────────────────────────
    {"name": "open_redirect", "vuln_class": "open_redirect", "payload": "//evil.com",
     "resp": _r(body="HTTP/1.1 302\r\nLocation: //evil.com\r\n", status="302"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "open_redirect_safe", "vuln_class": "open_redirect", "payload": "//evil.com",
     "resp": _r(body="HTTP/1.1 200\r\n<html>home</html>"), "control": _BENIGN_CONTROL, "vulnerable": False},

    # ── graphql ──────────────────────────────────────────────────────────────
    {"name": "graphql_introspection", "vuln_class": "graphql_abuse", "payload": "{__schema{types{name}}}",
     "resp": _r(body='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'), "control": _r(body='{"errors":["bad"]}'), "vulnerable": True},
    {"name": "graphql_blocked", "vuln_class": "graphql_abuse", "payload": "{__schema{types{name}}}",
     "resp": _r(body='{"errors":["introspection disabled"]}'), "control": _r(body='{"errors":["bad"]}'), "vulnerable": False},

    # ── ssrf (differential / metadata) ──────────────────────────────────────
    {"name": "ssrf_metadata", "vuln_class": "ssrf", "payload": "http://169.254.169.254/",
     "resp": _r(body="ami-id\ninstance-id\niam/security-credentials/role"), "control": _BENIGN_CONTROL, "vulnerable": True},
    {"name": "ssrf_safe_same_as_control", "vuln_class": "ssrf", "payload": "http://127.0.0.1/",
     "resp": _r(body="<html>normal page, query=swarmbenign42x</html>"), "control": _BENIGN_CONTROL, "vulnerable": False},

    # ── unreachable / connection failure must never be a positive ──────────
    {"name": "no_response", "vuln_class": "sqli", "payload": "' OR 1=1",
     "resp": _r(ok=False, status=None, body=""), "control": _BENIGN_CONTROL, "vulnerable": False},
    {"name": "unknown_class_failclosed", "vuln_class": "totally_unknown", "payload": "x",
     "resp": _r(body="anything at all"), "control": _BENIGN_CONTROL, "vulnerable": False},
]
