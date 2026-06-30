"""Tests for the consensus payload engine (_run_payload, _check_consensus).

After the C2/H1 fix, consensus must verify *exploitation*, not reachability:

1. A non-vulnerable endpoint that returns 200 to every payload → consensus FAILS.
2. Class-specific oracles (SQL error, XSS reflection, SSTI eval, cmdi marker)
   make consensus PASS only on genuinely vulnerable endpoints.
3. Non-curl commands and classes with no payloads fail closed (do NOT pass).

A local stub HTTP server provides deterministic vulnerable/safe endpoints so
the tests are hermetic (no network).
"""

import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Stub vulnerable/safe server ──────────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        # First query value, decoded
        val = ""
        if qs:
            val = next(iter(qs.values()))[0]

        if path == "/safe":
            # Never vulnerable: static body, no reflection, always 200.
            self._send(200, "hello world, nothing to see here")
        elif path == "/sqli":
            if "'" in val:
                self._send(500, "You have an error in your SQL syntax near ''")
            else:
                self._send(200, "ok")
        elif path == "/xss":
            # Reflect the decoded value unescaped.
            self._send(200, f"<html>results for: {val}</html>")
        elif path == "/ssti":
            if "7*7" in val:
                self._send(200, "49")
            else:
                self._send(200, val)
        elif path == "/cmdi":
            if any(t in val for t in (";id", "|id", "`id`", "id")):
                self._send(200, "uid=0(root) gid=0(root) groups=0(root)")
            else:
                self._send(200, "ok")
        elif path == "/redirect":
            # Open redirect: reflect target into Location on any non-benign value.
            if "evil.com" in val:
                self.send_response(302)
                self.send_header("Location", val)
                self.end_headers()
            else:
                self._send(200, "ok")
        else:
            self._send(404, "not found")


@pytest.fixture(scope="module")
def stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def srv():
    import server as srv_module

    return srv_module


# ── The critical anti-false-positive test ────────────────────────────────────
class TestNoFalsePositive:
    def test_safe_endpoint_fails_consensus_sqli(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/safe?id=1"', "sqli")
        assert not passed, f"Non-vulnerable endpoint must NOT pass sqli consensus: {results}"
        assert successes == 0, results

    def test_safe_endpoint_fails_consensus_xss(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/safe?q=1"', "xss")
        assert not passed, f"Non-vulnerable endpoint must NOT pass xss consensus: {results}"


# ── True-positive oracle tests ───────────────────────────────────────────────
class TestTruePositives:
    def test_sqli_error_based(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/sqli?id=1"', "sqli")
        assert passed, f"SQL-error endpoint should pass: {results}"
        assert successes >= 2, results

    def test_xss_reflection(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/xss?q=1"', "xss")
        assert passed, f"Reflecting endpoint should pass xss: {results}"

    def test_ssti_eval(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/ssti?x=1"', "ssti")
        assert passed, f"SSTI-eval endpoint should pass: {results}"

    def test_cmdi_marker(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/cmdi?c=1"', "cmdi")
        assert passed, f"cmdi endpoint should pass: {results}"


# ── Fail-closed tests ─────────────────────────────────────────────────────────
class TestFailClosed:
    def test_noncurl_fails_closed(self, srv):
        passed, successes, total, results = srv._check_consensus("echo hello", "xss")
        assert not passed, "Non-curl command must fail closed (was a bypass)"

    def test_unknown_class_fails_closed(self, srv, stub):
        passed, successes, total, results = srv._check_consensus(f'curl "{stub}/safe?id=1"', "unknown_vuln_class_xyz")
        assert not passed, "Unknown class (no payloads) must fail closed"

    def test_dns_failure_fails(self, srv):
        passed, successes, total, results = srv._check_consensus("curl --connect-timeout 3 https://nonexistent-domain-xyz123456.example/", "sqli")
        assert not passed, "Unreachable host must fail consensus"
        assert successes == 0


# ── _run_payload oracle unit tests ───────────────────────────────────────────
class TestRunPayloadOracle:
    def test_run_payload_reflects(self, srv, stub):
        cmd = srv._ensure_probe_flags(srv._build_poc_command(f'curl "{stub}/xss?q=1"', "<x>pew</x>"))
        control = srv._run_curl(srv._ensure_probe_flags(srv._build_poc_command(f'curl "{stub}/xss?q=1"', "swarmbenign42x")))
        success, msg = srv._run_payload(cmd, "<x>pew</x>", "xss", control)
        assert success, msg

    def test_run_payload_safe_no_evidence(self, srv, stub):
        cmd = srv._ensure_probe_flags(srv._build_poc_command(f'curl "{stub}/safe?q=1"', "<x>pew</x>"))
        success, msg = srv._run_payload(cmd, "<x>pew</x>", "xss", None)
        assert not success, msg


class TestReproducibilityM4:
    """M4: success requires the evidence to reproduce; counter never negative."""

    def test_count_never_negative_on_failure(self, srv):
        # A command that fails to even parse/run every time → 0 successes, not negative.
        res = srv._check_reproducibility("curl --connect-timeout 2 http://127.0.0.1:1/", 3)
        assert res.success_count == 0
        assert res.success_rate == 0.0

    def test_constant_error_page_not_reproducible(self, srv, stub):
        # Endpoint returns 200 every time but never contains the marker → not reproduced.
        res = srv._check_reproducibility(f'curl -s "{stub}/safe?q=1"', 3, expected_match="SECRET_MARKER_XYZ")
        assert res.success_count == 0, "Constant page without the marker must not count as reproduced"
        assert not res.all_succeeded

    def test_marker_present_reproduces(self, srv, stub):
        res = srv._check_reproducibility(f'curl -s "{stub}/xss?q=SECRET_MARKER_XYZ"', 3, expected_match="SECRET_MARKER_XYZ")
        assert res.success_count == 3
        assert res.all_succeeded
