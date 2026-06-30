"""Regression test for C1: server tool wrappers must not use `from server.X`.

The package is loaded as flat modules (`server/server.py` launched directly,
`packages = ["."]`), so `import server.response_diff` raises
ModuleNotFoundError at runtime. The bug lived inside lazy imports within tool
functions, so importing the module alone did NOT surface it — only *invoking*
the tools did. These tests drive the tool wrappers past their import lines.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _underlying(fn):
    """Unwrap a FastMCP-decorated tool to its plain callable."""
    return getattr(fn, "fn", getattr(fn, "__wrapped__", fn))


@pytest.fixture(scope="module")
def srv():
    import server

    return server


def test_no_server_dot_imports_in_source():
    """Static guard: no `from server.` / `import server.` anywhere in the package."""
    server_dir = Path(__file__).resolve().parent.parent
    offenders = []
    for py in server_dir.glob("*.py"):
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("from server.", "import server.")):
                offenders.append(f"{py.name}:{i}: {stripped}")
    assert not offenders, "Found `server.` package imports (flat layout breaks these):\n" + "\n".join(offenders)


def test_diff_response_tool_runs(srv):
    """diff_response executes its lazy `from response_diff import ...` line."""
    df = _underlying(srv.diff_response)
    out = df(
        engagement_id="e1",
        baseline_id="does-not-exist",
        attack_command="curl -s http://127.0.0.1:1/",
    )
    assert "not found" in out.lower()  # reached the post-import baseline lookup


def test_collect_baseline_tool_runs(srv):
    """collect_baseline executes its lazy `from response_diff import collect_baseline`."""
    # Baselines FK-reference engagements; register one in the server's own DB.
    srv._fdb.init_engagement("tool-import-test-eng", client="t")
    cb = _underlying(srv.collect_baseline)
    out = cb(
        engagement_id="tool-import-test-eng",
        url="http://127.0.0.1:1/",  # connection refused → fast, no network
        samples=1,
    )
    assert "Baseline" in out  # produced a baseline report without ModuleNotFoundError


def test_tool_verifies_supplied_token_even_when_not_confirmed(srv):
    """H2: a supplied poc_token must be verified regardless of incoming
    confidence, so escalation-to-confirmed inside add_vuln can't ride an
    unverified token. A bogus token with confidence='version_based' is
    rejected before reaching the DB."""
    add_finding = _underlying(srv.findings_add_vuln)
    srv._fdb.init_engagement("h2-tool", client="t")
    out = add_finding(
        engagement_id="h2-tool",
        title="Reflected XSS bogus token",
        severity="Medium",
        affected_url="https://t/x",
        evidence="x" * 30,
        confidence="version_based",
        poc_token="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        consensus_passed=True,
        reproduced=True,
    )
    assert "Invalid or expired poc_token" in out, out


def test_poc_token_full_match_not_prefix(srv):
    """M6: token verification must require an exact full-token match, not just
    an 8-hex filename-prefix collision."""
    import json
    import shutil

    eid = "m6-regression-eng"
    safe = srv._sanitize_id(eid)
    ev = srv.ENGAGEMENTS_DIR / safe / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    try:
        real = "a" * 64
        (ev / f"poc-{real[:8]}.json").write_text(json.dumps({"poc_token": real}))
        forged = "a" * 8 + "b" * 56  # same prefix, different full token
        assert srv._verify_poc_token(eid, real) is True
        assert srv._verify_poc_token(eid, forged) is False  # was True under prefix-only check
        assert srv._verify_poc_token(eid, "f" * 64) is False
        assert srv._verify_poc_token(eid, "") is False
    finally:
        shutil.rmtree(srv.ENGAGEMENTS_DIR / safe, ignore_errors=True)


def test_findings_db_noise_filter_import(tmp_path):
    """findings_db.add_vuln must be able to import NoiseDetector (was silently dead).

    M1: classification runs on the real HTTP response only, and the downgrade is
    advisory — confidence drops and a note is added, but severity is preserved.
    """
    import findings_db

    db = findings_db.FindingsDB(str(tmp_path / "t.db"))
    db.init_engagement("e1", client="c")
    v = db.add_vuln(
        "e1",
        title="Some informational note",
        severity="Low",
        affected_url="https://x/y",
        evidence="ok",
        response_body="your request was blocked by the WAF",
    )
    # NoiseDetector runs on the response and annotates; severity preserved.
    assert v["severity"] == "Low"
    assert "[noise-filter]" in v["description"]
    db.close()
