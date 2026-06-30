"""Tests for the SQLite findings database."""

import os
import tempfile
import threading

import pytest

from findings_db import FindingsDB


@pytest.fixture
def db():
    """Create an isolated FindingsDB in a temp directory."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        fdb = FindingsDB(db_path)
        yield fdb
        fdb.close()


def _make_png(tmp_path) -> str:
    """Create a minimal non-empty .png file and return its path."""
    p = tmp_path / "shot.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
    return str(p)


class TestConfidenceEscalationGate:
    """H2: auto-escalation to 'confirmed' must require a poc_token."""

    def test_no_escalation_without_token(self, db, tmp_path):
        db.init_engagement(engagement_id="h2", client="c")
        db.mark_browser_verified("h2", "https://t/x", payload="p", screenshot_taken=True, screenshot_path=_make_png(tmp_path))
        # Score would be 80 (consensus35 + reproduced25 + browser20) → 'confirmed',
        # but with no poc_token escalation must be blocked.
        v = db.add_vuln(
            "h2",
            title="Reflected XSS in q",
            severity="High",
            affected_url="https://t/x",
            evidence="payload reflected in body",
            confidence="version_based",
            consensus_passed=True,
            reproduced=True,
            poc_token="",
        )
        assert v["confidence"] == "version_based", "Escalated to confirmed without a poc_token!"

    def test_escalation_with_token(self, db, tmp_path):
        db.init_engagement(engagement_id="h2b", client="c")
        db.mark_browser_verified("h2b", "https://t/x", payload="p", screenshot_taken=True, screenshot_path=_make_png(tmp_path))
        v = db.add_vuln(
            "h2b",
            title="Reflected XSS in q",
            severity="High",
            affected_url="https://t/x",
            evidence="payload reflected in body",
            confidence="version_based",
            consensus_passed=True,
            reproduced=True,
            poc_token="a" * 64,
        )
        assert v["confidence"] == "confirmed", "Should escalate to confirmed when a token is present"


class TestBrowserEvidenceGate:
    """H3: browser-evidence gate requires a real on-disk screenshot artifact."""

    def test_boolean_only_is_not_evidence(self, db):
        db.init_engagement(engagement_id="h3", client="c")
        db.mark_browser_verified("h3", "https://t/x", screenshot_taken=True)  # no path
        assert db.has_browser_evidence("h3", "https://t/x") is False

    def test_real_screenshot_is_evidence(self, db, tmp_path):
        db.init_engagement(engagement_id="h3b", client="c")
        db.mark_browser_verified("h3b", "https://t/x", screenshot_taken=True, screenshot_path=_make_png(tmp_path))
        assert db.has_browser_evidence("h3b", "https://t/x") is True

    def test_missing_file_is_not_evidence(self, db, tmp_path):
        db.init_engagement(engagement_id="h3c", client="c")
        db.mark_browser_verified("h3c", "https://t/x", screenshot_taken=True, screenshot_path=str(tmp_path / "gone.png"))
        assert db.has_browser_evidence("h3c", "https://t/x") is False

    def test_nonimage_file_is_not_evidence(self, db, tmp_path):
        db.init_engagement(engagement_id="h3d", client="c")
        txt = tmp_path / "ec.txt"
        txt.write_text("not an image")
        db.mark_browser_verified("h3d", "https://t/x", screenshot_taken=True, screenshot_path=str(txt))
        assert db.has_browser_evidence("h3d", "https://t/x") is False

    def test_url_match_ignores_query_and_trailing_slash(self, db, tmp_path):
        # L6: verified with ?foo=1, checked with ?foo=2 (and trailing slash) → still matches.
        db.init_engagement(engagement_id="h3e", client="c")
        db.mark_browser_verified("h3e", "https://t/x?foo=1", screenshot_taken=True, screenshot_path=_make_png(tmp_path))
        assert db.has_browser_evidence("h3e", "https://t/x/?foo=2") is True
        # Different path must still NOT match.
        assert db.has_browser_evidence("h3e", "https://t/other") is False


class TestNoiseFilterM1:
    """M1: noise filter classifies only the real HTTP response, not agent text."""

    def test_benign_keyword_in_evidence_not_downgraded(self, db):
        db.init_engagement(engagement_id="m1", client="c")
        # Evidence/poc mention 'login'/'blocked' (benign words) but there is NO
        # response_body — the finding must NOT be downgraded or annotated.
        v = db.add_vuln(
            "m1",
            title="Auth bypass via forced browsing",
            severity="High",
            affected_url="https://t/admin",
            evidence="bypassed the login page; access was not blocked by ACL",
            poc_output="GET /admin -> 200; login control absent",
        )
        assert v["severity"] == "High"
        assert "[noise-filter]" not in (v.get("description") or "")

    def test_noise_in_response_body_downgrades_advisorily(self, db):
        db.init_engagement(engagement_id="m1b", client="c")
        v = db.add_vuln(
            "m1b",
            title="Reflected XSS in q parameter",
            severity="High",
            affected_url="https://t/x",
            evidence="payload reflected unescaped in the search results panel of the page",
            confidence="version_based",
            response_body="<html>Access Denied. Your request was blocked. cf-ray: 123</html>",
        )
        # Severity preserved (non-destructive); confidence capped; annotated.
        assert v["severity"] == "High"
        assert v["confidence"] == "speculative"
        assert "[noise-filter]" in v["description"]


class TestConfidenceLogPhase5:
    """Phase 5: every finding records why it got its confidence."""

    def test_confidence_log_written_and_surfaced(self, db, tmp_path):
        db.init_engagement(engagement_id="cl", client="c")
        db.add_vuln(
            "cl",
            title="Reflected XSS in q",
            severity="High",
            affected_url="https://t/x",
            evidence="payload reflected unescaped in the page body here",
            confidence="version_based",
            consensus_passed=True,
            reproduced=True,
        )
        log = db.get_confidence_log("cl")
        assert len(log) == 1
        sig = log[0]["signals"]
        assert sig["consensus_passed"] is True and sig["reproduced"] is True
        assert sig["score"] == 60  # 35 + 25, no token → stays version_based
        assert log[0]["confidence"] == "version_based"
        # Surfaced in the handoff report.
        assert "## Confidence Audit" in db.handoff_markdown("cl")


class TestFindingsDB:
    """Suite for FindingsDB CRUD operations."""

    def test_init_creates_engagement(self, db):
        result = db.init_engagement(
            engagement_id="test-001",
            client="TestClient",
            etype="web",
            scope="*.test.com",
            notes="test engagement",
        )
        assert result["id"] == "test-001"
        assert result["client"] == "TestClient"
        assert result["status"] == "active"

    def test_add_vuln(self, db):
        db.init_engagement(engagement_id="test-002", client="Client")
        vuln = db.add_vuln(
            engagement_id="test-002",
            title="Test XSS",
            severity="High",
            cvss=6.5,
            affected_url="https://test.com/search",
            affected_parameter="q",
            description="Reflected XSS in search parameter",
            evidence="<script>alert(1)</script> reflected in response",
            poc_output="curl -s 'https://test.com/search?q=<script>alert(1)</script>'",
        )
        assert vuln["title"] == "Test XSS"
        assert vuln["severity"] == "High"
        assert vuln["status"] == "open"
        assert vuln["poc_output"] != ""

    def test_list_vulns_empty(self, db):
        db.init_engagement(engagement_id="test-003", client="Client")
        vulns = db.list_vulns(engagement_id="test-003")
        assert vulns == []

    def test_list_vulns_with_data(self, db):
        db.init_engagement(engagement_id="test-004", client="Client")
        db.add_vuln(
            engagement_id="test-004",
            title="Finding A",
            severity="Critical",
            cvss=9.0,
            affected_url="https://test.com/a",
            poc_output="<script>alert(1)</script>",
            confidence="confirmed",
            poc_token="test-poc-123",
        )
        db.add_vuln(
            engagement_id="test-004",
            title="Finding B",
            severity="Low",
            cvss=3.0,
            affected_url="https://test.com/b",
        )
        vulns = db.list_vulns(engagement_id="test-004")
        assert len(vulns) == 2
        # Should be sorted by severity descending
        assert vulns[0]["severity"] == "Critical"

    def test_update_vuln(self, db):
        db.init_engagement(engagement_id="test-005", client="Client")
        vuln = db.add_vuln(
            engagement_id="test-005",
            title="Old Title",
            severity="Medium",
            cvss=5.0,
            affected_url="https://test.com/old",
        )
        updated = db.update_vuln(
            vuln["id"],
            severity="High",
            title="Updated Title",
        )
        assert updated["severity"] == "High"
        assert updated["title"] == "Updated Title"

    def test_add_credential(self, db):
        db.init_engagement(engagement_id="test-006", client="Client")
        cred = db.add_credential(
            engagement_id="test-006",
            username="admin",
            secret="s3cret!",  # nosec B106
            secret_type="password",
            domain="test.com",
            access_level="admin",
            source="bruteforce",
        )
        assert cred["username"] == "admin"
        assert cred["secret_type"] == "password"

    def test_engagement_not_found(self, db):
        result = db.init_engagement("nonexistent")
        # Init with same ID should not fail
        result = db.init_engagement("nonexistent", client="New")
        assert result["id"] == "nonexistent"

    def test_schema_migration_race_concurrent_init(self):
        """C-7: Verify concurrent FindingsDB init doesn't corrupt schema."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "race.db")
            errors = []

            def create_db_only():
                try:
                    FindingsDB(db_path).close()
                except Exception as e:
                    errors.append(str(e))

            threads = [threading.Thread(target=create_db_only) for _ in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert not errors, f"Schema init race errors: {errors}"
            fdb = FindingsDB(db_path)
            cur = fdb._get_conn().execute("SELECT COUNT(*) FROM schema_version")
            assert cur.fetchone()[0] >= 1, "schema_version should have entries"
            fdb.close()

    def test_schema_migration_race_migrates_correctly(self):
        """C-7: Schema version and columns should be correct after concurrent init."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "migrate.db")

            def create_db():
                FindingsDB(db_path).close()

            threads = [threading.Thread(target=create_db) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            fdb = FindingsDB(db_path)
            cur = fdb._get_conn().execute("SELECT MAX(version) FROM schema_version")
            row = cur.fetchone()
            assert row[0] >= 3, f"Expected schema version >= 3, got {row[0]}"
            cur = fdb._get_conn().execute("PRAGMA table_info(vulns)")
            columns = {r[1] for r in cur.fetchall()}
            for col in ("confidence", "poc_token", "consensus_passed", "reproduced", "baseline_anomaly"):
                assert col in columns, f"Column '{col}' missing after migration"
            fdb.close()

    def test_init_engagement_toctou_race(self, db):
        """C-6: Verify concurrent init_engagement calls don't cause errors."""
        errors = []

        def try_init():
            try:
                db.init_engagement("race-eng", client="Race")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=try_init) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"TOCTOU race errors: {errors}"
        eng = db.get_engagement("race-eng")
        assert eng["id"] == "race-eng"

    def test_infer_vuln_class_no_substring_false_positive(self, db):
        """C-8: Word-boundary matching prevents substring false positives."""
        # 'sqli' should NOT match 'nosqli'
        assert "sqli" not in db._infer_vuln_class("NoSQL Injection found", "WSTG-INPV-05")
        assert "sqli" not in db._infer_vuln_class("NoSQL injection in login")
        # 'race' should NOT match 'trace'
        assert "race_condition" not in db._infer_vuln_class("Trace route shows open ports")
        # 'cors' should NOT match 'enforcement'
        assert "cors_misconfiguration" not in db._infer_vuln_class("Enforcement of access controls")

    def test_close_closes_all_thread_connections(self):
        """C-9: close() must close connections from ALL threads, not just caller's."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "leak.db")
            fdb = FindingsDB(db_path)

            results = {}

            def get_conn_in_thread(tid):
                conn = fdb._get_conn()
                conn.execute("SELECT 1")
                results[tid] = id(conn)

            threads = [threading.Thread(target=get_conn_in_thread, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(fdb._all_conns) >= 5, f"Expected >= 5 conns, got {len(fdb._all_conns)}"
            fdb.close()
            assert len(fdb._all_conns) == 0, f"Expected 0 conns after close, got {len(fdb._all_conns)}"

    def test_infer_vuln_class_still_matches_correctly(self, db):
        """C-8: Word-boundary matching still catches all correct patterns."""
        classes = db._infer_vuln_class("Reflected XSS found in search", "WSTG-INPV-01")
        assert "xss_reflected" in classes, f"Expected xss_reflected, got {classes}"

        classes = db._infer_vuln_class("SQL injection in login parameter", "WSTG-INPV-05")
        assert "sqli" in classes, f"Expected sqli, got {classes}"

        classes = db._infer_vuln_class("NoSQL Injection in MongoDB query", "WSTG-INPV-05")
        assert "nosqli" in classes, f"Expected nosqli, got {classes}"
        # 'sqli' should not leak into nosqli findings
        assert "sqli" not in classes, f"sqli should not match 'nosqli': got {classes}"

        classes = db._infer_vuln_class("Server-side template injection in Jinja2", "WSTG-INPV-18")
        assert "ssti" in classes, f"Expected ssti, got {classes}"

        classes = db._infer_vuln_class("Cross-Site Scripting in user input")
        assert "xss_reflected" in classes, f"Expected xss_reflected, got {classes}"

    def test_vuln_status_filter(self, db):
        db.init_engagement(engagement_id="test-007", client="Client")
        db.add_vuln(
            engagement_id="test-007",
            title="Open Finding",
            severity="High",
            cvss=7.0,
            affected_url="https://test.com/o",
        )
        open_vulns = db.list_vulns(engagement_id="test-007", status="open")
        assert len(open_vulns) == 1
        db.update_vuln(open_vulns[0]["id"], status="fixed")
        still_open = db.list_vulns(engagement_id="test-007", status="open")
        assert len(still_open) == 0
