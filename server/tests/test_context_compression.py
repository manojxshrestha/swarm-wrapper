"""Tests for context compression — C-4: read findings from SQLite, not stale JSON."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from findings_db import FindingsDB


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary findings DB with some test data."""
    db_path = tmp_path / "test_findings.db"
    db = FindingsDB(db_path)
    db.init_engagement("test-eng-1", client="Test Client")
    db.add_vuln(
        engagement_id="test-eng-1",
        title="SQL Injection in login",
        severity="Critical",
        affected_url="https://example.com/login",
    )
    db.add_vuln(
        engagement_id="test-eng-1",
        title="XSS in search",
        severity="High",
        affected_url="https://example.com/search",
    )
    db.add_vuln(
        engagement_id="test-eng-1",
        title="Info leak in headers",
        severity="Low",
        affected_url="https://example.com/",
    )
    db.close()
    return db_path


class TestLoadFindings:
    """Verify _load_findings reads from SQLite, not stale JSON."""

    def test_loads_from_sqlite(self, temp_db, monkeypatch):
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)
        from context_compression import _load_findings
        findings = _load_findings("test-eng-1")
        assert len(findings) == 3
        titles = {f["title"] for f in findings}
        assert "SQL Injection in login" in titles
        assert "XSS in search" in titles
        assert "Info leak in headers" in titles

    def test_normalizes_column_names(self, temp_db, monkeypatch):
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)
        from context_compression import _load_findings
        findings = _load_findings("test-eng-1")
        for f in findings:
            assert "id" in f, f"Missing 'id' in {f}"
            assert "title" in f, f"Missing 'title' in {f}"
            assert "severity" in f, f"Missing 'severity' in {f}"
            assert "url" in f, f"Missing 'url' in {f}"
            assert "timestamp" in f, f"Missing 'timestamp' in {f}"

    def test_returns_empty_for_unknown_engagement(self, temp_db, monkeypatch):
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)
        from context_compression import _load_findings
        findings = _load_findings("nonexistent-eng")
        assert findings == []

    def test_returns_empty_when_db_unavailable(self, monkeypatch):
        monkeypatch.setattr("findings_db.get_db", lambda: (_ for _ in ()).throw(Exception("DB error")))
        from context_compression import _load_findings
        findings = _load_findings("any-eng")
        assert findings == []

    def test_severity_counts_in_summary(self, temp_db, monkeypatch, tmp_path):
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)
        from context_compression import configure, get_engagement_summary
        configure(tmp_path, lambda p, d: None, lambda e, d: None)
        summary = get_engagement_summary("test-eng-1")
        assert "Total" in summary and "3" in summary.split("Total")[-1][:5]
        assert "findings logged" in summary

    def test_load_findings_returns_sqlite_data(self, temp_db, monkeypatch):
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)
        from context_compression import _load_findings
        findings = _load_findings("test-eng-1")
        assert len(findings) == 3
        assert findings[0]["id"].startswith("FINDING-")
        assert findings[0]["url"] == "https://example.com/login"

    def test_ignores_stale_json_findings_file(self, temp_db, monkeypatch, tmp_path):
        """Prove that findings come from SQLite, not from JSON files."""
        monkeypatch.setattr("findings_db.get_default_db_path", lambda: temp_db)

        # Even if a stale JSON findings file says "No findings", SQLite wins
        stale_dir = tmp_path / "findings"
        stale_dir.mkdir(parents=True)
        stale_file = stale_dir / "test-eng-1.json"
        stale_file.write_text(json.dumps([]))

        from context_compression import _load_findings, configure

        # Configure with tmp_path so it would read from stale file if it still used JSON
        configure(tmp_path, lambda p, d: None, lambda e, d: None)

        findings = _load_findings("test-eng-1")
        assert len(findings) == 3, f"Expected 3 findings from SQLite, got {len(findings)}"
