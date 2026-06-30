"""SQLite findings database with 7-table schema for cross-session persistence.

Schema:
  engagements  -> hosts -> services
               -> vulns
               -> credentials
               -> chains
               -> session_log

Port of pentest-ai-agents' findings.sh approach as a Python module.
"""

import json
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crypto_utils import decrypt_secret, encrypt_secret

logger = logging.getLogger("swarm-findings-db")

# Cross-process file locking — POSIX (fcntl) or Windows (msvcrt), with a
# graceful no-op fallback when neither is available. The in-process
# threading.RLock still serializes threads in that degenerate case.
try:
    import fcntl as _fcntl

    def _lock_fd(fd: int) -> None:
        _fcntl.flock(fd, _fcntl.LOCK_EX)

    def _unlock_fd(fd: int) -> None:
        _fcntl.flock(fd, _fcntl.LOCK_UN)

except ImportError:  # pragma: no cover - platform-specific
    try:
        import msvcrt as _msvcrt

        def _lock_fd(fd: int) -> None:
            _msvcrt.locking(fd, _msvcrt.LK_LOCK, 1)

        def _unlock_fd(fd: int) -> None:
            try:
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass

    except ImportError:  # pragma: no cover - no file locking available

        def _lock_fd(fd: int) -> None:
            logger.debug("No cross-process file lock available on this platform")

        def _unlock_fd(fd: int) -> None:
            pass


# ── Schema ───────────────────────────────────────────────────────────────────
SCHEMA_SQL: str = (Path(__file__).parent / "schema.sql").read_text()


# ── Database Manager ─────────────────────────────────────────────────────────
class FindingsDB:
    """Thread-safe SQLite findings database."""

    def __init__(self, db_path: str | Path, extra_keywords: dict[str, list[str]] | None = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.RLock()
        self._closed = False
        self._all_conns: set[sqlite3.Connection] = set()
        self._schema_lock_path = self.db_path.with_suffix(".schema.lock")
        self._init_schema_with_lock()
        # M05: Merge extra keywords into vuln class keyword map
        self._vuln_class_keywords = dict(self.VULN_CLASS_KEYWORDS)
        if extra_keywords:
            for cls_name, keywords in extra_keywords.items():
                if cls_name in self._vuln_class_keywords:
                    existing = set(self._vuln_class_keywords[cls_name])
                    self._vuln_class_keywords[cls_name].extend(kw for kw in keywords if kw not in existing)
                else:
                    self._vuln_class_keywords[cls_name] = list(keywords)

    def close(self) -> None:
        self._closed = True
        with self._lock:
            for conn in list(self._all_conns):
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
        if hasattr(self._local, "conn"):
            self._local.conn = None

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection, tracking it for clean shutdown."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
            with self._lock:
                self._all_conns.add(conn)
        return self._local.conn

    def _init_schema_with_lock(self) -> None:
        """Initialize schema with cross-process file lock to prevent migration races."""
        lock_path = self._schema_lock_path
        lock_fd = None
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
            _lock_fd(lock_fd)
            with self._lock:
                self._init_schema()
        finally:
            if lock_fd is not None:
                try:
                    _unlock_fd(lock_fd)
                    os.close(lock_fd)
                except OSError:
                    pass

    def _init_schema(self) -> None:
        """Create schema if not exists. Runs migrations as needed."""
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)
        # Check current schema version
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current_version = row[0] if row and row[0] is not None else 0

        if current_version == 0:
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (1, _now_iso()),
            )
            current_version = 1
            conn.commit()

        # FIX #9: Migration 1→2 — Add ON DELETE CASCADE to credentials FK
        if current_version == 1:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                    host_id INTEGER REFERENCES hosts(id),
                    username TEXT NOT NULL DEFAULT '',
                    secret TEXT NOT NULL DEFAULT '',
                    secret_type TEXT NOT NULL DEFAULT 'password',
                    domain TEXT NOT NULL DEFAULT '',
                    access_level TEXT NOT NULL DEFAULT 'unknown',
                    valid INTEGER NOT NULL DEFAULT 1,
                    source TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT ''
                )
            """)
            # L5: name columns explicitly instead of SELECT * (which silently
            # breaks if the legacy column order ever differs).
            conn.execute("""INSERT INTO credentials_new
                   (id, engagement_id, host_id, username, secret, secret_type,
                    domain, access_level, valid, source, notes)
                   SELECT id, engagement_id, host_id, username, secret, secret_type,
                          domain, access_level, valid, source, notes
                   FROM credentials""")
            conn.execute("DROP TABLE credentials")
            conn.execute("ALTER TABLE credentials_new RENAME TO credentials")
            conn.execute("PRAGMA foreign_keys = ON")
            # Rebuild indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id)")
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (2, _now_iso()),
            )
            conn.commit()
            current_version = 2

        # FIX-issue: Migration 2→3 — Add confidence column to vulns
        if current_version == 2:
            try:
                conn.execute("ALTER TABLE vulns ADD COLUMN confidence TEXT NOT NULL DEFAULT 'version_based'")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            try:
                conn.execute("ALTER TABLE vulns ADD COLUMN poc_token TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            try:
                conn.execute("ALTER TABLE vulns ADD COLUMN consensus_passed INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            try:
                conn.execute("ALTER TABLE vulns ADD COLUMN reproduced INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            try:
                conn.execute("ALTER TABLE vulns ADD COLUMN baseline_anomaly INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (3, _now_iso()),
            )
            conn.commit()
            current_version = 3

        # H3: Migration 3→4 — record the screenshot artifact path so the
        # browser-verification gate can require a real on-disk screenshot
        # rather than trusting a self-reported boolean.
        if current_version == 3:
            try:
                conn.execute("ALTER TABLE browser_verifications ADD COLUMN screenshot_path TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (4, _now_iso()),
            )
            conn.commit()
            current_version = 4

        # Phase 5: Migration 4→5 — confidence_log records WHY each finding got
        # its confidence (which signals/oracles fired), for human audit.
        if current_version == 4:
            conn.execute("""CREATE TABLE IF NOT EXISTS confidence_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    finding_ref TEXT NOT NULL DEFAULT '',
                    confidence TEXT NOT NULL DEFAULT '',
                    signals_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_conflog_eng ON confidence_log(engagement_id)")
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (5, _now_iso()),
            )
            conn.commit()
            current_version = 5

    # ── Helpers ───────────────────────────────────────────────────────────

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._get_conn()
        return conn.execute(sql, params)

    def _fetchone(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._execute(sql, params).fetchone()

    def _fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._execute(sql, params).fetchall()

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict:
        if row is None:
            return {}
        return dict(row)

    def _rows_to_list(self, rows: list[sqlite3.Row]) -> list[dict]:
        return [dict(r) for r in rows]

    # ── Engagements ──────────────────────────────────────────────────────

    def init_engagement(
        self,
        engagement_id: str,
        client: str = "",
        etype: str = "web",
        scope: str = "",
        notes: str = "",
    ) -> dict:
        """Create a new engagement. Returns the engagement dict."""
        with self._lock:
            existing = self._fetchone("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
            if existing:
                return self._row_to_dict(existing)
            self._execute(
                """INSERT INTO engagements (id, client, type, scope, status, start_date, notes)
                   VALUES (?, ?, ?, ?, 'active', ?, ?)""",
                (engagement_id, client, etype, scope, _now_iso(), notes),
            )
            self._get_conn().commit()
        return self.get_engagement(engagement_id)

    def get_engagement(self, engagement_id: str) -> dict:
        row = self._fetchone("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        return self._row_to_dict(row)

    def list_engagements(self, status: str = "") -> list[dict]:
        if status:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM engagements WHERE status = ? ORDER BY start_date DESC",
                    (status,),
                )
            )
        return self._rows_to_list(self._fetchall("SELECT * FROM engagements ORDER BY start_date DESC"))

    def update_engagement(self, engagement_id: str, **kwargs) -> dict:
        allowed = {"client", "type", "scope", "status", "end_date", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v}
        if not updates:
            return self.get_engagement(engagement_id)
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [engagement_id]
        with self._lock:
            self._execute(f"UPDATE engagements SET {sets} WHERE id = ?", tuple(vals))
            self._get_conn().commit()
        return self.get_engagement(engagement_id)

    def close_engagement(self, engagement_id: str) -> dict:
        return self.update_engagement(engagement_id, status="closed", end_date=_now_iso())

    # ── Hosts ────────────────────────────────────────────────────────────

    def add_host(
        self,
        engagement_id: str,
        ip: str = "",
        hostname: str = "",
        os: str = "",
        role: str = "",
        discovered_by: str = "",
        notes: str = "",
    ) -> dict:
        existing = self._fetchone(
            "SELECT * FROM hosts WHERE engagement_id = ? AND ip = ? AND hostname = ?",
            (engagement_id, ip, hostname),
        )
        if existing:
            return self._row_to_dict(existing)
        with self._lock:
            self._execute(
                """INSERT INTO hosts (engagement_id, ip, hostname, os, role, status, discovered_by, notes)
                   VALUES (?, ?, ?, ?, ?, 'discovered', ?, ?)""",
                (engagement_id, ip, hostname, os, role, discovered_by, notes),
            )
            self._get_conn().commit()
        row = self._fetchone(
            "SELECT * FROM hosts WHERE engagement_id = ? AND ip = ? AND hostname = ?",
            (engagement_id, ip, hostname),
        )
        return self._row_to_dict(row)

    def list_hosts(self, engagement_id: str) -> list[dict]:
        return self._rows_to_list(
            self._fetchall(
                "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY ip",
                (engagement_id,),
            )
        )

    # ── Services ─────────────────────────────────────────────────────────

    def add_service(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        service: str = "",
        version: str = "",
        banner: str = "",
        notes: str = "",
    ) -> dict:
        with self._lock:
            self._execute(
                """INSERT INTO services (host_id, port, protocol, service, version, banner, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (host_id, port, protocol, service, version, banner, notes),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM services WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def list_services(self, host_id: int = 0, engagement_id: str = "") -> list[dict]:
        if host_id:
            return self._rows_to_list(self._fetchall("SELECT * FROM services WHERE host_id = ?", (host_id,)))
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    """SELECT svc.* FROM services svc
                       JOIN hosts h ON svc.host_id = h.id
                       WHERE h.engagement_id = ?""",
                    (engagement_id,),
                )
            )
        return []

    # ── Vulnerabilities ──────────────────────────────────────────────────

    def add_vuln(
        self,
        engagement_id: str,
        title: str,
        severity: str = "medium",
        cvss: float = 0.0,
        cve: str = "",
        mitre_id: str = "",
        test_id: str = "",
        tool_used: str = "",
        affected_url: str = "",
        affected_parameter: str = "",
        description: str = "",
        evidence: str = "",
        poc_output: str = "",
        remediation: str = "",
        domain: str = "",
        host_id: int = 0,
        finding_ref: str = "",
        confidence: str = "version_based",
        poc_token: str = "",
        consensus_passed: bool = False,
        reproduced: bool = False,
        baseline_anomaly: bool = False,
        independent_engine: bool = False,
        response_body: str = "",
    ) -> dict:
        # ── Verification Gate ────────────────────────────────────────────
        if confidence == "confirmed" and not poc_token:
            raise ValueError("confidence='confirmed' requires a valid poc_token. " "Run validate_poc() first, then pass poc_token=...")

        # Severity gating — require stronger evidence for higher ratings
        cvss_confidence_caps = {"confirmed": 10.0, "version_based": 6.0, "speculative": 3.9}
        cvss = min(cvss, cvss_confidence_caps.get(confidence, 6.0))
        if severity.lower() == "critical":
            if not poc_output or not poc_output.strip() or cvss < 7.0:
                severity = "High"
        elif severity.lower() == "high":
            if len(evidence.strip()) < 20 and (not poc_output or not poc_output.strip()):
                severity = "Medium"

        # ── Auto Confidence Scoring (Phase D → F) — runs FIRST ────────────
        browser_confirmed = False
        chain_count = 0
        computed = confidence
        noise_classes: list = []
        if confidence in ("version_based", "speculative"):
            browser_confirmed = self.has_browser_evidence(engagement_id, affected_url)
            # L4: detect_chains() is O(patterns·vulns²); skip it for the common
            # single-finding case (chains need >= 2 vulns, so the result is the
            # same empty list) via a cheap COUNT pre-check.
            _vc = self._fetchone("SELECT COUNT(*) AS c FROM vulns WHERE engagement_id = ?", (engagement_id,))
            _existing_vulns = _vc["c"] if _vc else 0
            chain_count = len(self.detect_chains(engagement_id)) if _existing_vulns >= 2 else 0
            computed = self._compute_confidence(
                poc_token=poc_token,
                poc_output=poc_output,
                evidence=evidence,
                cvss=cvss,
                chain_count=chain_count,
                consensus_passed=consensus_passed,
                reproduced=reproduced,
                browser_confirmed=browser_confirmed,
                baseline_anomaly=baseline_anomaly,
                independent_engine=independent_engine,
            )
            # H2: never auto-escalate to "confirmed" without a PoC token. The
            # caller-supplied consensus_passed/reproduced booleans alone must
            # not be able to mint a confirmed finding that bypasses the
            # poc_token gate enforced for explicit confidence='confirmed'.
            if computed == "confirmed" and poc_token:
                confidence = computed

        # ── Verification Gates (Phase J) — checks per VERIFICATION_REQUIREMENTS ──
        vuln_classes = self._infer_vuln_class(title, test_id, description or evidence)
        for c in vuln_classes:
            req = self.VERIFICATION_REQUIREMENTS.get(c, "")
            if req == "browser" and confidence == "confirmed":
                if not self.has_browser_evidence(engagement_id, affected_url):
                    confidence = "version_based"
            elif req == "diff" and confidence == "confirmed":
                if not baseline_anomaly:
                    confidence = "version_based"
            # "consensus" and "custom" gates are handled by validate_poc() at runtime

        # ── Noise Filter (Phase F) — classify ONLY the real HTTP response (M1) ──
        # Never classify agent-authored evidence/poc_output: benign words like
        # "login"/"blocked"/"error" there caused valid findings to be nuked to
        # Informational. The downgrade is now advisory — confidence is capped
        # and the reason annotated, but the agent's severity is preserved.
        if response_body:
            try:
                from response_diff import NoiseDetector

                noise_classes = NoiseDetector.classify(response_body, {}) or []
                if noise_classes:
                    if confidence == "confirmed":
                        confidence = "version_based"
                    elif confidence == "version_based":
                        confidence = "speculative"
                    note = f"[noise-filter] captured response resembles a security control / error: {', '.join(noise_classes)}"
                    description = (description + "\n\n" + note).strip() if description else note
            except ImportError:
                pass

        # Title and URL required
        if not title or len(title.strip()) < 5:
            raise ValueError("Finding title must be at least 5 characters")
        if not affected_url:
            raise ValueError("affected_url is required")

        # Normalize severity casing
        severity = severity.capitalize()

        valid_confidence = {"confirmed", "version_based", "speculative"}
        if confidence not in valid_confidence:
            confidence = "version_based"
        now = _now_iso()
        with self._lock:
            # Auto-generate finding_ref via atomic MAX query (no race)
            if not finding_ref:
                max_ref = self._fetchone(
                    "SELECT COALESCE(MAX(CAST(SUBSTR(finding_ref, 9) AS INTEGER)), 0) + 1 as next " "FROM vulns WHERE engagement_id = ? AND finding_ref LIKE 'FINDING-%'",
                    (engagement_id,),
                )
                next_num = max_ref["next"] if max_ref else 1
                finding_ref = f"FINDING-{next_num:03d}"
            self._execute(
                """INSERT INTO vulns
                   (engagement_id, host_id, finding_ref, title, severity, cvss, cve, mitre_id,
                    test_id, tool_used, status, affected_url, affected_parameter,
                    description, evidence, poc_output, remediation, domain, confidence, poc_token,
                    consensus_passed, reproduced, baseline_anomaly, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    engagement_id,
                    host_id or None,
                    finding_ref,
                    title,
                    severity,
                    cvss,
                    cve,
                    mitre_id,
                    test_id,
                    tool_used,
                    affected_url,
                    affected_parameter,
                    description,
                    evidence,
                    poc_output,
                    remediation,
                    domain,
                    confidence,
                    poc_token,
                    1 if consensus_passed else 0,
                    1 if reproduced else 0,
                    1 if baseline_anomaly else 0,
                    now,
                    now,
                ),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM vulns WHERE id = last_insert_rowid()")

        # Phase 5: record WHY this finding got its confidence, for human audit.
        self._log_confidence(
            engagement_id,
            finding_ref,
            confidence,
            {
                "poc_token_present": bool(poc_token),
                "consensus_passed": bool(consensus_passed),
                "reproduced": bool(reproduced),
                "browser_confirmed": bool(browser_confirmed),
                "baseline_anomaly": bool(baseline_anomaly),
                "independent_engine": bool(independent_engine),
                "chain_count": chain_count,
                "score": self._compute_score(poc_token, consensus_passed, reproduced, browser_confirmed, baseline_anomaly, independent_engine, chain_count),
                "computed_confidence": computed,
                "final_confidence": confidence,
                "vuln_classes": vuln_classes,
                "noise_classes": noise_classes,
            },
        )
        return self._row_to_dict(row)

    @staticmethod
    def _compute_score(poc_token, consensus_passed, reproduced, browser_confirmed, baseline_anomaly, independent_engine, chain_count) -> int:
        """The numeric score behind _compute_confidence — surfaced for the log."""
        w = FindingsDB.SCORING_WEIGHTS
        s = 0
        if poc_token:
            s += 5
        if consensus_passed:
            s += w["payload_consensus"]
        if reproduced:
            s += w["reproduced"]
        if browser_confirmed:
            s += w["browser_confirmed"]
        if baseline_anomaly:
            s += w["baseline_anomaly"]
        if independent_engine:
            s += w["independent_engine"]
        if chain_count > 0:
            s += 5
        return s

    def _log_confidence(self, engagement_id: str, finding_ref: str, confidence: str, signals: dict) -> None:
        with self._lock:
            self._execute(
                "INSERT INTO confidence_log (engagement_id, finding_ref, confidence, signals_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (engagement_id, finding_ref, confidence, json.dumps(signals), _now_iso()),
            )
            self._get_conn().commit()

    def get_confidence_log(self, engagement_id: str, finding_ref: str = "") -> list[dict]:
        """Audit trail of confidence decisions for an engagement (Phase 5)."""
        if finding_ref:
            rows = self._fetchall(
                "SELECT * FROM confidence_log WHERE engagement_id = ? AND finding_ref = ? ORDER BY created_at",
                (engagement_id, finding_ref),
            )
        else:
            rows = self._fetchall("SELECT * FROM confidence_log WHERE engagement_id = ? ORDER BY created_at", (engagement_id,))
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["signals"] = json.loads(d.get("signals_json", "{}"))
            except (json.JSONDecodeError, TypeError):
                d["signals"] = {}
            out.append(d)
        return out

    def get_vuln_by_ref(self, engagement_id: str, finding_ref: str) -> dict | None:
        """Public API: lookup a single vuln by its finding_ref string."""
        row = self._fetchone(
            "SELECT * FROM vulns WHERE engagement_id = ? AND finding_ref = ?",
            (engagement_id, finding_ref),
        )
        return self._row_to_dict(row) if row else None

    def list_vulns(
        self,
        engagement_id: str = "",
        severity: str = "",
        status: str = "",
        tool_used: str = "",
        confidence: str = "",
    ) -> list[dict]:
        parts = ["SELECT * FROM vulns WHERE 1=1"]
        params = []
        if engagement_id:
            parts.append("AND engagement_id = ?")
            params.append(engagement_id)
        if severity:
            parts.append("AND severity = ?")
            params.append(severity)
        if status:
            parts.append("AND status = ?")
            params.append(status)
        if tool_used:
            parts.append("AND tool_used = ?")
            params.append(tool_used)
        if confidence:
            parts.append("AND confidence = ?")
            params.append(confidence)
        parts.append("ORDER BY CASE severity " "WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 " "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END")
        return self._rows_to_list(self._fetchall(" ".join(parts), tuple(params)))

    def update_vuln(self, vuln_id: int, **kwargs) -> dict:
        allowed = {
            "severity",
            "cvss",
            "cve",
            "mitre_id",
            "test_id",
            "tool_used",
            "status",
            "poc_output",
            "title",
            "description",
            "evidence",
            "remediation",
            "confidence",
            "poc_token",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed and v}
        if not updates:
            row = self._fetchone("SELECT * FROM vulns WHERE id = ?", (vuln_id,))
            return self._row_to_dict(row)
        updates["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [vuln_id]
        with self._lock:
            self._execute(f"UPDATE vulns SET {sets} WHERE id = ?", tuple(vals))
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM vulns WHERE id = ?", (vuln_id,))
        return self._row_to_dict(row)

    # ── Credentials ──────────────────────────────────────────────────────

    def add_credential(
        self,
        engagement_id: str,
        username: str,
        secret: str,
        secret_type: str = "password",
        domain: str = "",
        access_level: str = "unknown",
        source: str = "",
        notes: str = "",
        host_id: int = 0,
    ) -> dict:
        encrypted = encrypt_secret(secret)
        with self._lock:
            self._execute(
                """INSERT INTO credentials
                   (engagement_id, host_id, username, secret, secret_type, domain,
                    access_level, valid, source, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (
                    engagement_id,
                    host_id or None,
                    username,
                    encrypted,
                    secret_type,
                    domain,
                    access_level,
                    source,
                    notes,
                ),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM credentials WHERE id = last_insert_rowid()")
        result = self._row_to_dict(row)
        if "secret" in result:
            result["secret"] = decrypt_secret(result["secret"])
        return result

    # FIX #4: Audit log — every credential list is recorded
    def list_credentials(self, engagement_id: str = "") -> list[dict]:
        target_id = engagement_id or "__all_engagements__"
        rows = []
        if engagement_id:
            rows = self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM credentials WHERE engagement_id = ?",
                    (engagement_id,),
                )
            )
        else:
            rows = self._rows_to_list(self._fetchall("SELECT * FROM credentials"))
        for r in rows:
            if "secret" in r:
                r["secret"] = decrypt_secret(r["secret"])
        with self._lock:
            self._execute(
                "INSERT INTO credential_access_log (engagement_id, action, timestamp) VALUES (?, 'list', ?)",
                (target_id, _now_iso()),
            )
            self._get_conn().commit()
        return rows

    # END FIX #4

    # ── Attack Chains ────────────────────────────────────────────────────

    def add_chain(
        self,
        engagement_id: str,
        name: str,
        score: float = 0.0,
        steps: list | str | None = None,
        mitre_ids: str = "",
        notes: str = "",
    ) -> dict:
        now = _now_iso()
        steps_json = json.dumps(steps or [])
        with self._lock:
            self._execute(
                """INSERT INTO chains
                   (engagement_id, name, score, status, steps, mitre_ids, notes, created_at, updated_at)
                   VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?)""",
                (engagement_id, name, score, steps_json, mitre_ids, notes, now, now),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM chains WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def list_chains(self, engagement_id: str = "") -> list[dict]:
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM chains WHERE engagement_id = ?",
                    (engagement_id,),
                )
            )
        return self._rows_to_list(self._fetchall("SELECT * FROM chains"))

    def update_chain(self, chain_id: int, **kwargs) -> dict:
        allowed = {"name", "score", "status", "steps", "mitre_ids", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if "steps" in updates and isinstance(updates["steps"], list):
            updates["steps"] = json.dumps(updates["steps"])
        if not updates:
            logger.info("update_chain(%s): no valid fields to update, returning current state", chain_id)
            row = self._fetchone("SELECT * FROM chains WHERE id = ?", (chain_id,))
            return self._row_to_dict(row)
        updates["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [chain_id]
        with self._lock:
            self._execute(f"UPDATE chains SET {sets} WHERE id = ?", tuple(vals))
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM chains WHERE id = ?", (chain_id,))
        return self._row_to_dict(row)

    # ── Session Log ──────────────────────────────────────────────────────

    def log_action(
        self,
        engagement_id: str,
        agent: str = "",
        action: str = "",
        summary: str = "",
        detail: str = "",
    ) -> dict:
        with self._lock:
            self._execute(
                """INSERT INTO session_log (engagement_id, agent, action, summary, detail, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (engagement_id, agent, action, summary, detail, _now_iso()),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM session_log WHERE id = last_insert_rowid()")
        return self._row_to_dict(row)

    def get_session_log(self, engagement_id: str = "", limit: int = 50) -> list[dict]:
        if engagement_id:
            return self._rows_to_list(
                self._fetchall(
                    "SELECT * FROM session_log WHERE engagement_id = ? ORDER BY created_at DESC LIMIT ?",
                    (engagement_id, limit),
                )
            )
        return self._rows_to_list(
            self._fetchall(
                "SELECT * FROM session_log ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        )

    # ── Chain Detection (auto-chaining from vulns) ──────────────────────

    VULN_CLASS_KEYWORDS: dict[str, list[str]] = {
        "xss_reflected": ["xss", "cross-site", "reflected xss", "WSTG-INPV-01"],
        "xss_stored": ["stored xss", "persistent xss", "WSTG-INPV-02"],
        "xss_dom": ["dom xss", "dom-based", "WSTG-CLNT-01"],
        "sqli": ["sql injection", "sqli", "WSTG-INPV-05"],
        "ssrf": ["ssrf", "server-side request", "WSTG-INPV-19"],
        "ssti": ["ssti", "template injection", "WSTG-INPV-18"],
        "cmdi": ["command injection", "cmdi", "WSTG-INPV-12"],
        "idor": ["idor", "insecure direct", "WSTG-ATHZ-04"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "WSTG-ATHZ-03"],
        "open_redirect": ["open redirect", "url redirect", "WSTG-CLNT-04"],
        "cors_misconfiguration": ["cors", "cross-origin", "WSTG-CLNT-07"],
        "missing_csp": [
            "missing csp",
            "weak csp",
            "content-security-policy",
            "WSTG-CONF-12",
        ],
        "weak_csp": ["weak csp", "content-security-policy"],
        "no_lockout": ["no lockout", "rate limiting", "brute force", "WSTG-ATHN-09"],
        "no_mfa": ["no mfa", "missing mfa", "WSTG-ATHN-11"],
        "weak_password_policy": ["weak password", "password policy", "WSTG-ATHN-07"],
        "auth_bypass": ["auth bypass", "authentication bypass", "WSTG-ATHN-01"],
        "brute_force": ["brute force", "credential stuffing", "WSTG-ATHN-07"],
        "nosqli": ["nosql injection", "nosqli", "mongo injection", "WSTG-INPV-05"],
        "xxe": ["xxe", "xml external entity", "xml entity", "WSTG-INPV-07"],
        "ldap_injection": ["ldap injection", "ldapi", "WSTG-INPV-11"],
        "graphql_abuse": ["graphql", "graphql abuse", "graphql introspection"],
        "http_smuggling": ["http smuggling", "request smuggling", "WSTG-INPV-11"],
        "host_header_injection": ["host header", "host header injection", "WSTG-INPV-17"],
        "race_condition": ["race condition", "race", "toctou", "WSTG-BUSL-09"],
        "mass_assignment": ["mass assignment", "parameter binding", "WSTG-BUSL-03"],
    }

    CHAIN_PATTERNS_SQLITE = [
        {
            "name": "xss_to_session_theft",
            "description": "XSS + weak cookie attributes = session hijacking",
            "source_classes": ["xss_reflected", "xss_stored", "xss_dom"],
            "severity_upgrade": "XSS upgrades one level (High → Critical when combined with session theft)",
        },
        {
            "name": "xss_no_csp",
            "description": "XSS + missing/weak CSP = no browser mitigation",
            "source_classes": ["xss_reflected", "xss_stored", "xss_dom"],
            "target_classes": ["missing_csp", "weak_csp"],
            "severity_upgrade": "Add note about increased exploitability",
        },
        {
            "name": "ssrf_to_cloud_metadata",
            "description": "SSRF + cloud metadata endpoint = credential theft",
            "source_classes": ["ssrf"],
            "severity_upgrade": "SSRF upgrades to Critical",
        },
        {
            "name": "idor_to_admin",
            "description": "IDOR + privilege escalation = admin access",
            "source_classes": ["idor"],
            "target_classes": ["auth_bypass"],
            "severity_upgrade": "IDOR upgrades to Critical",
        },
        {
            "name": "auth_bypass_chain",
            "description": "No lockout + no MFA / weak password = credential attack chain",
            "source_classes": ["no_lockout", "brute_force"],
            "target_classes": ["no_mfa", "weak_password_policy"],
            "severity_upgrade": "Both findings upgrade one level",
        },
        {
            "name": "open_redirect_to_xss",
            "description": "Open redirect + XSS = phishing without CSP bypass",
            "source_classes": ["open_redirect"],
            "target_classes": ["xss_reflected", "xss_stored", "xss_dom"],
            "severity_upgrade": "Open redirect upgrades from Medium to High",
        },
        {
            "name": "cors_to_data_theft",
            "description": "CORS misconfiguration + sensitive endpoint = data theft",
            "source_classes": ["cors_misconfiguration"],
            "severity_upgrade": "CORS upgrades from Medium to High",
        },
    ]

    def _infer_vuln_class(self, title: str, test_id: str = "", description: str = "") -> list[str]:
        """Infer vulnerability class(es) from title, test_id, and description.
        Uses word-boundary matching to avoid false positives (e.g., 'sqli' no longer
        matches 'nosqli', 'race' no longer matches 'trace')."""
        text = f"{title} {test_id} {description}".lower()
        classes = []
        for vuln_class, keywords in self._vuln_class_keywords.items():
            if any(re.search(rf"\b{re.escape(kw)}\b", text) for kw in keywords):
                classes.append(vuln_class)
        return sorted(set(classes))

    # ── Baseline CRUD (Phase C) ──────────────────────────────────────────

    def save_baseline(self, baseline: dict) -> str:
        """Save a baseline profile to the database.
        Returns the baseline ID."""
        import uuid as _uuid
        from datetime import timedelta

        if not baseline.get("id"):
            baseline["id"] = _uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        profile_json = json.dumps(baseline.get("profile", {}))
        with self._lock:
            self._execute(
                """INSERT OR REPLACE INTO baselines
                   (id, engagement_id, url, method, request_body, label,
                    profile_json, created_at, expires_at, sample_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    baseline["id"],
                    baseline.get("engagement_id", ""),
                    baseline.get("url", ""),
                    baseline.get("method", "GET"),
                    baseline.get("request_body", ""),
                    baseline.get("label", ""),
                    profile_json,
                    now,
                    expires,
                    baseline.get("sample_count", 0),
                ),
            )
            self._get_conn().commit()
        return baseline["id"]

    def get_baseline(self, baseline_id: str) -> dict | None:
        """Load a baseline profile by ID."""
        row = self._fetchone("SELECT * FROM baselines WHERE id = ?", (baseline_id,))
        if not row:
            return None
        d = dict(row)
        try:
            d["profile"] = json.loads(d.get("profile_json", "{}"))
        except (json.JSONDecodeError, TypeError):
            d["profile"] = {}
        return d

    def list_baselines(self, engagement_id: str, url: str = "", include_expired: bool = False) -> list[dict]:
        """List baselines for an engagement, optionally filtered by URL.
        Filters out expired baselines unless include_expired=True."""
        expiry_filter = "" if include_expired else " AND expires_at > datetime('now')"
        if url:
            rows = self._fetchall(
                f"SELECT * FROM baselines WHERE engagement_id = ? AND url = ?{expiry_filter} ORDER BY created_at DESC",
                (engagement_id, url),
            )
        else:
            rows = self._fetchall(
                f"SELECT * FROM baselines WHERE engagement_id = ?{expiry_filter} ORDER BY url, created_at DESC",
                (engagement_id,),
            )
        return [dict(r) for r in rows]

    # ── Browser Verification (Phase E) ───────────────────────────────────

    # Image extensions accepted as browser-verification artifacts.
    _SCREENSHOT_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif")

    def mark_browser_verified(
        self,
        engagement_id: str,
        url: str,
        payload: str = "",
        screenshot_taken: bool = False,
        screenshot_path: str = "",
    ) -> None:
        """Record that browser-based validation was performed for a URL.

        `screenshot_path` should point to the captured evidence image. The
        confidence gate (`has_browser_evidence`) only counts verifications
        backed by a real on-disk screenshot — see H3.
        """
        now = _now_iso()
        with self._lock:
            self._execute(
                """INSERT INTO browser_verifications
                   (engagement_id, url, payload, screenshot_taken, screenshot_path, verified_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (engagement_id, url, payload, 1 if screenshot_taken else 0, screenshot_path or "", now),
            )
            self._get_conn().commit()

    @classmethod
    def _is_valid_screenshot(cls, path: str) -> bool:
        """A browser-evidence artifact must be a non-empty image file on disk."""
        if not path:
            return False
        try:
            p = Path(path)
            return p.is_file() and p.stat().st_size > 0 and p.suffix.lower() in cls._SCREENSHOT_EXTS
        except OSError:
            return False

    @staticmethod
    def _norm_url(url: str) -> str:
        """Normalize for matching: drop query/fragment, lowercase host, strip
        trailing slash (L6 — query-string variance caused false gate misses)."""
        from urllib.parse import urlsplit

        p = urlsplit(url.strip())
        host = (p.netloc or "").lower()
        path = (p.path or "").rstrip("/")
        return f"{p.scheme.lower()}://{host}{path}" if host else url.strip().rstrip("/")

    def has_browser_evidence(self, engagement_id: str, url: str) -> bool:
        """True only if a browser verification for this URL is backed by a real
        on-disk screenshot artifact (H3). URLs match after normalization (L6)."""
        target = self._norm_url(url)
        # ponytail: O(n) scan over one engagement's verifications; fine at this
        # scale. Add a normalized-url column + index if it ever gets large.
        rows = self._fetchall(
            "SELECT url, screenshot_path FROM browser_verifications WHERE engagement_id = ?",
            (engagement_id,),
        )
        return any(self._norm_url(r["url"]) == target and self._is_valid_screenshot(r["screenshot_path"]) for r in rows)

    # ── Verification Requirements per Vuln Class (Phase J) ─────────────
    # Maps each vuln class to its required verification strategy:
    #   "consensus" — validate_poc() with require_consensus=True
    #   "browser"   — mark_browser_verified() must be called
    #   "diff"      — diff_response() must show baseline_anomaly
    #   "custom"    — agent must provide extra_payloads (no auto-gate)
    #   ""          — no automatic gate
    VERIFICATION_REQUIREMENTS: dict[str, str] = {
        "xss_reflected": "consensus",
        "xss_stored": "consensus",
        "xss_dom": "consensus",
        "sqli": "consensus",
        "ssrf": "consensus",
        "ssti": "consensus",
        "cmdi": "consensus",
        "path_traversal": "consensus",
        "open_redirect": "consensus",
        "nosqli": "consensus",
        "xxe": "consensus",
        "ldap_injection": "consensus",
        "graphql_abuse": "custom",
        "clickjacking": "browser",
        "csrf": "browser",
        "cors_misconfiguration": "browser",
        "missing_csp": "browser",
        "weak_csp": "browser",
        "prototype_pollution": "browser",
        "idor": "diff",
        "auth_bypass": "diff",
        "brute_force": "custom",
        "no_lockout": "custom",
        "no_mfa": "custom",
        "weak_password_policy": "custom",
        "host_header_injection": "diff",
        "mass_assignment": "custom",
        "race_condition": "custom",
        "http_smuggling": "custom",
    }
    # Kept for reference: old BROWSER_REQUIRED_CLASSES equivalent
    BROWSER_REQUIRED_CLASSES: set = {k for k, v in VERIFICATION_REQUIREMENTS.items() if v == "browser"}

    # ── Auto Confidence Scoring (Phase D → F rewrite) ─────────────────

    SCORING_WEIGHTS = {
        "payload_consensus": 35,  # require_consensus=True passed
        "reproduced": 25,  # auto_retry >= 3 and consistent
        "browser_confirmed": 20,  # mark_browser_verified() called for URL
        "baseline_anomaly": 10,  # diff_response() returned DIFFERENT or SUSPICIOUS
        "independent_engine": 10,  # at least 2 detection methods agreed (Phase G stub)
    }
    # >=80 -> confirmed, >=50 -> version_based, else -> speculative

    @staticmethod
    def _compute_confidence(
        poc_token: str = "",
        poc_output: str = "",
        evidence: str = "",
        cvss: float = 0.0,
        chain_count: int = 0,
        consensus_passed: bool = False,
        reproduced: bool = False,
        browser_confirmed: bool = False,
        baseline_anomaly: bool = False,
        independent_engine: bool = False,
    ) -> str:
        """Compute confidence level from objective evidence signals.

        Reweighted in Phase F to prioritize verification signals over
        evidence length / CVSS."""
        score = 0
        if poc_token:
            score += 5  # poc_token is a hard gate for confirmed, not a weight signal
        if consensus_passed:
            score += FindingsDB.SCORING_WEIGHTS["payload_consensus"]
        if reproduced:
            score += FindingsDB.SCORING_WEIGHTS["reproduced"]
        if browser_confirmed:
            score += FindingsDB.SCORING_WEIGHTS["browser_confirmed"]
        if baseline_anomaly:
            score += FindingsDB.SCORING_WEIGHTS["baseline_anomaly"]
        if independent_engine:
            score += FindingsDB.SCORING_WEIGHTS["independent_engine"]
        if chain_count > 0:
            score += 5
        if score >= 80:
            return "confirmed"
        elif score >= 50:
            return "version_based"
        else:
            return "speculative"

    def detect_chains(self, engagement_id: str, new_vuln_id: int | None = None) -> list[dict]:
        """Detect attack chains across all vulns in an engagement.

        Returns a list of chain dicts with name, score, steps, and finding_refs.
        If new_vuln_id is provided, only detect chains involving that vuln.
        """
        vulns = self.list_vulns(engagement_id=engagement_id)
        if not vulns or len(vulns) < 2:
            return []

        # Classify each vuln
        classified: list[dict] = []
        for v in vulns:
            classes = self._infer_vuln_class(v.get("title", ""), v.get("test_id", ""), v.get("description", ""))
            classified.append(
                {
                    "vuln": v,
                    "classes": classes,
                    "id": v.get("id"),
                    "finding_ref": v.get("finding_ref", f"FINDING-{v['id']:03d}"),
                    "severity": v.get("severity", "Medium"),
                    "cvss": v.get("cvss", 0.0),
                }
            )

        chains = []
        for pattern in self.CHAIN_PATTERNS_SQLITE:
            source_classes = set(pattern["source_classes"])
            target_classes = set(pattern.get("target_classes", []))

            for source in classified:
                if not source["classes"]:
                    continue
                if not source_classes.intersection(source["classes"]):
                    continue
                # If new_vuln_id is specified, only match if this source is the new vuln
                if new_vuln_id is not None and source["id"] != new_vuln_id:
                    continue

                if target_classes:
                    for target in classified:
                        if target["id"] == source["id"]:
                            continue
                        if not target_classes.intersection(target["classes"]):
                            continue
                        # If new_vuln_id is specified, also match if target is the new vuln
                        if new_vuln_id is not None and target["id"] != new_vuln_id:
                            continue
                        score = self._score_chain(pattern, source, target)
                        steps = [
                            f"[{source['finding_ref']}] {source['vuln']['title']} ({source['severity']})",
                            f"[{target['finding_ref']}] {target['vuln']['title']} ({target['severity']})",
                        ]
                        mitre_ids = self._infer_mitre_ids(source["classes"] + target["classes"])
                        chains.append(
                            {
                                "name": pattern["name"],
                                "description": pattern["description"],
                                "score": score,
                                "steps": steps,
                                "finding_refs": [
                                    source["finding_ref"],
                                    target["finding_ref"],
                                ],
                                "mitre_ids": mitre_ids,
                                "severity_upgrade": pattern["severity_upgrade"],
                            }
                        )
                else:
                    # Single-finding pattern (SSRF -> cloud metadata, CORS -> data theft)
                    score = source.get("cvss", 5.0) + 2.0  # Base score + chain bonus
                    steps = [
                        f"[{source['finding_ref']}] {source['vuln']['title']} ({source['severity']})",
                        f"→ Exploit: {pattern['description']}",
                    ]
                    mitre_ids = self._infer_mitre_ids(source["classes"])
                    chains.append(
                        {
                            "name": pattern["name"],
                            "description": pattern["description"],
                            "score": min(score, 10.0),
                            "steps": steps,
                            "finding_refs": [source["finding_ref"]],
                            "mitre_ids": mitre_ids,
                            "severity_upgrade": pattern["severity_upgrade"],
                        }
                    )

        return chains

    @staticmethod
    def _score_chain(pattern: dict, source: dict, target: dict) -> float:
        """Score a chain (0.0-10.0) based on CVSS + severity + pattern boost."""
        base = max(source.get("cvss", 5.0), target.get("cvss", 5.0))
        sev_weights = {
            "Critical": 10.0,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Informational": 0.0,
        }
        source_sev = sev_weights.get(source["severity"], 5.0)
        target_sev = sev_weights.get(target["severity"], 5.0)
        avg_sev = (source_sev + target_sev) / 2
        chain_score = max(base, avg_sev) + 1.5  # Chain bonus
        return min(chain_score, 10.0)

    @staticmethod
    def _infer_mitre_ids(classes: list[str]) -> str:
        """Infer MITRE ATT&CK technique IDs from vulnerability classes."""
        mapping = {
            "xss_reflected": "T1059.007",
            "xss_stored": "T1059.007",
            "xss_dom": "T1059.007",
            "sqli": "T1190",
            "ssrf": "T1190",
            "ssti": "T1059",
            "cmdi": "T1059",
            "idor": "T1213",
            "open_redirect": "T1204.001",
            "cors_misconfiguration": "T1090",
            "missing_csp": "T1027",
            "auth_bypass": "T1548",
            "brute_force": "T1110",
            "no_lockout": "T1110",
            "no_mfa": "T1556.006",
        }
        seen = set()
        ids = []
        for c in classes:
            mid = mapping.get(c)
            if mid and mid not in seen:
                seen.add(mid)
                ids.append(mid)
        return ", ".join(ids)

    def _extract_finding_refs_from_steps(self, steps_json: str) -> set:
        """Extract finding refs (e.g. 'FINDING-001') from chain step descriptions."""
        try:
            steps = json.loads(steps_json)
        except (json.JSONDecodeError, TypeError) as e:
            logger.debug("_extract_finding_refs_from_steps: failed to parse steps JSON: %s", e)
            return set()
        refs = set()
        for step in steps:
            m = re.match(r"\[(FINDING-\d+)\]", step)
            if m:
                refs.add(m.group(1))
        return refs

    def add_auto_chain(self, engagement_id: str, chain: dict) -> dict | None:
        """Add an auto-detected chain if it doesn't already exist.

        Checks for duplicates by comparing finding_refs before inserting.
        """
        existing = self.list_chains(engagement_id=engagement_id)
        new_refs = set(chain.get("finding_refs", []))
        for ec in existing:
            existing_refs = self._extract_finding_refs_from_steps(ec.get("steps", "[]"))
            # Check overlap: same finding_refs → skip duplicate
            if new_refs and existing_refs and new_refs == existing_refs:
                return None

        steps_json = json.dumps(chain.get("steps", []))
        now = _now_iso()
        with self._lock:
            self._execute(
                """INSERT INTO chains
                   (engagement_id, name, score, status, steps, mitre_ids, notes, created_at, updated_at)
                   VALUES (?, ?, ?, 'auto-discovered', ?, ?, ?, ?, ?)""",
                (
                    engagement_id,
                    chain["name"],
                    chain.get("score", 0.0),
                    steps_json,
                    chain.get("mitre_ids", ""),
                    f"Auto-chain: {chain.get('description', '')}. " f"Severity impact: {chain.get('severity_upgrade', '')}. " f"Findings: {', '.join(chain.get('finding_refs', []))}",
                    now,
                    now,
                ),
            )
            self._get_conn().commit()
        row = self._fetchone("SELECT * FROM chains WHERE id = last_insert_rowid()")
        return self._row_to_dict(row) if row else None

    # ── Stats & Export ───────────────────────────────────────────────────

    def stats(self, engagement_id: str) -> dict[str, Any]:
        data: dict[str, Any] = {
            "engagement": self.get_engagement(engagement_id),
        }
        host_count = self._fetchone(
            "SELECT COUNT(*) as c FROM hosts WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["hosts"] = host_count["c"] if host_count else 0
        svc_count = self._fetchone(
            """SELECT COUNT(*) as c FROM services svc
               JOIN hosts h ON svc.host_id = h.id
               WHERE h.engagement_id = ?""",
            (engagement_id,),
        )
        data["services"] = svc_count["c"] if svc_count else 0
        vuln_total = self._fetchone(
            "SELECT COUNT(*) as c FROM vulns WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["vulns"] = {"total": vuln_total["c"] if vuln_total else 0}
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            n = self._fetchone(
                "SELECT COUNT(*) as c FROM vulns WHERE engagement_id = ? AND severity = ?",
                (engagement_id, sev),
            )
            data["vulns"][sev.lower()] = n["c"] if n else 0
        cred_count = self._fetchone(
            "SELECT COUNT(*) as c FROM credentials WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["credentials"] = cred_count["c"] if cred_count else 0
        chain_count = self._fetchone(
            "SELECT COUNT(*) as c FROM chains WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["chains"] = chain_count["c"] if chain_count else 0
        log_count = self._fetchone(
            "SELECT COUNT(*) as c FROM session_log WHERE engagement_id = ?",
            (engagement_id,),
        )
        data["session_entries"] = log_count["c"] if log_count else 0
        return data

    def export_json(self, engagement_id: str) -> str:
        data = {
            "engagement": self.get_engagement(engagement_id),
            "hosts": self.list_hosts(engagement_id),
            "services": self.list_services(engagement_id=engagement_id),
            "vulns": self.list_vulns(engagement_id=engagement_id),
            "credentials": self.list_credentials(engagement_id=engagement_id),
            "chains": self.list_chains(engagement_id=engagement_id),
            "session_log": self.get_session_log(engagement_id=engagement_id, limit=1000),
            "confidence_log": self.get_confidence_log(engagement_id),
        }
        return json.dumps(data, indent=2, default=str)

    def handoff_markdown(self, engagement_id: str) -> str:
        """Generate a handoff report in Markdown for the next session."""
        eng = self.get_engagement(engagement_id)
        hosts = self.list_hosts(engagement_id)
        vulns = self.list_vulns(engagement_id=engagement_id)
        vulns_by_sev: dict[str, list] = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Informational": [],
        }
        for v in vulns:
            vulns_by_sev.get(v["severity"], []).append(v)
        creds = self.list_credentials(engagement_id=engagement_id)
        chains = self.list_chains(engagement_id=engagement_id)
        log = self.get_session_log(engagement_id=engagement_id, limit=30)

        lines = []
        lines.append(f"# Engagement Handoff: {engagement_id}")
        lines.append("")
        lines.append(f"**Client:** {eng.get('client', 'N/A')}")
        lines.append(f"**Type:** {eng.get('type', 'N/A')}")
        lines.append(f"**Scope:** {eng.get('scope', 'N/A')}")
        lines.append(f"**Status:** {eng.get('status', 'N/A')}")
        lines.append(f"**Start:** {eng.get('start_date', 'N/A')}")
        if eng.get("end_date"):
            lines.append(f"**End:** {eng['end_date']}")
        lines.append("")

        # Hosts
        lines.append("## Hosts")
        lines.append("")
        lines.append("| IP | Hostname | OS | Role | Status |")
        lines.append("|----|----------|----|------|--------|")
        for h in hosts:
            lines.append(f"| {h['ip']} | {h['hostname']} | {h['os']} | {h['role']} | {h['status']} |")
        lines.append("")

        # Vulnerabilities
        lines.append("## Vulnerabilities")
        lines.append("")
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            items = vulns_by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev} ({len(items)})")
            lines.append("")
            lines.append("| ID | Title | URL | Status | Tool |")
            lines.append("|----|-------|-----|--------|------|")
            for v in items:
                vid = v.get("id", "")
                lines.append(f"| {vid} | {v['title']} | {v.get('affected_url', '')} " f"| {v.get('status', '')} | {v.get('tool_used', '')} |")
            lines.append("")

        # Credentials
        if creds:
            lines.append("## Credentials")
            lines.append("")
            lines.append("| Username | Type | Domain | Access Level | Valid |")
            lines.append("|----------|------|--------|-------------|-------|")
            for c in creds:
                lines.append(f"| {c['username']} | {c['secret_type']} | {c['domain']} " f"| {c['access_level']} | {'Yes' if c['valid'] else 'No'} |")
            lines.append("")

        # Attack Chains
        if chains:
            lines.append("## Attack Chains")
            lines.append("")
            lines.append("| Name | Score | Status | MITRE IDs |")
            lines.append("|------|-------|--------|-----------|")
            for c in chains:
                lines.append(f"| {c['name']} | {c['score']} | {c['status']} | {c.get('mitre_ids', '')} |")
            lines.append("")

        # Confidence Audit (Phase 5) — why each finding got its rating
        clog = self.get_confidence_log(engagement_id)
        if clog:
            lines.append("## Confidence Audit")
            lines.append("")
            lines.append("| Finding | Confidence | Score | Signals fired |")
            lines.append("|---------|-----------|-------|---------------|")
            for entry in clog:
                s = entry.get("signals", {})
                fired = [k for k in ("poc_token_present", "consensus_passed", "reproduced", "browser_confirmed", "baseline_anomaly", "independent_engine") if s.get(k)]
                if s.get("chain_count"):
                    fired.append(f"chains={s['chain_count']}")
                if s.get("noise_classes"):
                    fired.append(f"noise={','.join(s['noise_classes'])}")
                lines.append(f"| {entry.get('finding_ref', '')} | {entry.get('confidence', '')} | {s.get('score', 0)} | {', '.join(fired) or 'none'} |")
            lines.append("")

        # Recent Activity
        lines.append("## Recent Activity")
        lines.append("")
        lines.append("| Time | Agent | Action | Summary |")
        lines.append("|------|-------|--------|---------|")
        for e in log[:20]:
            lines.append(f"| {e.get('created_at', '')} | {e.get('agent', '')} " f"| {e.get('action', '')} | {e.get('summary', '')} |")
        lines.append("")

        # Suggested Next Steps
        lines.append("## Suggested Next Steps")
        lines.append("")
        unconfirmed = [v for v in vulns if v.get("status") == "open"]
        if unconfirmed:
            lines.append(f"- **{len(unconfirmed)} unconfirmed vulns** — run PoC validation")
        open_creds = [c for c in creds if c.get("valid")]
        if open_creds:
            lines.append("- **Valid credentials available** — test for privilege escalation")
        incomplete_chains = [c for c in chains if c.get("status") in ("draft", "")]
        if incomplete_chains:
            lines.append("- **Incomplete attack chains** — continue chain development")
        if not unconfirmed and not open_creds and not incomplete_chains:
            lines.append("- All findings validated. Ready for report generation.")
        lines.append("")

        return "\n".join(lines)


# ── Shorthand ─────────────────────────────────────────────────────────────────


def get_db(db_path: str | Path | None = None) -> FindingsDB:
    return FindingsDB(str(db_path or get_default_db_path()))


def get_default_db_path() -> Path:
    return Path(
        os.environ.get(
            "DST_FINDINGS_DB",
            str(Path(__file__).parent / "data" / "findings.db"),
        )
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Evidence path helpers ─────────────────────────────────────────────────────


def slugify(text: str, max_len: int = 40) -> str:
    """Convert text to lowercase hyphenated slug, max max_len chars."""
    s = text.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s[:max_len].rstrip("-")


def evidence_path(
    domain: str,
    vuln_id: int,
    title: str,
    base_dir: str | Path | None = None,
    finding_ref: str = "",
) -> Path:
    """Return the evidence directory path for a finding.

    Path: <base_dir>/engagements/recon/<domain>/evidence/finding-<id>-<slug>/
    """
    slug = slugify(title)
    if not base_dir:
        base_dir = Path(__file__).resolve().parent.parent
    return Path(base_dir) / "engagements" / "recon" / domain / "evidence" / f"finding-{vuln_id:03d}-{slug}"


def evidence_path_from_row(
    row: dict,
    domain: str = "",
    base_dir: str | Path | None = None,
) -> Path:
    """Return the evidence directory path from a vuln DB row dict."""
    if not domain:
        domain = row.get("domain", "").split(",")[0].strip() or "unknown"
    title = row.get("title", "untitled")
    vid = row.get("id", 0)
    return evidence_path(domain, vid, title, base_dir)
