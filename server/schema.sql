
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'web',
    scope TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    start_date TEXT NOT NULL,
    end_date TEXT,
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    ip TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered',
    discovered_by TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    UNIQUE(engagement_id, ip, hostname)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    banner TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    host_id INTEGER REFERENCES hosts(id),
    finding_ref TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    cvss REAL DEFAULT 0.0,
    cve TEXT NOT NULL DEFAULT '',
    mitre_id TEXT NOT NULL DEFAULT '',
    test_id TEXT NOT NULL DEFAULT '',
    tool_used TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    poc_output TEXT NOT NULL DEFAULT '',
    affected_url TEXT NOT NULL DEFAULT '',
    affected_parameter TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'version_based',
    poc_token TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_ref ON vulns(engagement_id, finding_ref);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    host_id INTEGER REFERENCES hosts(id),
    username TEXT NOT NULL DEFAULT '',
    secret TEXT NOT NULL DEFAULT '',
    secret_type TEXT NOT NULL DEFAULT 'password',
    domain TEXT NOT NULL DEFAULT '',
    access_level TEXT NOT NULL DEFAULT 'unknown',
    valid INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    name TEXT NOT NULL,
    score REAL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'draft',
    steps TEXT NOT NULL DEFAULT '[]',
    mitre_ids TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    agent TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- FIX #4: Audit log table for credential access
CREATE TABLE IF NOT EXISTS credential_access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'list',
    timestamp TEXT NOT NULL
);
-- END FIX #4

-- Baselines table for response diff engine
CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    request_body TEXT DEFAULT '',
    label TEXT DEFAULT '',
    profile_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_baselines_engagement ON baselines(engagement_id);
CREATE INDEX IF NOT EXISTS idx_baselines_url ON baselines(url);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_engagement ON vulns(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulns(cve);
CREATE INDEX IF NOT EXISTS idx_vulns_tool ON vulns(tool_used);
CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_chains_engagement ON chains(engagement_id);
CREATE INDEX IF NOT EXISTS idx_session_log_engagement ON session_log(engagement_id);

-- Browser verifications for Phase E validation gate
CREATE TABLE IF NOT EXISTS browser_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    payload TEXT DEFAULT '',
    screenshot_taken INTEGER DEFAULT 0,
    verified_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bv_engagement_url ON browser_verifications(engagement_id, url);
