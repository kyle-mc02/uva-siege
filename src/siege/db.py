"""SQLite schema and low-level access for one engagement.

One SQLite file == one engagement (see HANDOFF.md). This module owns the
schema and thin row helpers; it does not know about parsers or merge policy.

Design notes:
- Foreign keys are enforced (PRAGMA foreign_keys=ON per connection).
- Natural keys that merge depends on are UNIQUE so upserts are race-free:
  host.ip, (service.host_id, port, proto). That is what makes re-importing a
  scan update rather than duplicate.
- Timestamps are ISO-8601 UTC strings. SQLite has no datetime type; strings
  sort correctly and stay human-readable in the file.
- `imports` keeps the raw input blob + its sha256 so we can re-parse later.
- `events` is append-only and drives the future wallboard ticker / timeline.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 4

# Columns added after v1. CREATE TABLE IF NOT EXISTS won't alter an existing
# table, so for a DB created by an older siege we add any missing column.
# Additive only — we never drop or retype, so this is safe to run every startup.
_EXPECTED_COLUMNS = {
    "hosts": {
        "os_family": "TEXT",
        "domain": "TEXT",
        "dns_name": "TEXT",
        "ad_high_value": "INTEGER NOT NULL DEFAULT 0",
        "ad_is_dc": "INTEGER NOT NULL DEFAULT 0",
    },
    "edges": {"description": "TEXT"},
    "findings": {"created_by": "TEXT NOT NULL DEFAULT 'operator'"},  # operator attribution
}

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A host, keyed by IP. mac/hostname are merge fallbacks, not identity here.
-- The ad_* / domain / dns_name columns are populated only for domain-joined
-- boxes (BloodHound ingest, Phase 3); standalone hosts leave them NULL/0.
-- os_family ('windows'|'linux'|'other') is classified from nmap OS or AD data.
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY,
    ip            TEXT    NOT NULL UNIQUE,
    mac           TEXT,
    hostname      TEXT,
    os            TEXT,
    os_family     TEXT,
    state         TEXT    NOT NULL DEFAULT 'discovered',
    in_scope      INTEGER NOT NULL DEFAULT 1,
    domain        TEXT,                           -- AD domain, if domain-joined
    dns_name      TEXT,                           -- FQDN from AD, if known
    ad_high_value INTEGER NOT NULL DEFAULT 0,     -- BloodHound highvalue
    ad_is_dc      INTEGER NOT NULL DEFAULT 0,     -- is a domain controller
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    source_file   TEXT
);

-- A port/service on a host. (host_id, port, proto) is the natural key.
-- product/version/banner are attacker-controlled text; never render as HTML.
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    proto       TEXT    NOT NULL,               -- 'tcp' | 'udp'
    state       TEXT,                           -- 'open' | 'filtered' | ...
    name        TEXT,
    product     TEXT,
    version     TEXT,
    banner      TEXT,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    source_file TEXT,
    UNIQUE (host_id, port, proto)
);

-- Graph edges between hosts: subnet grouping, traceroute, operator-drawn, etc.
CREATE TABLE IF NOT EXISTS edges (
    id          INTEGER PRIMARY KEY,
    src_host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    dst_host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,               -- subnet|traceroute|pivot|creds_reuse|operator
    label       TEXT,                           -- short tag, e.g. the BloodHound edge ('AdminTo')
    description TEXT,                            -- how to abuse it (Windows/Linux aware)
    created_by  TEXT    NOT NULL DEFAULT 'import',
    created_at  TEXT    NOT NULL,
    UNIQUE (src_host_id, dst_host_id, type)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    service_id  INTEGER REFERENCES services(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info'
                CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    notes       TEXT,
    created_by  TEXT    NOT NULL DEFAULT 'operator',
    created_at  TEXT    NOT NULL
);

-- Evidence pinned to exactly one host, service, or finding (real FKs, so
-- deleting the target cascades). Content lives on disk by sha256.
CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY,
    host_id       INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    service_id    INTEGER REFERENCES services(id) ON DELETE CASCADE,
    finding_id    INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    kind          TEXT    NOT NULL CHECK (kind IN ('screenshot', 'log', 'note')),
    sha256        TEXT    NOT NULL,
    path          TEXT    NOT NULL,            -- relative to the evidence dir
    original_name TEXT,                        -- uploader-supplied; untrusted text
    caption       TEXT,
    added_by      TEXT    NOT NULL DEFAULT 'operator',
    added_at      TEXT    NOT NULL,
    CHECK ((host_id IS NOT NULL) + (service_id IS NOT NULL) + (finding_id IS NOT NULL) = 1)
);

-- Raw imported files, kept for provenance + re-parsing.
CREATE TABLE IF NOT EXISTS imports (
    id          INTEGER PRIMARY KEY,
    filename    TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    raw         TEXT    NOT NULL,
    imported_at TEXT    NOT NULL
);

-- Append-only activity log. Drives the wallboard ticker and timeline replay.
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    type    TEXT NOT NULL,                       -- import|state_change|evidence_added|edge_added|finding_added|scope_set
    actor   TEXT NOT NULL,
    ts      TEXT NOT NULL,
    payload TEXT                                 -- JSON blob
);

-- Imported engagement scope. in_scope hosts are fair game; out rules win ties.
-- Enforcement (flagging hosts) lives in scope.py; this is just the ruleset.
CREATE TABLE IF NOT EXISTS scope_rules (
    id       INTEGER PRIMARY KEY,
    cidr     TEXT    NOT NULL,                    -- e.g. '10.10.10.0/24' or a single host
    in_scope INTEGER NOT NULL,                    -- 1 = in scope, 0 = explicitly excluded
    note     TEXT,
    added_at TEXT    NOT NULL,
    UNIQUE (cidr, in_scope)
);

-- Display groupings for the graph: each host is drawn inside the most-specific
-- subnet that contains it. Arbitrary masks (/16, /23, /25, …), so an engagement
-- spanning many subnets renders correctly instead of being chopped into /24s.
-- Candidate subnets come from here plus the scope include CIDRs; if a host
-- matches none, it falls back to its /24 (v4) or /64 (v6). See queries.py.
CREATE TABLE IF NOT EXISTS subnets (
    id       INTEGER PRIMARY KEY,
    cidr     TEXT    NOT NULL UNIQUE,            -- e.g. '10.0.0.0/16'
    label    TEXT,                               -- optional display name, e.g. 'Server VLAN'
    added_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_evidence_host ON evidence(host_id);
CREATE INDEX IF NOT EXISTS idx_evidence_service ON evidence(service_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


def utcnow() -> str:
    """ISO-8601 UTC timestamp, e.g. '2026-10-12T19:30:00+00:00'."""
    return datetime.now(timezone.utc).isoformat()


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) an engagement DB with sane pragmas.

    `path` may be ":memory:" for tests. Rows come back as sqlite3.Row so
    callers can use column names.

    check_same_thread=False: FastAPI may run a request's sync dependency and its
    endpoint on different threadpool threads, so a connection created in the
    dependency gets used by the endpoint on another thread. We open one
    connection per request and never share it between concurrent requests, so
    disabling the same-thread guard is safe (no two threads touch it at once).
    """
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add any columns introduced after a DB was first created. Additive only."""
    for table, cols in _EXPECTED_COLUMNS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col, decl in cols.items():
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if absent, apply additive migrations, stamp version. Idempotent."""
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()
