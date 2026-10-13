"""Merge/normalize: turn a ScanResult into rows, upserting with provenance.

This is the only module that decides how observations combine. Rules
(HANDOFF.md):
- Match hosts by IP, fall back to MAC, then hostname. Upsert, never duplicate.
- Every fact carries source_file + timestamps (first_seen / last_seen).
- Re-importing the same scan, or a later scan of the same hosts, updates
  existing rows instead of creating new ones.
- Never downgrade a host's kill-chain state; bump it forward only.
- New, non-empty values win over old ones for mutable fields (os, product,
  version, banner, hostname, mac); we don't blank a field we once knew.

Keep the raw import and emit an append-only `event` so the timeline/wallboard
(Phase 2) can replay what happened.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

from . import scope
from .db import utcnow
from .models import (
    BloodHoundResult,
    FaradayResult,
    HostState,
    ParsedHost,
    ParsedService,
    ScanResult,
    classify_os,
    is_progression,
)


def _coalesce(new: str | None, old: str | None) -> str | None:
    """Prefer a new non-empty value; otherwise keep the old one."""
    return new if new else old


def _find_host(conn: sqlite3.Connection, h: ParsedHost) -> sqlite3.Row | None:
    """Locate an existing host by IP, then MAC, then hostname."""
    row = conn.execute("SELECT * FROM hosts WHERE ip = ?", (h.ip,)).fetchone()
    if row:
        return row
    if h.mac:
        row = conn.execute("SELECT * FROM hosts WHERE mac = ?", (h.mac,)).fetchone()
        if row:
            return row
    if h.hostname:
        row = conn.execute(
            "SELECT * FROM hosts WHERE hostname = ?", (h.hostname,)
        ).fetchone()
        if row:
            return row
    return None


def _upsert_host(
    conn: sqlite3.Connection, h: ParsedHost, source_file: str, ts: str
) -> int:
    """Insert or update a host, returning its id."""
    existing = _find_host(conn, h)
    if existing is None:
        cur = conn.execute(
            """INSERT INTO hosts
                 (ip, mac, hostname, os, os_family, state, in_scope, first_seen, last_seen, source_file)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (
                h.ip,
                h.mac,
                h.hostname,
                h.os,
                classify_os(h.os),
                HostState.DISCOVERED.value,
                ts,
                ts,
                source_file,
            ),
        )
        return int(cur.lastrowid)

    host_id = int(existing["id"])
    # If a later scan enumerated services on a host we'd only discovered, that's
    # forward progress. Never downgrade (e.g. operator already marked it owned).
    new_state = existing["state"]
    if h.services and is_progression(existing["state"], HostState.ENUMERATED.value):
        new_state = HostState.ENUMERATED.value

    new_os = _coalesce(h.os, existing["os"])
    conn.execute(
        """UPDATE hosts SET
             ip = ?, mac = ?, hostname = ?, os = ?, os_family = ?, state = ?, last_seen = ?
           WHERE id = ?""",
        (
            existing["ip"],  # IP is identity; don't rewrite it from a MAC/hostname match
            _coalesce(h.mac, existing["mac"]),
            _coalesce(h.hostname, existing["hostname"]),
            new_os,
            _coalesce(classify_os(h.os), existing["os_family"]),
            new_state,
            ts,
            host_id,
        ),
    )
    return host_id


def _upsert_service(
    conn: sqlite3.Connection,
    host_id: int,
    s: ParsedService,
    source_file: str,
    ts: str,
) -> None:
    """Insert or update one service keyed by (host_id, port, proto)."""
    existing = conn.execute(
        "SELECT * FROM services WHERE host_id = ? AND port = ? AND proto = ?",
        (host_id, s.port, s.proto),
    ).fetchone()
    if existing is None:
        conn.execute(
            """INSERT INTO services
                 (host_id, port, proto, state, name, product, version, banner,
                  first_seen, last_seen, source_file)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                host_id,
                s.port,
                s.proto,
                s.state,
                s.name,
                s.product,
                s.version,
                s.banner,
                ts,
                ts,
                source_file,
            ),
        )
        return

    conn.execute(
        """UPDATE services SET
             state = ?, name = ?, product = ?, version = ?, banner = ?, last_seen = ?
           WHERE id = ?""",
        (
            _coalesce(s.state, existing["state"]),
            _coalesce(s.name, existing["name"]),
            _coalesce(s.product, existing["product"]),
            _coalesce(s.version, existing["version"]),
            _coalesce(s.banner, existing["banner"]),
            ts,
            int(existing["id"]),
        ),
    )


def ingest(
    conn: sqlite3.Connection, scan: ScanResult, actor: str = "import"
) -> dict:
    """Merge a ScanResult into the DB. Returns a small summary dict.

    Records the raw import and an append-only `import` event. Commits once at
    the end so a failed parse/merge leaves the DB untouched.
    """
    ts = scan.scanned_at
    sha = hashlib.sha256(scan.raw.encode("utf-8", "replace")).hexdigest()

    conn.execute(
        "INSERT INTO imports (filename, tool, sha256, raw, imported_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (scan.source_file, scan.tool, sha, scan.raw, ts),
    )

    hosts_seen = 0
    services_seen = 0
    for h in scan.hosts:
        host_id = _upsert_host(conn, h, scan.source_file, ts)
        hosts_seen += 1
        for s in h.services:
            _upsert_service(conn, host_id, s, scan.source_file, ts)
            services_seen += 1

    # Newly imported hosts must be judged against the current scope ruleset
    # immediately, so an out-of-scope box never shows up as fair game.
    scope.reclassify_all(conn)

    conn.execute(
        "INSERT INTO events (type, actor, ts, payload) VALUES ('import', ?, ?, ?)",
        (
            actor,
            ts,
            json.dumps(
                {
                    "source_file": scan.source_file,
                    "tool": scan.tool,
                    "sha256": sha,
                    "hosts": hosts_seen,
                    "services": services_seen,
                }
            ),
        ),
    )
    conn.commit()
    return {
        "source_file": scan.source_file,
        "hosts": hosts_seen,
        "services": services_seen,
        "sha256": sha,
    }


def _short(name: str | None) -> str | None:
    """First DNS label, lowercased: 'DC01.LAB.LOCAL' -> 'dc01'."""
    if not name:
        return None
    return name.split(".")[0].strip().lower()


def _match_host_by_name(conn: sqlite3.Connection, comp) -> sqlite3.Row | None:
    """Find the scanned host this AD computer refers to, by FQDN or short name.

    We never create a host from AD data — hosts are keyed by a scanned IP, and
    inventing IP-less hosts would pollute the graph. An unmatched computer is
    reported back so the operator knows to scan it.
    """
    full = (comp.dns_name or comp.name or "").strip().lower()
    short = _short(comp.name) or _short(comp.dns_name)
    for h in conn.execute("SELECT * FROM hosts").fetchall():
        hn = (h["hostname"] or "").strip().lower()
        if not hn:
            continue
        if full and (hn == full or _short(hn) == _short(full)):
            return h
        if short and _short(hn) == short:
            return h
    # Also allow matching against a dns_name we set on a previous BH import.
    if full:
        return conn.execute("SELECT * FROM hosts WHERE lower(dns_name) = ?", (full,)).fetchone()
    return None


def merge_bloodhound(conn: sqlite3.Connection, result: BloodHoundResult, actor: str = "import") -> dict:
    """Annotate scanned hosts with AD facts from BloodHound. Commits once.

    Only domain-joined computer objects that match a scanned host are applied;
    unmatched names are returned so the team can go scan them.
    """
    ts = utcnow()
    sha = hashlib.sha256(result.raw.encode("utf-8", "replace")).hexdigest()
    conn.execute(
        "INSERT INTO imports (filename, tool, sha256, raw, imported_at) VALUES (?, 'bloodhound', ?, ?, ?)",
        (result.source_file, sha, result.raw, ts),
    )

    matched, unmatched = [], []
    for comp in result.computers:
        host = _match_host_by_name(conn, comp)
        if host is None:
            unmatched.append(comp.dns_name or comp.name)
            continue
        conn.execute(
            """UPDATE hosts SET
                 domain = ?, dns_name = ?, os = ?, os_family = ?,
                 ad_high_value = ?, ad_is_dc = ?, last_seen = ?
               WHERE id = ?""",
            (
                _coalesce(comp.domain, host["domain"]),
                _coalesce(comp.dns_name, host["dns_name"]),
                _coalesce(comp.os, host["os"]),
                _coalesce(comp.os_family, host["os_family"]),
                1 if comp.high_value else host["ad_high_value"],
                1 if comp.is_dc else host["ad_is_dc"],
                ts,
                host["id"],
            ),
        )
        # An owned mark in BloodHound is real progress; bump state forward only.
        if comp.owned and is_progression(host["state"], HostState.OWNED.value):
            conn.execute("UPDATE hosts SET state = 'owned' WHERE id = ?", (host["id"],))
        matched.append(host["ip"])

    conn.execute(
        "INSERT INTO events (type, actor, ts, payload) "
        "VALUES ('import', ?, ?, json_object('tool', 'bloodhound', 'source_file', ?, 'matched', ?, 'unmatched', ?))",
        (actor, ts, result.source_file, len(matched), len(unmatched)),
    )
    conn.commit()
    return {
        "source_file": result.source_file,
        "tool": "bloodhound",
        "computers": len(result.computers),
        "matched": matched,
        "unmatched": unmatched,
        "sha256": sha,
    }


def _upsert_finding(conn, host_id, service_id, title, severity, notes, ts) -> bool:
    """Insert a finding, or update an existing one with the same target+title.

    Returns True if a new finding was created. Dedup keeps a re-imported
    Faraday workspace from piling up duplicate findings.
    """
    existing = conn.execute(
        "SELECT id FROM findings WHERE title = ? AND host_id IS ? AND service_id IS ?",
        (title, host_id, service_id),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE findings SET severity = ?, notes = COALESCE(?, notes) WHERE id = ?",
            (severity, notes, existing["id"]),
        )
        return False
    conn.execute(
        "INSERT INTO findings (host_id, service_id, title, severity, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, service_id, title, severity, notes, ts),
    )
    return True


def merge_faraday(conn: sqlite3.Connection, result: FaradayResult, actor: str = "import") -> dict:
    """Merge Faraday hosts/services (like a scan) and vulns (as findings). Commits."""
    ts = utcnow()
    sha = hashlib.sha256(result.raw.encode("utf-8", "replace")).hexdigest()
    conn.execute(
        "INSERT INTO imports (filename, tool, sha256, raw, imported_at) VALUES (?, 'faraday', ?, ?, ?)",
        (result.source_file, sha, result.raw, ts),
    )

    hosts_seen = services_seen = 0
    for h in result.hosts:
        host_id = _upsert_host(conn, h, result.source_file, ts)
        hosts_seen += 1
        for s in h.services:
            _upsert_service(conn, host_id, s, result.source_file, ts)
            services_seen += 1

    findings_new = 0
    unmatched_vulns = 0
    for v in result.vulns:
        host = conn.execute("SELECT id FROM hosts WHERE ip = ?", (v.host_ip,)).fetchone()
        if host is None:
            unmatched_vulns += 1  # a vuln for a host Faraday knew but we didn't ingest
            continue
        service_id = None
        if v.port is not None:
            svc = conn.execute(
                "SELECT id FROM services WHERE host_id = ? AND port = ? AND proto = ?",
                (host["id"], v.port, v.proto or "tcp"),
            ).fetchone()
            service_id = svc["id"] if svc else None
        if _upsert_finding(conn, host["id"], service_id, v.title, v.severity, v.notes, ts):
            findings_new += 1

    scope.reclassify_all(conn)
    conn.execute(
        "INSERT INTO events (type, actor, ts, payload) "
        "VALUES ('import', ?, ?, json_object('tool', 'faraday', 'source_file', ?, 'hosts', ?, 'services', ?, 'findings', ?))",
        (actor, ts, result.source_file, hosts_seen, services_seen, findings_new),
    )
    conn.commit()
    return {
        "source_file": result.source_file,
        "tool": "faraday",
        "hosts": hosts_seen,
        "services": services_seen,
        "findings_new": findings_new,
        "vulns": len(result.vulns),
        "unmatched_vulns": unmatched_vulns,
        "sha256": sha,
    }
