"""Engagement scope: decide which hosts are fair game.

A scope ruleset is a list of CIDRs tagged in (fair game) or out (explicitly
excluded). A host is in scope iff some `in` rule contains it AND no `out` rule
does — exclusions always win, so a carve-out inside an allowed range is
respected. With no rules at all we fail OPEN (in_scope=1): an empty scope means
"not yet imported", and flagging every host out-of-scope on a fresh DB would be
misleading. Once any `in` rule exists, hosts outside it flip to out-of-scope.

This is the enforcement half of HANDOFF.md security must-do #5. The UI then
makes out-of-scope hosts loud and hard to act on.
"""

from __future__ import annotations

import ipaddress
import sqlite3

from .db import utcnow


def _networks(conn: sqlite3.Connection, in_scope: int) -> list:
    nets = []
    for r in conn.execute("SELECT cidr FROM scope_rules WHERE in_scope = ?", (in_scope,)):
        try:
            nets.append(ipaddress.ip_network(r["cidr"], strict=False))
        except ValueError:
            continue  # a malformed stored rule shouldn't break classification
    return nets


def is_in_scope(ip: str, includes: list, excludes: list) -> bool:
    """Apply the include/exclude rules to one IP. Fails open if no includes."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if any(addr in n for n in excludes):
        return False
    if not includes:
        return True
    return any(addr in n for n in includes)


def reclassify_all(conn: sqlite3.Connection) -> int:
    """Recompute in_scope for every host. Returns the number that changed.

    Does not commit; the caller owns the transaction.
    """
    includes = _networks(conn, 1)
    excludes = _networks(conn, 0)
    changed = 0
    for h in conn.execute("SELECT id, ip, in_scope FROM hosts").fetchall():
        want = 1 if is_in_scope(h["ip"], includes, excludes) else 0
        if want != h["in_scope"]:
            conn.execute("UPDATE hosts SET in_scope = ? WHERE id = ?", (want, h["id"]))
            changed += 1
    return changed


def parse_scope_text(text: str) -> list[tuple[str, int, str | None]]:
    """Parse a scope file into (cidr, in_scope, note) rows.

    Format (one rule per line; '#' comments; blank lines ignored):
        10.10.10.0/24            # in scope (default)
        !10.10.10.99             # leading '!' = exclude
        192.168.5.5  out  gw     # explicit keyword + note also accepted
    A bare IP becomes a /32 (or /128). Raises ValueError on an unparseable CIDR.
    """
    rows: list[tuple[str, int, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        in_scope = 1
        if line.startswith("!"):
            in_scope = 0
            line = line[1:].strip()
        parts = line.split()
        token = parts[0]
        note = None
        if len(parts) > 1:
            if parts[1].lower() in ("in", "out"):
                in_scope = 1 if parts[1].lower() == "in" else 0
                note = " ".join(parts[2:]) or None
            else:
                note = " ".join(parts[1:]) or None
        net = ipaddress.ip_network(token, strict=False)  # raises on garbage
        rows.append((str(net), in_scope, note))
    return rows


def replace_rules(conn: sqlite3.Connection, rows: list[tuple[str, int, str | None]], actor: str = "operator") -> dict:
    """Replace the whole ruleset, reclassify hosts, log an event. Commits."""
    now = utcnow()
    conn.execute("DELETE FROM scope_rules")
    for cidr, in_scope, note in rows:
        conn.execute(
            "INSERT OR IGNORE INTO scope_rules (cidr, in_scope, note, added_at) VALUES (?, ?, ?, ?)",
            (cidr, in_scope, note, now),
        )
    changed = reclassify_all(conn)
    n_in = sum(1 for _, s, _ in rows if s == 1)
    n_out = sum(1 for _, s, _ in rows if s == 0)
    conn.execute(
        "INSERT INTO events (type, actor, ts, payload) "
        "VALUES ('scope_set', ?, ?, json_object('includes', ?, 'excludes', ?, 'hosts_changed', ?))",
        (actor, now, n_in, n_out, changed),
    )
    conn.commit()
    return {"rules": len(rows), "includes": n_in, "excludes": n_out, "hosts_reclassified": changed}
