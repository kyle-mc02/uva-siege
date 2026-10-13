"""Display subnets: how hosts are grouped into boxes on the graph/TV.

An engagement usually spans several subnets with different masks (a /16 flat
office net, a few /24 VLANs, point-to-point /30s). Grouping everything by a
fixed /24 is wrong for all but the /24 case, so the operator can define the real
subnets here (any mask), and the graph draws each host inside the most-specific
subnet that contains it.

Candidate groupings = these explicit subnets ∪ the scope include CIDRs (so if
scope already lists the subnets, grouping just works with no extra step). A host
matching none falls back to its /24 (v4) / /64 (v6). The classifier itself lives
in queries.py (it's read on every graph build); this module is import/CRUD.
"""

from __future__ import annotations

import ipaddress
import sqlite3

from .db import utcnow


def parse_subnet_text(text: str) -> list[tuple[str, str | None]]:
    """Parse a subnets file into (cidr, label) rows.

    One per line; '#' comments; blank lines ignored. An optional label follows
    the CIDR: `10.0.5.0/24  Server VLAN`. A bare IP becomes a /32 (or /128).
    Raises ValueError on an unparseable CIDR.
    """
    rows: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        net = ipaddress.ip_network(parts[0], strict=False)  # raises on garbage
        label = parts[1].strip() if len(parts) > 1 else None
        rows.append((str(net), label or None))
    return rows


def replace_subnets(conn: sqlite3.Connection, rows: list[tuple[str, str | None]], actor: str = "operator") -> dict:
    """Replace the whole subnet set and log an event. Commits.

    Grouping is purely visual, so this does not touch hosts; the next graph
    build picks up the new boundaries.
    """
    now = utcnow()
    conn.execute("DELETE FROM subnets")
    for cidr, label in rows:
        conn.execute(
            "INSERT OR IGNORE INTO subnets (cidr, label, added_at) VALUES (?, ?, ?)",
            (cidr, label, now),
        )
    conn.execute(
        "INSERT INTO events (type, actor, ts, payload) VALUES ('subnets_set', ?, ?, json_object('count', ?))",
        (actor, now, len(rows)),
    )
    conn.commit()
    return {"subnets": len(rows)}


def list_subnets(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM subnets ORDER BY cidr")]
