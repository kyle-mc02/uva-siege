"""Read-side queries shared by the API and exporters.

Everything returned here is plain dicts/lists ready for JSON. String values
that came from scans or uploads are untrusted; consumers render them as text.
"""

from __future__ import annotations

import ipaddress
import sqlite3


def _row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r is not None else None


def list_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT h.*,
                  (SELECT COUNT(*) FROM services s
                    WHERE s.host_id = h.id AND s.state LIKE 'open%') AS open_ports
             FROM hosts h
            ORDER BY h.ip"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_host(conn: sqlite3.Connection, host_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone())


def host_services(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM services WHERE host_id = ? ORDER BY proto, port", (host_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def host_findings(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    """Findings on the host itself or on any of its services."""
    rows = conn.execute(
        """SELECT f.* FROM findings f
            WHERE f.host_id = ?
               OR f.service_id IN (SELECT id FROM services WHERE host_id = ?)
            ORDER BY f.id""",
        (host_id, host_id),
    ).fetchall()
    return [dict(r) for r in rows]


def host_evidence(conn: sqlite3.Connection, host_id: int) -> list[dict]:
    """Evidence pinned to the host, its services, or its findings."""
    rows = conn.execute(
        """SELECT e.* FROM evidence e
            WHERE e.host_id = ?
               OR e.service_id IN (SELECT id FROM services WHERE host_id = ?)
               OR e.finding_id IN (
                    SELECT f.id FROM findings f
                     WHERE f.host_id = ?
                        OR f.service_id IN (SELECT id FROM services WHERE host_id = ?))
            ORDER BY e.added_at, e.id""",
        (host_id, host_id, host_id, host_id),
    ).fetchall()
    return [dict(r) | {"target": evidence_target(conn, r)} for r in rows]


def finding_host_id(conn: sqlite3.Connection, finding: sqlite3.Row | dict) -> int | None:
    if finding["host_id"] is not None:
        return finding["host_id"]
    if finding["service_id"] is not None:
        r = conn.execute(
            "SELECT host_id FROM services WHERE id = ?", (finding["service_id"],)
        ).fetchone()
        return r["host_id"] if r else None
    return None


def evidence_target(conn: sqlite3.Connection, ev: sqlite3.Row | dict) -> dict:
    """Describe what an evidence row is pinned to, resolved down to its host."""
    if ev["service_id"] is not None:
        s = conn.execute("SELECT * FROM services WHERE id = ?", (ev["service_id"],)).fetchone()
        h = get_host(conn, s["host_id"]) if s else None
        return {
            "type": "service",
            "id": ev["service_id"],
            "host_id": h["id"] if h else None,
            "host_ip": h["ip"] if h else None,
            "hostname": h["hostname"] if h else None,
            "port": s["port"] if s else None,
            "proto": s["proto"] if s else None,
            "service": s["name"] if s else None,
        }
    if ev["finding_id"] is not None:
        f = conn.execute("SELECT * FROM findings WHERE id = ?", (ev["finding_id"],)).fetchone()
        hid = finding_host_id(conn, f) if f else None
        h = get_host(conn, hid) if hid is not None else None
        return {
            "type": "finding",
            "id": ev["finding_id"],
            "host_id": hid,
            "host_ip": h["ip"] if h else None,
            "hostname": h["hostname"] if h else None,
            "finding": f["title"] if f else None,
            "severity": f["severity"] if f else None,
        }
    h = get_host(conn, ev["host_id"])
    return {
        "type": "host",
        "id": ev["host_id"],
        "host_id": ev["host_id"],
        "host_ip": h["ip"] if h else None,
        "hostname": h["hostname"] if h else None,
    }


def fallback_subnet(ip: str) -> str:
    """Last-resort grouping when no defined subnet contains the host.

    /24 for IPv4, /64 for IPv6 — a reasonable guess at a broadcast domain.
    """
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def grouping_networks(conn: sqlite3.Connection) -> list[tuple]:
    """Candidate grouping subnets, most-specific first.

    Explicit `subnets` (with labels) take priority over scope include CIDRs with
    the same prefix; both feed the graph so multi-subnet engagements group by
    real boundaries, not a fixed mask. Returns (network, label|None) tuples.
    """
    seen: dict[str, str | None] = {}
    # Explicit subnets first so their labels win over an unlabeled scope CIDR.
    for r in conn.execute("SELECT cidr, label FROM subnets"):
        seen.setdefault(r["cidr"], r["label"])
    for r in conn.execute("SELECT cidr FROM scope_rules WHERE in_scope = 1"):
        seen.setdefault(r["cidr"], None)

    nets = []
    for cidr, label in seen.items():
        try:
            nets.append((ipaddress.ip_network(cidr, strict=False), label))
        except ValueError:
            continue
    # Most-specific (longest prefix) first so a /24 inside a /16 wins.
    nets.sort(key=lambda nl: nl[0].prefixlen, reverse=True)
    return nets


def subnet_for(ip: str, nets: list[tuple]) -> tuple[str, str | None]:
    """Return (cidr, label) of the most-specific defined subnet containing `ip`,
    or the /24 /64 fallback (label None) if none match."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip, None
    for net, label in nets:  # already sorted most-specific first
        if addr in net:
            return str(net), label
    return fallback_subnet(ip), None


def graph_elements(conn: sqlite3.Connection) -> list[dict]:
    """Cytoscape elements: subnet compound nodes containing host nodes.

    Ports are summarised on the host (count + short list) rather than drawn as
    nodes, to keep large engagements from turning into a hairball.
    """
    hosts = list_hosts(conn)
    ports_by_host: dict[int, list[str]] = {}
    for r in conn.execute(
        "SELECT host_id, port, proto FROM services WHERE state LIKE 'open%' ORDER BY port"
    ):
        ports_by_host.setdefault(r["host_id"], []).append(f"{r['port']}/{r['proto']}")
    ev_counts = {
        r["host_id"]: r["n"]
        for r in conn.execute(
            "SELECT host_id, COUNT(*) AS n FROM evidence WHERE host_id IS NOT NULL GROUP BY host_id"
        )
    }

    nets = grouping_networks(conn)
    elements: list[dict] = []
    subnets: set[str] = set()
    for h in hosts:
        net, net_label = subnet_for(h["ip"], nets)
        if net not in subnets:
            subnets.add(net)
            # Label shows the CIDR, plus the operator's name for it when given.
            label = f"{net_label}\n{net}" if net_label else net
            elements.append({"group": "nodes", "data": {"id": f"net:{net}", "label": label, "cidr": net, "kind": "subnet"}})
        ports = ports_by_host.get(h["id"], [])
        elements.append(
            {
                "group": "nodes",
                "data": {
                    "id": f"host:{h['id']}",
                    "parent": f"net:{net}",
                    "kind": "host",
                    "host_id": h["id"],
                    "ip": h["ip"],
                    "hostname": h["hostname"],
                    "state": h["state"],
                    "in_scope": bool(h["in_scope"]),
                    "os_family": h["os_family"],
                    "domain": h["domain"],
                    "ad_high_value": bool(h["ad_high_value"]),
                    "ad_is_dc": bool(h["ad_is_dc"]),
                    "open_ports": len(ports),
                    "ports": ports[:8],
                    "evidence": ev_counts.get(h["id"], 0),
                },
            }
        )
    for e in conn.execute("SELECT * FROM edges"):
        elements.append(
            {
                "group": "edges",
                "data": {
                    "id": f"edge:{e['id']}",
                    "source": f"host:{e['src_host_id']}",
                    "target": f"host:{e['dst_host_id']}",
                    "type": e["type"],
                    "label": e["label"],
                    "description": e["description"],
                },
            }
        )
    return elements
