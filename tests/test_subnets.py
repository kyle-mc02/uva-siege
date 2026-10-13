"""Multi-subnet graph grouping: arbitrary masks, most-specific wins, scope + fallback."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siege import db, queries, scope, subnets
from siege.server import create_app

W = {"X-Requested-By": "siege", "Authorization": "Bearer t0ken"}


def _conn():
    c = db.connect(":memory:")
    db.init_db(c)
    return c


def _add_host(conn, ip):
    conn.execute(
        "INSERT INTO hosts (ip, state, in_scope, first_seen, last_seen) VALUES (?, 'discovered', 1, 't', 't')",
        (ip,),
    )
    conn.commit()


def _subnet_ids(conn):
    return sorted(
        e["data"]["cidr"] for e in queries.graph_elements(conn) if e["data"]["kind"] == "subnet"
    )


def _parent_of(conn, ip):
    els = queries.graph_elements(conn)
    hid = next(e["data"]["id"] for e in els if e["data"].get("ip") == ip)
    return next(e["data"]["parent"] for e in els if e["data"].get("id") == hid)


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "e.sqlite", tmp_path / "ev", engagement="sub", token="t0ken")
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t0ken"})
        yield c


def test_fallback_is_24_when_nothing_defined():
    conn = _conn()
    for ip in ("10.0.1.5", "10.0.2.9", "192.168.5.20"):
        _add_host(conn, ip)
    # Three /24s -> three subnet boxes (unchanged behaviour).
    assert _subnet_ids(conn) == ["10.0.1.0/24", "10.0.2.0/24", "192.168.5.0/24"]


def test_explicit_subnet_groups_many_24s_into_one_box():
    conn = _conn()
    for ip in ("10.0.1.5", "10.0.2.9", "10.0.250.1"):
        _add_host(conn, ip)
    subnets.replace_subnets(conn, [("10.0.0.0/16", "Office")])
    # All three collapse into the one /16 instead of three /24s.
    assert _subnet_ids(conn) == ["10.0.0.0/16"]
    assert _parent_of(conn, "10.0.250.1") == "net:10.0.0.0/16"


def test_most_specific_subnet_wins():
    conn = _conn()
    _add_host(conn, "10.0.5.10")   # inside both /16 and /24
    _add_host(conn, "10.0.9.10")   # inside /16 only
    subnets.replace_subnets(conn, [("10.0.0.0/16", "Office"), ("10.0.5.0/24", "Server VLAN")])
    assert _parent_of(conn, "10.0.5.10") == "net:10.0.5.0/24"
    assert _parent_of(conn, "10.0.9.10") == "net:10.0.0.0/16"


def test_odd_masks_23_and_25():
    conn = _conn()
    _add_host(conn, "10.1.0.5")    # in 10.1.0.0/23
    _add_host(conn, "10.1.1.200")  # also in 10.1.0.0/23
    _add_host(conn, "172.16.0.10") # in 172.16.0.0/25
    subnets.replace_subnets(conn, [("10.1.0.0/23", None), ("172.16.0.0/25", None)])
    assert _parent_of(conn, "10.1.1.200") == "net:10.1.0.0/23"
    assert _parent_of(conn, "172.16.0.10") == "net:172.16.0.0/25"


def test_scope_includes_drive_grouping_without_explicit_subnets():
    conn = _conn()
    _add_host(conn, "10.50.0.5")
    _add_host(conn, "10.50.3.5")
    scope.replace_rules(conn, [("10.50.0.0/22", 1, None)])
    assert _parent_of(conn, "10.50.3.5") == "net:10.50.0.0/22"


def test_explicit_label_wins_over_scope_cidr():
    conn = _conn()
    _add_host(conn, "10.60.0.5")
    scope.replace_rules(conn, [("10.60.0.0/24", 1, None)])
    subnets.replace_subnets(conn, [("10.60.0.0/24", "DMZ")])
    label = next(e["data"]["label"] for e in queries.graph_elements(conn) if e["data"]["kind"] == "subnet")
    assert "DMZ" in label


def test_unmatched_host_falls_back_while_others_group():
    conn = _conn()
    _add_host(conn, "10.0.0.5")       # in the defined /16
    _add_host(conn, "203.0.113.9")    # outside everything -> /24 fallback
    subnets.replace_subnets(conn, [("10.0.0.0/16", None)])
    assert _subnet_ids(conn) == ["10.0.0.0/16", "203.0.113.0/24"]


def test_subnets_endpoint(client):
    r = client.post("/api/subnets", data={"text": "10.0.0.0/16 Office\n10.0.5.0/24 Servers"}, headers=W)
    assert r.status_code == 200 and r.json()["subnets"] == 2
    got = client.get("/api/subnets").json()["subnets"]
    assert {s["cidr"] for s in got} == {"10.0.0.0/16", "10.0.5.0/24"}
    assert client.post("/api/subnets", data={"text": "not-a-cidr"}, headers=W).status_code == 400
