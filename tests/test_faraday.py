"""Faraday ingest: hosts/services merge like a scan; vulns become findings."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siege import db, merge
from siege.parsers import faraday as fd
from siege.parsers import nmap
from siege.server import create_app

FIXTURES = Path(__file__).parent / "fixtures"
W = {"X-Requested-By": "siege", "Authorization": "Bearer t0ken"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "e.sqlite", tmp_path / "ev", engagement="fday", token="t0ken")
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t0ken"})
        yield c


def _load():
    return fd.parse_bytes((FIXTURES / "faraday_workspace.json").read_bytes(), "ws.json")


def test_parser_extracts_hosts_services_vulns():
    r = _load()
    assert {h.ip for h in r.hosts} == {"10.10.10.20", "10.10.10.50"}
    fs = next(h for h in r.hosts if h.ip == "10.10.10.20")
    assert {s.port for s in fs.services} == {445}  # telnet (closed) dropped
    titles = {v.title: v for v in r.vulns}
    assert titles["SMB signing not required"].port == 445  # service-scoped
    assert titles["SMB signing not required"].severity == "medium"  # 'med' normalized
    assert titles["EternalBlue (MS17-010) likely"].severity == "critical"
    assert titles["EternalBlue (MS17-010) likely"].port is None  # host-scoped
    assert "10.10.10.99" in {v.host_ip for v in r.vulns}  # flat orphan vuln


def test_merge_creates_findings_and_dedupes():
    conn = db.connect(":memory:")
    db.init_db(conn)
    summary = merge.merge_faraday(conn, _load())
    assert summary["hosts"] == 2
    assert summary["findings_new"] == 2  # the .99 orphan has no scanned host
    assert summary["unmatched_vulns"] == 1

    # service-scoped finding is attached to the right service
    smb = conn.execute("SELECT id FROM services WHERE port = 445").fetchone()
    f = conn.execute("SELECT * FROM findings WHERE title = 'SMB signing not required'").fetchone()
    assert f["service_id"] == smb["id"]
    eb = conn.execute("SELECT * FROM findings WHERE title LIKE 'EternalBlue%'").fetchone()
    assert eb["service_id"] is None and eb["severity"] == "critical"

    # re-import must not duplicate findings
    merge.merge_faraday(conn, _load())
    assert conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 2


def test_faraday_enriches_prior_nmap_host():
    conn = db.connect(":memory:")
    db.init_db(conn)
    with open(FIXTURES / "deepscan.xml") as f:
        merge.ingest(conn, nmap.parse(f.read(), "deepscan.xml"))
    before = conn.execute("SELECT COUNT(*) AS n FROM hosts").fetchone()["n"]
    merge.merge_faraday(conn, _load())
    after = conn.execute("SELECT COUNT(*) AS n FROM hosts").fetchone()["n"]
    # 10.10.10.20 already existed (merge), 10.10.10.50 is new -> exactly one added
    assert after == before + 1


def test_faraday_endpoint(client):
    with open(FIXTURES / "faraday_workspace.json", "rb") as f:
        r = client.post("/api/import/faraday", files={"file": ("ws.json", f, "application/json")}, headers=W)
    assert r.status_code == 200, r.text
    assert r.json()["findings_new"] == 2

    hid = next(h["id"] for h in client.get("/api/hosts").json() if h["ip"] == "10.10.10.20")
    detail = client.get(f"/api/hosts/{hid}").json()
    assert any("EternalBlue" in f["title"] for f in detail["findings"])


def test_faraday_bad_json_400(client):
    r = client.post("/api/import/faraday", files={"file": ("x.json", b"not json", "application/json")}, headers=W)
    assert r.status_code == 400
