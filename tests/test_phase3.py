"""Phase 3: BloodHound ingest, chosen-path edges, Ghostwriter push (mocked)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siege import attackpath, db, merge
from siege.export import ghostwriter as gw
from siege.models import classify_os
from siege.parsers import bloodhound as bh
from siege.parsers import nmap
from siege.server import create_app

FIXTURES = Path(__file__).parent / "fixtures"
W = {"X-Requested-By": "siege", "Authorization": "Bearer t0ken"}


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "e.sqlite", tmp_path / "ev", engagement="p3", token="t0ken")
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t0ken"})
        c.tmp = tmp_path
        yield c


def _import_nmap(client):
    with open(FIXTURES / "deepscan.xml", "rb") as f:
        assert client.post("/api/import", files={"file": ("d.xml", f, "text/xml")}, headers=W).status_code == 200


def _hid(client, ip):
    return next(h["id"] for h in client.get("/api/hosts").json() if h["ip"] == ip)


# --- unit: classification / parser ------------------------------------------

def test_classify_os():
    assert classify_os("Windows Server 2019") == "windows"
    assert classify_os("Ubuntu 22.04 (Linux)") == "linux"
    assert classify_os("Cisco IOS") == "other"
    assert classify_os(None) is None


def test_bloodhound_parser_reads_computers():
    data = (FIXTURES / "bloodhound_computers.json").read_bytes()
    result = bh.parse_bytes(data, "computers.json")
    names = {c.name for c in result.computers}
    assert names == {"fileserver", "gw", "ws07"}
    fs = next(c for c in result.computers if c.name == "fileserver")
    assert fs.high_value and fs.os_family == "windows" and fs.domain == "LAB.EXAMPLE"
    gwc = next(c for c in result.computers if c.name == "gw")
    assert gwc.os_family == "linux"


def test_bloodhound_parser_reads_sharphound_zip():
    data = (FIXTURES / "bloodhound_computers.json").read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("20260101_computers.json", data)
        zf.writestr("20260101_users.json", json.dumps({"meta": {"type": "users"}, "data": []}))
    result = bh.parse_bytes(buf.getvalue(), "export.zip")
    assert len(result.computers) == 3


# --- bloodhound merge -------------------------------------------------------

def test_bloodhound_annotates_only_scanned_domain_hosts():
    conn = db.connect(":memory:")
    db.init_db(conn)
    with open(FIXTURES / "deepscan.xml") as f:
        merge.ingest(conn, nmap.parse(f.read(), "deepscan.xml"))
    result = bh.parse_bytes((FIXTURES / "bloodhound_computers.json").read_bytes(), "c.json")
    summary = merge.merge_bloodhound(conn, result)

    # FILESERVER and GW match scanned hosts; WS07 wasn't scanned -> unmatched.
    assert set(summary["matched"]) == {"10.10.10.20", "10.10.10.5"}
    assert summary["unmatched"] == ["WS07.LAB.EXAMPLE"]

    fs = conn.execute("SELECT * FROM hosts WHERE ip = '10.10.10.20'").fetchone()
    assert fs["domain"] == "LAB.EXAMPLE"
    assert fs["dns_name"] == "FILESERVER.LAB.EXAMPLE"
    assert fs["ad_high_value"] == 1
    assert fs["os_family"] == "windows"

    gw_host = conn.execute("SELECT * FROM hosts WHERE ip = '10.10.10.5'").fetchone()
    assert gw_host["domain"] == "LAB.EXAMPLE"
    assert gw_host["os_family"] == "linux"  # Linux box handled cleanly
    assert gw_host["ad_high_value"] == 0


def test_standalone_hosts_have_no_ad_fields():
    conn = db.connect(":memory:")
    db.init_db(conn)
    with open(FIXTURES / "deepscan.xml") as f:
        merge.ingest(conn, nmap.parse(f.read(), "deepscan.xml"))
    # No BloodHound import: every host stays domainless.
    for h in conn.execute("SELECT * FROM hosts"):
        assert h["domain"] is None and h["ad_high_value"] == 0


# --- attack path ------------------------------------------------------------

def test_attack_path_describe_is_os_aware():
    wtype, wlabel, wdesc = attackpath.describe("AdminTo", "windows")
    assert wtype == "pivot" and wlabel == "AdminTo" and "SMB" in wdesc
    _, _, ldesc = attackpath.describe("AdminTo", "linux")
    assert "SSH" in ldesc
    assert attackpath.describe("MadeUpEdge", "windows") == ("operator", "MadeUpEdge", None)


def test_attack_path_endpoint_draws_edges(client):
    _import_nmap(client)
    # annotate with AD so target OS families are known
    client.post("/api/import/bloodhound",
                files={"file": ("c.json", (FIXTURES / "bloodhound_computers.json").read_bytes(), "application/json")},
                headers=W)
    gw_id, fs_id = _hid(client, "10.10.10.5"), _hid(client, "10.10.10.20")

    r = client.post("/api/attack-path", json={
        "path": [gw_id, fs_id],
        "steps": [{"edge": "AdminTo"}],
    }, headers=W)
    assert r.status_code == 201, r.text
    assert len(r.json()["created"]) == 1

    els = client.get("/api/graph").json()["elements"]
    edge = next(e for e in els if e["group"] == "edges")
    assert edge["data"]["type"] == "pivot"
    assert edge["data"]["label"] == "AdminTo"
    assert "SMB" in edge["data"]["description"]  # target FILESERVER is Windows


def test_attack_path_length_mismatch_422(client):
    _import_nmap(client)
    a, b = _hid(client, "10.10.10.5"), _hid(client, "10.10.10.20")
    r = client.post("/api/attack-path", json={"path": [a, b], "steps": []}, headers=W)
    assert r.status_code == 422


# --- ghostwriter (mocked transport) -----------------------------------------

def test_ghostwriter_client_builds_graphql():
    sent = []

    def fake_transport(url, headers, body):
        sent.append((url, headers, json.loads(body)))
        payload = json.loads(body)
        if "CreateFinding" in payload["query"]:
            return {"data": {"insert_reportFindingLink_one": {"id": 42, "title": "x"}}}
        if "UploadEvidence" in payload["query"]:
            return {"data": {"insert_evidence_one": {"id": 7, "friendlyName": "n"}}}
        return {"data": {"__typename": "query_root"}}

    c = gw.GhostwriterClient("https://gw.example", "secret", transport=fake_transport)
    assert c.endpoint == "https://gw.example/v1/graphql"
    assert c.test_connection() is True
    fid = c.create_finding(1, {"title": "RCE", "severity": "critical", "notes": "details"})
    assert fid == 42
    # severity mapped, bearer header set
    _, headers, payload = sent[1]
    assert headers["Authorization"] == "Bearer secret"
    assert payload["variables"]["object"]["severity"] == "Critical"
    eid = c.upload_evidence(42, "shot.png", b"\x89PNG", "cap")
    assert eid == 7


def test_ghostwriter_errors_surface():
    def erroring(url, headers, body):
        return {"errors": [{"message": "permission denied"}]}

    c = gw.GhostwriterClient("https://gw.example/v1/graphql", "t", transport=erroring)
    with pytest.raises(gw.GhostwriterError):
        c.create_finding(1, {"title": "x"})


def test_ghostwriter_push_aggregates_and_tolerates_failure():
    calls = {"n": 0}

    def flaky(url, headers, body):
        payload = json.loads(body)
        if "CreateFinding" in payload["query"]:
            calls["n"] += 1
            if calls["n"] == 2:
                return {"errors": [{"message": "boom"}]}
            return {"data": {"insert_reportFindingLink_one": {"id": calls["n"], "title": "t"}}}
        return {"data": {"insert_evidence_one": {"id": 1, "friendlyName": "n"}}}

    c = gw.GhostwriterClient("https://gw.example", "t", transport=flaky)
    log = gw.push(c, 1,
                  [{"title": "a"}, {"title": "b"}],
                  [{"name": "e1", "content": b"x", "finding_index": 0},
                   {"name": "e2", "content": b"y", "finding_index": 1}])  # links to failed finding
    assert log["findings"][0]["ok"] is True
    assert log["findings"][1]["ok"] is False
    assert log["evidence"][0]["ok"] is True
    assert log["evidence"][1]["ok"] is False  # couldn't link to the failed finding
    assert log["errors"]


def test_ghostwriter_endpoint_offline(client, monkeypatch):
    _import_nmap(client)
    hid = _hid(client, "10.10.10.5")
    client.post("/api/findings", json={"host_id": hid, "title": "Weak config", "severity": "high"}, headers=W)

    captured = {}

    def fake_transport(url, headers, body):
        captured["url"] = url
        payload = json.loads(body)
        if "CreateFinding" in payload["query"]:
            return {"data": {"insert_reportFindingLink_one": {"id": 1, "title": "t"}}}
        return {"data": {"__typename": "query_root"}}

    monkeypatch.setattr(gw, "_urllib_transport", fake_transport)
    r = client.post("/api/export/ghostwriter",
                    json={"url": "https://gw.example", "token": "secret", "report_id": 9}, headers=W)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["unverified"] is True
    assert out["findings"][0]["ok"] is True
    assert captured["url"] == "https://gw.example/v1/graphql"
