"""Delete/edit endpoints (mistake recovery) + operator attribution."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siege.server import create_app

FIXTURES = Path(__file__).parent / "fixtures"
W = {"X-Requested-By": "siege", "Authorization": "Bearer t0ken"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "e.sqlite", tmp_path / "ev", engagement="crud", token="t0ken")
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t0ken"})
        c.tmp = tmp_path
        yield c


def _import(client):
    with open(FIXTURES / "deepscan.xml", "rb") as f:
        assert client.post("/api/import", files={"file": ("d.xml", f, "text/xml")}, headers=W).status_code == 200


def _hid(client, ip):
    return next(h["id"] for h in client.get("/api/hosts").json() if h["ip"] == ip)


def test_delete_host_cascades(client):
    _import(client)
    hid = _hid(client, "10.10.10.5")
    # add a finding + evidence so we can prove the cascade
    f = client.post("/api/findings", json={"host_id": hid, "title": "x", "severity": "low"}, headers=W).json()
    client.post("/api/evidence", data={"finding_id": f["id"], "kind": "screenshot"},
                files={"file": ("a.png", PNG, "image/png")}, headers=W)
    assert client.delete(f"/api/hosts/{hid}?actor=alice", headers=W).status_code == 204
    assert client.get(f"/api/hosts/{hid}").status_code == 404
    assert all(h["ip"] != "10.10.10.5" for h in client.get("/api/hosts").json())
    # orphan blob swept (no evidence rows remain referencing it)
    evdir = client.tmp / "ev"
    assert not any(p.is_file() for sub in evdir.iterdir() if sub.is_dir() for p in sub.iterdir())
    ev = client.get("/api/events").json()
    assert any(e["type"] == "host_deleted" and e["actor"] == "alice" for e in ev)


def test_delete_host_404(client):
    assert client.delete("/api/hosts/9999", headers=W).status_code == 404


def test_edit_finding(client):
    _import(client)
    hid = _hid(client, "10.10.10.5")
    f = client.post("/api/findings", json={"host_id": hid, "title": "typo", "severity": "low", "created_by": "bob"}, headers=W).json()
    assert f["created_by"] == "bob"
    r = client.patch(f"/api/findings/{f['id']}", json={"title": "Fixed title", "severity": "high"}, headers=W)
    assert r.status_code == 200
    assert r.json()["title"] == "Fixed title" and r.json()["severity"] == "high"
    assert client.patch(f"/api/findings/{f['id']}", json={"severity": "bogus"}, headers=W).status_code == 422
    assert client.patch("/api/findings/9999", json={"severity": "high"}, headers=W).status_code == 404


def test_delete_finding(client):
    _import(client)
    hid = _hid(client, "10.10.10.5")
    f = client.post("/api/findings", json={"host_id": hid, "title": "x"}, headers=W).json()
    assert client.delete(f"/api/findings/{f['id']}", headers=W).status_code == 204
    assert client.delete(f"/api/findings/{f['id']}", headers=W).status_code == 404
    assert client.get(f"/api/hosts/{hid}").json()["findings"] == []


def test_delete_evidence_keeps_shared_blob(client):
    _import(client)
    hid = _hid(client, "10.10.10.5")
    svc = client.get(f"/api/hosts/{hid}").json()["services"][0]
    # two evidence rows sharing one blob (same bytes dedupe to one file)
    e1 = client.post("/api/evidence", data={"host_id": hid, "kind": "screenshot"},
                     files={"file": ("a.png", PNG, "image/png")}, headers=W).json()
    e2 = client.post("/api/evidence", data={"service_id": svc["id"], "kind": "screenshot"},
                     files={"file": ("b.png", PNG, "image/png")}, headers=W).json()
    assert e1["path"] == e2["path"]
    blob = client.tmp / "ev" / e1["path"]
    # delete one row: blob must survive (still referenced by the other)
    assert client.delete(f"/api/evidence/{e1['id']}", headers=W).status_code == 204
    assert blob.exists()
    # delete the second: blob now swept
    assert client.delete(f"/api/evidence/{e2['id']}", headers=W).status_code == 204
    assert not blob.exists()


def test_operator_attribution_threads_through(client):
    _import(client)
    a, b = _hid(client, "10.10.10.5"), _hid(client, "10.10.10.20")
    client.post("/api/findings", json={"host_id": a, "title": "f", "created_by": "carol"}, headers=W)
    client.post("/api/edges", json={"src_host_id": a, "dst_host_id": b, "type": "pivot", "created_by": "carol"}, headers=W)
    client.post("/api/evidence", data={"host_id": a, "kind": "note", "note": "n", "added_by": "carol"}, headers=W)
    client.patch(f"/api/hosts/{a}", json={"state": "owned", "actor": "carol"}, headers=W)
    actors = {e["actor"] for e in client.get("/api/events").json()}
    assert "carol" in actors
    detail = client.get(f"/api/hosts/{a}").json()
    assert detail["findings"][0]["created_by"] == "carol"
    assert detail["evidence"][0]["added_by"] == "carol"
