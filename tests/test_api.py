"""Phase 1 API tests: import, read, findings, evidence, export, local hardening."""

from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siege import db
from siege.server import create_app, main

FIXTURES = Path(__file__).parent / "fixtures"
W = {"X-Requested-By": "siege"}  # required on every write
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "eng.sqlite", tmp_path / "evidence", engagement="practice-01", token="t0ken")
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t0ken"})  # every /api call is authed by default
        c.tmp = tmp_path
        yield c


def _import(client, name):
    with open(FIXTURES / name, "rb") as f:
        r = client.post("/api/import", files={"file": (name, f, "text/xml")}, data={"tool": "nmap"}, headers=W)
    assert r.status_code == 200, r.text
    return r.json()


def _host_id(client, ip):
    return next(h["id"] for h in client.get("/api/hosts").json() if h["ip"] == ip)


def test_import_twice_merges(client):
    _import(client, "pingsweep.xml")
    _import(client, "deepscan.xml")
    hosts = client.get("/api/hosts").json()
    assert len(hosts) == 2
    by_ip = {h["ip"]: h for h in hosts}
    assert by_ip["10.10.10.5"]["open_ports"] == 2
    assert by_ip["10.10.10.20"]["open_ports"] == 2


def test_host_detail_and_graph(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    d = client.get(f"/api/hosts/{hid}").json()
    assert {s["port"] for s in d["services"]} == {22, 80}
    assert client.get("/api/hosts/9999").status_code == 404

    els = client.get("/api/graph").json()["elements"]
    subnets = [e for e in els if e["data"].get("kind") == "subnet"]
    hosts = [e for e in els if e["data"].get("kind") == "host"]
    assert [s["data"]["id"] for s in subnets] == ["net:10.10.10.0/24"]
    assert all(h["data"]["parent"] == "net:10.10.10.0/24" for h in hosts)
    assert all(e["data"].get("kind") != "service" for e in els)  # ports are badges, not nodes


def test_bad_import_is_400_not_500(client):
    r = client.post("/api/import", files={"file": ("x.xml", b"<foo/>", "text/xml")}, headers=W)
    assert r.status_code == 400
    r = client.post("/api/import", files={"file": ("x.xml", b"not xml", "text/xml")}, headers=W)
    assert r.status_code == 400


def test_writes_require_header(client):
    with open(FIXTURES / "pingsweep.xml", "rb") as f:
        r = client.post("/api/import", files={"file": ("p.xml", f, "text/xml")})
    assert r.status_code == 403


def test_rejects_foreign_host_header(client):
    r = client.get("/api/hosts", headers={"Host": "attacker.example"})
    assert r.status_code == 400


def test_security_headers_present(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_finding_severity_enum(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    ok = client.post("/api/findings", json={"host_id": hid, "title": "Weak SSH config", "severity": "high"}, headers=W)
    assert ok.status_code == 201
    bad = client.post("/api/findings", json={"host_id": hid, "title": "x", "severity": "urgent"}, headers=W)
    assert bad.status_code == 422
    both = client.post("/api/findings", json={"title": "x"}, headers=W)
    assert both.status_code == 422


def test_db_check_constraints():
    conn = db.connect(":memory:")
    db.init_db(conn)
    conn.execute("INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.0.0.1', 't', 't')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO findings (host_id, title, severity, created_at) VALUES (1, 'x', 'urgent', 't')")
    # evidence must point at exactly one target
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO evidence (kind, sha256, path, added_at) VALUES ('note', 'a', 'b', 't')")
    conn.execute("INSERT INTO findings (host_id, title, created_at) VALUES (1, 'f', 't')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO evidence (host_id, finding_id, kind, sha256, path, added_at) "
            "VALUES (1, 1, 'note', 'a', 'b', 't')"
        )


def test_evidence_store_by_sha_and_cascade(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    svc = client.get(f"/api/hosts/{hid}").json()["services"][0]

    r1 = client.post("/api/evidence", data={"host_id": hid, "kind": "screenshot", "caption": "login page"},
                     files={"file": ("shot.png", PNG, "image/png")}, headers=W)
    assert r1.status_code == 201, r1.text
    r2 = client.post("/api/evidence", data={"service_id": svc["id"], "kind": "screenshot"},
                     files={"file": ("same.png", PNG, "image/png")}, headers=W)
    e1, e2 = r1.json(), r2.json()
    assert e1["sha256"] == e2["sha256"] and e1["path"] == e2["path"]  # deduped on disk
    stored = client.tmp / "evidence" / e1["path"]
    assert stored.read_bytes() == PNG

    note = client.post("/api/evidence", data={"host_id": hid, "kind": "note", "note": "creds reused from .20"}, headers=W)
    assert note.status_code == 201

    detail = client.get(f"/api/hosts/{hid}").json()
    assert len(detail["evidence"]) == 3
    assert {e["target"]["type"] for e in detail["evidence"]} == {"host", "service"}


def test_evidence_validation(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    none = client.post("/api/evidence", data={"kind": "note", "note": "x"}, headers=W)
    assert none.status_code == 422
    two = client.post("/api/evidence", data={"host_id": hid, "finding_id": 1, "kind": "note", "note": "x"}, headers=W)
    assert two.status_code == 422
    badkind = client.post("/api/evidence", data={"host_id": hid, "kind": "video", "note": "x"}, headers=W)
    assert badkind.status_code == 422
    missing = client.post("/api/evidence", data={"host_id": 9999, "kind": "note", "note": "x"}, headers=W)
    assert missing.status_code == 404
    empty = client.post("/api/evidence", data={"host_id": hid, "kind": "log"}, headers=W)
    assert empty.status_code == 422


def test_evidence_content_served_safely(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    img = client.post("/api/evidence", data={"host_id": hid, "kind": "screenshot"},
                      files={"file": ("a.png", PNG, "image/png")}, headers=W).json()
    page = client.post("/api/evidence", data={"host_id": hid, "kind": "log"},
                       files={"file": ("page.html", b"<html>hi</html>", "text/html")}, headers=W).json()

    r = client.get(f"/api/evidence/{img['id']}/content")
    assert r.headers["content-type"] == "image/png"
    assert r.headers["content-disposition"].startswith("inline")

    # Non-image uploads are never served with their claimed type.
    r = client.get(f"/api/evidence/{page['id']}/content")
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"].startswith("attachment")
    assert "sandbox" in r.headers["content-security-policy"]


def test_export_bundle(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    client.post("/api/evidence", data={"host_id": hid, "kind": "screenshot", "caption": "a|b *c*"},
                files={"file": ("../../etc/passwd shot.png", PNG, "image/png")}, headers=W)

    r = client.get("/api/export/evidence.zip")
    assert r.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert "manifest.json" in names and "manifest.md" in names
    files = [n for n in names if n.startswith("evidence/")]
    assert len(files) == 1
    assert ".." not in files[0] and "/" not in files[0].removeprefix("evidence/")

    manifest = json.loads(zf.read("manifest.json"))
    item = manifest["items"][0]
    assert manifest["engagement"] == "practice-01"
    assert item["integrity_ok"] is True
    assert item["target"]["host_ip"] == "10.10.10.5"
    assert zf.read(item["file"]) == PNG

    md = zf.read("manifest.md").decode()
    assert "a\\|b \\*c\\*" in md  # caption can't break the table or add formatting


def test_api_requires_token(client):
    assert client.get("/api/hosts", headers={"Authorization": ""}).status_code == 401
    assert client.get("/api/hosts", headers={"Authorization": "Bearer wrong"}).status_code == 401
    # The SPA shell and wallboard are public (they hold no data).
    assert client.get("/", headers={"Authorization": ""}).status_code == 200
    assert client.get("/wall", headers={"Authorization": ""}).status_code == 200


def test_scope_flags_out_of_scope_hosts(client):
    _import(client, "deepscan.xml")  # 10.10.10.5 and .20
    # Only allow .5; everything else becomes out of scope.
    r = client.post("/api/scope", data={"text": "10.10.10.5\n!10.10.10.0/28  carve-out"}, headers=W)
    assert r.status_code == 200, r.text
    hosts = {h["ip"]: h for h in client.get("/api/hosts").json()}
    assert hosts["10.10.10.20"]["in_scope"] == 0
    # .5 is inside the include but also inside the !/28 exclude — exclusions win.
    assert hosts["10.10.10.5"]["in_scope"] == 0

    scope = client.get("/api/scope").json()
    assert scope["out_of_scope_hosts"] == 2


def test_scope_bad_cidr_is_400(client):
    r = client.post("/api/scope", data={"text": "not-a-cidr"}, headers=W)
    assert r.status_code == 400


def test_host_state_patch(client):
    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    r = client.patch(f"/api/hosts/{hid}", json={"state": "owned"}, headers=W)
    assert r.status_code == 200 and r.json()["state"] == "owned"
    assert client.patch(f"/api/hosts/{hid}", json={"state": "pwned"}, headers=W).status_code == 422
    # a state_change event is logged
    evs = client.get("/api/events").json()
    assert any(e["type"] == "state_change" for e in evs)


def test_operator_edges(client):
    _import(client, "deepscan.xml")
    a, b = _host_id(client, "10.10.10.5"), _host_id(client, "10.10.10.20")
    r = client.post("/api/edges", json={"src_host_id": a, "dst_host_id": b, "type": "pivot", "label": "ssh key reuse"}, headers=W)
    assert r.status_code == 201
    eid = r.json()["id"]
    # shows up in the graph as an edge, not a node
    els = client.get("/api/graph").json()["elements"]
    assert any(e["group"] == "edges" and e["data"]["type"] == "pivot" for e in els)
    # duplicate rejected, self-loop rejected, missing host 404
    assert client.post("/api/edges", json={"src_host_id": a, "dst_host_id": b, "type": "pivot"}, headers=W).status_code == 409
    assert client.post("/api/edges", json={"src_host_id": a, "dst_host_id": a, "type": "pivot"}, headers=W).status_code == 422
    assert client.post("/api/edges", json={"src_host_id": a, "dst_host_id": 9999, "type": "pivot"}, headers=W).status_code == 404
    assert client.delete(f"/api/edges/{eid}", headers=W).status_code == 204
    assert client.delete(f"/api/edges/{eid}", headers=W).status_code == 404


def test_websocket_rejects_bad_token_and_broadcasts(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=wrong") as ws:
            ws.receive_text()

    _import(client, "deepscan.xml")
    hid = _host_id(client, "10.10.10.5")
    with client.websocket_connect("/ws?token=t0ken") as ws:
        client.post("/api/findings", json={"host_id": hid, "title": "live", "severity": "low"}, headers=W)
        msg = ws.receive_json()
        assert msg["type"] == "finding_added"
        assert msg["engagement"] == "practice-01"


def test_selfsigned_cert_generates():
    from siege.server import _selfsigned_cert

    cert, key = _selfsigned_cert()
    assert Path(cert).read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" in Path(key).read_text()


def test_main_refuses_offbox_without_tls(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--db", str(tmp_path / "e.sqlite"), "--bind", "0.0.0.0"])
    assert "refusing to bind" in str(exc.value)
