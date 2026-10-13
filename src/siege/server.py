"""FastAPI app for one engagement.

Run:  siege --db engagement.sqlite
The startup banner prints a tokenized URL — open it to authenticate. Put the
same URL (it carries ?token=) on the room TV at /wall for a live wallboard.

Phase 2 hardening (still no multi-user accounts; see auth.py):
- Per-engagement bearer token gates every /api/* and /ws request.
- Binds loopback by default. Binding off-loopback (team VPN / Tailscale)
  requires BOTH an explicit --bind and TLS (--tls-cert/--tls-key or
  --tls-selfsigned); we refuse plaintext off the box.
- TrustedHostMiddleware blocks DNS-rebinding; writes require X-Requested-By.
- Strict security headers / CSP on every response.
- Out-of-scope hosts are flagged on import and surfaced loudly in the UI.

TODO(phase 3): BloodHound/Faraday ingest, Ghostwriter/SysReptor push.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import sqlite3
import sys
import tempfile
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator
from starlette.background import BackgroundTask
from starlette.websockets import WebSocketDisconnect

from . import attackpath, auth, db, evidence as evstore, merge, parsers, queries, scope, subnets as subnets_mod
from .export import bundle
from .export import ghostwriter as gw
from .hub import Hub
from .models import EDGE_TYPES, EVIDENCE_KINDS, HostState
from .parsers import bloodhound as bh_parser
from .parsers import faraday as fd_parser

MAX_IMPORT_BYTES = 100 * 1024 * 1024
MAX_EVIDENCE_BYTES = 50 * 1024 * 1024
MAX_SCOPE_BYTES = 1 * 1024 * 1024
MAX_BLOODHOUND_BYTES = 200 * 1024 * 1024
CSRF_HEADER = "x-requested-by"
CSRF_VALUE = "siege"
LOCAL_HOSTS = ["127.0.0.1", "localhost", "[::1]", "::1", "testserver"]
EDITABLE_STATES = tuple(s.value for s in HostState)

STATIC_DIR = Path(str(resources.files("siege") / "static"))

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' blob:; connect-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


Severity = Literal["info", "low", "medium", "high", "critical"]


class FindingIn(BaseModel):
    host_id: int | None = None
    service_id: int | None = None
    title: str = Field(min_length=1, max_length=300)
    severity: Severity = "info"
    notes: str | None = Field(default=None, max_length=20000)
    created_by: str = "operator"

    @model_validator(mode="after")
    def _one_target(self):
        if (self.host_id is None) == (self.service_id is None):
            raise ValueError("set exactly one of host_id or service_id")
        return self


class FindingPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    severity: Severity | None = None
    notes: str | None = Field(default=None, max_length=20000)


class HostPatch(BaseModel):
    state: Literal["discovered", "enumerated", "vulnerable", "foothold", "owned", "out_of_scope"] | None = None
    in_scope: bool | None = None
    actor: str = "operator"


class EdgeIn(BaseModel):
    src_host_id: int
    dst_host_id: int
    type: Literal["pivot", "creds_reuse", "operator", "subnet", "traceroute"] = "operator"
    label: str | None = Field(default=None, max_length=200)
    created_by: str = "operator"


class AttackStep(BaseModel):
    edge: str | None = Field(default=None, max_length=100)  # BloodHound edge name
    type: str | None = None  # optional siege edge-type override
    note: str | None = Field(default=None, max_length=2000)  # overrides auto description


class AttackPathIn(BaseModel):
    path: list[int] = Field(min_length=2)  # host ids in order
    steps: list[AttackStep] = Field(default_factory=list)
    created_by: str = "operator"


class GhostwriterPush(BaseModel):
    url: str = Field(min_length=1)
    token: str = Field(min_length=1)  # treated as a secret; never logged or stored
    report_id: int


def create_app(db_path: str | Path, evidence_dir: str | Path, engagement: str | None = None, token: str | None = None) -> FastAPI:
    db_path = str(db_path)
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    engagement = engagement or Path(db_path).stem
    token = token or auth.load_or_create_token(db_path)
    hub = Hub()

    init = db.connect(db_path)
    db.init_db(init)
    init.close()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Bind the running loop so the hub can broadcast from threadpool threads.
        hub.bind_loop(asyncio.get_running_loop())
        yield

    app = FastAPI(title="siege", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.hub = hub
    app.state.token = token
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=LOCAL_HOSTS)

    def _authed(request: Request) -> bool:
        presented = request.headers.get("authorization") or request.query_params.get("token")
        return auth.token_matches(token, presented)

    @app.middleware("http")
    async def gate(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            if not _authed(request):
                return JSONResponse({"detail": "invalid or missing token"}, status_code=401)
            if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
                return JSONResponse({"detail": "missing X-Requested-By header"}, status_code=403)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    def get_conn():
        conn = db.connect(db_path)
        try:
            yield conn
        finally:
            conn.close()

    def notify(msg: dict):
        hub.notify(msg | {"engagement": engagement})

    def _sweep_orphan_blobs(conn: sqlite3.Connection) -> None:
        referenced = {r["path"] for r in conn.execute("SELECT path FROM evidence")}
        evstore.sweep_orphans(evidence_dir, referenced)

    # --- import -----------------------------------------------------------

    @app.post("/api/import")
    def import_scan(
        file: UploadFile = File(...),
        tool: str = Form("nmap"),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        try:
            parse = parsers.get(tool)
        except KeyError:
            raise HTTPException(400, f"unknown tool; available: {parsers.available()}")
        data = file.file.read(MAX_IMPORT_BYTES + 1)
        if len(data) > MAX_IMPORT_BYTES:
            raise HTTPException(413, "import too large")
        try:
            raw = data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "import must be UTF-8 text")
        try:
            scan = parse(raw, file.filename or "upload")
        except Exception as exc:
            raise HTTPException(400, f"could not parse {tool} input: {type(exc).__name__}")
        summary = merge.ingest(conn, scan)
        notify({"type": "import", **summary})
        return summary

    # --- read -------------------------------------------------------------

    @app.get("/api/hosts")
    def list_hosts(conn: sqlite3.Connection = Depends(get_conn)):
        return queries.list_hosts(conn)

    @app.get("/api/hosts/{host_id}")
    def host_detail(host_id: int, conn: sqlite3.Connection = Depends(get_conn)):
        host = queries.get_host(conn, host_id)
        if host is None:
            raise HTTPException(404, "no such host")
        return {
            "host": host,
            "services": queries.host_services(conn, host_id),
            "findings": queries.host_findings(conn, host_id),
            "evidence": queries.host_evidence(conn, host_id),
        }

    @app.patch("/api/hosts/{host_id}")
    def patch_host(host_id: int, body: HostPatch, conn: sqlite3.Connection = Depends(get_conn)):
        host = queries.get_host(conn, host_id)
        if host is None:
            raise HTTPException(404, "no such host")
        if body.state is not None:
            conn.execute("UPDATE hosts SET state = ? WHERE id = ?", (body.state, host_id))
            conn.execute(
                "INSERT INTO events (type, actor, ts, payload) "
                "VALUES ('state_change', ?, ?, json_object('host_id', ?, 'from', ?, 'to', ?, 'ip', ?))",
                (body.actor, db.utcnow(), host_id, host["state"], body.state, host["ip"]),
            )
        if body.in_scope is not None:
            conn.execute("UPDATE hosts SET in_scope = ? WHERE id = ?", (1 if body.in_scope else 0, host_id))
        conn.commit()
        notify({"type": "state_change", "host_id": host_id})
        return queries.get_host(conn, host_id)

    @app.delete("/api/hosts/{host_id}", status_code=204)
    def delete_host(host_id: int, actor: str = "operator", conn: sqlite3.Connection = Depends(get_conn)):
        host = queries.get_host(conn, host_id)
        if host is None:
            raise HTTPException(404, "no such host")
        # FK ON DELETE CASCADE removes the host's services, findings, evidence
        # rows, and edges. On-disk evidence blobs are swept afterward (dedup-safe).
        conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        conn.execute(
            "INSERT INTO events (type, actor, ts, payload) VALUES ('host_deleted', ?, ?, json_object('ip', ?))",
            (actor, db.utcnow(), host["ip"]),
        )
        conn.commit()
        _sweep_orphan_blobs(conn)
        notify({"type": "host_deleted", "host_id": host_id})

    @app.get("/api/graph")
    def graph(conn: sqlite3.Connection = Depends(get_conn)):
        return {"engagement": engagement, "elements": queries.graph_elements(conn)}

    @app.get("/api/events")
    def events(since: int = 0, limit: int = 200, conn: sqlite3.Connection = Depends(get_conn)):
        limit = max(1, min(limit, 1000))
        rows = conn.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?", (since, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- findings ---------------------------------------------------------

    @app.post("/api/findings", status_code=201)
    def create_finding(body: FindingIn, conn: sqlite3.Connection = Depends(get_conn)):
        table, ref = ("hosts", body.host_id) if body.host_id is not None else ("services", body.service_id)
        if conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (ref,)).fetchone() is None:
            raise HTTPException(404, "target does not exist")
        now = db.utcnow()
        cur = conn.execute(
            "INSERT INTO findings (host_id, service_id, title, severity, notes, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (body.host_id, body.service_id, body.title, body.severity, body.notes, body.created_by, now),
        )
        conn.execute(
            "INSERT INTO events (type, actor, ts, payload) "
            "VALUES ('finding_added', ?, ?, json_object('finding_id', ?, 'title', ?, 'severity', ?))",
            (body.created_by, now, cur.lastrowid, body.title, body.severity),
        )
        conn.commit()
        notify({"type": "finding_added", "finding_id": cur.lastrowid, "severity": body.severity})
        return dict(conn.execute("SELECT * FROM findings WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.patch("/api/findings/{finding_id}")
    def patch_finding(finding_id: int, body: FindingPatch, conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "no such finding")
        fields = {k: v for k, v in body.model_dump(exclude_none=True).items()}
        if fields:
            sets = ", ".join(f"{k} = ?" for k in fields)
            conn.execute(f"UPDATE findings SET {sets} WHERE id = ?", (*fields.values(), finding_id))
            conn.commit()
        notify({"type": "finding_updated", "finding_id": finding_id})
        return dict(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone())

    @app.delete("/api/findings/{finding_id}", status_code=204)
    def delete_finding(finding_id: int, conn: sqlite3.Connection = Depends(get_conn)):
        cur = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))  # evidence cascades
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "no such finding")
        _sweep_orphan_blobs(conn)
        notify({"type": "finding_deleted", "finding_id": finding_id})

    # --- edges ------------------------------------------------------------

    @app.post("/api/edges", status_code=201)
    def create_edge(body: EdgeIn, conn: sqlite3.Connection = Depends(get_conn)):
        if body.src_host_id == body.dst_host_id:
            raise HTTPException(422, "an edge needs two different hosts")
        for ref in (body.src_host_id, body.dst_host_id):
            if conn.execute("SELECT 1 FROM hosts WHERE id = ?", (ref,)).fetchone() is None:
                raise HTTPException(404, f"host {ref} does not exist")
        now = db.utcnow()
        try:
            cur = conn.execute(
                "INSERT INTO edges (src_host_id, dst_host_id, type, label, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (body.src_host_id, body.dst_host_id, body.type, body.label, body.created_by, now),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "that edge already exists")
        conn.execute(
            "INSERT INTO events (type, actor, ts, payload) "
            "VALUES ('edge_added', ?, ?, json_object('edge_id', ?, 'type', ?, 'src', ?, 'dst', ?))",
            (body.created_by, now, cur.lastrowid, body.type, body.src_host_id, body.dst_host_id),
        )
        conn.commit()
        notify({"type": "edge_added", "edge_id": cur.lastrowid})
        return dict(conn.execute("SELECT * FROM edges WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.delete("/api/edges/{edge_id}", status_code=204)
    def delete_edge(edge_id: int, conn: sqlite3.Connection = Depends(get_conn)):
        cur = conn.execute("DELETE FROM edges WHERE id = ?", (edge_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "no such edge")
        notify({"type": "edge_removed", "edge_id": edge_id})

    # --- scope ------------------------------------------------------------

    @app.get("/api/scope")
    def get_scope(conn: sqlite3.Connection = Depends(get_conn)):
        rows = [dict(r) for r in conn.execute("SELECT * FROM scope_rules ORDER BY in_scope DESC, cidr")]
        out = conn.execute("SELECT COUNT(*) AS n FROM hosts WHERE in_scope = 0").fetchone()["n"]
        return {"rules": rows, "out_of_scope_hosts": out}

    @app.post("/api/scope")
    def set_scope(
        file: UploadFile | None = File(None),
        text: str | None = Form(None),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if file is not None and file.filename:
            raw = file.file.read(MAX_SCOPE_BYTES + 1)
            if len(raw) > MAX_SCOPE_BYTES:
                raise HTTPException(413, "scope file too large")
            body = raw.decode("utf-8", "replace")
        elif text is not None:
            body = text
        else:
            raise HTTPException(422, "provide a scope file or text")
        try:
            rows = scope.parse_scope_text(body)
        except ValueError as exc:
            raise HTTPException(400, f"bad scope rule: {exc}")
        summary = scope.replace_rules(conn, rows)
        notify({"type": "scope_set", **summary})
        return summary

    # --- subnets (graph grouping) -----------------------------------------

    @app.get("/api/subnets")
    def get_subnets(conn: sqlite3.Connection = Depends(get_conn)):
        return {"subnets": subnets_mod.list_subnets(conn)}

    @app.post("/api/subnets")
    def set_subnets(
        file: UploadFile | None = File(None),
        text: str | None = Form(None),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if file is not None and file.filename:
            raw = file.file.read(MAX_SCOPE_BYTES + 1)
            if len(raw) > MAX_SCOPE_BYTES:
                raise HTTPException(413, "subnets file too large")
            body = raw.decode("utf-8", "replace")
        elif text is not None:
            body = text
        else:
            raise HTTPException(422, "provide a subnets file or text")
        try:
            rows = subnets_mod.parse_subnet_text(body)
        except ValueError as exc:
            raise HTTPException(400, f"bad subnet: {exc}")
        summary = subnets_mod.replace_subnets(conn, rows)
        notify({"type": "subnets_set", **summary})
        return summary

    # --- bloodhound ingest ------------------------------------------------

    @app.post("/api/import/bloodhound")
    def import_bloodhound(
        file: UploadFile = File(...),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        data = file.file.read(MAX_BLOODHOUND_BYTES + 1)
        if len(data) > MAX_BLOODHOUND_BYTES:
            raise HTTPException(413, "bloodhound import too large")
        try:
            result = bh_parser.parse_bytes(data, file.filename or "bloodhound")
        except Exception as exc:
            raise HTTPException(400, f"could not parse bloodhound input: {type(exc).__name__}")
        summary = merge.merge_bloodhound(conn, result)
        notify({"type": "import", "tool": "bloodhound", "matched": len(summary["matched"])})
        return summary

    # --- faraday ingest ---------------------------------------------------

    @app.post("/api/import/faraday")
    def import_faraday(
        file: UploadFile = File(...),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        data = file.file.read(MAX_IMPORT_BYTES + 1)
        if len(data) > MAX_IMPORT_BYTES:
            raise HTTPException(413, "faraday import too large")
        try:
            result = fd_parser.parse_bytes(data, file.filename or "faraday")
        except Exception as exc:
            raise HTTPException(400, f"could not parse faraday input: {type(exc).__name__}")
        summary = merge.merge_faraday(conn, result)
        notify({"type": "import", "tool": "faraday", "findings": summary["findings_new"]})
        return summary

    # --- attack path ------------------------------------------------------

    @app.post("/api/attack-path", status_code=201)
    def create_attack_path(body: AttackPathIn, conn: sqlite3.Connection = Depends(get_conn)):
        try:
            summary = attackpath.apply_path(
                conn, body.path, [s.model_dump() for s in body.steps], body.created_by
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        notify({"type": "edge_added", "path": True, "created": len(summary["created"])})
        return summary

    # --- report push ------------------------------------------------------

    @app.post("/api/export/ghostwriter")
    def push_ghostwriter(body: GhostwriterPush, conn: sqlite3.Connection = Depends(get_conn)):
        # UNVERIFIED against a live Ghostwriter; see export/ghostwriter.py.
        findings = [dict(r) for r in conn.execute("SELECT * FROM findings ORDER BY id")]
        ev_rows = conn.execute("SELECT * FROM evidence ORDER BY id").fetchall()
        find_index = {f["id"]: i for i, f in enumerate(findings)}
        evidence_items = []
        for ev in ev_rows:
            if ev["finding_id"] is None or ev["finding_id"] not in find_index:
                continue  # Ghostwriter evidence must hang off a finding
            content = evstore.resolve(evidence_dir, ev["path"]).read_bytes()
            evidence_items.append({
                "name": bundle.safe_name(ev["original_name"] or ev["kind"]),
                "content": content,
                "caption": ev["caption"],
                "finding_index": find_index[ev["finding_id"]],
            })
        client = gw.GhostwriterClient(body.url, body.token)
        try:
            client.test_connection()
        except Exception as exc:
            raise HTTPException(502, f"ghostwriter unreachable or auth failed: {type(exc).__name__}")
        log = gw.push(client, body.report_id, findings, evidence_items)
        return {"unverified": True, "pushed_to": client.endpoint, **log}

    # --- evidence ---------------------------------------------------------

    @app.post("/api/evidence", status_code=201)
    def add_evidence(
        kind: str = Form(...),
        host_id: int | None = Form(None),
        service_id: int | None = Form(None),
        finding_id: int | None = Form(None),
        caption: str | None = Form(None),
        note: str | None = Form(None),
        added_by: str = Form("operator"),
        file: UploadFile | None = File(None),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if kind not in EVIDENCE_KINDS:
            raise HTTPException(422, f"kind must be one of {EVIDENCE_KINDS}")
        targets = {"hosts": host_id, "services": service_id, "findings": finding_id}
        set_targets = [(t, i) for t, i in targets.items() if i is not None]
        if len(set_targets) != 1:
            raise HTTPException(422, "set exactly one of host_id, service_id, finding_id")
        table, ref = set_targets[0]
        if conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (ref,)).fetchone() is None:
            raise HTTPException(404, "target does not exist")

        if file is not None and file.filename:
            content = file.file.read(MAX_EVIDENCE_BYTES + 1)
            if len(content) > MAX_EVIDENCE_BYTES:
                raise HTTPException(413, "evidence too large")
            original_name = file.filename
        elif note:
            content = note.encode("utf-8")
            original_name = "note.txt"
        else:
            raise HTTPException(422, "provide a file or note text")

        sha, rel = evstore.store(evidence_dir, content)
        now = db.utcnow()
        cur = conn.execute(
            """INSERT INTO evidence
                 (host_id, service_id, finding_id, kind, sha256, path,
                  original_name, caption, added_by, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, service_id, finding_id, kind, sha, rel, original_name, caption, added_by, now),
        )
        conn.execute(
            "INSERT INTO events (type, actor, ts, payload) VALUES ('evidence_added', ?, ?, json_object('evidence_id', ?, 'sha256', ?))",
            (added_by, now, cur.lastrowid, sha),
        )
        conn.commit()
        notify({"type": "evidence_added", "evidence_id": cur.lastrowid})
        return dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (cur.lastrowid,)).fetchone())

    @app.delete("/api/evidence/{evidence_id}", status_code=204)
    def delete_evidence(evidence_id: int, conn: sqlite3.Connection = Depends(get_conn)):
        cur = conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "no such evidence")
        _sweep_orphan_blobs(conn)  # removes the blob only if no other row shares it
        notify({"type": "evidence_deleted", "evidence_id": evidence_id})

    @app.get("/api/evidence/{evidence_id}/content")
    def evidence_content(evidence_id: int, conn: sqlite3.Connection = Depends(get_conn)):
        ev = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if ev is None:
            raise HTTPException(404, "no such evidence")
        path = evstore.resolve(evidence_dir, ev["path"])
        with open(path, "rb") as f:
            head = f.read(16)
        image_type = evstore.sniff_image_type(head)
        name = bundle.safe_name(ev["original_name"])
        return FileResponse(
            path,
            media_type=image_type or "application/octet-stream",
            filename=name,
            content_disposition_type="inline" if image_type else "attachment",
            headers={"Content-Security-Policy": "default-src 'none'; sandbox"},
        )

    # --- export -----------------------------------------------------------

    @app.get("/api/export/evidence.zip")
    def export_bundle(conn: sqlite3.Connection = Depends(get_conn)):
        fd, tmp = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        bundle.build(conn, evidence_dir, Path(tmp), engagement)
        return FileResponse(
            tmp,
            media_type="application/zip",
            filename=f"{bundle.safe_name(engagement)}-evidence.zip",
            background=BackgroundTask(lambda: Path(tmp).unlink(missing_ok=True)),
        )

    # --- websocket --------------------------------------------------------

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        # Browsers can't set headers on a WS handshake, so the token rides in
        # the query string. Reject before accept so an unauthed client learns
        # nothing about the engagement.
        if not auth.token_matches(token, websocket.query_params.get("token")):
            await websocket.close(code=1008)
            return
        await hub.connect(websocket)
        try:
            while True:
                await websocket.receive_text()  # we don't act on inbound; keep-alive only
        except WebSocketDisconnect:
            pass
        finally:
            hub.disconnect(websocket)

    # --- UI ---------------------------------------------------------------

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/wall")
    def wall():
        return FileResponse(STATIC_DIR / "wall.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _selfsigned_cert() -> tuple[str, str]:
    """Generate a throwaway self-signed cert/key pair, returning their paths."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "siege")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    d = Path(tempfile.mkdtemp(prefix="siege-tls-"))
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    return str(cert_path), str(key_path)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="siege", description="Engagement graph & evidence board.")
    p.add_argument("--db", required=True, help="engagement SQLite file (created if missing)")
    p.add_argument("--evidence-dir", help="evidence store dir (default: <db>-evidence)")
    p.add_argument("--bind", default="127.0.0.1", help="bind address (off-loopback requires TLS)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--tls-cert", help="TLS certificate PEM")
    p.add_argument("--tls-key", help="TLS private key PEM")
    p.add_argument("--tls-selfsigned", action="store_true", help="generate a throwaway self-signed cert")
    args = p.parse_args(argv)

    tls = bool(args.tls_selfsigned or (args.tls_cert and args.tls_key))
    if not _is_loopback(args.bind) and not tls:
        sys.exit(
            f"refusing to bind {args.bind!r} without TLS. Pass --tls-selfsigned (or "
            "--tls-cert/--tls-key), or bind 127.0.0.1 and share via SSH port-forward."
        )

    db_path = Path(args.db)
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else db_path.with_name(db_path.stem + "-evidence")
    token = auth.load_or_create_token(str(db_path))

    cert_path = key_path = None
    if args.tls_selfsigned:
        cert_path, key_path = _selfsigned_cert()
    elif args.tls_cert and args.tls_key:
        cert_path, key_path = args.tls_cert, args.tls_key

    scheme = "https" if tls else "http"
    shown = "localhost" if _is_loopback(args.bind) else args.bind
    print(f"\n  siege — engagement {db_path.stem!r}")
    print(f"  operator UI : {scheme}://{shown}:{args.port}/?token={token}")
    print(f"  wallboard   : {scheme}://{shown}:{args.port}/wall?token={token}")
    print(f"  (token also in {db_path}.token)\n")

    import uvicorn

    uvicorn.run(
        create_app(db_path, evidence_dir, token=token),
        host=args.bind,
        port=args.port,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
    )


if __name__ == "__main__":
    main()
