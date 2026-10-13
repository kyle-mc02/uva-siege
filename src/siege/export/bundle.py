"""Evidence bundle export: a zip of evidence files + JSON and Markdown manifests.

The bundle is the hand-off format to reporting (Ghostwriter/SysReptor) until
direct push lands in Phase 3. Every file is listed with its sha256 so a
reviewer can verify nothing changed between capture and report.

Security: hostnames, captions, filenames, and finding titles are untrusted
text. Archive names are sanitised to a safe charset, and Markdown output is
escaped so a hostile banner can't inject markup into the report pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import zipfile
from pathlib import Path

from .. import evidence as evstore
from ..db import utcnow
from ..queries import evidence_target

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~])")


def safe_name(name: str | None, max_len: int = 60) -> str:
    cleaned = _SAFE_NAME.sub("_", name or "").strip("._")
    return cleaned[:max_len] or "file"


def md_escape(text: object) -> str:
    """Escape untrusted text for inline Markdown (and neutralise raw HTML)."""
    if text is None:
        return ""
    s = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", s)


def _target_label(t: dict) -> str:
    host = t.get("host_ip") or "?"
    if t["type"] == "service":
        return f"{host} {t.get('port')}/{t.get('proto')}"
    if t["type"] == "finding":
        return f"{host} finding #{t['id']}: {t.get('finding')}"
    return host


def build(conn: sqlite3.Connection, evidence_dir: Path, out_path: Path, engagement: str) -> dict:
    """Write the bundle zip to out_path. Returns the manifest dict."""
    rows = conn.execute("SELECT * FROM evidence ORDER BY id").fetchall()
    items = []
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for ev in rows:
            target = evidence_target(conn, ev)
            arcname = f"evidence/{ev['id']:04d}-{ev['sha256'][:12]}-{safe_name(ev['original_name'] or ev['kind'])}"
            src = evstore.resolve(evidence_dir, ev["path"])
            data = src.read_bytes()
            actual = hashlib.sha256(data).hexdigest()
            zf.writestr(arcname, data)
            items.append(
                {
                    "id": ev["id"],
                    "kind": ev["kind"],
                    "file": arcname,
                    "sha256": ev["sha256"],
                    "integrity_ok": actual == ev["sha256"],
                    "original_name": ev["original_name"],
                    "caption": ev["caption"],
                    "added_by": ev["added_by"],
                    "added_at": ev["added_at"],
                    "target": target,
                }
            )

        manifest = {
            "engagement": engagement,
            "generated_at": utcnow(),
            "count": len(items),
            "items": items,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("manifest.md", _markdown(manifest))
    return manifest


def _markdown(manifest: dict) -> str:
    lines = [
        f"# Evidence bundle — {md_escape(manifest['engagement'])}",
        "",
        f"Generated {md_escape(manifest['generated_at'])}. {manifest['count']} item(s).",
        "",
        "| # | Target | Kind | Caption | File | SHA-256 | Added |",
        "|---|---|---|---|---|---|---|",
    ]
    for it in manifest["items"]:
        flag = "" if it["integrity_ok"] else " **HASH MISMATCH**"
        lines.append(
            "| {id} | {target} | {kind} | {caption} | `{file}` | `{sha}`{flag} | {by}, {at} |".format(
                id=it["id"],
                target=md_escape(_target_label(it["target"])),
                kind=md_escape(it["kind"]),
                caption=md_escape(it["caption"]),
                file=it["file"],  # already restricted to a safe charset
                sha=it["sha256"],
                flag=flag,
                by=md_escape(it["added_by"]),
                at=md_escape(it["added_at"]),
            )
        )
    return "\n".join(lines) + "\n"
