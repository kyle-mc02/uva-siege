"""Turn a chosen BloodHound path into siege edges between real hosts (Phase 3).

The team picks ONE path in BloodHound; we draw it on the graph/TV as edges
between the scanned hosts it traverses, each edge tagged with the BloodHound
edge abused and a short, actionable description. Descriptions are OS-aware:
the same logical access reads differently on a Windows box (SMB/WinRM/RDP) vs a
domain-joined Linux box (SSH/Kerberos), which is what the operator needs at a
glance. Exact syntax still lives in docs/playbook/bloodhound-edges.md.

This does not re-run path analysis — BloodHound owns that. We only record the
decision the team already made so the graph reflects reality.
"""

from __future__ import annotations

import sqlite3

from .db import utcnow
from .models import EDGE_TYPES

# BloodHound edge -> (siege edge type, {os_family: description}).
# 'default' applies when the target OS is unknown or 'other'. Keep these as
# orientation, not copy-paste exploits.
_ABUSE: dict[str, tuple[str, dict[str, str]]] = {
    "AdminTo": ("pivot", {
        "windows": "Local admin on target: execute via SMB/WMI (psexec/wmiexec) or WinRM.",
        "linux": "Admin on a domain-joined *nix host: SSH with the account or run via remote exec.",
        "default": "Administrative access to the target host; get code execution.",
    }),
    "HasSession": ("creds_reuse", {
        "windows": "A user session lives here: dump LSASS/tickets and reuse those creds.",
        "linux": "A session/keytab may be present: harvest Kerberos tickets / cached creds.",
        "default": "Reuse credentials from a live session on this host.",
    }),
    "CanRDP": ("pivot", {
        "windows": "Interactive RDP access to the target.",
        "linux": "Interactive access (RDP rarely applies on *nix; use SSH instead).",
        "default": "Interactive remote access to the target.",
    }),
    "CanPSRemote": ("pivot", {
        "windows": "WinRM/PowerShell Remoting to the target (evil-winrm).",
        "default": "Remote shell access to the target.",
    }),
    "ExecuteDCOM": ("pivot", {"default": "DCOM-based remote code execution on the target."}),
    "ForceChangePassword": ("creds_reuse", {"default": "Reset the target account's password, then authenticate as it."}),
    "GenericAll": ("creds_reuse", {"default": "Full control of the target object: reset password, set SPN, or add to a group."}),
    "GenericWrite": ("creds_reuse", {"default": "Write target attributes: targeted Kerberoast (set SPN) or similar."}),
    "WriteDacl": ("creds_reuse", {"default": "Rewrite the target DACL to grant yourself control, then abuse it."}),
    "WriteOwner": ("creds_reuse", {"default": "Take ownership of the target, grant rights, then abuse."}),
    "AddMember": ("creds_reuse", {"default": "Add a principal to the target group, inheriting its rights."}),
    "AddKeyCredentialLink": ("creds_reuse", {"default": "Shadow Credentials: add a key credential, then PKINIT for a TGT."}),
    "AllowedToDelegate": ("pivot", {"default": "Constrained delegation: request an S4U ticket to the target service."}),
    "AllowedToAct": ("pivot", {"default": "Resource-based constrained delegation: impersonate a privileged user to the target."}),
    "DCSync": ("creds_reuse", {"default": "Replicate secrets from the DC (secretsdump) — every hash, incl. krbtgt."}),
    "GetChanges": ("creds_reuse", {"default": "Replication right; combine with GetChangesAll for DCSync."}),
    "MemberOf": ("operator", {"default": "Group membership relationship (context, not a direct exploit)."}),
}


def describe(edge: str | None, target_os_family: str | None) -> tuple[str, str, str | None]:
    """Resolve (siege_type, label, description) for a BloodHound edge + target OS."""
    label = (edge or "operator").strip()
    spec = _ABUSE.get(label)
    if spec is None:
        return "operator", label, None
    etype, descs = spec
    fam = target_os_family if target_os_family in ("windows", "linux") else "default"
    desc = descs.get(fam) or descs.get("default")
    return etype, label, desc


def apply_path(
    conn: sqlite3.Connection,
    path: list[int],
    steps: list[dict],
    created_by: str = "operator",
) -> dict:
    """Create edges along a chosen path. Commits. Returns created/skipped summary.

    `path` is host ids in order; `steps[i]` describes moving path[i] -> path[i+1]
    with keys: edge (BloodHound edge name), type (optional override), note
    (optional, replaces the generated description). len(steps) == len(path)-1.
    """
    if len(path) < 2:
        raise ValueError("a path needs at least two hosts")
    if len(steps) != len(path) - 1:
        raise ValueError(f"expected {len(path) - 1} steps for {len(path)} hosts, got {len(steps)}")

    ids = {r["id"]: r for r in conn.execute("SELECT id, ip, os_family FROM hosts")}
    for hid in path:
        if hid not in ids:
            raise ValueError(f"host {hid} does not exist")

    now = utcnow()
    created, skipped = [], []
    for i, step in enumerate(steps):
        src, dst = path[i], path[i + 1]
        target = ids[dst]
        etype, label, auto_desc = describe(step.get("edge"), target["os_family"])
        if step.get("type") in EDGE_TYPES:
            etype = step["type"]
        description = step.get("note") or auto_desc
        try:
            cur = conn.execute(
                "INSERT INTO edges (src_host_id, dst_host_id, type, label, description, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (src, dst, etype, label, description, created_by, now),
            )
        except sqlite3.IntegrityError:
            skipped.append({"src": src, "dst": dst, "reason": "edge already exists"})
            continue
        conn.execute(
            "INSERT INTO events (type, actor, ts, payload) "
            "VALUES ('edge_added', ?, ?, json_object('edge_id', ?, 'type', ?, 'label', ?, 'src', ?, 'dst', ?))",
            (created_by, now, cur.lastrowid, etype, label, src, dst),
        )
        created.append(cur.lastrowid)
    conn.commit()
    return {"created": created, "skipped": skipped, "hosts": len(path)}
