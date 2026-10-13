"""BloodHound output -> AD computer annotations (Phase 3).

We ingest only Computer objects and only to annotate hosts we've already
scanned (domain, FQDN, OS, high-value, DC). Users/groups/GPOs and full path
analysis stay in BloodHound by design (HANDOFF.md: integrate, don't rebuild).

Accepts either a single collection JSON (`*_computers.json`) or a SharpHound
zip (we pull the computers file out of it). Tolerant of both legacy SharpHound
(`Properties`, PascalCase) and BloodHound CE (`properties`, lowercase) shapes.

Input is untrusted data: we only parse it as JSON (no eval, no import), bound
the size at the endpoint, and treat every extracted string as display text.
"""

from __future__ import annotations

import io
import json
import zipfile

from ..models import AdComputer, BloodHoundResult


def _prop(props: dict, *names: str):
    """Case-insensitive lookup across the candidate property names."""
    lowered = {k.lower(): v for k, v in props.items()}
    for n in names:
        if n.lower() in lowered:
            return lowered[n.lower()]
    return None


def _as_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _computer(obj: dict) -> AdComputer | None:
    props = obj.get("Properties") or obj.get("properties") or {}
    if not isinstance(props, dict):
        return None
    name = _prop(props, "name") or obj.get("Name") or obj.get("name")
    sam = _prop(props, "samaccountname")
    if not name and not sam:
        return None
    dns_name = str(name) if name and "." in str(name) else None
    short = ((str(name).split(".")[0] if name else str(sam).rstrip("$")) or "").lower()
    tags = obj.get("system_tags") or _prop(props, "system_tags") or ""
    is_dc = _as_bool(_prop(props, "isdc")) or _as_bool(obj.get("IsDC"))
    high_value = (
        _as_bool(_prop(props, "highvalue"))
        or _as_bool(obj.get("IsHighValue"))
        or ("admin_tier_0" in str(tags))
    )
    return AdComputer(
        name=short,
        dns_name=dns_name,
        domain=_prop(props, "domain"),
        os=_prop(props, "operatingsystem", "operating_system"),
        high_value=high_value,
        is_dc=is_dc,
        owned=_as_bool(obj.get("owned")) or _as_bool(_prop(props, "owned")),
    )


def _computers_from_json(doc) -> list[AdComputer]:
    # Collection file: {"data": [...], "meta": {"type": "computers"}}, or a bare list.
    if isinstance(doc, dict):
        meta = doc.get("meta") or {}
        if meta.get("type") and meta["type"] != "computers":
            return []
        data = doc.get("data", [])
    elif isinstance(doc, list):
        data = doc
    else:
        return []
    out = []
    for obj in data:
        if isinstance(obj, dict):
            c = _computer(obj)
            if c is not None:
                out.append(c)
    return out


def parse_bytes(data: bytes, source_file: str) -> BloodHoundResult:
    """Parse BloodHound JSON or a SharpHound zip into a BloodHoundResult."""
    computers: list[AdComputer] = []
    raw_repr = source_file  # keep a light provenance string; zips aren't UTF-8 text

    if data[:2] == b"PK":  # zip signature
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if not info.filename.lower().endswith(".json"):
                    continue
                try:
                    doc = json.loads(zf.read(info).decode("utf-8", "replace"))
                except (ValueError, zipfile.BadZipFile):
                    continue
                found = _computers_from_json(doc)
                if found:
                    computers.extend(found)
        raw_repr = f"[sharphound zip: {source_file}]"
    else:
        text = data.decode("utf-8", "replace")
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"not valid BloodHound JSON: {exc}")
        computers = _computers_from_json(doc)
        raw_repr = text

    return BloodHoundResult(source_file=source_file, computers=computers, raw=raw_repr)
