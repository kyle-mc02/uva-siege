"""Faraday workspace export -> hosts/services/vulns (Phase 3).

Faraday's value over a raw nmap import is its vulnerabilities, which become
siege findings. We ingest hosts + services (merged like any scan) and vulns
(attached to the host, or to a specific service when the port is known).

Faraday's export shape has drifted across versions, so this is tolerant:
- a workspace-ish doc: {"hosts": [{ip, hostnames, os, services[], vulnerabilities[]}]}
- a bare list of host objects
- the REST v3 rows wrapper: {"rows": [{"value": {...}}]} (we unwrap "value")
Vulns may live under each host/service, or in a flat top-level "vulnerabilities"
list that references a host by ip/target. We handle both.

Input is untrusted: parsed as JSON only, size-bounded at the endpoint, every
string treated as display text.
"""

from __future__ import annotations

import json

from ..models import FaradayResult, ParsedHost, ParsedService, ParsedVuln

# Faraday severity label -> siege severity.
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unclassified": "info",
    "": "info",
}


def _sev(raw) -> str:
    return _SEVERITY.get(str(raw or "").strip().lower(), "info")


def _first_hostname(host: dict) -> str | None:
    hs = host.get("hostnames") or host.get("hostname")
    if isinstance(hs, list):
        return str(hs[0]) if hs else None
    return str(hs) if hs else None


def _services(host: dict) -> list[ParsedService]:
    out = []
    for s in host.get("services", []) or []:
        if not isinstance(s, dict):
            continue
        try:
            port = int(s.get("port"))
        except (TypeError, ValueError):
            continue
        status = (s.get("status") or "open").lower()
        if status in ("closed", "filtered"):
            continue
        out.append(
            ParsedService(
                port=port,
                proto=(s.get("protocol") or s.get("proto") or "tcp").lower(),
                state="open",
                name=s.get("name"),
                version=s.get("version") or None,
                product=s.get("product") or None,
            )
        )
    return out


def _vuln_notes(v: dict) -> str | None:
    parts = [v.get("desc") or v.get("description"), v.get("resolution")]
    text = "\n\n".join(p for p in parts if p)
    return text or None


def _unwrap(doc):
    """Return a list of host dicts from any of the supported shapes."""
    if isinstance(doc, dict) and "rows" in doc and isinstance(doc["rows"], list):
        return [r.get("value", r) for r in doc["rows"] if isinstance(r, dict)]
    if isinstance(doc, dict) and "hosts" in doc:
        return doc["hosts"] or []
    if isinstance(doc, list):
        return doc
    return []


def parse_bytes(data: bytes, source_file: str) -> FaradayResult:
    text = data.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"not valid Faraday JSON: {exc}")

    hosts: list[ParsedHost] = []
    vulns: list[ParsedVuln] = []

    for host in _unwrap(doc):
        if not isinstance(host, dict):
            continue
        ip = host.get("ip") or host.get("address")
        if not ip:
            continue
        ip = str(ip)
        svcs = _services(host)
        # map service id/name -> (port, proto) so a vuln referencing a service resolves
        svc_port = {str(s.get("id") or s.get("name")): None for s in host.get("services", []) or []}
        hosts.append(
            ParsedHost(
                ip=ip,
                mac=host.get("mac") or None,
                hostname=_first_hostname(host),
                os=host.get("os") or None,
                services=svcs,
            )
        )
        # Per-host vulns, and per-service vulns.
        for v in host.get("vulnerabilities", []) or host.get("vulns", []) or []:
            if isinstance(v, dict) and (v.get("name") or v.get("title")):
                vulns.append(ParsedVuln(ip, v.get("name") or v.get("title"), _sev(v.get("severity")), _vuln_notes(v)))
        for s in host.get("services", []) or []:
            if not isinstance(s, dict):
                continue
            try:
                port = int(s.get("port"))
            except (TypeError, ValueError):
                port = None
            proto = (s.get("protocol") or s.get("proto") or "tcp").lower()
            for v in s.get("vulnerabilities", []) or s.get("vulns", []) or []:
                if isinstance(v, dict) and (v.get("name") or v.get("title")):
                    vulns.append(ParsedVuln(ip, v.get("name") or v.get("title"), _sev(v.get("severity")), _vuln_notes(v), port, proto))

    # Flat top-level vulns referencing a host by ip/target.
    if isinstance(doc, dict):
        for v in doc.get("vulnerabilities", []) or []:
            if not isinstance(v, dict):
                continue
            target = v.get("target") or v.get("ip") or v.get("host")
            name = v.get("name") or v.get("title")
            if target and name:
                vulns.append(ParsedVuln(str(target), name, _sev(v.get("severity")), _vuln_notes(v)))

    return FaradayResult(source_file=source_file, hosts=hosts, vulns=vulns, raw=text)
