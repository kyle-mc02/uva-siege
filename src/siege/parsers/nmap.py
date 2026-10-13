"""nmap XML -> normalized ScanResult.

Handles the common shapes we actually feed it:
- host discovery / ping sweep (`-sn`): hosts up, addresses, maybe hostnames,
  no <ports>.
- service/version scans (`-sV`): <ports> with <service> product/version/banner.
- OS detection (`-O`): best <osmatch>.
- traceroute (`--traceroute`): <trace> hops.

Security: parsed with defusedxml, never stdlib ElementTree, so a malicious scan
file (billion-laughs, external entity, etc.) can't blow us up. Every string we
pull out of the file is treated as untrusted data downstream.
"""

from __future__ import annotations

from datetime import datetime, timezone

# defusedxml hardens against entity-expansion / external-entity attacks.
from defusedxml.ElementTree import fromstring

from ..models import ParsedHost, ParsedService, ScanResult


def _epoch_to_iso(epoch: str | None) -> str | None:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        return None


def _join(*parts: str | None) -> str | None:
    """Join non-empty strings with a space; return None if nothing's left."""
    vals = [p for p in parts if p]
    return " ".join(vals) if vals else None


def parse(raw: str, source_file: str) -> ScanResult:
    """Parse nmap XML text into a ScanResult. Raises on non-XML / non-nmap input."""
    root = fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError(f"not an nmap XML document (root tag {root.tag!r})")

    scan_run_iso = _epoch_to_iso(root.get("start"))
    scanned_at = scan_run_iso or datetime.now(timezone.utc).isoformat()

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        # Keep only hosts nmap believes are up. "down" hosts in a sweep are noise.
        if status is not None and status.get("state") == "down":
            continue

        ip: str | None = None
        mac: str | None = None
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype")
            if kind in ("ipv4", "ipv6") and ip is None:
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
        if not ip:
            # No usable address -> we can't key or merge it. Skip.
            continue

        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        os_match = host_el.find("os/osmatch")
        os_name = os_match.get("name") if os_match is not None else None

        services: list[ParsedService] = []
        for port_el in host_el.findall("ports/port"):
            port_state_el = port_el.find("state")
            port_state = port_state_el.get("state") if port_state_el is not None else None
            # Skip closed ports; "open" and "open|filtered" are what we graph.
            if port_state and port_state.startswith("closed"):
                continue

            try:
                port_num = int(port_el.get("portid", ""))
            except ValueError:
                continue
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            name = product = version = banner = None
            if svc_el is not None:
                name = svc_el.get("name")
                product = svc_el.get("product")
                version = svc_el.get("version")
                # Banner-ish text: extrainfo + service fingerprint, all untrusted.
                banner = _join(svc_el.get("extrainfo"), svc_el.get("servicefp"))

            # NSE script output is also target-controlled text; fold it into banner.
            script_texts = [
                s.get("output") for s in port_el.findall("script") if s.get("output")
            ]
            if script_texts:
                banner = _join(banner, *script_texts)

            services.append(
                ParsedService(
                    port=port_num,
                    proto=proto,
                    state=port_state or "open",
                    name=name,
                    product=product,
                    version=version,
                    banner=banner,
                )
            )

        hops = [
            h.get("ipaddr")
            for h in host_el.findall("trace/hop")
            if h.get("ipaddr")
        ]

        hosts.append(
            ParsedHost(
                ip=ip,
                mac=mac,
                hostname=hostname,
                os=os_name,
                services=services,
                hops=hops,
            )
        )

    return ScanResult(
        source_file=source_file,
        tool="nmap",
        scanned_at=scanned_at,
        hosts=hosts,
        raw=raw,
    )
