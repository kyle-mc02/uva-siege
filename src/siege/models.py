"""Normalized observation types shared across parsers, merge, and the DB.

Parsers turn raw tool output into a `ScanResult` of plain, tool-agnostic
observations. `merge.py` is the only module that knows how those become rows.
Keeping this layer dumb (no DB, no I/O) is what lets us add parsers later
without touching storage.

Security note: every string reachable from a `ParsedService` or a hostname is
attacker-controlled (banners, service products, NSE/HTTP titles from the
target). These values are *data*, never markup. Store as text; render as text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HostState(str, Enum):
    """Where a host sits in the kill chain.

    Ordered discovered -> enumerated -> vulnerable -> foothold -> owned.
    out_of_scope is orthogonal (a host we found but must not act on).
    Merge never *downgrades* a host's state on re-import (see merge.py).
    """

    DISCOVERED = "discovered"
    ENUMERATED = "enumerated"
    VULNERABLE = "vulnerable"
    FOOTHOLD = "foothold"
    OWNED = "owned"
    OUT_OF_SCOPE = "out_of_scope"


# Kill-chain rank for comparing two states. out_of_scope is deliberately absent:
# it is a flag set by scope import/operator, not a rung merge can climb to.
_STATE_RANK = {
    HostState.DISCOVERED: 0,
    HostState.ENUMERATED: 1,
    HostState.VULNERABLE: 2,
    HostState.FOOTHOLD: 3,
    HostState.OWNED: 4,
}


def is_progression(old: str, new: str) -> bool:
    """True if `new` is further along the kill chain than `old`.

    Used by merge to bump state forward (e.g. a -sV scan enumerates a host that
    was only discovered) without ever clobbering operator-advanced progress.
    """
    o = _STATE_RANK.get(HostState(old))
    n = _STATE_RANK.get(HostState(new))
    if o is None or n is None:  # one of them is out_of_scope
        return False
    return n > o


SEVERITIES = ("info", "low", "medium", "high", "critical")  # mirrors findings CHECK
EVIDENCE_KINDS = ("screenshot", "log", "note")  # mirrors evidence CHECK
# Edge provenance. subnet/traceroute are derived; pivot/creds_reuse/operator are
# operator-drawn to show how access actually moved through the network.
EDGE_TYPES = ("subnet", "traceroute", "pivot", "creds_reuse", "operator")


@dataclass
class ParsedService:
    """One port/service observation on a host.

    product/version/banner come straight from the target — treat as untrusted.
    """

    port: int
    proto: str  # "tcp" | "udp"
    state: str = "open"  # open | closed | filtered | open|filtered ...
    name: str | None = None  # nmap service guess, e.g. "http"
    product: str | None = None
    version: str | None = None
    banner: str | None = None  # servicefp / extrainfo / NSE text, untrusted


@dataclass
class ParsedHost:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    services: list[ParsedService] = field(default_factory=list)
    # Traceroute hop IPs toward this host, nearest->farthest, if the scan had -tr.
    hops: list[str] = field(default_factory=list)


def classify_os(os_string: str | None) -> str | None:
    """Coarse OS family from a free-text OS string (nmap osmatch or AD).

    Returns 'windows' | 'linux' | 'other' | None. Used so the UI and the
    BloodHound path descriptions can treat Windows and *nix boxes differently.
    """
    if not os_string:
        return None
    s = os_string.lower()
    if "windows" in s or "microsoft" in s:
        return "windows"
    if any(k in s for k in ("linux", "ubuntu", "debian", "centos", "red hat", "rhel", "unix", "bsd", "mac os", "macos")):
        return "linux" if "mac" not in s else "other"
    return "other"


@dataclass
class AdComputer:
    """A domain computer observed in BloodHound output (Phase 3).

    Merged onto an existing host by name; we never create hosts from AD data
    alone (hosts are keyed by scanned IP). `owned` mirrors a BloodHound owned
    mark; `high_value`/`is_dc` drive graph emphasis.
    """

    name: str  # short name, e.g. 'DC01'
    dns_name: str | None = None  # FQDN, e.g. 'DC01.LAB.LOCAL'
    domain: str | None = None
    os: str | None = None
    high_value: bool = False
    is_dc: bool = False
    owned: bool = False

    @property
    def os_family(self) -> str | None:
        return classify_os(self.os)


@dataclass
class BloodHoundResult:
    source_file: str
    computers: list[AdComputer] = field(default_factory=list)
    raw: str = ""


@dataclass
class ParsedVuln:
    """A vulnerability from Faraday, to become a siege finding.

    Pins to a host by IP, optionally to a specific service (port/proto).
    title/notes are tool/attacker-influenced text; stored and shown as text.
    """

    host_ip: str
    title: str
    severity: str = "info"  # already normalized to siege's SEVERITIES
    notes: str | None = None
    port: int | None = None
    proto: str | None = None


@dataclass
class FaradayResult:
    """Hosts/services/vulns pulled from a Faraday workspace export."""

    source_file: str
    hosts: list[ParsedHost] = field(default_factory=list)
    vulns: list[ParsedVuln] = field(default_factory=list)
    raw: str = ""


@dataclass
class ScanResult:
    """Everything one parser extracted from one input file."""

    source_file: str  # original filename, for provenance
    tool: str  # e.g. "nmap"
    scanned_at: str  # ISO-8601 UTC; when the scan ran (from the file if known)
    hosts: list[ParsedHost] = field(default_factory=list)
    raw: str = ""  # raw input, kept so we can re-parse when a parser improves
