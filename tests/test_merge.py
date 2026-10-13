"""Phase 1 merge tests: re-importing scans must update, never duplicate.

The headline case mirrors real engagement flow: a ping sweep discovers hosts,
then a later -sV/-O/--traceroute deep scan enriches the same hosts. Host count
must stay flat while services/OS fill in.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from siege import db, merge
from siege.parsers import nmap

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    raw = (FIXTURES / name).read_text()
    return nmap.parse(raw, source_file=name)


@pytest.fixture()
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    yield c
    c.close()


def _count(conn, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]


def test_pingsweep_then_deepscan_merges(conn):
    # Ping sweep: 2 hosts up (the 3rd is "down" and must be dropped), no services.
    summary = merge.ingest(conn, _load("pingsweep.xml"))
    assert summary["hosts"] == 2
    assert _count(conn, "hosts") == 2
    assert _count(conn, "services") == 0

    # Deep scan of the SAME two IPs: hosts must merge, services get added.
    merge.ingest(conn, _load("deepscan.xml"))
    assert _count(conn, "hosts") == 2, "deep scan must not create duplicate hosts"

    # host .5: ssh + http (closed/none here). host .20: smb + open|filtered rdp
    # (telnet is closed and must be skipped). So 2 + 2 = 4 services.
    assert _count(conn, "services") == 4

    gw = conn.execute("SELECT * FROM hosts WHERE ip = '10.10.10.5'").fetchone()
    assert gw["os"] == "Linux 5.15 - 5.19"  # learned on the deep scan
    assert gw["hostname"] == "gw.lab.example"
    assert gw["mac"] == "00:0c:29:aa:bb:cc"
    assert gw["state"] == "enumerated"  # bumped from 'discovered' by the -sV scan
    # first_seen from the sweep, last_seen from the later deep scan.
    assert gw["first_seen"] < gw["last_seen"]

    # host .20 gained a PTR hostname only on the deep scan; coalesce fills it in.
    fs = conn.execute("SELECT * FROM hosts WHERE ip = '10.10.10.20'").fetchone()
    assert fs["hostname"] == "fileserver.lab.example"


def test_reimport_is_idempotent(conn):
    merge.ingest(conn, _load("deepscan.xml"))
    h1, s1 = _count(conn, "hosts"), _count(conn, "services")
    # Importing the exact same file again changes no counts.
    merge.ingest(conn, _load("deepscan.xml"))
    assert _count(conn, "hosts") == h1
    assert _count(conn, "services") == s1
    # But both imports are recorded for provenance.
    assert _count(conn, "imports") == 2


def test_closed_ports_dropped_open_filtered_kept(conn):
    merge.ingest(conn, _load("deepscan.xml"))
    ports = {
        (r["port"], r["state"])
        for r in conn.execute("SELECT port, state FROM services").fetchall()
    }
    assert (23, "closed") not in {(p, s) for p, s in ports}  # telnet dropped
    assert any(p == 3389 and s.startswith("open") for p, s in ports)  # rdp kept


def test_attacker_controlled_strings_stored_as_inert_text(conn):
    """Banners/titles from the target are stored verbatim as text, not markup.

    siege never renders these as HTML (frontend treats them as text nodes).
    The DB layer's job is simply to preserve them byte-for-byte so provenance
    and reporting are honest.
    """
    merge.ingest(conn, _load("deepscan.xml"))
    http = conn.execute(
        "SELECT * FROM services WHERE port = 80 AND host_id = "
        "(SELECT id FROM hosts WHERE ip='10.10.10.5')"
    ).fetchone()
    # The <script> payload survives intact as plain text in the banner column.
    assert "<script>alert(document.cookie)</script>" in http["banner"]

    rdp = conn.execute("SELECT * FROM services WHERE port = 3389").fetchone()
    assert 'onerror=alert(1)' in rdp["product"]


def test_rejects_non_nmap_xml():
    with pytest.raises(ValueError):
        nmap.parse("<foo><bar/></foo>", source_file="bogus.xml")
