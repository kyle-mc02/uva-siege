"""Push findings + evidence to Ghostwriter (Phase 3).

    ⚠ UNVERIFIED AGAINST A LIVE SERVER. Built from Ghostwriter's documented
    GraphQL API (the Hasura endpoint at <url>/v1/graphql, Bearer-token auth).
    The exact mutation/field names vary by Ghostwriter version, so the GraphQL
    documents here are centralized and easy to adjust, the transport is
    injectable for testing, and nothing is hard-wired to a schema we couldn't
    confirm. Verify against your instance before trusting a real report, and
    treat a 200 with GraphQL `errors` as a failure (we do).

Design:
- `GhostwriterClient(url, token, transport=...)` — `transport(url, headers, body)`
  returns a parsed JSON dict. Defaults to a stdlib urllib POST (no new dep).
- `push(report_id, findings, evidence_items)` creates a finding per finding and
  attaches evidence to it. Returns a per-item result log; it never raises on a
  single item's failure so a partial push is observable.

TODO(verify): confirm mutation names (`insert_reportedFinding` /
`reportFindingLink`, `uploadEvidence`) and the evidence upload mechanism
(GraphQL action vs multipart) against the target Ghostwriter version.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from typing import Callable

Transport = Callable[[str, dict, bytes], dict]

# siege severity -> Ghostwriter severity label.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

# Centralized so a version mismatch is a one-line fix, not a hunt. UNVERIFIED.
_M_CREATE_FINDING = """
mutation CreateFinding($object: reportFindingLink_insert_input!) {
  insert_reportFindingLink_one(object: $object) { id title }
}
"""
_M_UPLOAD_EVIDENCE = """
mutation UploadEvidence($object: evidence_insert_input!) {
  insert_evidence_one(object: $object) { id friendlyName }
}
"""
_Q_WHOAMI = "query { __typename }"


def _urllib_transport(url: str, headers: dict, body: bytes) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (operator-supplied URL)
        return json.loads(resp.read().decode("utf-8"))


class GhostwriterError(RuntimeError):
    pass


class GhostwriterClient:
    def __init__(self, url: str, token: str, transport: Transport | None = None):
        # Accept either the base URL or a full /v1/graphql URL.
        base = url.rstrip("/")
        self.endpoint = base if base.endswith("/graphql") else base + "/v1/graphql"
        self.token = token
        self._transport = transport or _urllib_transport

    def _gql(self, query: str, variables: dict | None = None) -> dict:
        body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        result = self._transport(self.endpoint, headers, body)
        if result.get("errors"):
            raise GhostwriterError(json.dumps(result["errors"]))
        return result.get("data", {})

    def test_connection(self) -> bool:
        self._gql(_Q_WHOAMI)
        return True

    def create_finding(self, report_id: int, finding: dict) -> int:
        obj = {
            "reportId": report_id,
            "title": finding.get("title") or "Untitled finding",
            "severity": SEVERITY_MAP.get((finding.get("severity") or "info").lower(), "Informational"),
            "description": finding.get("notes") or "",
        }
        data = self._gql(_M_CREATE_FINDING, {"object": obj})
        return data["insert_reportFindingLink_one"]["id"]

    def upload_evidence(self, finding_link_id: int, name: str, content: bytes, caption: str | None = None) -> int:
        obj = {
            "reportFindingLinkId": finding_link_id,
            "friendlyName": name,
            "caption": caption or "",
            "document": base64.b64encode(content).decode("ascii"),
        }
        data = self._gql(_M_UPLOAD_EVIDENCE, {"object": obj})
        return data["insert_evidence_one"]["id"]


def push(client: GhostwriterClient, report_id: int, findings: list[dict], evidence_items: list[dict]) -> dict:
    """Create findings and attach their evidence. Returns a result log.

    `evidence_items` entries: {name, content(bytes), caption?, finding_index?}.
    An item with finding_index links to findings[index]; otherwise it's skipped
    (Ghostwriter evidence must hang off a finding link).
    """
    log: dict = {"findings": [], "evidence": [], "errors": []}
    link_ids: list[int] = []
    for f in findings:
        try:
            link_ids.append(client.create_finding(report_id, f))
            log["findings"].append({"title": f.get("title"), "ok": True})
        except Exception as exc:  # keep going; report the failure
            link_ids.append(None)
            log["findings"].append({"title": f.get("title"), "ok": False, "error": str(exc)})
            log["errors"].append(str(exc))

    for ev in evidence_items:
        idx = ev.get("finding_index")
        link = link_ids[idx] if isinstance(idx, int) and 0 <= idx < len(link_ids) else None
        if link is None:
            log["evidence"].append({"name": ev.get("name"), "ok": False, "error": "no linked finding"})
            continue
        try:
            client.upload_evidence(link, ev["name"], ev["content"], ev.get("caption"))
            log["evidence"].append({"name": ev.get("name"), "ok": True})
        except Exception as exc:
            log["evidence"].append({"name": ev.get("name"), "ok": False, "error": str(exc)})
            log["errors"].append(str(exc))
    return log
