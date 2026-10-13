# Reporting & Ghostwriter — quick glance

CPTC is scored heavily on the report. The engagement's job is to produce clean,
client-ready findings with evidence attached — `siege` collects them as you go
and hands them to Ghostwriter so the write-up isn't an hour-eight scramble.

> Write the finding when you get the access, not at the end. A finding with its
> evidence attached at capture time is worth three reconstructed from memory.

## Finding structure (every one)

- **Title** — specific and client-legible ("SMB signing disabled enables NTLM
  relay to DC01"), not "SMB bad".
- **Severity** — `info / low / medium / high / critical`. Use impact, not
  excitement (see rubric below).
- **Affected host/service** — pin it to the exact target in `siege`.
- **Reproduction** — the exact commands/requests, in order.
- **Impact** — what it lets an attacker do *in this environment*.
- **Remediation** — a concrete fix the client can action.
- **Evidence** — command output + screenshots, pinned at capture time.

## Severity rubric (keep it defensible)

| Severity | Rough bar |
|---|---|
| critical | direct path to domain/enterprise compromise, or crown-jewel data exposure |
| high | reliable foothold / privilege escalation / sensitive data on one system |
| medium | meaningful weakness needing a condition or chaining to matter |
| low | limited impact / defense-in-depth gap |
| info | observation, no direct security impact |

Score impact × exploitability for *this* client; don't paste a generic CVSS and
walk away.

## Push to Ghostwriter from siege

`siege` pushes findings + their evidence to a Ghostwriter report over its
GraphQL API.

- UI: **Export** → Ghostwriter (URL + API token + report id), or
  `POST /api/export/ghostwriter {url, token, report_id}`.
- The token is treated as a secret — not logged, not stored.
- Only evidence attached to a **finding** is pushed (Ghostwriter hangs evidence
  off a finding). Evidence pinned only to a host/service stays in the local
  bundle — attach it to a finding first if it belongs in the report.
- Partial pushes are reported per item; a failed finding doesn't abort the rest.

> ⚠ **Verify against your Ghostwriter version first.** The push is built from the
> documented GraphQL API but is **not yet verified against a live server**; the
> mutation/field names can differ by version (see
> `src/siege/export/ghostwriter.py`). Do a dry run into a throwaway report
> before trusting it on the real one.

## Fallback: the evidence bundle

UI **Export evidence** / `GET /api/export/evidence.zip` → a zip with every
evidence file plus `manifest.json` and `manifest.md`, each file hashed
(SHA-256) so a reviewer can confirm nothing changed. Import into Ghostwriter /
SysReptor by hand, or keep as the engagement's evidence archive.
