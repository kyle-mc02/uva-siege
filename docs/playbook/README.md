# Team playbook

The engagement, in six phases. `siege` operationalizes this: most checklist
items here are a current or future feature. Keep this doc and the tool in sync —
when a step becomes a feature, link it.

**Quick-glance reference sheets** (roughly in engagement order):
- [preflight-roe.md](preflight-roe.md) — rules of engagement + first-15-minutes checklist
- [nmap-recon.md](nmap-recon.md) — recon & deep-scan command recipes
- [web-enum.md](web-enum.md) — the web attack surface, fastest-foothold first
- [initial-access.md](initial-access.md) — getting the first credential / shell (incl. lockout-aware spraying)
- [faraday.md](faraday.md) — feed scanners into Faraday, import its vulns as findings
- [bloodhound-edges.md](bloodhound-edges.md) — AD edge → tool/command cheat sheet
- [pivoting.md](pivoting.md) — tunneling to reach deeper segments
- [evidence-discipline.md](evidence-discipline.md) — capture & pin evidence as you go
- [reporting-ghostwriter.md](reporting-ghostwriter.md) — finding structure, severity rubric, Ghostwriter push

> Scope first, always. Every phase assumes the scope file is imported and
> out-of-scope hosts are flagged (`siege` draws them with a red dashed border
> and refuses to treat them as targets). If you're not sure a host is in scope,
> it isn't.

## 1. Setup / pre-flight — [preflight-roe.md](preflight-roe.md)
- Confirm rules of engagement, scope CIDRs, timing windows, and the client's
  "do not touch" list. Import scope into `siege` (`POST /api/scope`).
- Stand up one `siege` server for the engagement; put `/wall` on the room TV.
- Verify tooling: nmap, BloodHound/SharpHound, Impacket, your C2, Ghostwriter.
- Agree on evidence hygiene: every meaningful action gets a screenshot/log
  pinned in `siege` at capture time, not reconstructed later.

## 2. Recon & enumeration — [nmap-recon.md](nmap-recon.md), [web-enum.md](web-enum.md)
- Host discovery sweep, then targeted service/version scans. Import each nmap
  run; `siege` merges by IP and keeps provenance.
- Note web apps, default creds, SMB shares, exposed admin interfaces.
- Mark host states as you go: `discovered → enumerated`.
- Get the first credential / shell — [initial-access.md](initial-access.md) —
  before expecting AD path analysis to have a starting point.

## 3. AD mapping
- Run SharpHound, ingest into BloodHound. Import the computers into `siege`
  (**Import BloodHound**) to annotate scanned, domain-joined hosts with
  domain/FQDN/OS/high-value/DC — Windows and Linux both.
- Identify domain controllers, high-value targets (Domain Admins, Tier-0),
  and the shortest paths you actually have a foothold near.

## 4. Path analysis & prioritization
- In BloodHound, mark owned principals and run "shortest paths to Domain
  Admins" (and to any client-defined crown-jewel asset).
- For every edge on a candidate path, confirm you can actually execute the
  abuse **before** committing. This is our known failure mode — see
  [bloodhound-edges.md](bloodhound-edges.md).
- Prioritize paths by: number of edges, noise/detection risk, and whether each
  edge's abuse is one you've rehearsed.

## 5. Exploitation — [pivoting.md](pivoting.md)
- Execute the chosen path edge by edge. Pin evidence (`siege`) at each step:
  the command, the result, the new access.
- Reaching a deeper segment first? Tunnel through your foothold ([pivoting.md](pivoting.md)).
- Advance host state (`vulnerable → foothold → owned`) and draw operator edges
  (`pivot`, `creds_reuse`) so the graph and the TV reflect reality live.
- Re-run path analysis after each new owned principal; paths open up fast.

## 6. Evidence & reporting — [reporting-ghostwriter.md](reporting-ghostwriter.md)
- Each finding gets: title, severity, affected host/service, reproduction
  steps, and pinned evidence.
- Export the evidence bundle (`GET /api/export/evidence.zip`), or push findings
  + evidence straight to Ghostwriter (**Export** / `POST /api/export/ghostwriter`
  — verify against your Ghostwriter version first; see the tool's README).
- Map every finding to a remediation and a severity the client will recognize.
- See [evidence-discipline.md](evidence-discipline.md) for the capture habit.
