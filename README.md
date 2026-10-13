# uva-siege

A lightweight, self-hosted **red-team engagement graph & evidence board** for a
CPTC team. It ingests recon data (nmap, BloodHound, Faraday), shows the engagement as a
live network graph you can put on a room TV, lets operators pin evidence to the
exact host/service/finding it came from, and exports that evidence for
reporting.

It is **glue + dashboard over** existing tools (BloodHound, Ghostwriter), not a
replacement. One server process per engagement; the TV is just a browser at
`/wall`. See [docs/playbook/](docs/playbook/) for the team playbook.

> **Training aid, not competition-day tooling** until it has survived months of
> practice engagements. No multi-user accounts yet — it assumes one server per
> engagement on a trusted team network.

## Install

```bash
pip install -e '.[dev,tls]'      # or: uv pip install -e '.[dev,tls]'
```

Ships its prebuilt frontend inside the package — no Node required to run it.

For a full server deployment (systemd, TLS, the operator toolchain, Faraday and
Ghostwriter), see **[docs/server-setup.md](docs/server-setup.md)**.

## Run

```bash
siege --db practice-01.sqlite
```

The startup banner prints a tokenized URL — open it to authenticate. Put the
`/wall?token=…` URL on the room TV. One SQLite file + one evidence dir per
engagement.

Binding off-localhost (team VPN / Tailscale) requires TLS:

```bash
siege --db e.sqlite --bind 10.8.0.2 --tls-selfsigned
```

Plaintext off-loopback is refused (there is no auth-over-the-wire story without
TLS). For a quick share, prefer an SSH port-forward to localhost.

## Workflow

1. **Scope** — import in/out CIDRs; out-of-scope hosts are flagged loudly and
   are hard to act on. (`!cidr` or `cidr out` excludes; exclusions win.)
   Optionally import **subnets** (CIDR + label, any mask) to control how the
   graph groups hosts across multiple subnets; the scope include CIDRs are used
   automatically if you don't, with a `/24` fallback.
2. **Recon** — import nmap XML (repeatedly; it merges by IP with provenance).
3. **Vulns** — import a Faraday workspace export; its vulnerabilities become
   findings pinned to the host or service.
4. **AD** — import BloodHound computers (JSON or SharpHound zip) to annotate
   scanned, domain-joined hosts with domain/FQDN/OS/high-value/DC.
5. **Path** — draw the chosen attack path as edges between hosts; a BloodHound
   edge name (e.g. `AdminTo`) auto-fills an OS-aware abuse description.
6. **Evidence** — pin screenshots/logs/notes to a host/service/finding.
7. **Report** — export an evidence bundle (zip + manifest) or push findings +
   evidence to Ghostwriter.

## Security posture

- Binds `127.0.0.1` by default; off-loopback requires TLS.
- Per-engagement bearer token on every API/WS request (stored `0600` in
  `<db>.token`).
- All XML parsed with `defusedxml`. All scan-derived strings are treated as
  attacker-controlled: stored as text, rendered as text (never HTML), behind a
  strict CSP. Uploaded non-images are never served inline.
- DNS-rebinding blocked (host allow-list); writes require `X-Requested-By`.

## Tests

```bash
unset PYTHONPATH          # this host's profile sources ROS, which breaks pytest
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
```

## Status

- **Phase 1** ✓ packaging, SQLite schema, nmap parser, merge+provenance, REST
  (import/hosts/detail/evidence), Cytoscape UI, evidence bundle export, tests.
- **Phase 2** ✓ token auth + TLS, WebSocket live updates, `/wall`, operator
  edges + host-state editing, scope-file enforcement, playbook docs.
- **Phase 3** ✓ BloodHound computer ingest, chosen-path edges with OS-aware
  descriptions, Faraday ingest (vulns → findings), Ghostwriter push *(built
  against the documented API, **not yet verified against a live server** — see
  `src/siege/export/ghostwriter.py`)*.
- **Multi-subnet grouping** ✓ graph groups hosts by their real subnet (any
  mask), driven by imported subnets + scope CIDRs, `/24` fallback.
- **Mistake recovery** ✓ delete host (cascades) / finding / evidence, edit
  finding title+severity; on-disk evidence blobs swept when unreferenced.
- **Operator identity** ✓ a per-browser operator name tags the findings,
  evidence, edges and state changes you add (full auth still deferred).
- **Browser smoke test** ✓ headless Playwright test renders the UI, imports,
  clicks a host, adds a finding, opens `/wall`; fails on any uncaught JS error.
  Run: `pip install -e '.[dev]' && playwright install chromium`.
- **TODO** SysReptor push; verify Ghostwriter live; Faraday REST pull (file
  import works today); nested subnet compound nodes (grouping is flat today).
