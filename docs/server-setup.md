# siege server setup

How to stand up the machine that runs `siege` for an engagement, plus the
supporting tooling and services the playbook references. Commands target
Debian/Ubuntu (24.04/22.04); adapt for other distros. For the *operator* boxes,
Kali ships most of the toolchain already — see [§7](#7-operator-toolchain).

> siege is **one server process per engagement**: one SQLite file + one evidence
> directory. To run several engagements, run several processes on different
> ports/files (the templated systemd unit in §4 does this cleanly).

## 0. Roles — decide what goes where

| Role | Runs | Put it on |
|---|---|---|
| **siege server** | the `siege` process, the engagement DB + evidence | its own small VM, or the lead operator's box |
| **Operator box(es)** | nmap, Impacket, NetExec, BloodHound collectors, tunnels | Kali VMs (one per operator) |
| **Faraday** | vuln-management workspace | its own VM (or operator box) |
| **Ghostwriter** | reporting | its own VM |

Simplest for a practice engagement: siege + Faraday + Ghostwriter each on a small
VM on a **team-only network** (lab VLAN, VPN, or Tailscale), operators on Kali.

## 1. Host requirements (siege server)

- Linux, **Python 3.11+**, ~1 GB RAM, disk sized for evidence (screenshots add
  up — budget a few GB).
- A **team-only network interface** if you want to reach it from other boxes
  (binding off-loopback requires TLS — see §3).
- No Node, no database server, no internet at runtime — siege bundles its
  frontend and uses local SQLite.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
# Only needed if a pip wheel has to build from source (rare on x86_64):
sudo apt install -y build-essential python3-dev libffi-dev
```

## 2. Install siege

Pick **A** (from source) for a box you'll also develop on, or **B** (from a
built wheel) for a clean deployment.

**A — from source**
```bash
sudo mkdir -p /opt/siege && sudo chown "$USER" /opt/siege
git clone <your-repo-url> /opt/siege/uva-siege      # or copy the tree in
cd /opt/siege/uva-siege
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[tls]'          # add ,dev,ui for tests + the browser smoke test
```

**B — from a wheel (no source tree needed)**
```bash
# On a build box with the source:
python3 -m build --wheel            # -> dist/siege-0.1.0-py3-none-any.whl
# On the server:
python3 -m venv /opt/siege/.venv && /opt/siege/.venv/bin/pip install \
    /path/to/siege-0.1.0-py3-none-any.whl 'cryptography>=42.0'
```

Extras: `[tls]` (self-signed cert generation), `[dev]` (test deps +
cryptography + Playwright), `[ui]` (just Playwright). The wheel already contains
the whole frontend, so `pip install` is all you need to serve the UI.

Verify:
```bash
siege --help          # or /opt/siege/.venv/bin/siege --help
```

## 3. Run it

**Localhost (single operator on the box):**
```bash
siege --db practice-01.sqlite
```
The startup banner prints a tokenized URL — open it to authenticate. The token
is also saved `0600` in `practice-01.sqlite.token`.

**On the team network (TLS required off-loopback):**
```bash
siege --db practice-01.sqlite \
      --evidence-dir practice-01-evidence \
      --bind 10.8.0.2 --port 8000 --tls-selfsigned
```
siege **refuses to bind a non-loopback address without TLS** (no plaintext
secrets on the wire). `--tls-selfsigned` generates a throwaway cert — browsers
show a one-time warning you accept. For a trusted cert, pass
`--tls-cert`/`--tls-key` instead (see §5).

Put the printed `/wall?token=…` URL on the room TV (kiosk/full-screen browser).

**Firewall — expose only on the team interface:**
```bash
sudo ufw allow in on tailscale0 to any port 8000 proto tcp   # example: Tailscale iface
sudo ufw enable
```
If you'd rather not open a port at all, keep siege on `127.0.0.1` and reach it
over SSH: `ssh -L 8000:127.0.0.1:8000 user@siege-server`.

## 4. Run as a service (systemd)

So siege survives reboots and restarts on crash. This **templated** unit runs
one instance per engagement name (`siege@practice-01`).

```bash
sudo useradd --system --home /var/lib/siege --create-home siege
sudo mkdir -p /var/lib/siege && sudo chown siege:siege /var/lib/siege
```

`/etc/systemd/system/siege@.service`:
```ini
[Unit]
Description=siege engagement server (%i)
After=network-online.target
Wants=network-online.target

[Service]
User=siege
Group=siege
WorkingDirectory=/var/lib/siege
# Bind to your team interface IP; drop --bind/--tls-selfsigned for localhost-only.
ExecStart=/opt/siege/.venv/bin/siege \
    --db /var/lib/siege/%i.sqlite \
    --evidence-dir /var/lib/siege/%i-evidence \
    --bind 10.8.0.2 --port 8000 --tls-selfsigned
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/siege
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siege@practice-01
sudo systemctl status siege@practice-01
```

**Get the access URL / token** (the banner goes to the journal; the token also
lives in the file):
```bash
journalctl -u siege@practice-01 | grep -A2 'operator UI'
sudo cat /var/lib/siege/practice-01.sqlite.token
```
Run a second engagement on another port by copying the unit to a port-specific
one, or set the port per instance via an `EnvironmentFile`.

## 5. Trusted TLS (optional)

Self-signed (`--tls-selfsigned`) is fine for a practice lab. For a real cert:

- **Bring your own**: `--tls-cert fullchain.pem --tls-key privkey.pem` (readable
  by the `siege` user; keep the key `0600`).
- **Behind a reverse proxy** (Caddy/nginx terminating TLS): run siege on
  `127.0.0.1` without TLS and proxy to it. The proxy must forward WebSockets
  (for `/ws`) and pass the `Host` header as `localhost`/`127.0.0.1` (siege's
  anti-rebinding host allow-list only accepts loopback names). Simplest reliable
  path for a lab is siege's own `--tls-selfsigned` or an SSH tunnel.

## 6. Backups & data

An engagement is three things next to each other: `NAME.sqlite` (+ its
`-wal`/`-shm` while running), `NAME-evidence/`, and `NAME.sqlite.token`.

- **Consistent DB copy while running** (don't just `cp` the live file):
  ```bash
  sqlite3 /var/lib/siege/practice-01.sqlite ".backup '/backups/practice-01.sqlite'"
  ```
- Back up the `-evidence/` directory alongside it (plain files, sha256-named).
- The `.token` is a credential — protect backups accordingly, or rotate by
  deleting it and restarting (a new token is generated).
- Snapshot the VM between sessions so you can roll back a botched import.

## 7. Operator toolchain

The playbook commands assume these on the **operator** boxes (not the siege
server). On **Kali** most are preinstalled — prefer Kali to skip per-tool setup.
On Ubuntu:

```bash
sudo apt install -y nmap pipx seclists hashcat john
pipx ensurepath
pipx install impacket          # secretsdump, GetUserSPNs, getST, ntlmrelayx, ...
pipx install netexec           # nxc — spraying/exec/enumeration
pipx install certipy-ad        # AD CS abuse
pipx install bloodyAD          # clean LDAP/ACL abuse
# kerbrute, Responder, ligolo-ng, chisel: grab release binaries
#   kerbrute:  https://github.com/ropnop/kerbrute/releases
#   ligolo-ng: https://github.com/nicocha30/ligolo-ng/releases  (agent + proxy)
#   chisel:    https://github.com/jpillora/chisel/releases
```

BloodHound (CE) + collectors:
```bash
# BloodHound CE via Docker (its own box or an operator box)
curl -L https://ghst.ly/getbhce -o docker-compose.yml   # official CE compose
docker compose up -d                                     # UI on http://localhost:8080
# Collect with SharpHound (Windows) or bloodhound.py / azurehound, then upload.
```
See [playbook/bloodhound-edges.md](playbook/bloodhound-edges.md) and the
collection/pre-flight checklists there.

## 8. Supporting services

**Faraday** (feeds vulns that siege imports as findings — see
[playbook/faraday.md](playbook/faraday.md)):
```bash
pip install faradaysec && faraday-manage create-superuser && faraday-server
# or run the official Docker image; server on http://localhost:5985
```

**Ghostwriter** (report push target — see
[playbook/reporting-ghostwriter.md](playbook/reporting-ghostwriter.md)):
```bash
git clone https://github.com/GhostManager/Ghostwriter && cd Ghostwriter
./ghostwriter-cli-linux install     # Docker-based; follow the printed admin URL/creds
```
> Verify siege's Ghostwriter push against your Ghostwriter **version** on a
> throwaway report first — the GraphQL field names are documented but unverified
> against a live server.

## 9. Verify the install

```bash
cd /opt/siege/uva-siege && . .venv/bin/activate
# import a bundled sample and check the API:
siege --db /tmp/smoke.sqlite --port 8099 &   # localhost
TOK=$(cat /tmp/smoke.sqlite.token)
curl -s -H "Authorization: Bearer $TOK" -H 'X-Requested-By: siege' \
     -F file=@tests/fixtures/deepscan.xml http://127.0.0.1:8099/api/import
# open http://127.0.0.1:8099/?token=$TOK and http://127.0.0.1:8099/wall?token=$TOK
```

Run the test suite (dev install):
```bash
python -m pytest
# Browser smoke test needs: pip install -e '.[dev]' && playwright install chromium
#   (and `playwright install-deps` if the browser won't launch for missing libs)
# If pytest auto-loads an unrelated broken plugin on this host, prefix:
#   PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
```

## 10. Security recap (don't skip)

- **Loopback by default; TLS required off-box.** Never bind `0.0.0.0` on an
  untrusted network.
- **Token on every API/WS request**; keep `NAME.sqlite.token` `0600` and off
  shared storage. Rotate by deleting it + restarting.
- **Don't run siege as root.** Use the `siege` system user (§4).
- **One file per engagement.** Don't reuse a DB across clients.
- Scan-derived text is rendered as text behind a strict CSP; uploaded
  non-images are never served inline — but still treat evidence as untrusted.
