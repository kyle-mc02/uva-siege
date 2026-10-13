# Pre-flight & rules of engagement — quick glance

The first 15 minutes decide whether the next 8 hours are smooth or a scramble.
Do this before touching a target. The BloodHound sheet has an AD-specific
pre-flight; this is the engagement-wide one.

> If it's not in scope, it doesn't exist. If the clock is skewed, Kerberos
> fails. If roles aren't assigned, three people scan the same box.

## Rules of engagement — confirm in writing

- [ ] **Scope**: in-scope CIDRs/hosts, and the explicit **do-not-touch** list.
      Import both into `siege` (`POST /api/scope`, `!cidr` to exclude).
- [ ] **Time window**: start/stop, and any blackout periods.
- [ ] **Allowed actions**: is DoS off-limits? password spraying lockout risk
      accepted? social engineering in or out? data exfil simulated or real?
- [ ] **Client contacts**: who to call if something breaks or you suspect you've
      hit production you shouldn't have.
- [ ] **Deconfliction**: how the client tells your traffic from a real attacker.

## Environment pre-flight

- [ ] **Clock sync to the DC** — `sudo ntpdate DC` (Kerberos dies on >5 min skew).
- [ ] **Name resolution** — can you resolve the DC / target vhosts? Add to
      `/etc/hosts` if DNS is flaky; Kerberos needs FQDNs.
- [ ] **Tooling smoke-test + version-pin** — `nmap`, `nxc --version`,
      `impacket-version`, `bloodyAD --help`, `certipy --version`, your C2,
      `ligolo`/`chisel` all run. Pin versions so a mid-engagement surprise
      doesn't cost you the path.
- [ ] **siege up** — one server for the engagement, scope imported, `/wall` on
      the room TV, token shared with the team, evidence dir on disk. (Standing
      up the host: [../server-setup.md](../server-setup.md).)
- [ ] **Ghostwriter / SysReptor** reachable; report created; push credentials
      ready (see [reporting-ghostwriter.md](reporting-ghostwriter.md)).

## Roles (assign up front)

- **Recon** — sweeps, service enum, keeps `siege` current.
- **Web** — the HTTP/HTTPS attack surface.
- **AD** — SharpHound/BloodHound, path selection.
- **Pivot/infra** — tunnels, C2, keeps routes alive.
- **Scribe** — owns evidence discipline and the report; nags everyone to pin.

Rotate as needed, but someone owns each at all times.

## Decide the objective first

Ask BloodHound (and the client's crown-jewel definition) for the shortest
*achievable* path to the objective — not the globally shortest path you have no
foothold near. Write the objective on the whiteboard; re-check progress against
it each hour. See [bloodhound-edges.md](bloodhound-edges.md) and
[initial-access.md](initial-access.md).
