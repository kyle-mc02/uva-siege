# Initial access — quick glance

The step the AD cheat sheet assumes you've already done: turn "we can see the
network" into "we have a valid credential / a shell." Until you own one
principal, BloodHound path analysis has no starting node.

> Prefer the quietest credential you can get. A single valid domain user
> unlocks SharpHound and most enumeration — you don't need admin to start.

## Where first creds come from

- **Web** — default/weak creds, an upload-to-shell, an exposed config/`.env`,
  SSRF to an internal secret. See [web-enum.md](web-enum.md). Often the fastest.
- **Unauthenticated AD** — AS-REP roasting (users with pre-auth disabled) and,
  if you have *any* creds, Kerberoasting; crack offline. See
  [bloodhound-edges.md](bloodhound-edges.md).
- **Network services** — anonymous SMB/FTP, NFS exports, SNMP `public`,
  unauthenticated databases, printers leaking LDAP creds.
- **Poisoning** — Responder for LLMNR/NBT-NS/mDNS → capture NetNTLMv2, crack or
  relay (`ntlmrelayx`) where signing is off. Loud; note detections.
- **Password reuse / spraying** — see below.

## Password spraying (lockout-aware)

Spraying beats brute force in AD: one or two passwords across *many* users,
slowly, to avoid lockout.

```bash
# Enumerate the lockout policy FIRST (threshold + observation window)
nxc smb DC -u user -p pass --pass-pol

# Spray one password across a userlist; respect the window between rounds
nxc smb DC -u users.txt -p 'Season2026!' --continue-on-success
kerbrute passwordspray -d DOMAIN --dc DC users.txt 'Season2026!'
```

Rules:
- **Count attempts, not passwords.** Stay at least one below the lockout
  threshold per observation window; wait out the window between rounds.
- One spray can lock hundreds of accounts and burn the engagement's goodwill —
  confirm the policy and the window before you fire.
- Good candidate passwords: `Season+Year!`, company name + year, `Welcome1`,
  `Password1`, the breach-reuse list if the client allows it.
- Build the userlist from recon (web, SMB, LDAP, `GetNPUsers`, OSINT).

## Validate and record

- Confirm a hit actually authenticates (`nxc smb TARGET -u u -p p`), note where
  it's local admin (`(Pwn3d!)`), and whether it's a domain user or local.
- In `siege`: advance the host state, add a finding (how the cred was obtained),
  pin evidence (the capture/spray output, redact the live secret). Then collect
  SharpHound from that context and move to AD mapping.
