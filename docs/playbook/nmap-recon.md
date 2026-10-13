# nmap recon — quick glance

Copy/paste recipes for the recon & enumeration phase. Replace `TARGETS`
(`10.10.10.0/24`, a file `-iL hosts.txt`, or a single IP) and keep everything
**in scope** — check the scope file first. Always write XML (`-oX`) so it
imports into `siege`.

> Rule of thumb: sweep wide and shallow first, then go deep only on what's up
> and in scope. Import each run into siege; it merges by IP.

## 1. Host discovery (ping sweep) — fast, find what's alive

```bash
nmap -sn -oX sweep.xml TARGETS
```

- `-sn` = no port scan, just discovery. On a local segment it uses ARP (fast).
- Import `sweep.xml` → hosts appear as `discovered`.

## 2. Service / version deep scan — the workhorse

```bash
nmap -sV -sC -O -oA deep_TARGET -T4 --top-ports 1000 TARGET
```

- `-sV` service/version, `-sC` default safe scripts, `-O` OS detect.
- `-oA base` writes `.nmap/.gnmap/.xml` at once; import the `.xml`.
- `-T4` is a sane LAN speed; drop to `-T3` on fragile/noisy networks.
- Deep-scan a host and siege bumps it `discovered → enumerated`.

## 3. All TCP ports (don't miss a high port)

```bash
nmap -p- --min-rate 2000 -oX allports.xml TARGET      # find open ports fast
nmap -sV -sC -p <csv of open ports> -oX deep.xml TARGET  # then enumerate them
```

Two-step is faster than `-sV -p-`: the first pass finds ports, the second only
version-scans the ones that are open.

## 4. UDP (slow — target the usual suspects)

```bash
nmap -sU --top-ports 50 -oX udp.xml TARGET
```

Key UDP services: DNS 53, SNMP 161, NetBIOS 137, NTP 123, IKE 500.

## 5. Targeted NSE scripts (examples)

```bash
nmap -p445 --script smb-enum-shares,smb-os-discovery -oX smb.xml TARGET
nmap -p80,443 --script http-title,http-enum -oX web.xml TARGET
nmap -p389,636 --script ldap-rootdse -oX ldap.xml TARGET
```

NSE output is **attacker-controlled** — siege stores and shows it as text,
never HTML (a hostile http-title can't XSS the wallboard).

## 6. Timing & stealth knobs

- `-T0..T5` slowest→fastest; `--min-rate`/`--max-rate` pin packet rate.
- `--max-retries 1` and `--host-timeout 5m` keep a big sweep from stalling.
- Scans are loud by design here — note likely detections for the report.

## Import into siege

Operator UI → **Import nmap** (or `POST /api/import` with the `.xml`). Re-import
freely: hosts merge by IP, services by port, provenance (`source_file` +
timestamps) is kept. Next: BloodHound for AD (`bloodhound-edges.md`), Faraday
for vulns (`faraday.md`).
