# Web enumeration — quick glance

Every CPTC environment has web targets, and they're often the fastest foothold
(default creds, an upload, an exposed admin panel). Work each HTTP/HTTPS service
`siege` found; pin what you learn as evidence/findings on that service.

> Order: identify the stack → map content → check the boring wins (defaults,
> known CVEs) → then attack logic. Don't fuzz for an hour before trying
> admin/admin.

## Identify the service

```bash
whatweb http://TARGET                      # stack fingerprint
curl -sI http://TARGET                     # headers, server, redirects
curl -s http://TARGET -o /dev/null -w '%{http_code} %{redirect_url}\n'
openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
```

TLS SANs and vhost redirects often reveal hostnames — add them to `/etc/hosts`
and re-request; many apps only answer on their real vhost.

## Map content

```bash
# Directory / file discovery
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,204,301,302,307,401,403 -o ffuf.json
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak,zip

# Virtual-host discovery (when one IP hosts many sites)
ffuf -u http://TARGET -H "Host: FUZZ.DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <baseline-size>
```

Filter noise: baseline the response size of a known-404 and `-fs` it.

## The boring high-value checks (do these first)

- **Default / weak creds** on every login and admin panel (`admin:admin`,
  vendor defaults, `Tomcat`/`manager`, Jenkins, Grafana, printers, iDRAC/iLO).
- **Known-CVE on the fingerprinted version** — a quick `searchsploit <product
  version>` before any manual work.
- **Exposed interfaces**: `/actuator`, `/.git/`, `/server-status`, `.env`,
  backup files (`*.bak`, `*.zip`, `*.sql`), Swagger/`/api/docs`.
- **nikto** for a fast misconfig sweep: `nikto -h http://TARGET -o nikto.xml`
  (feed it through Faraday → `siege` as findings).

## Then the app logic

- Auth: bypass, weak reset, JWT `alg=none`/weak secret, IDOR on object ids.
- Injection: SQLi (`sqlmap -u '...' --batch`), command injection, SSTI, path
  traversal / LFI, SSRF to internal services.
- File upload → webshell (check allowed types, double extensions, content-type).

## Record in siege

For each web service: set/raise the host state, add a **finding** on that
service (title + severity + repro), and pin evidence (request/response,
screenshot of the panel, the shell landing). A hostile page title or banner is
rendered as text — safe to paste verbatim. See
[evidence-discipline.md](evidence-discipline.md).
