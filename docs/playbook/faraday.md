# Faraday — quick glance

[Faraday](https://github.com/infobyte/faraday) is a vulnerability-management
workspace: point many tools at it, it de-dupes hosts/services/vulns into one
place. `siege` doesn't replace it — it **imports Faraday's vulns as findings**
so the graph and the evidence board know what's wrong with each host.

> What siege takes from Faraday: hosts, services, and **vulnerabilities →
> findings** (pinned to the host, or to a specific service when the port is
> known). Users/paths/reporting stay where they belong.

## Setup (once per engagement)

```bash
pip install faradaysec        # or run the Docker image
faraday-manage create-superuser
faraday-server                # http://127.0.0.1:5985
faraday-cli auth -f http://127.0.0.1:5985 -u <user>
faraday-cli workspace create cptc
```

## Feed tools into Faraday

Faraday ingests most tools' native output. Examples:

```bash
faraday-cli tool report nmap_deep.xml -w cptc        # import an nmap XML
nmap -sV -oX - TARGET | faraday-cli tool report - -w cptc   # or stream it
faraday-cli tool report nikto_out.xml -w cptc
```

Faraday merges by host/service, so run your scanners into it all engagement.

## Export a workspace → import into siege

Get the workspace out as JSON, then import that file into siege:

```bash
# Faraday REST (v3): hosts with nested services/vulns
curl -s -u user:pass "http://127.0.0.1:5985/_api/v3/ws/cptc/hosts" -o faraday_cptc.json
```

Operator UI → **Import Faraday** (or `POST /api/import/faraday`). siege's
parser is tolerant of a few shapes: a `{"hosts":[…]}` export, a bare host list,
or the REST `{"rows":[{"value":…}]}` wrapper. Vulns may be nested under a host
or a service, or in a flat top-level `vulnerabilities` list that names a
`target` ip.

## How vulns map to siege findings

| Faraday | siege |
|---|---|
| host → service → vuln | finding on that **service** |
| host → vuln | finding on that **host** |
| flat vuln, `target` matches a scanned host | finding on that host |
| vuln for a host siege never scanned | counted as `unmatched_vulns`, skipped |

Severity map: `critical→critical`, `high→high`, `med/medium→medium`,
`low→low`, `informational/info/unclassified→info`.

## Gotchas

- **Scan the host first.** A vuln for an IP siege hasn't ingested is reported
  as `unmatched_vulns` and dropped — import the matching scan (nmap or Faraday
  hosts) so the finding has something to pin to.
- **Re-import is safe.** Findings dedupe on (host, service, title); severity and
  notes update in place, no duplicate pile-up.
- **Vuln text is untrusted** (names/descriptions come from tools and targets);
  siege renders it as text, never HTML.
- siege does not push findings back into Faraday — the flow is Faraday →
  siege → Ghostwriter.
