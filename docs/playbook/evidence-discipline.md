# Evidence discipline — quick glance

Reports are won or lost here. The rule: **capture at the moment of
exploitation**, not at hour eight when you're trying to remember what you did.
siege's evidence board exists to make this a 10-second habit, not a chore.

> One action → one piece of evidence, pinned to the exact host/service/finding,
> while the terminal is still on screen.

## What to capture, every time

- **The command** you ran (copy it verbatim — flags matter).
- **The output** proving it worked (or the error, if it didn't — negative
  results are findings too).
- **A screenshot** when the proof is visual (a shell, a web page, a creds dump
  header — redact actual secrets).
- **Timestamp + who** (siege records `added_by` and `added_at` for you).

## Pin it in siege

Click the host → **Evidence** panel → choose the target (host, a specific
service, or a finding) → attach a file or paste a note → add a caption.

- Files are stored by SHA-256 (deduped; the hash goes in the report so a
  reviewer can verify nothing changed between capture and report).
- Only real images render inline; logs and other files download — a hostile
  file can't execute in the board.
- A **note** is fine when there's no file: paste the command + output as text.

## Tie it to the graph

After an exploit, in siege:

1. **Advance the host state** (`vulnerable → foothold → owned`).
2. **Draw the edge** you used (`pivot` / `creds_reuse`), or for an AD edge type
   its BloodHound name (`AdminTo`, `DCSync`, …) — siege writes an OS-aware
   abuse description automatically.
3. The wallboard updates live, so the room sees the route as it happens.

## Finding hygiene

Every finding needs: a clear **title**, a **severity** the client recognizes
(`info/low/medium/high/critical`), the affected **host/service**, reproduction
steps, and its pinned evidence. Faraday vulns arrive as findings already — add
the evidence and tighten the title/severity.

## Export for the report

Operator UI → **Export evidence** (zip + `manifest.json`/`manifest.md`, every
file hashed), or push findings + evidence straight to **Ghostwriter**. Do this
continuously, not once at the end.
