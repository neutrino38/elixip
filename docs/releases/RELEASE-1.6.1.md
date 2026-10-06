# Release 1.6.1

2026-09-27 — since 1.6.0 (2026-09-26). Theme: kelescope shows presence live,
and the journal of a live scenario.

## Observability — the presence panel

`Kelix.Control` has been improved to enable proper presence observability
from kelescope. See [presence.md](../kelixip/modules/presence.md#live-presence-panel).

## Observability — the journal of a live scenario


Live traces can be activated on a scenario while it runs. Transitions, commands and
SIP messages are stored in an interla journal and can be rendered as text or PlantUML.

```console
$ kelixip monitor
$ kelictl debug 12 on          # the monitor marks row 12 with ●
$ kelictl debug 12 off         # write it now (the end of the scenario does too)
$ kelictl debug list
$ kelictl debug show 12        # sngrep-like ladder; --full adds each message
$ kelictl debug show 12 --format-puml > call-12.puml
```

Journal retention can be configurer in the `[debug]` section of  `config.toml`:

| Key | Default | Meaning |
|---|---|---|
| `trace_retention` | `3600` | seconds a journal is kept after it is written |
| `max_traces` | `100` | journals kept; the oldest is dropped to make room |
| `max_trace_bytes` | `1048576` | message text kept per journal; past it, the journal is cut |

Traces can be activated by API and obtained by API

REST: `POST /scenarios/<id>/debug` (`409` when already written),
`GET /traces`, and `GET /traces/<id>`, which answers the journal **unrendered**,
as JSON. Reference: [administration.md](../kelixip/administration.md#the-journal-of-a-live-scenario).

## Protocol — `gzip` bodies are accepted

**Visible to peers.** A request whose body is `Content-Encoding: gzip` (or
`x-gzip`) used to be answered **415**; it is now decoded and processed.
`Accept-Encoding` advertizes `deflate, gzip, identity`.


## Dependency

FSL goes from 0.2.1 to **0.4.1** (`finite_state_language` on hex): the live
journal and the hand-off of its events before any rendering
(`FSL.Host.journal_events/2`). elixipp's `--log-sequence` still writes its
PlantUML file as before.

## Fixes

**`kelictl presence list` shows a registered presentity.** 

**The registrar no longer renders an AOR on every REGISTER when nobody watches
its domain.** 
