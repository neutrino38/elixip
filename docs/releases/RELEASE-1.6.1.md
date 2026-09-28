# Release 1.6.1

2026-09-27 — since 1.6.0 (2026-09-26). Theme: kelescope shows presence live,
and the journal of a live scenario.

## Observability — the presence panel

[kelescope](https://github.com/neutrino38/kelescope) follows a domain's
presentities the way it follows its registrations: one snapshot, then the
changes as they happen, with no polling.

| New in `Kelix.Control` | What the subscriber receives |
|---|---|
| `subscribe_presence/2` | `{:kelix_presence, domain, {:upsert, row}}`, or `{:remove, aor}` when nothing is published about an AOR and nobody watches it |

```elixir
{:ok, %{domain: "example.com", presentities: [row]}} =
  Kelix.Control.subscribe_presence(self(), "example.com")

row :: %{domain, aor, presentity_uri, status, activity, note, states, watchers}
```

- A presentity is listed while it holds a publication, a watcher or a reported
  registration.
- `status` is `"open"`, `"closed"` or `nil` — what a watcher of the `presence`
  package is told, registrations included. `activity` and `note` come from the
  same document.
- `states` and `watchers` carry the columns of `kelictl presence list` and
  `kelictl presence watchers`.
- A row is pushed on a publication, refresh, removal or expiry, on
  `kelictl presence remove`, when a watcher comes or goes, and when a
  presentity registers or unregisters.

`domain` is matched by name or alias; an unserved domain answers
`{:error, :not_found}`. Without the presence module the list is empty.
`unsubscribe_presence/2` stops the pushes, and a subscriber that dies is dropped.

The module half is `Kelix.Mod.Presence.subscribe_presentities/2` /
`unsubscribe_presentities/2`. Reference:
[presence.md](../kelixip/modules/presence.md#live-presence-panel).

## Observability — the journal of a live scenario

A call that misbehaves can be traced while it runs, without restarting anything.
The node keeps the journal — the scenario's transitions, commands and SIP
messages — and each reader draws it: `kelictl` as a ladder or PlantUML,
kelescope in a popup.

```console
$ kelictl debug 12 on          # the monitor marks row 12 with ●
$ kelictl debug 12 off         # write it now (the end of the scenario does too)
$ kelictl debug list
$ kelictl debug show 12        # sngrep-like ladder; --full adds each message
$ kelictl debug show 12 --format-puml > call-12.puml
```

- **One journal per scenario instance.** Once written, `on` is refused
  ("already written", exit code 4) and the scenario goes on untraced.
- Every SIP message of the scenario's dialogs is recorded, both legs of a B2BUA
  included, as its **text with the body decoded**: a `deflate` or `gzip` body
  is shown in clear, and each message is clipped at 8 KiB.
- Journals are kept **in memory only**; a restart loses them. New `[debug]`
  keys in `config.toml`:

| Key | Default | Meaning |
|---|---|---|
| `trace_retention` | `3600` | seconds a journal is kept after it is written |
| `max_traces` | `100` | journals kept; the oldest is dropped to make room |
| `max_trace_bytes` | `1048576` | message text kept per journal; past it, the journal is cut |

REST: `POST /scenarios/<id>/debug` (`409` when already written),
`GET /traces`, and `GET /traces/<id>`, which answers the journal **unrendered**,
as JSON. Reference: [administration.md](../kelixip/administration.md#the-journal-of-a-live-scenario).

### The contract kelescope codes against

| In `Kelix.Control` | What the caller gets |
|---|---|
| `subscribe_monitor/1` (existing) | each row gains `traced: boolean()` — the instance's journal is on |
| `debug_scenario/3` (`id, :on \| :off, admin`) | `:ok`, `{:error, :not_found}`, or `{:error, :journal_written}` on `:on` |
| `subscribe_traces/1` | `%{limits: %{trace_retention, max_traces, max_trace_bytes}, traces: [summary]}`, then `{:kelix_traces, {:upsert, summary}}` or `{:remove, id}` |
| `traces/0` | `[summary]`, least recently written first |
| `trace/1` | `{:ok, summary + %{meta, events}}` or `{:error, :not_found}` |

```elixir
summary :: %{id, scenario, domain, script, written_at, expires_at,
             running, sip_count, bytes}
```

- `:upsert` is pushed when a journal is stored and again when its instance ends
  (`running` goes false); `:remove` when it expires or is evicted.
  `unsubscribe_traces/1` stops the pushes, and a subscriber that dies is
  dropped.
- `events` are the `FSL.Journal` events, oldest first: `:transition`,
  `:command`, `:terminal`, `:message` (with `body`, `clipped`, `decoded_from`),
  and `:cut` when `max_trace_bytes` was reached. **A reader skips any other
  kind.**
- `meta.config` is the scenario's `config` block as declared, passwords
  included: mask it with `FSL.Diagram.mask/2` before showing it.
- kelescope renders with `{:fsl, "~> 0.4.1", hex: :finite_state_language}`
  (`FSL.Diagram.message_lanes/1`, `FSL.Diagram.PlantUML.render/2`).

Everything is plain data: it crosses the distribution as is, and `GET /traces`
answers the same shapes in JSON. The full contract, field by field:
[kelescope-debug-scenario.md](../design/kelescope-debug-scenario.md#4-the-contract-kelescope-codes-against).

## Protocol — `gzip` bodies are accepted

**Visible to peers.** A request whose body is `Content-Encoding: gzip` (or
`x-gzip`) used to be answered **415**; it is now decoded and processed.
`Accept-Encoding` says `deflate, gzip, identity`.

Every compressed body, `deflate` included, is now inflated **within the node's
`max_message_size`**. A body that inflates past it is treated as corrupt and
gets the same 415: a few hundred compressed octets can no longer expand to
gigabytes before the parser sees them.

## Dependency

FSL goes from 0.2.1 to **0.4.1** (`finite_state_language` on hex): the live
journal and the hand-off of its events before any rendering
(`FSL.Host.journal_events/2`). elixipp's `--log-sequence` still writes its
PlantUML file as before.

## Fixes

**`kelictl presence list` shows a registered presentity.** A subscriber reported
registered by `registrar-presence.exs` is open for its watchers, but the command
answered `(none)` unless it PUBLISHed. The registration is now a state of its own,
with `source` `registrar`, beside the publications (`source` `publish`); `list`
and `show` gain the `source` and `status` columns. A domain served by
`registrar.exs` reports nothing and still lists nothing.

**The registrar no longer renders an AOR on every REGISTER when nobody watches
its domain.** The skip meant for a domain without a registrations panel open
never triggered, so every REGISTER built the AOR's detail for no one. Nothing
was sent and nothing was wrong on the wire; the cost is gone.
