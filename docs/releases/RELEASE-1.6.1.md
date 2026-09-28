# Release 1.6.1

2026-09-27 — since 1.6.0 (2026-09-26). Theme: kelescope shows presence live.

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
