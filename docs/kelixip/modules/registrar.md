# registrar

The **usrloc / location service**: it stores each Address-of-Record (AOR) and its
registered contacts from `REGISTER` requests, and rewrites in-dialog requests to
reach the registered UA(s). Domains are strongly separated — one contact store
per domain.

The module **decides**; it never composes the SIP response. The registrar script
maps the facade result onto the `SIP.Session.Registrar.*` helpers.

## Loading

The `registrar` block lives in **`domains.toml`** (not `config.toml`) so it is
hot-reloadable alongside the domains it serves — it reloads on
`kelictl domain reload-all`. A `[module.registrar]` in `config.toml` is ignored.

```toml
# domains.toml
[module.registrar]
max_contacts_per_aor = 10
min_expires = 60
```

```elixir
import Kelix.Mod.Registrar, only: [save: 4, lookup: 1]
```

Per-domain activation and expiry bounds are a **separate** block, on each domain:

```toml
# domains.toml
[[domain]]
name = "example.com"

  [domain.registrar]
  script           = "uas_register"   # the registrar scenario for this domain
  default_expires  = 3600
  min_expires      = 60
  keepalive_period = 30
```

## Parameters

Module block — `[module.registrar]` (in `domains.toml`):

| Key | Type | Default | Description |
|---|---|---|---|
| `max_contacts_per_aor` | integer | `10` | Max simultaneous contacts stored per AOR (beyond ⇒ `403`) |
| `min_expires` | integer | `60` | Lowest `Expires` accepted (below ⇒ `423 Interval Too Brief`) |
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |

Per-domain block — `[domain.registrar]` (activates the function for a domain):

| Key | Type | Default | Description |
|---|---|---|---|
| `script` | string | **required** | Scenario script handling REGISTER for this domain |
| `default_expires` | integer | `3600` | Granted expiry when the request asks for more |
| `min_expires` | integer | `60` | Per-domain lower bound |
| `keepalive_period` | integer | — | OPTIONS keep-alive interval (s) |

> The maximum granted expiry is capped at `3600`s regardless of the requested
> value.

## Facades

### `save/4`

```elixir
save(req, domain, dialog_pid \\ nil, info \\ nil) ::
  {:ok, granted} | {:error, {code, reason}} | {:error, :down | :timeout}
```

Register or unregister the contacts of a `REGISTER` under `domain`. `dialog_pid`
is the backing dialog (stored per contact, used for teardown); `info` is
arbitrary scenario data. `granted` is `%{aor, contacts, expires}` — the contacts
and expiry **actually** granted (an all-`Expires: 0` request unregisters and
grants `0`). It does not build the `200 OK`; the script does.

- The AOR is the `To` user-part (RFC 3261), case-insensitive.
- The stored `received` is the **real** transport source of the REGISTER (proto,
  IP, port) — not the announced, possibly-NATed `Contact`.
- Errors map to SIP codes: `400` (no Contact), `423` (too brief), `403` (too
  many contacts).

### `lookup/1`

```elixir
lookup(req) :: {:ok, [req]} | :notfound | {:error, term} | {:error, :down | :timeout}
```

Rewrite `req` so its R-URI reaches the AOR's live contacts (one rewritten request
per contact, with the resolved destination + flow). Expired contacts are filtered
out on read.

### `subscribe_register_event/2`, `unsubscribe_register_event/2`

```elixir
subscribe_register_event(uri, pid)   :: :ok | {:error, :down | :timeout}
unsubscribe_register_event(uri, pid) :: :ok | {:error, :down | :timeout}
```

Subscribe/unsubscribe `pid` to registration events for an AOR (the AOR may not be
registered yet).

## Events

Subscribers receive:

```elixir
{:registrar, event, "aor@domain"}
# event :: :registered | :unregistered | :expired | :disconnected
```

`:disconnected` fires when the connected transport / backing dialog of a contact
drops (WebRTC-critical): the binding is invalidated even before its `Expires`.

## Control commands

None yet. Registrations are inspected with the core commands
`kelictl registration list [domain]` / `registration show <domain> <aor>`
(see [administration.md](../administration.md)).

## Examples

```toml
# domains.toml
[module.registrar]
max_contacts_per_aor = 5
min_expires = 30

[[domain]]
name = "example.com"

  [domain.registrar]
  script = "uas_register"
```

```elixir
# in the registrar scenario
import Kelix.Mod.Registrar, only: [save: 4]

case save(register_req, "example.com", dialog_pid, nil) do
  {:ok, granted} -> reply_registrar_ok(granted)         # script builds 200 OK
  {:error, {code, reason}} -> reply(code, reason)
  {:error, :down} -> reply(500, "Server Internal Error")
end
```
