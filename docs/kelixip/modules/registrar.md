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

### `targets/2`

```elixir
targets(domain, req) ::
  {:ok, %SIP.B2bua.Peer{}} | :notfound | :no_aor | :unavailable
```

Where to call the AOR `req` asks for, as a peer ready to hand to
`b2bua_forward/3`. The B2BUA-shaped counterpart of `lookup/1`: a B2BUA builds its
own forwarded request and needs targets, not rewritten requests.

The AOR is the R-URI user part of `req`, case-insensitive, in `domain` — not the
R-URI domain, which may be an alias the store folds.

The returned peer carries the policy a registered AOR implies:

| Field | Value |
|---|---|
| `uris` | the live contacts, each stamped with its destination and registration flow, ordered by descending Contact `q` (absent `q` ranks top; equal `q` keeps registration order) |
| `ruri` | `:peer` — a registered contact is reached by asking for it by name |
| `use_srv` | `false` — the contacts already carry the flow they registered over |
| `fork` | `:serial` — the devices are tried in `q` order, one after the other |

A script wanting another policy edits the struct it gets back
(`%{peer | fork: :none}`).

> **`:serial`, where kamailio is parallel.** `lookup("location")` + `t_relay()`
> rings every contact of a q group at once. Parallel forking is not built yet, and
> `fork: :parallel` is not a value the hunt honours — it dials the highest-q
> contact and never fails over. This returns `:serial` until it exists.

Each failure is one atom, mapping to one SIP answer:

| Verdict | Meaning | Typical response |
|---|---|---|
| `:notfound` | the AOR has no live binding | `480 Temporarily Unavailable` |
| `:no_aor` | the request carries no usable R-URI user part | `400 Bad Request` |
| `:unavailable` | the store or the module could not answer (the reason is logged) | `500` |

Used by the reference scripts
[`direct-call.exs`](../../../apps/kelixip/scripts/direct-call.exs) and
[`b2bua.exs`](../../../apps/kelixip/scripts/b2bua.exs); commented in
[B2BUA.md](../../../B2BUA.md).

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
