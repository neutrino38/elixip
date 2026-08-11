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
import Kelix.Mod.Registrar, only: [save: 2, lookup: 1]
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

### `save/2`, `save/4`

```elixir
save(sip_ctx, req)                                   # scenario form
save(req, domain, dialog_pid \\ nil, info \\ nil)    # programmatic form
  :: {:registered, granted}
   | {:unregistered, granted}
   | {:error, {code, reason}}
   | {:error, :down | :timeout}
```

Register or unregister the contacts of a `REGISTER`. In the scenario form the
served domain and the backing dialog are read off the scenario context
(`sip_ctx.domain`, `sip_ctx.dialogpid`), so a script carries neither. In the
programmatic form `dialog_pid` is the backing dialog (stored per contact, used for
teardown) and `info` is arbitrary scenario data.

The verdict says what happened to the AOR:

| Verdict | Meaning |
|---|---|
| `{:registered, granted}` | the AOR has live bindings |
| `{:unregistered, granted}` | its last binding is gone (`Expires: 0`, or the `Contact: *` wildcard); `granted.contacts` is empty and `granted.expires` is `0` |
| `{:error, {code, reason}}` | `400` (no Contact / bad wildcard), `423` (too brief), `403` (too many contacts) |
| `{:error, :down \| :timeout}` | the store could not answer |

`granted` is `%{aor, contacts, expires}`: **all** the AOR's current bindings, each
stamped with its own remaining lifetime (RFC 3261 §10.3 step 8). It does not build
the `200 OK`; the script does, with
`SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)`.

- The AOR is the `To` user-part (RFC 3261), case-insensitive.
- The stored `received` is the **real** transport source of the REGISTER (proto,
  IP, port) — not the announced, possibly-NATed `Contact`.
- The call is reported to the monitor as a `:db` command.

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
| `uris` | the live contacts, each stamped with its destination and registration flow, as a list of **q groups** — one entry per Contact `q` value, in descending order (absent `q` means no stated preference, taken as the highest; equal `q` keeps registration order) |
| `ruri` | `:peer` — a registered contact is reached by asking for it by name |
| `use_srv` | `false` — the contacts already carry the flow they registered over |
| `fork` | `:parallel` — a group rings all at once, and the groups are walked in order |

That is kamailio's `lookup("location")` + `t_relay()`, and what RFC 3261 §16.6
prescribes: devices of equal preference ring together, and a group that all
refuses hands the call to the next one down.

A script wanting another policy edits the struct it gets back —
`%{peer | fork: :serial}` rings the contacts one at a time, `:none` tries the
first and stops.

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
# in the registrar scenario — see apps/kelixip/scripts/registrar.exs
state save_registration do
  req = last_uas_req()

  case Kelix.Mod.Registrar.save(sip_ctx, req) do
    {:registered, granted} ->
      SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
      goto wait_refresh, "200 OK"

    {:unregistered, granted} ->
      SIP.Session.Registrar.accept_registration(sip_ctx, req, granted)
      scenario_success("unregistered")

    {:error, {423, reason}} ->
      min = Kelix.Mod.Registrar.min_expires(sip_ctx.domain)
      SIP.Session.Registrar.reject_registration(sip_ctx, req, 423, min)
      goto wait_register, "423 #{reason}"

    {:error, reason} when reason in [:down, :timeout] ->
      SIP.Session.Registrar.reject_registration(sip_ctx, req, 503, "Service Unavailable")
      scenario_failure("503 store down")

    {:error, {code, reason}} ->
      SIP.Session.Registrar.reject_registration(sip_ctx, req, code, reason)
      scenario_failure("save() failed: #{code} #{reason}")
  end
end
```
