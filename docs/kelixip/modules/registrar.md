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

Used by the reference script
[`direct-call.exs`](../../../apps/kelixip/scripts/direct-call.exs) and its
authenticated variants; commented in [B2BUA.md](../../../B2BUA.md).

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

The module itself contributes **no** `describe_control/0` command. Its store is
inspected and edited through the **core** `registration` commands, documented here
rather than in [administration.md](../administration.md) because what they mean is
this module's contract: they read the very bindings `save/2` wrote, with the
per-domain separation and the expiry rules stated above.

Both frontals are listed together — one operation, two frontals, and the online
help (`kelictl registration help`) prints the same routes next to the same
commands.

| `kelictl` | REST | R/W |
|---|---|---|
| `registration list` | `GET /registrations` | R |
| `registration list <domain>` | `GET /domains/<domain>/registrations` | R |
| `registration show <domain> <aor>` | `GET /domains/<domain>/registrations/<aor>` | R |
| `registration remove <domain> <aor> [contact]` | `DELETE /domains/<domain>/registrations/<aor>[?contact=…]` | W |

### Addressing a registration

An AOR is only unique **within a domain**, so the domain is part of the address
rather than a filter on it: `show` and `remove` take `<domain> <aor>`, `list` groups
its answer per domain, and over REST a registration is a **sub-resource of the
domain** (`/domains/<domain>/registrations/<aor>`), never a query parameter.

With no argument, `list` prints one section per **served** domain — including the
ones nobody is registered in, because "served, empty" and "not served at all" are
what an operator is usually trying to tell apart. `<domain>` is resolved the way
inbound traffic is (name **or** alias, case-insensitively), so the host seen on the
wire is a valid argument; an unserved one is `no such domain` / `404` on the
collection itself, which is *not* the same answer as a served domain with an empty
`registrations` list. `GET /registrations` is the cross-domain view: one object per
served domain, in `domains.toml` order.

`<aor>` is the user-part (`alice`), or the full `alice@example.com` copied out of a
log — in which case its domain part must be that same domain, rather than being
silently ignored. `remove` takes an optional `contact` to drop just that binding
instead of the whole AOR; there is deliberately no form that removes an AOR from
every domain at once.

### What a binding shows

`show` prints what the registrar stored, not just the URI: `expires` both ways (the
remaining time is the operator's question, the instant is what a log line carries),
`source` — where the REGISTER actually came from, which behind a NAT is **not** what
the contact URI says, and the usual reason a call to a registered phone never
arrives — the transport it is reachable over, and the identity the handset sent
(`instance`, `reg-id`, `methods`, RFC 5626/3840). A field the handset did not send
gets no line at all in the CLI, and `null` in JSON.

```console
$ kelictl registration list
example.com
  aor    contacts  expires  bindings
  alice  2         4m58s    sip:alice@10.0.0.9:5060, sip:alice@10.0.0.9:5062
  bob    1         9m12s    sip:bob@10.0.0.22:5060

lab.example.net
  (no registration)

$ kelictl registration list lab.example.net
lab.example.net
  (no registration)

$ kelictl registration show example.com alice
aor:          alice@example.com
contacts:     2
  1. sip:alice@10.0.0.9:5060
     expires:   in 4m58s (2026-08-02T12:34:56Z)
     source:    udp 203.0.113.7:45112
     transport: udp
     instance:  <urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>
     reg-id:    1
  2. sip:alice@10.0.0.9:5062
     expires:   in 9m40s (2026-08-02T12:39:38Z)
     source:    tls 203.0.113.7:51044
     transport: tls

$ kelictl registration remove example.com alice
ok

$ kelictl registration show ghost.example.org alice
no such domain
```

### The same over REST

`GET /domains/<domain>/registrations` returns the domain's whole store;
`GET /domains/<domain>/registrations/<aor>` returns one of its inner objects (or
`404`), so the list and the detail view cannot disagree.

```json
{
  "domain": "example.com",
  "registrations": [
    {
      "domain": "example.com",
      "aor": "alice",
      "contacts": [
        {
          "uri": "sip:alice@10.0.0.9:5060",
          "expires_at": "2026-08-02T12:34:56Z",
          "expires_in": 298,
          "source": "udp 203.0.113.7:45112",
          "transport": "udp",
          "instance": "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>",
          "reg_id": "1",
          "methods": null
        }
      ]
    }
  ]
}
```

```bash
TOKEN=change-me
BASE=http://127.0.0.1:8090
H="Authorization: Bearer $TOKEN"

curl -s -H "$H" $BASE/registrations
curl -s -H "$H" $BASE/domains/example.com/registrations
curl -s -H "$H" $BASE/domains/example.com/registrations/alice

# drop one binding rather than the whole AOR
curl -s -X DELETE -H "$H" \
     "$BASE/domains/example.com/registrations/alice?contact=sip:alice@10.0.0.9:5060"
```

Authentication, the `[control_api]` block and the shared result mapping are the
frontal's own concern, not this module's — see [rest-api.md](../rest-api.md).

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
