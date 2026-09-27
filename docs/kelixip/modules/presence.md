# presence

This module holds the presence collection: the state published about each
presentity, the live subscriptions to it, and the fan-out that turns one PUBLISH
into one NOTIFY per watcher. One collection per domain, strongly separated.

The module stores and pushes. **It decides nothing about who may watch whom**:
that is the subscribe script's, and
[`presence-subscribe.exs`](../../../apps/kelixip/scripts/presence-subscribe.exs)
is where a deployment writes its rule.

Both reference scripts authenticate the sender before anything else. A SUBSCRIBE
and a PUBLISH are challenged with a **401**, in the realm of the served domain,
through `Kelix.Mod.AuthDb` — so they need `kelixip-mod-auth_db` installed and a
`[module.auth_db]` block. A refresh is challenged like the first request.

A user publishes their **own** state only. `presence-publish.exs` answers **403**
to a PUBLISH whose presentity is not the user the digest proved: Alice holding a
valid password does not make her the authority on Bob's state. The presentity is
the Request-URI's user part (RFC 3903 §4.1).

Both scripts log one line per state change: the PUBLISH names the presentity, the
new state and the entity-tag; the NOTIFY names the watcher, the presentity, the
package and the state sent.

```
PUBLISH presence for sip:bob@example.com: new: open, on-the-phone (etag 3f2a…, 3600s)
NOTIFY presence to sip:alice@example.com about sip:bob@example.com: open, on-the-phone
```

Its records are kamailio's `presentity` and `active_watchers` rows, held in
memory. Nothing survives a restart: a dialog cannot be resurrected, so a watcher
re-subscribes and a publisher re-publishes.

> The reference scripts are
> [`presence-subscribe.exs`](../../../apps/kelixip/scripts/presence-subscribe.exs),
> [`presence-publish.exs`](../../../apps/kelixip/scripts/presence-publish.exs) and
> [`presence-rls.exs`](../../../apps/kelixip/scripts/presence-rls.exs).
> The design document is [DESIGN-PRESENCE.md](../../design/DESIGN-PRESENCE.md).

## Installing and activating the module

### Installing the `kelixip-mod-presence` package

`dnf install kelixip-mod-presence` / `apt install kelixip-mod-presence`

The package carries the module and the three reference scripts.

### Declaring the module in config.toml

```toml
# config.toml
[module.presence]
call_timeout_ms = 5000
```

Every key has a default, so an empty `[module.presence]` block is a valid one.

### Declaring the packages a domain serves, in domains.toml

One `[[domain.presence]]` block per event package. The package is the key: the
`Event` header of a SUBSCRIBE or a PUBLISH selects the block, and a package the
domain declares none for is answered **489 Bad Event** before any script runs,
with `Allow-Events` naming the ones it does serve.

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.presence]]
  event-package = "presence"
  subscribe     = "presence-subscribe.exs"
  publish       = "presence-publish.exs"
```

`subscribe` is required. `publish` is optional: a package with no publish script
answers **405** to a PUBLISH.

Two blocks declaring the same event package are refused when the file is loaded.

### Serving buddy lists

A client opens its whole roster with one SUBSCRIBE to a list URI it carries
hard-coded — Linphone sends `sip:rls@sip.linphone.org` whatever the account's own
domain is — and puts the list itself in the request body (RFC 4662, RFC 5367).

Declare that host as a domain of its own, served by `presence-rls.exs`:

```toml
# domains.toml
[[domain]]
name = "sip.linphone.org"

  [[domain.presence]]
  event-package = "presence"
  subscribe     = "presence-rls.exs"
```

The script authenticates the watcher on the realm of its own `From`, then watches
every entry of the list on the entry's own domain. The answer is one NOTIFY
carrying an RLMI manifest and one PIDF part per buddy; state changes that follow
are batched into one partial NOTIFY every 500 ms.

Each entry is answered as described in [State of a resource](#state-of-a-resource);
an entry with no state is reported `terminated;reason=noresource`.

### State of a resource

The state notified for a resource is, in order:

1. the live document its presentity PUBLISHed;
2. a state another module reported for it with `report/4` — a conference room,
   reported by [`mcu_presence`](mcu_presence.md);
3. **open** while one of the user's devices is registered, as reported by the
   registrar script (see [Registrations as presence](#registrations-as-presence));
4. on a domain with a `[domain.registrar]` block and for a user known to
   `auth_db`: **closed**;
5. otherwise no state (`nil`): a domain with no registrar, a domain this node does
   not serve, an unknown user, or an event package other than `presence`.

A resource with no state ends its subscription: the reference scripts notify
`terminated;reason=noresource`, when the SUBSCRIBE is accepted as well as when the
state goes while it is watched.

### Registrations as presence

The reference script `registrar-presence.exs` is `registrar.exs` plus a report to
this module each time a registration changes: a REGISTER saved, the device's
connection dropped, or a registration not refreshed in time. Serve the domain's
registrar with it:

```toml
# domains.toml
[[domain]]
name = "example.com"

  [domain.registrar]
  script = "registrar-presence.exs"
```

The subscriber is open while at least one of its devices holds a registration,
and closed when the last one goes. A registration that is not refreshed is
reported when it lapses in the registrar; a refused refresh (403, 423, 400, 503)
leaves the registration running, and its lapse is reported the same way. Its watchers are NOTIFYed on each change;
refreshing a registration notifies nothing, and neither does a change while a
PUBLISH is live.

A domain served by `registrar.exs` reports nothing: its subscribers are closed
unless they publish. The script needs the `registrar`, `auth_db` and `presence`
modules, and ships with `kelixip-mod-presence`.

A watcher that does not advertise `Supported: eventlist`, or whose `Accept` does
not name both `multipart/related` and `application/rlmi+xml`, is answered **406**
and falls back to one subscription per buddy.

## Parameters

Module block — `[module.presence]` (in `config.toml`):

| Key | Type | Default | Description |
|---|---|---|---|
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |

The expiry bounds of a subscription and of a publication belong to the event
package (RFC 6665 §4.4.1), so this block carries none.

Per-domain block — `[[domain.presence]]` (activates the function for a domain):

| Key | Type | Default | Description |
|---|---|---|---|
| `event-package` | string | **required** | The package this block serves (`presence`, `dialog`, …) |
| `subscribe` | string | **required** | Script serving SUBSCRIBE for this package |
| `publish` | string | — | Script serving PUBLISH; absent ⇒ `405` |

## Facades

```elixir
import Kelix.Mod.Presence,
  only: [publish: 2, watch: 2, watch_many: 3, unwatch: 1, state_of: 2, exists?: 2, own_state?: 1]
```

Each facade is non-blocking: a collection that is down answers `{:error, :down}`
and a slow one `{:error, :timeout}`, leaving the script in control of the SIP
response.

### `publish/2`

```elixir
publish(sip_ctx, %SIP.Publication{}) ::
  {:ok, etag :: String.t() | nil, expires :: non_neg_integer}
  | {:error, 412}
  | {:error, :down | :timeout}
```

Stores what a PUBLISH asks for and pushes the result to every watcher of the
resource. The publication is the one `check_publish/1` handed the script.

| Return | Meaning |
|---|---|
| `{:ok, etag, expires}` | Published. A **new** entity-tag is minted per publication (RFC 3903 §4.1); it is what the next refresh must present in `SIP-If-Match` |
| `{:ok, nil, 0}` | Removal (`Expires: 0`). No entity-tag: there is no state left to name |
| `{:error, 412}` | The tag presented is unknown or spent. The publisher must start over with an initial PUBLISH |

A refresh keeps the document it refreshes and moves only its lifetime; a
modification replaces it.

### `watch/2`

```elixir
watch(sip_ctx, %SIP.Subscription{}) :: {:ok, document | nil} | {:error, :down | :timeout}
```

Registers the calling instance as a watcher of the subscription it has just
accepted, and hands back the state as it stands (see
[State of a resource](#state-of-a-resource)) — `nil` when there is none.

The instance is monitored: a watcher that dies with its dialog is dropped on its
own. A subscription granted zero seconds (an un-SUBSCRIBE) is not stored.

### `watch_many/3`

```elixir
watch_many(sip_ctx, %SIP.Subscription{}, uris :: [String.t()]) ::
  {:ok, %{String.t() => document | nil}} | {:error, :down | :timeout}
```

The same, for the N resources of one list subscription (RFC 4662). `uris` are the
entries as the watcher wrote them — `sub.list_entries` — and the answer is keyed
on those very strings.

Each entry is watched on **the domain its own URI names**, not on the domain that
routed the SUBSCRIBE: the entries of one buddy list routinely sit on several
domains. Each entry is answered its [state](#state-of-a-resource). An entry on a
domain this node does not serve is answered `nil` and is not registered.

The instance is monitored, as with `watch/2`: it is dropped from every resource it
watches when it dies.

### `unwatch/1`

```elixir
unwatch(sip_ctx) :: :ok | {:error, :down | :timeout}
```

Stops watching, on every domain the instance was registered on. For the scenario
that ends its subscription and keeps running.

### `registration_changed/1`, `registration_ended/1`

```elixir
registration_changed(sip_ctx) :: :ok | {:error, :down | :timeout}
registration_ended(sip_ctx)   :: :ok | {:error, :down | :timeout}
registration_changed(domain, aor) :: :ok | {:error, :down | :timeout}
```

Called by the registrar script, with the context of the REGISTER dialog.
`registration_changed/1` follows a `Kelix.Mod.Registrar.save/2`, whatever its
verdict; `registration_ended/1` follows the end of the dialog — connection lost,
or registration not refreshed.

`registration_changed/2` is the same report for a registration removed by hand:
`kelictl registration remove` and `DELETE /domains/<domain>/registrations/<aor>`
call it when the presence module is loaded.

None states open or closed: the module asks the registrar whether any device of
the AOR still holds a registration, leaving out the ending dialog's own bindings
(`Kelix.Mod.Registrar.registered?/3`).

### `exists?/2`

```elixir
exists?(sip_ctx, aor :: String.t()) :: boolean
```

Whether the presentity `aor` (a user part) exists on the context's domain: a
subscriber known to `auth_db`, or a resource a module reports a state for. The
reference subscribe script answers **404** when it does not. A collection that is
down answers `false`.

### `own_state?/1`

```elixir
own_state?(sip_ctx) :: boolean
```

Whether the PUBLISH the instance serves is about the user its digest proved —
the Request-URI's user part against the identity `assert_identity/1` recorded,
case-insensitively. `false` when nothing was authenticated. What
`presence-publish.exs` asks before it publishes anything.

### `report/4`

```elixir
report(domain, user, source :: atom, document | nil) :: :ok | {:error, :down | :timeout}
```

For a module, not a script: states the presence of `sip:<user>@<domain>` on the
module's own authority, under the name `source`. `nil` withdraws it. The state
ranks as described in [State of a resource](#state-of-a-resource), and the
watchers are pushed when the resulting state changes.

Every state a process reported is withdrawn when that process ends.

### `state_of/2`

```elixir
state_of(sip_ctx, {username, event_package}) :: document | nil | {:error, :down | :timeout}
```

The document published about a resource, for a script that wants it without
subscribing.

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl presence list domain=D` | `GET /modules/presence/presentities` | States held: one row per entity-tag, one per reported registration |
| `kelictl presence show domain=D aor=bob` | `GET /modules/presence/presentities/bob` | One presentity: its states and its watchers |
| `kelictl presence watchers domain=D aor=bob` | `GET /modules/presence/presentities/bob/watchers` | The live subscriptions to one presentity |
| `kelictl presence remove domain=D aor=bob` | `DELETE /modules/presence/presentities/bob` | Drops the published state and tells the watchers |

The columns are kamailio's, under kamailio's names — `presentity_uri`, `event`,
`etag`, `expires`, `status`, `callid`.

A state has a `source`: `publish` for a PUBLISH, `registrar` for a registration
reported by the registrar script (see
[Registrations as presence](#registrations-as-presence)), and the name a module
reported it under — `mcu` for a conference room. A `registrar` or module state has
no `etag`, `expires` nor `sender`, and is listed beside a live publication of the
same presentity, which it does not override.

`remove` drops the published state, not the subscriptions: a watcher stays
subscribed and is told there is no state left.

## Events

The fan-out reaches the watcher's **scenario instance**, which sends the NOTIFY
from its own state:

```elixir
{:presence, :state, {username, domain, event_package}, document | nil}
```

When the last publication goes — a removal, or a lifetime that lapsed — the
document pushed is the [state](#state-of-a-resource) that follows: a reported
state, open or closed from the registrations, or `nil` where none applies. A
reported state or a registration that changes on a watched resource is pushed the
same way. What to notify for `nil` is the script's decision; the reference
scripts end the subscription with `noresource`.

### Live presence panel

`Kelix.Control.subscribe_presence(pid, domain)` returns a domain's presentities
and then pushes their changes to `pid` (kelescope's presence panel):

```elixir
{:ok, %{domain: "example.com", presentities: [row]}}

{:kelix_presence, domain, {:upsert, row}}
{:kelix_presence, domain, {:remove, aor}}

row :: %{domain, aor, presentity_uri, status, activity, note, states, watchers}
```

A presentity is listed while it holds a publication, a watcher, a reported
registration or a state a module reported; `states` then holds a `registrar` or
an `mcu` state. `status` is
`"open"`, `"closed"` or `nil`, as a watcher of the `presence` package is told;
`states` and `watchers` carry the columns of `list` and `watchers`.
`unsubscribe_presence(pid, domain)` stops the pushes; a subscriber that dies is
dropped. Without the presence module, the list is empty.

## Examples

Authenticating the sender, in both scripts:

```elixir
state authenticate_watcher do
  AuthDb.SBB.authenticate(code: 401)

  on_events do
    {:auth, :authenticated, %{user: user}} ->
      goto(authorize, "SUBSCRIBE authenticated as #{user}")

    {:auth, :refused, %{attempts: attempts}} ->
      scenario_success("gave up on this watcher after #{attempts} refused attempts")
  end
end
```

Answering a SUBSCRIBE, in `presence-subscribe.exs`:

```elixir
state subscribe do
  case accept_subscription(
         package: ctx_get(:event_package),
         allow_events: Kelix.Domains.event_packages(sip_ctx.domain)
       ) do
    {:ok, sub} ->
      case Kelix.Mod.Presence.watch(sip_ctx, sub) do
        {:ok, nil} ->
          terminate_subscription(:noresource)
          goto(ending, "200 + NOTIFY noresource")

        {:ok, doc} ->
          notify(doc)
          goto(subscribed, "200 + NOTIFY")

        {:error, reason} ->
          terminate_subscription(:noresource)
          scenario_failure("presence store #{reason}")
      end

    {:error, code} ->
      goto(wait_subscribe, "#{code}")
  end
end
```

Sending the state on when it changes:

```elixir
state subscribed do
  on_events do
    {:presence, :state, _resource, nil} ->
      terminate_subscription(:noresource)
      goto(ending, "state gone: noresource")

    {:presence, :state, _resource, doc} ->
      notify(doc)
      stay("state pushed")
  end
end
```

Answering a PUBLISH, in `presence-publish.exs`:

```elixir
state publish do
  case check_publish(package: ctx_get(:event_package)) do
    {:ok, pub} ->
      case Kelix.Mod.Presence.publish(sip_ctx, pub) do
        {:ok, etag, expires} ->
          reply_publish(200, etag: etag, expires: expires)
          scenario_success("published #{SIP.Publication.presentity_uri(pub)} (#{expires}s)")

        {:error, 412} ->
          reply_publish(412, "Conditional Request Failed")
          scenario_success("412 unknown entity-tag")
      end

    {:error, code} ->
      scenario_success("PUBLISH refused with #{code}")
  end
end
```

## Limitations

- **Full state only.** Partial state (`application/pidf-diff+xml`, RFC 5262) is
  not emitted.
- **No composition.** Several publishers may hold state for one presentity at the
  same time, each with its own entity-tag; what is notified is the most recent
  publication, not a composite of them.
- **In memory.** The collection does not survive a restart, and is local to one
  node.

- **No consent flow.** `presence.winfo` (RFC 3857/3858) and the authorization
  rules of RFC 5025 carried over XCAP are not implemented; admission is the
  subscribe script's.
