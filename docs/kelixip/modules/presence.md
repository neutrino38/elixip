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

An entry on a domain this node does not serve is reported
`terminated;reason=noresource`.

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
  only: [publish: 2, watch: 2, watch_many: 3, unwatch: 1, state_of: 2]
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
accepted, and hands back the state as it stands — `nil` when nothing has been
published about the resource yet.

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
domains. An entry on a domain this node does not serve is answered `nil` and is
not registered.

The instance is monitored, as with `watch/2`: it is dropped from every resource it
watches when it dies.

### `unwatch/1`

```elixir
unwatch(sip_ctx) :: :ok | {:error, :down | :timeout}
```

Stops watching, on every domain the instance was registered on. For the scenario
that ends its subscription and keeps running.

### `state_of/2`

```elixir
state_of(sip_ctx, {username, event_package}) :: document | nil | {:error, :down | :timeout}
```

The document published about a resource, for a script that wants it without
subscribing.

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl presence list domain=D` | `GET /modules/presence/presentities` | Published states, one row per entity-tag |
| `kelictl presence show domain=D aor=bob` | `GET /modules/presence/presentities/bob` | One presentity: its states and its watchers |
| `kelictl presence watchers domain=D aor=bob` | `GET /modules/presence/presentities/bob/watchers` | The live subscriptions to one presentity |
| `kelictl presence remove domain=D aor=bob` | `DELETE /modules/presence/presentities/bob` | Drops the published state and tells the watchers |

The columns are kamailio's, under kamailio's names — `presentity_uri`, `event`,
`etag`, `expires`, `status`, `callid`.

`remove` drops the published state, not the subscriptions: a watcher stays
subscribed and is told there is no state left.

## Events

The fan-out reaches the watcher's **scenario instance**, which sends the NOTIFY
from its own state:

```elixir
{:presence, :state, {username, domain, event_package}, document | nil}
```

`nil` means nothing is published about the resource any more — a removal, or a
publication whose lifetime lapsed. What to notify then is the script's decision;
the reference script sends an explicitly closed state.

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
        {:ok, doc} ->
          notify(doc || SIP.Presence.Doc.new(sub.presentity_uri, :closed))
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
    {:presence, :state, _resource, doc} ->
      sub = last_subscription()
      notify(doc || SIP.Presence.Doc.new(sub.presentity_uri, :closed))
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
          scenario_success("published (#{expires}s)")

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
