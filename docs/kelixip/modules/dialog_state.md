# dialog_state

This module shows who is on the phone. For every user of a served domain, it
follows the calls that cross this node and reports them to the
[`presence`](presence.md) module, where three kinds of reader find them:

| Reader | What it sees |
|---|---|
| a desk phone's BLF key, subscribed with `Event: dialog` (RFC 4235) | the user's calls: none, ringing, or up — lit while ringing or talking |
| a buddy list, subscribed with `Event: presence` | the user `open`, doing `on-the-phone`, while one call is up |
| an ACD, through `Kelix.Control.subscribe_dialogs/2` | one row per call, pushed on every change |

A ringing user is not on the phone: a buddy list sees nothing change until the
call is answered. The ACD reads the ringing from the call's row.

**Only a proven user counts.** A call is reported under a user only when a module
proved that the far end of that leg is this user:

- the caller, when its INVITE passed the digest of [`auth_db`](auth_db.md)
  (`AuthDb.SBB.authenticate`);
- the callee, when [`registrar`](registrar.md) found the leg's contacts among the
  user's registrations (`Registrar.targets/2`).

A `From` header proves nothing. A trunk that writes our domain in its `From`
lights no key. The reference `direct-call.exs` authenticates nobody, so only its
callee is reported; `direct-call-with-auth.exs` reports both parties.

The module needs the [`presence`](presence.md) module, and does not start
without it.

## Installing and activating the module

### Installing the `kelixip-mod-dialog_state` package

`dnf install kelixip-mod-dialog_state` / `apt install kelixip-mod-dialog-state`

The package installs `kelixip-mod-presence` with it.

### Declaring the module in config.toml

```toml
# config.toml
[module.presence]

[module.dialog_state]
domains = ["example.com"]
```

Every key is optional: an empty `[module.dialog_state]` block is valid.

### Serving the dialog package on the domain

A BLF key subscribes with `Event: dialog`. The domain serves it with the
reference subscribe script, in a block of its own:

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.presence]]
  event-package = "presence"
  subscribe     = "presence-subscribe.exs"

  [[domain.presence]]
  event-package = "dialog"
  subscribe     = "presence-subscribe.exs"
```

The `dialog` block has no `publish` script: a phone does not publish its calls,
this node sees them. A PUBLISH on that package is answered `405`.

A user `auth_db` knows and who is on no call is an empty dialog list, not
`noresource`: the key stays subscribed and shows "idle". A user nobody
provisioned is refused `404`.

### Restart kelixip

`systemctl restart kelixip`

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `domains` | list of strings | every served domain | The domains whose users' calls are reported. A call of a user on another domain is not reported |

## Facades

None for scripts. A script changes nothing to be followed: the stamps come from
`auth_db` and `registrar`.

For a process of the node — an ACD — `Kelix.Control` gives the live feed:

### `Kelix.Control.subscribe_dialogs/2`

```elixir
subscribe_dialogs(pid, domain) ::
  {:ok, %{domain, owner, dialogs: [row]}} | {:error, :not_found}
```

Returns the calls of the domain's users as they stand, then sends `pid`:

- `{:kelix_dialogs, domain, {:upsert, row}}` on every change of a call — the last
  one is its `terminated` row, with the reason;
- `{:kelix_dialogs, domain, {:remove, id}}` once the call is gone.

```elixir
%{domain: "example.com", aor: "sip:bob@example.com",
  id: "a84b4c76e66710",                     # the Call-ID
  direction: :initiator | :recipient,       # did bob place the call, or receive it
  state: :trying | :proceeding | :early | :confirmed | :terminated,
  event: nil | :local_bye | :remote_bye | :cancelled | :rejected | :timeout | :error,
  remote: "sip:alice@example.com",          # the other party
  since: ~U[2026-09-27 21:58:11Z]}          # created — or answered, once confirmed
```

`event` says why a call ended, from the user's side: `remote_bye` when the user
hung up, `local_bye` when this node hung up the user's leg (the other party hung
up), `cancelled` when the caller gave up before the answer. `owner` is the process
holding the subscription: monitor it and subscribe again on `:DOWN`. `owner: nil`
with an empty list means the module is not loaded. `domain` may be an alias.

`unsubscribe_dialogs(pid, domain)` stops the feed. A subscriber that dies is
dropped on its own.

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl dialog_state list domain=D` | `GET /modules/dialog_state/dialogs` | The live calls of the domain's users, and the presence each user was reported in |

The columns are the user's address (`aor`), the Call-ID, the `direction`, the
`state`, the other party (`remote`), `since`, and `presence` — `on_the_phone`
while the user's presence says so.

`kelictl presence list <domain>` names `dialog_state` among a user's `sources`
and counts its `calls`; `kelictl presence show <user>@<domain>` shows its two
states: one on the `dialog` package ("N dialogs"), one on `presence` whose
`activity` is `on_the_phone` while a call is up.

## Events

The ACD feed above.

## Examples

Alice calls Bob, both users of `example.com`, through `direct-call-with-auth.exs`:

```bash
kelictl dialog_state list example.com
# aor                   callid          direction  state      remote                 presence
# sip:alice@example.com a84b4c76e66710  initiator  confirmed  sip:bob@example.com    on_the_phone
# sip:bob@example.com   5170167685      recipient  confirmed  sip:alice@example.com  on_the_phone
```

A BLF key on Bob lights when his phone rings and stays lit until the call ends.
Alice's contacts see her `on-the-phone` from the answer to the hang-up, then
back to what her registration says.

## Limitations

- **One call per leg, forks included.** A call ringing two phones of one user at
  once is one early call, not two.
- **Calls that cross this node only.** A phone's own calls, placed elsewhere, are
  not seen. Nothing publishes on the `dialog` package.
- **No shared line appearances** (RFC 7463), and no SDP in the document.
- **A user on the phone who also publishes a presence** is shown as they
  publish: a publication wins over this module's report.
