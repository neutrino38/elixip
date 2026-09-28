# mcu_presence

This module shows each conference room in the users' buddy lists. A user adds the
room's address, `sip:<did>@<domain>`, to their contacts, as they would add a
colleague, and sees at a glance whether the room can be joined:

| The room | Shown to the user |
|---|---|
| running, with free places | online |
| running, full | online, busy |
| unavailable (its media server is unreachable) | offline |
| destroyed, or never created | removed from the list |

A room is full when it holds its `max_participants`: the next caller would be
refused as busy.

The module needs the [`mcu`](mcu.md) and [`presence`](presence.md) modules, and
does not start without both.

## Installing and activating the module

### Installing the `kelixip-mod-mcu_presence` package

`dnf install kelixip-mod-mcu_presence` / `apt install kelixip-mod-mcu-presence`

The package installs `kelixip-mod-mcu` and `kelixip-mod-presence` with it.

### Declaring the module in config.toml

```toml
# config.toml
[module.mcu]
[module.presence]

[module.mcu_presence]
domains = ["example.com"]
```

Every key is optional: an empty `[module.mcu_presence]` block is valid.

### Serving presence on the rooms' domain

The rooms' domain serves presence with the reference subscribe script:

```toml
# domains.toml
[[domain]]
name = "example.com"

  [[domain.presence]]
  event-package = "presence"
  subscribe     = "presence-subscribe.exs"
```

A contact that is no room — a DID nobody created — is refused (`404`).

> **Rooms on a domain of their own.** `presence-subscribe.exs` challenges on the
> served domain. When the rooms live on a domain no user account belongs to
> (`conf.example.com`), no watcher can answer that challenge. Serve that domain
> with a copy of the script that challenges on the watcher's domain instead:
>
> ```elixir
> AuthDb.SBB.authenticate(code: 401, realm: :from_domain)
> ```

### Restart kelixip

`systemctl restart kelixip`

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `domains` | list of strings | every domain | The domains whose rooms are shown. A room on another domain is not shown |

## Facades

None.

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl mcu_presence list` | `GET /modules/mcu_presence/rooms` | The rooms shown, and the state each one shows |

The columns are the room's address, its `status` (`open` / `closed`), its
`activity` (`busy` or empty) and the conference `uid`, as `kelictl mcu` names it.

`kelictl presence list <domain>` lists the rooms too, with the source `mcu`.

## Events

None.

## Examples

A room of eight, created by the operator:

```toml
# config.toml
[module.mcu]
did_range        = "8000-8099"
max_participants = 8

[module.presence]

[module.mcu_presence]
```

```bash
kelictl mcu conference.create domain=example.com did=8001 name="Daily"
kelictl mcu_presence list
# presentity_uri          status  activity  uid
# sip:8001@example.com    open              c-45b284ba
```

A user who added `sip:8001@example.com` to their contacts sees the room online,
busy once the eighth participant is in, offline while the media server is
unreachable, and removed when the room is destroyed.

## Limitations

- **Available, busy or offline only.** The number of participants, who is
  speaking and the room's name are not shown.
- **No participant list.** A contact shows the room, not who is in it.
