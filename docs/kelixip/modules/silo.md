# silo

This module keeps the instant messages (SIP `MESSAGE`, RFC 3428) that no device
of the recipient took, and delivers them when one of the recipient's devices
registers.

| When | What happens |
|---|---|
| a MESSAGE finds no device, or none that answers | the chat script stores it; the sender gets `202 Accepted` |
| a device of the recipient registers | the registrar script asks for a flush; every stored message goes to that device, in arrival order, dated when it was sent |
| the same device registers again | nothing: a device is served a message once |
| another device of the recipient registers | it gets every stored message too |
| a message reaches the end of its retention | it is deleted, delivered or not |

A device is known by its `+sip.instance` (RFC 5626). A device that registers
from a new address with the same instance ID is the same device. A device that
sends no instance ID is known by its contact address, and gets the messages
again from a new one.

A message is kept for all the recipient's devices, not consumed by the first:
only retention and quotas remove it.

Storage is SQL — MariaDB/MySQL or PostgreSQL — on an account of the module's
own. Every node of a domain uses the same database: a message stored on one node
is delivered by the node the device registers on.

The content of a message is never written to the logs, to a journal, nor shown
by a control command.

## Installing and activating the module

### Installing the `kelixip-mod-silo` package

`dnf install kelixip-mod-silo` / `apt install kelixip-mod-silo`

The package ships the module, the SQL schema for both engines under
`/usr/share/kelixip/sql/silo/`, and the reference chat scripts
`p2p-chat.exs` and `registrar-chat.exs`.

### Creating the schema

The module never creates nor alters tables. Create them once, with an account
allowed to, then grant the module's account what it needs:

```bash
# MariaDB / MySQL
mysql -u root kelixip_silo < /usr/share/kelixip/sql/silo/mysql.sql
mysql -u root -e "GRANT SELECT, INSERT, UPDATE, DELETE ON kelixip_silo.* TO 'silo'@'%'"

# PostgreSQL
psql -U postgres -d kelixip_silo -f /usr/share/kelixip/sql/silo/postgres.sql
psql -U postgres -d kelixip_silo -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO silo; GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO silo"
```

Without the tables, or with tables of another version, the module does not
start and says why in the log.

### Declaring the module in config.toml

```toml
# config.toml
[module.silo]
driver   = "postgres"
host     = "db.example.net"
database = "kelixip_silo"
username = "silo"
password = "secret"

[module.silo.defaults]
retention = 259200          # 3 days
```

### Serving chat on the domain

```toml
# domains.toml
[[domain]]
name = "example.com"

  [domain.registrar]
  script = "registrar-chat.exs"

  [[domain.chat]]
  default = true
  script  = "p2p-chat.exs"
```

`registrar-chat.exs` is `registrar-presence.exs` plus the flush, and needs the
`presence` module. `p2p-chat.exs` needs `registrar` and `auth_db`.

### Restart kelixip

`systemctl restart kelixip`

### Checking

`kelictl silo show` shows whether the database answers, and what the Silo holds.
`kelictl silo list bob@example.com` shows what is stored for Bob.

## Parameters

The connection keys are those of every SQL module; each may come from a
`[database]` block of `config.toml` instead.

| Key | Type | Default | Description |
|---|---|---|---|
| `driver` | string | `"mysql"` | `mysql` (MariaDB/MySQL) or `postgres` (PostgreSQL) |
| `host` | string | `"127.0.0.1"` | Database host |
| `port` | integer | `3306` (`5432` for `postgres`) | Database port |
| `database` | string | **required** | Database holding the silo tables |
| `username` | string | **required** | Account of the module |
| `password` | string | — | Its password |
| `pool_size` | integer | `4` | Connections kept open |
| `connect_timeout_ms` | integer | `5000` | Upper bound on establishing one connection |
| `call_timeout_ms` | integer | `5000` | Upper bound on one query (ms) |
| `ssl_ca_cert_file` | string | — | CA that must sign the server certificate |
| `ssl` | boolean | — | `false` asks for cleartext, and needs the key below |
| `allow_insecure_db_connection` | boolean | `false` | Accept a cleartext link |
| `lease` | integer | `300` | Seconds a flush holds a recipient's messages; past it, another node may take them |

`[module.silo.defaults]`:

| Key | Type | Default | Description |
|---|---|---|---|
| `retention` | integer | `259200` | Seconds a message is kept when neither the sender nor the script says |
| `max_retention` | integer | `604800` | The longest retention granted, whoever asks |
| `max_messages` | integer | `200` | Messages kept per recipient |
| `max_bytes` | integer | `1048576` | Bytes kept per recipient |

The retention of a message is, in order: the `Expires` the sender put on it, the
`retention:` the script gives, `retention` above — never more than
`max_retention`.

## Facades

### `store/3`

```elixir
Kelix.Mod.Silo.store(sip_ctx, req, opts \\ []) ::
  {:stored, %{id: integer, expires_in: seconds}}
  | {:error, :quota | :expired | :no_aor | :down}
```

Stores the MESSAGE `req` for the user of its Request-URI, on the script's
domain. The body is kept as it came, CPIM wrapper included.

| Option | Meaning |
|---|---|
| `served:` | device keys that already have it (the `served` of `SBB.Page`'s outcome) |
| `retention:` | seconds, when the sender gave none |

| Result | Meaning | Usual answer |
|---|---|---|
| `{:stored, _}` | kept | `202` |
| `{:error, :quota}` | the recipient has `max_messages` or `max_bytes` already | `486` |
| `{:error, :expired}` | the sender sent `Expires: 0` | `480` |
| `{:error, :no_aor}` | the Request-URI names no user | `400` |
| `{:error, :down}` | the module or its database does not answer | `503` |

### `flush/2`

```elixir
Kelix.Mod.Silo.flush(sip_ctx, register_req) :: :ok | {:error, :down}
```

Delivers what is stored for the AOR of the REGISTER to the devices it binds,
over the connection it came on. Call it **after** the `200 OK`. It returns at
once: delivery runs in the module.

Per device, a message leaves once the previous one is answered. An answer of
2xx, or a refusal (`403`, `413`, `415`, `488`, `603`, `606`), counts as served.
Any other answer stops that device's delivery until its next REGISTER.

A REGISTER that binds nothing (an un-registration) flushes nothing.

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl silo show` | `GET /modules/silo/db` | The database link (state, host, port, database, account, driver, TLS, pool size, error when down), the schema check, what is stored (`messages`, `aors`, `bytes`, `claimed` by a flush in progress) and, under `since_start`, this node's counters |
| `kelictl silo list <aor>` | `GET /modules/silo/messages/<aor>` | Messages stored for `user@domain`: id, sender, type, size, arrival, time left, devices served. Never the content |
| `kelictl silo purge <aor>` | `DELETE /modules/silo/messages/<aor>` | Deletes them |

`kelictl status` also shows, under `silo`, what this node did since it started:
`stored`, `delivered`, `accepted`, `refused`, `unreachable`, `expired`,
`expired_undelivered`.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `kelix_silo_expired_undelivered_total` | `domain` | Messages deleted at the end of their retention without reaching any device |

Alert on it. A registrar script that does not call `flush/2` stores messages
that are never delivered, and this counter is the only sign of it.

## Events

None.

## Examples

The reference scripts, installed under `/usr/share/kelixip/`:

- [`p2p-chat.exs`](../../../apps/kelixip/scripts/p2p-chat.exs) — authenticates
  the sender, relays to every device of the recipient, stores what nobody took;
- [`registrar-chat.exs`](../../../apps/kelixip/scripts/registrar-chat.exs) —
  flushes after each `200 OK` that leaves the user registered.

```elixir
# in a chat script, once no device took the message
case Kelix.Mod.Silo.store(sip_ctx, req, served: served) do
  {:stored, _} -> reply_message(202)
  {:error, :quota} -> reply_message(486)
  {:error, _} -> reply_message(503)
end
```
