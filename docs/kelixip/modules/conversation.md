# conversation

This module keeps the chat conversations a script sets aside, so a bot or a
long exchange survives the end of its instance, a node restart, and a move to
another node.

A chat script calls `hibernate/1` — typically when the conversation goes quiet
or the sender's connection drops. Its instance ends, and what it named is kept:
the state to resume in and some of its data. The next MESSAGE between the same
two parties, on any node of the domain, starts the script again in that state,
with that data.

| When | What happens |
|---|---|
| the script calls `hibernate(resume: :state, keep: [:key], ttl: 3600)` | its state and data are kept for `ttl` seconds; the instance ends |
| a MESSAGE arrives between the same sender and recipient | the script starts at `:state`, with the kept data |
| no MESSAGE arrives before the TTL | the conversation is deleted; the next MESSAGE starts a new one |

Storage is SQL — MariaDB/MySQL or PostgreSQL — on an account of the module's
own, shared by every node of the domain. What a script keeps is never shown by
a control command.

## Installing and activating the module

### Installing the `kelixip-mod-conversation` package

`dnf install kelixip-mod-conversation` / `apt install kelixip-mod-conversation`

The package ships the module and the SQL schema for both engines under
`/usr/share/kelixip/sql/conversation/`.

### Creating the schema

The module never creates nor alters tables. Create them once:

```bash
# MariaDB / MySQL
mysql -u root kelixip < /usr/share/kelixip/sql/conversation/mysql.sql
mysql -u root -e "GRANT SELECT, INSERT, UPDATE, DELETE ON kelixip.conversation TO 'conversation'@'%'; GRANT SELECT ON kelixip.conversation_version TO 'conversation'@'%'"

# PostgreSQL
psql -U postgres -d kelixip -f /usr/share/kelixip/sql/conversation/postgres.sql
psql -U postgres -d kelixip -c "GRANT SELECT, INSERT, UPDATE, DELETE ON conversation TO conversation; GRANT SELECT ON conversation_version TO conversation"
```

Without the tables, or with tables of another version, the module does not
start and says why in the log.

### Declaring the module in config.toml

```toml
# config.toml
[module.conversation]
driver      = "postgres"
host        = "db.example.net"
database    = "kelixip"
username    = "conversation"
password    = "secret"
default_ttl = 86400
```

### Restart kelixip

`systemctl restart kelixip`

## Parameters

The connection keys are those of every SQL module (see [silo.md](silo.md#parameters));
each may come from a `[database]` block of `config.toml` instead.

| Key | Type | Default | Description |
|---|---|---|---|
| `database` | string | **required** | Database holding the conversation tables |
| `username` | string | **required** | Account of the module |
| `default_ttl` | integer | `86400` | Seconds a conversation is kept when the script names no `ttl` |
| `max_ttl` | integer | `604800` | The longest TTL granted, whoever asks |

## In a script

```elixir
hibernate(resume: :awaiting_answer, keep: [:step, :cart], ttl: 3600)
```

| Option | Meaning |
|---|---|
| `resume:` | the state the script starts in when woken (**required**) |
| `keep:` | the appdata keys kept. Plain data only: a pid, a reference or a function is refused |
| `ttl:` | seconds, bounded by `max_ttl` |

The script woken is the version installed at that time. If it no longer has the
`resume:` state, it starts at `initial_state` with the kept data, and the log
says so.

## Facades

Called by the node, not by scripts:

| Function | Result |
|---|---|
| `hibernate(key, snapshot)` | `{:ok, granted_ttl}` or `{:error, reason}` |
| `wake(key)` | `{:ok, snapshot}`, then no longer kept — or `:none`, also when the database does not answer |

## Control commands

| Command | REST | Description |
|---|---|---|
| `kelictl conversation show` | `GET /modules/conversation/db` | The database link (state, host, port, database, account, driver, TLS, pool size, error when down), the schema check, the conversations kept (`conversations`, `domains`), `default_ttl` and `max_ttl`, and, under `since_start`, this node's counters: `hibernated`, `woken`, `expired` |
| `kelictl conversation list` | `GET /modules/conversation/conversations` | Conversations kept: domain, rule, parties, script, resume state, time left. Never the data |

## Events

None.
