# auth_db

Registrar **authentication** backed by a MariaDB/MySQL `subscriber` table
(Kamailio-style). It reads the stored **HA1** for a user and returns an
authentication **verdict**; it never composes the SIP response — the registrar
script maps the verdict onto `401` (challenge), accept, or reject.

## Loading

The `auth_db` block lives in **`config.toml`**. Its supervised service is a
connection pool to the database.

```toml
# config.toml
[module.auth_db]
host     = "127.0.0.1"
port     = 3306
database = "kamailio"
username = "kamailio"
password = "…"
```

```elixir
import Kelix.Mod.AuthDb, only: [do_registration_auth: 3]
```

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | Database host |
| `port` | integer | `3306` | Database port |
| `database` | string | **required** | Schema holding the subscriber table |
| `username` | string | **required** | DB user |
| `password` | string | — | DB password |
| `table` | string | `"subscriber"` | Subscriber table name |
| `ha1_column` | string | `"ha1"` | Column holding the HA1 digest |
| `user_column` | string | `"username"` | Column matched against the SIP username |
| `domain_column` | string | `"domain"` | Column matched against the realm |
| `password_hash` | string | `"md5"` | HA1 hash: `md5` or `sha256` |
| `call_timeout_ms` | integer | `5000` | Upper bound on a DB query / facade call (ms) |

The realm used for lookup and digest is the **domain's nominal name** (aliases
fold to it).

## Prerequisites

A Kamailio-style `subscriber` table where the secret is stored as the **HA1**:

```
ha1 = H(username : realm : password)      # H = md5 (default) or sha256
```

No cleartext password is needed. If your schema differs, remap the columns with
`table` / `ha1_column` / `user_column` / `domain_column`.

## Facades

### `do_registration_auth/3`

```elixir
do_registration_auth(req, domain, opts \\ []) ::
  :ok
  | {:requireauth, stale? :: boolean}
  | {:reject, code :: integer, reason :: String.t()}
```

The verdict for a `REGISTER` against `domain` (the realm):

| Verdict | Meaning | Script maps to |
|---|---|---|
| `:ok` | Credentials valid | accept (continue to registrar) |
| `{:requireauth, false}` | No/forged credentials | `401` with a **fresh** nonce |
| `{:requireauth, true}` | Nonce stale or replayed | `401` with `stale=true` |
| `{:reject, 403, _}` | Wrong password / unknown user / realm mismatch | `403 Forbidden` |
| `{:reject, 500, _}` | DB error or service down | `500 Server Internal Error` |

Supports RFC 2617 `qop=auth` (with `nc` anti-replay) and the RFC 2069 fallback.

`opts` (mainly for tests): `:ha1_lookup` (`fn user, realm -> {:ok, ha1} |
:notfound | {:error, r}`) to bypass the DB, plus `:now` / `:max_age` forwarded to
nonce validation.

### `lookup_ha1/2`

```elixir
lookup_ha1(username, realm) ::
  {:ok, ha1} | :notfound | {:error, term} | {:error, :down}
```

The stored HA1 for `username`@`realm`. Returns `{:error, :down}` when the DB pool
is not running and `{:error, _}` on a query error; the query is bounded by
`call_timeout_ms`.

## Control commands

None yet. (Frontals: P7.)

## Events

None.

## Examples

```toml
# config.toml
[module.auth_db]
database = "kamailio"
username = "kamailio"
password = "s3cret"
password_hash = "md5"
```

```elixir
# in the registrar scenario, before Registrar.save/4
import Kelix.Mod.AuthDb, only: [do_registration_auth: 3]

case do_registration_auth(register_req, "example.com") do
  :ok -> proceed_to_save()
  {:requireauth, stale?} -> challenge(stale?)          # script builds 401
  {:reject, code, reason} -> reply(code, reason)
end
```

See the credential-gated live test
(`apps/kelixip/test/auth_db_live_test.exs`) for a full DB → verdict example.
