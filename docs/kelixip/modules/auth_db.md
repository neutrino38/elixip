# auth_db

Digest **authentication** backed by a MariaDB/MySQL `subscriber` table
(Kamailio-style). It reads the stored **HA1** for a user and returns an
authentication **verdict**; it never composes the SIP response — the script maps
the verdict onto a `401`/`407` challenge, an accept, or a `403`.

It authenticates **any** request, not only `REGISTER`: `authenticate/3` is the
general form and `do_registration_auth/3` is it, applied to a registration.

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
import Kelix.Mod.AuthDb, only: [authenticate: 3, challengeable?: 1]
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
| `identity_check` | string | `"warn"` | What to do when the digest proves one identity and the request claims another: `strict` (403), `warn` (allow + log), `off` |
| `call_timeout_ms` | integer | `5000` | Upper bound on a DB query / facade call (ms) |
| `pool_size` | integer | `4` | Connections kept open to the base. `1` serialises every REGISTER behind one socket |
| `connect_timeout_ms` | integer | `5000` | Upper bound on establishing one connection |
| `ssl_ca_cert_file` | string | — | CA that must sign the server certificate. Present ⇒ the server is **verified**; absent ⇒ encrypted but unauthenticated |
| `ssl` | boolean | — | `true` is redundant (TLS is tried anyway); `false` asks for cleartext outright, and needs the key below to confirm it |
| `allow_insecure_db_connection` | boolean | `false` | Accept a cleartext link when the server refuses TLS. **The only way** to end up unencrypted |

The realm used for lookup and digest is the **domain's nominal name** (aliases
fold to it).

## The link to the database

The module's supervised service is a **permanent connection pool**
(`Kelix.Mod.AuthDb.Pool`, registered `Kelix.Mod.AuthDb.Conn`): `pool_size`
connections opened once and kept open — a query never connects. DBConnection pings
the idle ones about every second, so the server's `wait_timeout` never cuts them
and a dead socket is noticed in seconds; a base that restarts is reconnected
automatically with a 1 s → 30 s backoff. A base that is **down at boot does not
abort the boot**: the pool retries in the background and every authentication
answers `500` until it answers.

### TLS first, cleartext only when the block says so

TLS is **always tried first**, whether or not the block mentions it: an operator
who configured nothing gets an encrypted link to the table holding every
subscriber's HA1. The choice is made by **probing** — one throwaway connection and
a `SELECT 1` — because DBConnection opens its connections asynchronously and
retries for ever, so a pool that *started* proves nothing about TLS.

| The server… | `allow_insecure_db_connection` | The pool opens |
|---|---|---|
| speaks TLS | anything | **TLS** |
| refuses TLS, answers in clear | `true` | **cleartext**, logged as the downgrade it is |
| refuses TLS, answers in clear | absent | **TLS** — nothing works, every auth answers `500`, and one log line says which key would fix it |
| answers on neither transport | anything | **TLS** — it is unreachable, not TLS-less |

That last row is the one worth stating: a base that answers nowhere must **not**
be taken for a TLS-less one. The transport is decided once, at start, so
downgrading on a transient outage would leave a permanent cleartext link behind.

`ssl_ca_cert_file` is what turns the encrypted link into an *authenticated* one
(`verify_peer` against that CA, hostname checked). Without it the server is
unverified — usable against a self-signed dev server, and said out loud both in the
logs and in `kelictl auth_db show`, so nobody mistakes it for a secure link.

`ssl = false` asks for cleartext directly and goes through the **same** gate:
without `allow_insecure_db_connection = true` the block is refused at load (and the
module is not started). One key means one thing — cleartext implies somebody
confirmed it, which is what makes `show` readable.

The transport is negotiated at **start**, which is what a `systemctl restart
kelixip` or a `kelictl module reload auth_db` re-does (the module has no
`reload/2`, so its child is restarted cleanly). A base that gains or loses TLS
while the node runs is not re-negotiated on the fly.

## Prerequisites

A Kamailio-style `subscriber` table where the secret is stored as the **HA1**:

```
ha1 = H(username : realm : password)      # H = md5 (default) or sha256
```

No cleartext password is needed. If your schema differs, remap the columns with
`table` / `ha1_column` / `user_column` / `domain_column`.

## Facades

### `authenticate/3`

```elixir
authenticate(req, realm, opts \\ []) ::
  {:ok, %{user: String.t(), realm: String.t()}}
  | {:requireauth, stale? :: boolean}
  | {:reject, code :: integer, reason :: String.t()}
```

The verdict for **any** request against `realm`:

| Verdict | Meaning | Script maps to |
|---|---|---|
| `{:ok, identity}` | Credentials valid; `identity.user` is the subscriber proved | proceed |
| `{:requireauth, false}` | No/forged credentials | `401`/`407` with a **fresh** nonce |
| `{:requireauth, true}` | Nonce stale or replayed | `401`/`407` with `stale=true` |
| `{:reject, 403, _}` | Wrong password / unknown user / realm mismatch / identity mismatch | `403 Forbidden` |
| `{:reject, 500, _}` | DB error or service down | `500 Server Internal Error` |

Supports RFC 2617 `qop=auth` (with `nc` anti-replay) and the RFC 2069 fallback,
and reads `Authorization` as well as `Proxy-Authorization`.

**`realm` is the realm to require, and choosing it is the caller's job**, because
it differs by method: a `REGISTER` authenticates the holder of the AOR in `To`, an
`INVITE` authenticates the *caller*, whose realm is the domain of its `From` — not
necessarily the domain that routed the request. A script serving one domain passes
`sip_ctx.domain` and is right in both cases.

The digest covers the **method**, so a credential is not transferable between
requests: a registration's `Authorization` replayed on an `INVITE` is refused.

`opts`:

| Option | Default | Meaning |
|---|---|---|
| `:identity_check` | `[module.auth_db] identity_check` (`warn`) | `:strict` / `:warn` / `:off` — see below |
| `:identity` | `:auto` | Which claim to check: `:auto` (`To` for REGISTER, `From` otherwise), `:to`, `:from`, `:none` |
| `:ha1_lookup` | — | `fn user, realm -> {:ok, ha1} \| :notfound \| {:error, r}`, for tests |
| `:now`, `:max_age`, `:secret` | — | forwarded to nonce validation |

#### The identity check

A valid digest proves **who holds the password**. It does *not* prove that the
`From` is theirs. Without a check, Alice authenticates with her own credentials
and places a call as `From: Bob` — identity spoofing, and in a metered deployment,
fraud.

`identity_check` decides what happens on a mismatch. It ships as **`warn`**:
`strict` is the safe answer but it refuses deployments that are legitimate (a trunk
account asserting many `From` identities, a subscriber registering an AOR that is
not its username), so turning those into `403`s on upgrade would be an ambush. Run
in `warn`, read the logs, then decide.

A refused request logs one line naming the cause (`bad_password`, `unknown_user`,
`bad_realm`) while the wire answer stays a bare `403` — nothing leaks whether the
account exists.

### `challengeable?/1`

```elixir
challengeable?(req) :: boolean
```

Should this request be authenticated at all? The rule is **an initial request,
other than `ACK`, `CANCEL` and `OPTIONS`**:

- `ACK` has no response to carry a challenge (RFC 3261 §17.1.1.3);
- `CANCEL` must be accepted for the transaction it cancels (§22.1);
- `OPTIONS` is what liveness probing uses — challenging it makes this node look
  down to its own infrastructure;
- an **in-dialog** request (a To tag) was authenticated when the dialog was
  created; re-challenging mid-call breaks UAs and proves nothing new.

### `do_registration_auth/3`

```elixir
do_registration_auth(req, domain, opts \\ []) ::
  :ok | {:requireauth, boolean} | {:reject, integer, String.t()}
```

`authenticate/3` for a `REGISTER`: the identity checked is the `To` (the AOR being
bound), and a success answers the bare `:ok` the registrar scripts match on.

### `fetch_credential/3`

```elixir
fetch_credential(username, realm, opts \\ []) ::
  {:ok, {:ha1, algorithm, hex}} | :notfound | {:error, term}
```

The secret, in the shape an authentication needs — **the backend's abstraction
point**. Everything above it (nonce, digest, identity) is storage-agnostic, so a
different backend is this one function rewritten. The algorithm comes back *with*
the credential because it is a property of the stored secret, not of the request.

See [DESIGN-AUTH.md](../../design/DESIGN-AUTH.md) for the rules behind these
verdicts, and [evolution-auth-db.md](../../design/evolution-auth-db.md) for where this leads
(an `Auth` behaviour, and a Diameter backend).

### `lookup_ha1/2`

```elixir
lookup_ha1(username, realm) ::
  {:ok, ha1} | :notfound | {:error, term} | {:error, :down}
```

The stored HA1 for `username`@`realm`. Returns `{:error, :down}` when the DB pool
is not running and `{:error, _}` on a query error; the query is bounded by
`call_timeout_ms`.

## Service building blocks

### `SBB.authenticate/1`

```elixir
use Kelix.Mod.AuthDb          # alias + the blocks this module publishes

AuthDb.SBB.authenticate(opts \\ [])
```

Runs the whole challenge cycle on the request the scenario is serving —
challenge, wait for the credentials, verify them, challenge again — and answers
one event. Written in a state of its own, with an `on_events` matching the
outcomes:

| Outcome | Data | Meaning |
|---|---|---|
| `{:auth, :authenticated, …}` | `%{user, realm}` | The digest checked out |
| `{:auth, :cancelled, …}` | `%{}` | The caller CANCELled the challenged request |
| `{:auth, :caller_gone, …}` | `%{reason}` | The dialog ended while waiting for credentials |
| `{:auth, :timeout, …}` | `%{block}` | No credentials came back before the block's deadline |
| `{:auth, :refused, …}` | `%{code, reason, attempts}` | `max_attempts` rejected attempts were answered |

`args`:

| Option | Default | Meaning |
|---|---|---|
| `:realm` | `sip_ctx.domain` | The realm to require |
| `:code` | `407` | `407` (Proxy-Authenticate) or `401` (WWW-Authenticate) |
| `:max_attempts` | `3` | Rejected attempts to answer before `:refused`; `:infinity` to answer within the deadline only |

Options of `sbb_fsm/2` are accepted too — `timeout:` overrides the block's own
32 s deadline.

A rejected attempt is answered and the block keeps waiting: a `403` is one
request's verdict, and a client that fixes its credentials is served. The
identity proved is recorded in the session context, so the leg the scenario
places next carries `P-Asserted-Identity: <sip:user@realm>` — unless the request
asks for `Privacy: id`, which asserts nothing.

The facades stay available: a scenario needing another policy calls
`authenticate/3` and composes its own responses.

## Control commands

### `auth_db show`

```
kelictl auth_db show          [GET /modules/auth_db/db]
```

Where the subscriber-DB link points, how it is protected, and whether it answers
**right now**:

```
$ kelictl auth_db show
State:            up
Host:             db.example.com
Port:             3306
Database:         kamailio
Username:         kamailio
Table:            subscriber
Tls:              true
Certificate:      not verified
Transport:        TLS, server certificate NOT verified (no ssl_ca_cert_file)
Pool size:        4
Query timeout ms: 5000
```

| Field | Says |
|---|---|
| `state` | `up` / `down` — a **live** `SELECT 1`, not a flag cached at boot |
| `error` | only when `down`: why, in one line |
| `host` `port` `database` `username` `table` | where it points, as the running pool was opened |
| `tls` | `true` / `false` — encrypted or not, the machine-readable answer |
| `certificate` | `verified` (a CA was configured) / `not verified` / `-` on a cleartext link |
| `transport` | the same thing in one line, **including why** it is what it is (a fallback that was taken names itself) |
| `pool_size` `query_timeout_ms` | the two bounds an operator tunes |

The **password is never in it** — not in the command's output, not in the map the
REST route returns.

`down` is an answer, not an error: the command exits `0` and prints the reason, so
it stays usable exactly when the base is unreachable. It is also bounded — a pool
that does not answer within `call_timeout_ms` is reported, never joined. The one
thing it refuses is an argument (it takes none), which exits `2` rather than being
silently ignored.

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
# in a registrar scenario — see apps/kelixip/scripts/registrar.exs
case Kelix.Mod.AuthDb.do_registration_auth(req, sip_ctx.domain) do
  :ok -> goto save_registration, "REGISTER auth OK"
  {:requireauth, stale} -> ...                          # the script builds the 401
  {:reject, code, reason} -> ...
end
```

```elixir
# in a call scenario — see apps/kelixip/scripts/direct-call-with-auth.exs
state authenticate_caller do
  AuthDb.SBB.authenticate()

  on_events do
    {:auth, :authenticated, %{user: user}} ->
      goto place_call, "INVITE authenticated as #{user}"

    {:auth, :cancelled, _} ->
      scenario_success("caller cancelled the challenged call")

    {:auth, :caller_gone, %{reason: reason}} ->
      scenario_success("caller gave up: #{inspect(reason)}")

    {:auth, :timeout, _} ->
      scenario_success("no credentials came back")

    {:auth, :refused, %{attempts: attempts}} ->
      scenario_success("gave up after #{attempts} refused attempts")
  end
end
```

The reference call script is
[`apps/kelixip/scripts/direct-call-with-auth.exs`](../../../apps/kelixip/scripts/direct-call-with-auth.exs)
(`direct-call.exs` plus one state that authenticates the caller); it is covered
by `apps/kelix_modules/test/direct_call_auth_script_test.exs`, and the block
itself by `apps/kelix_modules/test/auth_sbb_test.exs` — both inject the
subscriber table as a function instead of a database.

See the credential-gated live test
(`apps/kelixip/test/auth_db_live_test.exs`) for a full DB → verdict example.
