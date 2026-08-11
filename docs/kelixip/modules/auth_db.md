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

See [evolution-auth-db.md](../../design/evolution-auth-db.md) for where this leads
(an `Auth` behaviour, and a Diameter backend).

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
# in a registrar scenario — see apps/kelixip/scripts/registrar.exs
case Kelix.Mod.AuthDb.do_registration_auth(req, sip_ctx.domain) do
  :ok -> goto save_registration, "REGISTER auth OK"
  {:requireauth, stale} -> ...                          # the script builds the 401
  {:reject, code, reason} -> ...
end
```

```elixir
# in a call scenario: challenge the caller before placing the second leg
state screen_caller do
  req = last_uas_req()

  if Kelix.Mod.AuthDb.challengeable?(req) do
    case Kelix.Mod.AuthDb.authenticate(req, sip_ctx.domain) do
      {:ok, identity} ->
        appdata_set(:caller, identity.user)
        goto place_call, "caller #{identity.user}"

      {:requireauth, _stale} ->
        # 407 + Proxy-Authenticate is what UAs expect on a call. Pass the
        # algorithm: the challenge must name the hash the base can verify, and
        # the dialog layer otherwise advertises MD5 — against a sha256 base that
        # re-challenges for ever.
        challenge_invite({sip_ctx.domain, Kelix.Mod.AuthDb.challenge_algorithm()}, 407)
        goto wait_authenticated_invite, "407 challenge"

      {:reject, code, reason} ->
        reply_invite(code, reason)
        scenario_failure("caller refused: #{code}")
    end
  else
    goto place_call, "no auth required"
  end
end
```

See the credential-gated live test
(`apps/kelixip/test/auth_db_live_test.exs`) for a full DB → verdict example.
