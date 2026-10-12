# sip_servers

This module declares the remote SIP servers a domain exchanges calls with, and
keeps their state: whether each is reachable, whether a trunk is registered.
A script asks it where an inbound request comes from and how to forward a call to
a server, then hands the result to the B2BUA.

A server belongs to one domain and is one of three types:

| Type | The remote host is | Example |
|---|---|---|
| `sip-application` | an application server that sends and takes calls for our users | an ACD, an IVR |
| `sip-proxy` | a proxy/registrar with users of its own | a partner PBX |
| `sip-trunk` | an account at an operator | a SIP trunk |

What each type changes on a call forwarded to it:

| | `sip-application` | `sip-proxy` | `sip-trunk` |
|---|---|---|---|
| Request-URI | rewritten: the dialled user at the server | kept; its host becomes `ext_domain` when it names our domain | rewritten: the dialled user at `ext_domain`, else at the trunk host |
| To | kept | follows the Request-URI | follows the Request-URI |
| From | kept | kept | the trunk account |
| REGISTER, answers challenges | no | no | yes |
| Remote AORs probed, reported to presence | no | yes | no |

What the module does for a server:

| When | What happens |
|---|---|
| `send_keepalive` is on | an OPTIONS to each URI every `keepalive_interval` seconds; any final answer but `503` marks the URI up, no answer marks it down |
| a request from the server reaches a script that calls `matches_server/2` | the server is marked up |
| a call is forwarded to the server | a URI known to be down is skipped without sending anything |
| the trunk's operator challenges a request (INVITE, re-INVITE, UPDATE, BYE, MESSAGE) | it is sent again once with the trunk's credentials |
| `register` is on (a trunk) | the account is registered, refreshed before it expires, retried on failure, un-registered when the server is deleted or the node stops |
| `probe_remote_aors` is on (a proxy) | an OPTIONS to each remote AOR through the proxy, spread over `probe_interval`; the answer is the AOR's presence |
| the server's host names change address | the module resolves them again when their DNS TTL runs out |

A URI never probed nor heard from is `unknown`, and counts as reachable.

The module recognises; it does not trust. What a request from a server is worth,
and whether its P-Asserted-Identity is kept, is the script's decision.

Servers are not described in `config.toml` nor in `domains.toml`. They are created
with `kelictl`, the REST API or kelescope, and kept in the module's file.

## Installing and activating the module

### Installing the `kelixip-mod-sip_servers` package

`dnf install kelixip-mod-sip_servers` / `apt install kelixip-mod-sip-servers`

### Declaring the module in config.toml

```toml
# config.toml
[module.sip_servers]
server_file = "/var/lib/kelixip/sip_servers.json"
```

Without `server_file` the servers live in memory only, and a restart forgets
them. The module says so in the log at start.

### Reaching the domain

A request from a server is routed like any other: its Request-URI host, else its
To host, must name the domain or one of its `aliases`. An operator that calls
`sip:+33123456789@203.0.113.10`, or puts its own domain in the Request-URI, needs
that address or domain in the domain's `aliases`. Otherwise the node answers `404`
before any script runs.

### Answering the servers' OPTIONS

The OPTIONS a server sends are answered by a script, which tells the module the
server is alive by calling `matches_server/2`. Without a `[[domain.options]]` rule
the node answers them itself, and the module is not told.

```toml
# domains.toml
[[domain]]
name    = "example.com"
aliases = ["203.0.113.10"]

  [[domain.options]]
  keepalive = true
  script    = "options-sip-servers.exs"
```

`options-sip-servers.exs` is written below, under Examples.

### Restart kelixip

`systemctl restart kelixip`

### Declaring the servers

```console
$ kelictl sip_servers server.create domain=example.com slug=acd \
    type=sip-application primary_uri=sip:10.0.0.5:5060
$ kelictl sip_servers server.create domain=example.com slug=operator \
    type=sip-trunk primary_uri=sip:0123456789@sbc.operator.net \
    backup_uri=sip:0123456789@sbc2.operator.net ext_domain=operator.net \
    auth_username=0123456789 auth_realm=operator.net auth_password=secret
$ kelictl sip_servers server.create domain=example.com slug=partner-pbx \
    type=sip-proxy primary_uri=sip:pbx.partner.net ext_domain=partner.net \
    probe_remote_aors=true
$ kelictl sip_servers aor.add example.com partner-pbx alice@partner.net
```

### Checking

`kelictl sip_servers server.show example.com operator` shows the state of each
URI under `reachability` and the trunk's `registration`.

## Parameters

`[module.sip_servers]`:

| Key | Type | Default | Description |
|---|---|---|---|
| `server_file` | string | — | The file the servers are kept in, mode `0600`. Unset: memory only |
| `keepalive_interval` | integer | `30` | Seconds between two OPTIONS to a server's URI |
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |

## Server fields

The arguments of `server.create` and `server.update`. A field given to a type that
does not use it is refused. On an update, a field not given is kept, and an empty
value clears an optional one (`backup_uri=` drops the backup).

| Field | Types | Default | Description |
|---|---|---|---|
| `domain` | all | **required** | The kelixip domain the server belongs to |
| `slug` | all | **required** | Its name, hostname-shaped, unique within the domain |
| `type` | all | **required** | `sip-application`, `sip-proxy` or `sip-trunk` |
| `primary_uri` | all | **required** | `sip:` or `sips:` URI. A trunk's carries the account's user part; the others' have none |
| `backup_uri` | all | — | Tried when the primary fails or is down |
| `use_dns_srv` | all | `false` | Resolve each URI through SRV records |
| `send_keepalive` | all | `true` | Send the OPTIONS liveness probe |
| `initiate_connection` | all | `true` | Over TCP or TLS, the node opens the connection |
| `ha_mode` | all | `failover` | `failover`: primary first. `loadsharing`: each call starts on the next URI |
| `ext_domain` | proxy, trunk | — | The remote domain. For a trunk, the host of the Request-URI, To, From and REGISTER |
| `ext_domain_aliases` | proxy | `[]` | Other names of the proxy's domain, comma-separated |
| `probe_remote_aors` | proxy | `false` | Probe the remote AORs and report them to presence |
| `probe_interval` | proxy | `60` | Seconds to probe every remote AOR once |
| `register` | trunk | `true` | Register the account. `false`: no REGISTER, challenges still answered |
| `register_expires` | trunk | `600` | REGISTER lifetime asked, in seconds |
| `register_retry` | trunk | `30` | Seconds before a failed registration is tried again, doubled on each failure up to an hour |
| `auth_username` | trunk | — | The account's user name |
| `auth_realm` | trunk | — | The realm its challenges are expected for |
| `auth_password` | trunk | — | Write-only. Needs `auth_username` and `auth_realm`; only its MD5 and SHA-256 HA1 are kept |

Within a domain, two servers never claim the same host, address or remote domain:
the hosts of their URIs, a proxy's `ext_domain` and aliases, and the addresses
these resolve to. A creation or an update that would is refused.

Changing `auth_username` or `auth_realm` of a trunk that has a password needs
`auth_password` again.

A challenge for a realm other than `auth_realm` is not answered: the request
fails, and an alarm names both realms. Entering the password again with the right
realm clears it.

A remote host that authenticates the node by its address alone, with no account,
is a `sip-application`, not a trunk.

## Facades

Each facade takes the script's context first (or a domain name).

### `matches_server/2`

```elixir
Kelix.Mod.SipServers.matches_server(sip_ctx, req) ::
  {slug, %SIP.B2bua.Peer{}} | :no_match
```

The server of the domain `req` comes from, recognised by its source address and
transport. The source port is not compared. An address two servers of the domain
have come to share answers `:no_match` (alarm `shared_address`).

A request recognised is proof of life: the server is marked up.

### `find_server/2`

```elixir
Kelix.Mod.SipServers.find_server(sip_ctx, req) :: slug | :no_match
```

The server `req` is addressed to, from the host of its Request-URI: a `sip-proxy` by
its `ext_domain` and aliases, a `sip-application` by the hosts of its URIs. A trunk
is never found this way.

### `forward/3`

```elixir
Kelix.Mod.SipServers.forward(sip_ctx, req, slug) ::
  {newreq, %SIP.B2bua.Peer{}}
  | {:error, :not_found | :not_resolved | :down | :timeout}
```

The request as the server expects it, and the peer to hand to `call/1` (`SBB.Call`)
or `b2bua_forward/4`.

| Result | Meaning | Usual answer |
|---|---|---|
| `{newreq, peer}` | forward `newreq` to `peer` | — |
| `{:error, :not_found}` | no server of that name in the domain | `404` |
| `{:error, :not_resolved}` | a trunk with an `ext_domain` whose URIs have not resolved yet | `503` |
| `{:error, :down}`, `{:error, :timeout}` | the module does not answer | `503` |

When every URI of the server is known to be down, nothing is sent and the forward
fails: `call/1` ends with `{:call, :failed, %{reason: :forward_failed, cause:
{:b2bua, :no_reachable_target}}}`.

## Control commands

`<server>` is `<domain> <slug>` for `kelictl`, `<domain>/<slug>` in a path.

| Command | REST | Description |
|---|---|---|
| `kelictl sip_servers server.create …` | `POST /modules/sip_servers/servers` | Declares a server (`201`). `409` when its name, host, address or remote domain is taken; `400` for a domain the node does not serve |
| `kelictl sip_servers server.list [domain]` | `GET /modules/sip_servers/servers` | The servers, optionally of one domain |
| `kelictl sip_servers server.show <server>` | `GET /modules/sip_servers/servers/<server>` | One server: its fields (never the password; `auth` says `set` or `none`), `reachability`, `registration`, `aor_states`, `metrics`, `alarms` |
| `kelictl sip_servers server.update <server> …` | `PUT` or `PATCH /modules/sip_servers/servers/<server>` | Changes the fields given |
| `kelictl sip_servers server.delete <server>` | `DELETE /modules/sip_servers/servers/<server>` | Deletes it; a registered trunk is un-registered |
| `kelictl sip_servers aor.add <server> <aor>` | `POST /modules/sip_servers/servers/<server>/aors` | Attaches a remote AOR (`user@domain`) to a proxy |
| `kelictl sip_servers aor.rm <server> <aor>` | `DELETE /modules/sip_servers/servers/<server>/aors/<aor>` | Detaches it; its presence is withdrawn |
| `kelictl sip_servers aor.list <server>` | `GET /modules/sip_servers/servers/<server>/aors` | A proxy's remote AORs and their `state`: `unknown`, `open`, `closed`, `none` when not probed |

In `server.show`:

| Key | Content |
|---|---|
| `reachability` | Each URI and its state: `up`, `down`, `unknown` |
| `registration` | A registering trunk's `state` (`unregistered`, `registering`, `registered`, `failed`) and last `error`; `null` otherwise |
| `aor_states` | A proxy's remote AORs and their probed state |
| `metrics` | Since the server's process started: `calls_in`, `calls_out`, `answered`, `failures` by response code, `options_rtt_ms` (`last`, `mean`) |
| `alarms` | Active alarms, see Events |

`calls_in` counts the INVITEs `matches_server/2` recognised, `calls_out` the
INVITEs `forward/3` shaped. `answered` and `failures` count the attempts the B2BUA
made on the server's URIs.

## Events

`Kelix.Control.subscribe_sip_servers(pid, domain)` answers
`{:ok, %{owner: pid, servers: [row]}}`, each row as `server.show` renders it, then
sends `pid`:

| Message | When |
|---|---|
| `{:kelix_sip_servers, domain, {:upsert, row}}` | a server is created or changed, or its state, counters or alarms change. The whole row |
| `{:kelix_sip_servers, domain, {:remove, slug}}` | a server is deleted |
| `{:kelix_sip_servers, domain, {:alarm, alarm}}` | an alarm is raised |

Counters alone are sent at most once a second. `owner: nil` with no row means the
module is not loaded. The subscription ends with `unsubscribe_sip_servers(pid,
domain)`, with the subscriber's death, or with `owner`'s.

An alarm is a map with `kind` and `server`, and stays in the row while it is
active:

| `kind` | Keys | Raised when | Cleared when |
|---|---|---|---|
| `realm_mismatch` | `expected`, `received` | a trunk is challenged for another realm | the server's definition changes |
| `shared_address` | `address`, `servers` | two servers of the domain resolve to one address; raised on each | the address is no longer shared |

kelescope shows these in the SIP servers section of its domain screen.

## Examples

Answering the servers' OPTIONS, and telling the module (`options-sip-servers.exs`):

```elixir
defmodule Kelix.OptionsSipServers do
  use SIP.Scenario

  uas(:options)
  config(uses_modules: [:sip_servers])

  state initial_state do
    goto(wait_options)
  end

  state wait_options do
    on_events do
      {:OPTIONS, req, _trans, _dlg} ->
        _ = Kelix.Mod.SipServers.matches_server(sip_ctx, req)
        b2bua_reply(req, 200, "OK", [{"Allow", Kelix.Options.allow()}])
        scenario_success("keepalive answered")

      {:dialog_terminated, _dlg, _reason} ->
        scenario_aborted("sender vanished before the OPTIONS")
    after
      5_000 -> scenario_failure("no OPTIONS received")
    end
  end
end
```

A call from a trusted server keeps its P-Asserted-Identity. The branch that
records it moves on to the next state itself, so the context it changed goes
with it:

```elixir
state classify do
  req = last_uas_req()

  case Kelix.Mod.SipServers.matches_server(sip_ctx, req) do
    {_slug, _peer} ->
      trust_asserted_identity(req)
      goto(place_call, "from a trusted server")

    :no_match ->
      goto(authenticate, "from a user")
  end
end
```

A call out through the trunk, in a call script built on `SBB.Call`:

```elixir
state place_call do
  req = last_uas_req()

  # The errors first: `{:error, reason}` is a pair too.
  case Kelix.Mod.SipServers.forward(sip_ctx, req, "operator") do
    {:error, :not_found} ->
      b2bua_reply(req, 404, "Not Found")
      scenario_failure("no server named operator")

    {:error, _} ->
      b2bua_reply(req, 503, "Service Unavailable")
      scenario_success("the trunk cannot take the call now")

    {newreq, peer} ->
      call(args: %{peer: peer, request: newreq})

      on_events do
        {:call, :connected, _} -> goto(connected, "call established")
        {:call, :rejected, %{code: code}} -> scenario_success("operator said #{code}")
        {:call, :failed, %{reason: reason}} -> scenario_failure("call failed: #{reason}")
      end
  end
end
```

A call to a partner PBX, the server found from the Request-URI and kept for the
state that forwards to it, `place_call` above with `appdata_get(:server)` in place
of `"operator"`:

```elixir
state route do
  req = last_uas_req()

  case Kelix.Mod.SipServers.find_server(sip_ctx, req) do
    :no_match ->
      goto(local_user, "not for a partner")

    slug ->
      appdata_set(:server, slug)
      goto(place_call, "for #{slug}")
  end
end
```
