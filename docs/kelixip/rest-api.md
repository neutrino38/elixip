# REST control API (core)

> **Status: implemented (P8).** The REST frontal is `Kelix.ControlAPI` (a
> `Plug.Router` served by Bandit), the auth boundary is `Kelix.ControlAPI.Auth`,
> and `Kelix.ControlAPI.Endpoint` starts the server only when
> `[control_api].enabled`. Every route is a thin translation onto the same
> `Kelix.Control` function `kelictl` calls.

The REST API is the second frontal onto the same control layer as `kelictl` —
**one operation, two frontals**, so parity is automatic.

## Enabling & authentication (boundary concern)

Auth is enforced at the frontal boundary, before any command runs — the command
logic never inspects credentials. Configured in `config.toml`:

```toml
[control_api]
enabled = true
addr    = "127.0.0.1"   # loopback by default; network exposure = explicit
port    = 8090
auth    = "token"       # "token" (Bearer) | "mtls" | "none"
token   = "change-me"   # required when auth = "token"

# For auth = "mtls", provide the server cert/key and the CA that signs the
# accepted client certificates:
# cert   = "/etc/kelixip/tls/server.pem"
# key    = "/etc/kelixip/tls/server.key"
# cacert = "/etc/kelixip/tls/client-ca.pem"
```

Absent `[control_api]` (or `enabled = false`) → the server is not started.

- `token` (default) — a single admin **Bearer** token, constant-time compare.
  Bind on loopback (`addr`) unless exposure is intended.
- `mtls` — HTTPS with `verify_peer` + `fail_if_no_peer_cert`: the TLS layer
  rejects a client that presents no certificate signed by `cacert`.
- `none` — trusted local only (no credential).

The basic model is a **single admin token** (all commands, all domains, including
module endpoints); per-domain RBAC is roadmap.

A rejected request returns `401` (missing/invalid token) or `403` (mtls, no client
cert) with a JSON body `{"error": "…"}`.

## Core endpoints

| Method & path | R/W | Maps to |
|---|---|---|
| `GET /status` | R | `kelictl status` |
| `GET /scenarios` | R | `kelictl monitor` |
| `GET /registrations` | R | `kelictl registration list` |
| `GET /registrations/<aor>` | R | `kelictl registration show` |
| `GET /domains` | R | `kelictl domain list` |
| `GET /domains/<domain>` | R | `kelictl domain show` |
| `GET /mediaservers` | R | `kelictl mediaserver list` |
| `GET /mediaservers/<name>` | R | `kelictl mediaserver show` |
| `DELETE /registrations/<aor>` | W | `kelictl registration remove` |
| `POST /scenarios/<id>/shutdown` | W | `kelictl stop` |
| `POST /scripts/reload[?notify=1]` | W | `kelictl reload-script` |
| `POST /domains/reload` | W | `kelictl domain reload-all` |
| `POST /modules/<name>/reload` | W | `kelictl module reload` |
| `POST /mediaservers/<name>` | W | `kelictl mediaserver enable\|disable` |
| `PUT /log/level` | W | `kelictl log-level` |
| `POST /graceful-shutdown` | W | `kelictl graceful-shutdown` |

Request bodies are JSON (`Content-Type: application/json`); responses are JSON.
Result mapping: `:ok` → `200 {"result":"ok"}`; not-found → `404`; a bad
argument → `400`; `graceful-shutdown` → `202 {"result":"draining"}`.

`GET /domains` returns the list of these objects, in `domains.toml` order;
`GET /domains/<domain>` returns one (matched on the name **or** an alias,
case-insensitively) or `404`. Both read the live snapshot — what the router uses
now, not what is on disk. `dial_plan` is ordered and first-match-wins, the
catch-all being the entry with `"default": true` (and no `pattern`); a function
absent from `functions` is not served on that domain (`registrar` / `presence`
are then `null`).

```json
{
  "name": "example.com",
  "aliases": ["example.fr"],
  "max_calls": 500,
  "functions": ["registrar", "calls"],
  "registrar": {"script": "registrar.exs", "default_expires": 3600},
  "presence": null,
  "dial_plan": [
    {"pattern": "0[1-9]XXXXXXXX", "default": false, "script": "user2pstn.exs"},
    {"pattern": null, "default": true, "script": "catchall.exs"}
  ],
  "active_calls": 0,
  "registrations": 0
}
```

`GET /registrations` returns one object per AOR (filtered by `?aor=`);
`GET /registrations/<aor>` returns the **list** of objects that AOR matches — a
bare user-part can be registered in several domains — or `404`. Each binding
carries what the registrar stored: the expiry both ways (`expires_in` in seconds
is the operator question, `expires_at` the instant), the `source` the REGISTER
actually came from (behind a NAT, not what the contact URI says), the transport,
and the RFC 5626/3840 identity the handset sent. A field the handset did not send
is `null`.

```json
{
  "domain": "example.com",
  "aor": "alice",
  "contacts": [
    {
      "uri": "sip:alice@10.0.0.9:5060",
      "expires_at": "2026-08-02T12:34:56Z",
      "expires_in": 298,
      "source": "udp 203.0.113.7:45112",
      "transport": "udp",
      "instance": "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>",
      "reg_id": "1",
      "methods": null
    }
  ]
}
```

`GET /mediaservers` returns the `[mediaserver.pool.*]` entries in config order
(the round-robin order); `GET /mediaservers/<name>` returns one or `404`.
`enabled` is the operator switch (`POST /mediaservers/<name>` flips it), `healthy`
the pool's own probe, and `modules` what each module driving that server says
about it — the `mcu` module holds its own control channel, so its `status` and the
pool's `healthy` are two different healths of the same box (see
[administration](administration.md)). A module contributes its own shape; the
core adds nothing to it.

```json
{
  "name": "mcu1",
  "module": "mendooze",
  "url": "http://10.0.0.1:8080",
  "enabled": true,
  "healthy": true,
  "modules": {
    "mcu": {"name": "mcu1", "url": "http://10.0.0.1:8080", "status": "up", "queue_id": "q-42"}
  }
}
```

```bash
TOKEN=change-me
BASE=http://127.0.0.1:8090

# read verbs
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status
curl -s -H "Authorization: Bearer $TOKEN" $BASE/scenarios
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/registrations?aor=alice@example.com"
curl -s -H "Authorization: Bearer $TOKEN" $BASE/registrations/alice@example.com
curl -s -H "Authorization: Bearer $TOKEN" $BASE/domains
curl -s -H "Authorization: Bearer $TOKEN" $BASE/domains/example.com
curl -s -H "Authorization: Bearer $TOKEN" $BASE/mediaservers
curl -s -H "Authorization: Bearer $TOKEN" $BASE/mediaservers/mcu1

# write verbs
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
     "$BASE/registrations/alice@example.com"
curl -s -X POST   -H "Authorization: Bearer $TOKEN" $BASE/scenarios/42/shutdown
curl -s -X POST   -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"names":["uas_register"]}' "$BASE/scripts/reload?notify=1"
curl -s -X POST   -H "Authorization: Bearer $TOKEN" $BASE/domains/reload
curl -s -X POST   -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"enabled":false}' $BASE/mediaservers/mcu1
curl -s -X PUT    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"level":"debug"}' $BASE/log/level
curl -s -X POST   -H "Authorization: Bearer $TOKEN" $BASE/graceful-shutdown
```

## Module endpoints

Modules register their commands into `Kelix.Control.Registry` from the same
`describe_control/0` declaration that produces their `kelictl` sub-commands (see
[modules/README.md](modules/README.md#control-surface-kelictl--rest)). Each
declared command is reachable as `<method> /modules/<name>/<cmd>` — the method is
the one it declared (`get` for reads, `post` for writes) — with the JSON request
body passed through as the command args. A command reached with the wrong method
→ `405`; an undeclared command → `404`. None are contributed by the core modules
yet.

## Observability

`/metrics` (Prometheus) and `/health` are served **separately**, on the
`[metrics]` port (loopback:9095 by default), not by this control API — no auth,
scraped by a local Prometheus. Enable with:

```toml
[metrics]
enabled = true
addr    = "127.0.0.1"
port    = 9095
```

- `GET /metrics` — Prometheus text. Metrics carry a `domain` label where natural:
  `kelix_dispatch_accepted_count` / `kelix_dispatch_rejected_count` (by
  `domain`,`function`,`code`), `kelix_registrar_event_count` (by `domain`,`event`),
  and the gauges `kelix_calls_active`, `kelix_registrations_active`,
  `kelix_mediaserver_up`.
- `GET /health` — `{"live":true,"ready":true}` with `200` when ready (config
  surfaces up), `503` while not ready — for systemd / orchestrators.
