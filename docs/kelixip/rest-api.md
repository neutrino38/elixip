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
| `GET /registrations` | R | `kelictl regs` |
| `DELETE /registrations/<aor>` | W | `kelictl unregister` |
| `POST /scenarios/<id>/shutdown` | W | `kelictl stop` |
| `POST /scripts/reload[?notify=1]` | W | `kelictl reload-script` |
| `POST /domains/reload` | W | `kelictl reload-domains` |
| `POST /modules/<name>/reload` | W | `kelictl module reload` |
| `POST /mediaservers/<name>` | W | `kelictl mcu … on\|off` |
| `PUT /log/level` | W | `kelictl log-level` |
| `POST /graceful-shutdown` | W | `kelictl graceful-shutdown` |

Request bodies are JSON (`Content-Type: application/json`); responses are JSON.
Result mapping: `:ok` → `200 {"result":"ok"}`; not-found → `404`; a bad
argument → `400`; `graceful-shutdown` → `202 {"result":"draining"}`.

```bash
TOKEN=change-me
BASE=http://127.0.0.1:8090

# read verbs
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status
curl -s -H "Authorization: Bearer $TOKEN" $BASE/scenarios
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/registrations?aor=alice@example.com"

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
