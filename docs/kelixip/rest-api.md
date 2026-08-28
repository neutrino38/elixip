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
| `GET /registrations` | R | `kelictl registration list` — [registrar](modules/registrar.md#control-commands) |
| `GET /domains` | R | `kelictl domain list` |
| `GET /domains/<domain>` | R | `kelictl domain show` |
| `GET /domains/<domain>/registrations` | R | `kelictl registration list <domain>` — *idem* |
| `GET /domains/<domain>/registrations/<aor>` | R | `kelictl registration show` — *idem* |
| `GET /mediaservers` | R | `kelictl mediaserver list` |
| `GET /mediaservers/<name>` | R | `kelictl mediaserver show` |
| `GET /modules` | R | `kelictl module list` |
| `GET /modules/<name>` | R | `kelictl <name> help` |
| `DELETE /domains/<domain>/registrations/<aor>` | W | `kelictl registration remove` — *idem* |
| `POST /scenarios/<id>/shutdown` | W | `kelictl stop` |
| `POST /scripts/reload[?notify=1]` | W | `kelictl reload-script` |
| `POST /domains/reload` | W | `kelictl domain reload-all` |
| `POST /reload-all` | W | `kelictl reload-all` (what `systemctl reload` runs) |
| `POST /modules/<name>/reload` | W | `kelictl module reload` |
| `POST /mediaservers/<name>` | W | `kelictl mediaserver enable\|disable` |
| `PUT /log/level` | W | `kelictl log-level` |
| `POST /drain` / `POST /undrain` | W | `kelictl drain` / `kelictl undrain` |
| `POST /graceful-shutdown` | W | `kelictl graceful-shutdown` |

Request bodies are JSON (`Content-Type: application/json`); responses are JSON.
Result mapping: `:ok` → `200 {"result":"ok"}`; not-found → `404`; a bad
argument → `400`; `graceful-shutdown` → `202 {"result":"draining"}`.

`POST /reload-all` answers a per-stage report — `200` when it was applied, `400` when
it was refused (the body says by what, and nothing was changed):

```json
{
  "domains": "ok",
  "version": 4,
  "scripts": {"registrar.exs": 1, "mcu.exs": 2},
  "modules": {"registrar": "unchanged", "mcu": ["skipped", "restart_required"]}
}
```

On a refusal, `domains` carries the reason and the later stages are empty — the
running configuration is unchanged:

```json
{
  "domains": ["error", "1 script(s) rejected:\n  - domain example.com [domain.registrar]: …"],
  "version": 4,
  "scripts": {},
  "modules": {}
}
```

`GET /domains` returns the list of these objects, in `domains.toml` order;
`GET /domains/<domain>` returns one (matched on the name **or** an alias,
case-insensitively) or `404`. Both read the live snapshot — what the router uses
now, not what is on disk. `dial_plan` is ordered and first-match-wins, the
catch-all being the entry with `"default": true` (and no `pattern`); a function
absent from `functions` is not served on that domain (`registrar` / `presence`
are then `null`).

Every place a `script` appears — the `dial_plan` entries and the function blocks —
carries the **`module`** the BEAM actually runs for it and its load **`version`**, as
soon as the script is loaded (both keys are absent until then). The module comes from
the file's own `defmodule`, not from its name, so it is the only reliable answer to
"what does this rule run". A **`stale`** key is added *only when it is one*, comparing
the loaded code with the file at read time: `"changed"` (edited since load — a
`reload-script` would pick it up), `"missing"` (the file is gone; the loaded version
keeps serving) or `"unknown"` (it could not be stat'ed at load).

```json
{
  "name": "example.com",
  "aliases": ["example.fr"],
  "max_calls": 500,
  "functions": ["registrar", "calls"],
  "registrar": {
    "script": "registrar.exs", "default_expires": 3600,
    "module": "Registrar.Example.V1", "version": 1
  },
  "presence": null,
  "dial_plan": [
    {"pattern": "0[1-9]XXXXXXXX", "default": false, "script": "user2pstn.exs",
     "module": "User2Pstn.V1", "version": 1},
    {"pattern": null, "default": true, "script": "catchall.exs",
     "module": "Catchall.V3", "version": 3, "stale": "changed"}
  ],
  "active_calls": 0,
  "registrations": 0
}
```

**Registrations are a sub-resource of the domain** — an AOR is only unique within a
domain, so it is addressed as `/domains/<domain>/registrations/<aor>` and never as a
query filter. The three registration routes, their payloads and what each field of a
binding means are documented with the module whose store they read:
**[modules/registrar.md](modules/registrar.md#control-commands)**.

`GET /mediaservers` returns the `[mediaserver.pool.*]` entries in config order
(the round-robin order); `GET /mediaservers/<name>` returns one or `404`.
`enabled` is the operator switch (`POST /mediaservers/<name>` flips it), `healthy`
the pool's own probe, and `modules` what each module driving that server says
about it — the `mcu` module holds its own control channel, so its `status` and the
pool's `healthy` are two different healths of the same box (see
[administration](administration.md)). A module contributes its own shape; the
core adds nothing to it.

`server` is the media server's own answer on its `GET /status/general` endpoint,
passed through **verbatim** — version, real codec capabilities, text transports,
encryption, addressing profiles, load. `"unknown"` on a server that does not
describe itself. Two warnings for whoever consumes it:

* `capabilities.video.decode` and `capabilities.video.encode` are different
  lists (the server decodes codecs it cannot encode), so read the one matching
  the direction you need;
* the body is the media server's schema, not ours. It is not reshaped here, on
  purpose: rewriting it would make this a copy, and a copy drifts. The field
  reference is the mediaserver repository, `docs/reference/status-http.md`.

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
curl -s -H "Authorization: Bearer $TOKEN" $BASE/domains
curl -s -H "Authorization: Bearer $TOKEN" $BASE/domains/example.com
curl -s -H "Authorization: Bearer $TOKEN" $BASE/mediaservers
curl -s -H "Authorization: Bearer $TOKEN" $BASE/mediaservers/mcu1

# the registration routes have their own examples in modules/registrar.md

# write verbs
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
[modules/README.md](modules/README.md#module-administration-kelictl--rest-api)). A command
declares a **path template** relative to `/modules/<name>`, so it is reachable
both as a resource (`GET /modules/mcu/conferences/c-3f9a`) and in the flat form
`<method> /modules/<name>/<cmd>`, for a client that cannot build URLs. Both
dispatch to the same handler.

Args are merged **path < query < body** (a body that tries to change a path
parameter is a `400`). The declaration also carries the HTTP concerns the frontal
derives: the success status (`201` on a creation), a `Location` template, and the
per-reason error statuses (that is how a module answers `409`). A command reached
with the wrong method → `405`; an undeclared one → `404`.

**Discovery.** `GET /modules` returns what every loaded module contributes and
`GET /modules/<name>` one module's surface — the command names, their methods,
their path templates and their arguments, plus the facade functions the module
exports to scripts. That is the same data `kelictl module list` / `kelictl <name>
help` render, so a client can build its URLs from the node instead of from
out-of-band documentation.

Of the shipped modules, [mcu](modules/mcu.md) contributes fourteen commands
(conferences, participants, recording and mosaic slots) — its endpoints are documented
one by one, with their payloads, in **[modules/mcu-api.md](modules/mcu-api.md)**;
`registrar` and `auth_db` contribute none.

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
