# REST control API (core)

> **Status: skeleton.** The REST frontal (`Kelix.ControlAPI`, served by Bandit)
> lands in **P7**. Endpoints below mirror the locked control surface (§10); each
> gets request/response examples when implemented.

The REST API is the second frontal onto the same control layer as `kelictl` —
**one operation, two frontals**, so parity is automatic.

## Authentication (boundary concern)

Auth is enforced at the frontal boundary, before any command runs — the command
logic never inspects credentials. Configured in `config.toml`:

```toml
[control_api]
addr = "127.0.0.1"
port = 8080
auth = "token"        # "token" (loopback + Bearer) | "mtls" | "none"
```

- `token` (default) — loopback + a single admin **Bearer** token (constant-time
  compare).
- `mtls` — adds client-certificate verification for network exposure.
- `none` — trusted local only.

The basic model is a **single admin token** (all commands, all domains, including
module endpoints); per-domain RBAC is roadmap.

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

```bash
# TODO (P7): curl examples with the Bearer token, per endpoint
```

## Module endpoints

Modules register `/modules/<name>/…` routes from the same declaration that
produces their `kelictl` sub-commands (see
[modules/README.md](modules/README.md#control-surface-kelictl--rest)). None are
contributed yet.

## Observability

`/metrics` (Prometheus) and `/health` are served separately, on the `[metrics]`
port — see the roadmap (**P9**), not this control API.
