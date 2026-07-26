# kelixip modules

A **module** extends kelixip with a stateful service (a connection pool, a
store, a socket) **plus stateless facades** that scenario scripts import. This is
the same idea as a Kamailio module: it has parameters, it may add control
commands, and scripts call into it.

The core release ships **no** SIP function on its own — a kelixip-based product
loads exactly the modules it needs.

## Anatomy of a module

A module has two facets:

- **A service** — an OTP process (often a pool supervisor) that kelixip starts
  under `Kelix.ModuleSupervisor`, configured from its `[module.<name>]` block.
- **Facades** — the functions a script imports (`import Kelix.Mod.AuthDb`),
  which are stateless, resolve the running service by name, and delegate to it.

Facades are **non-blocking for the scenario instance**: if the service is down a
facade returns `{:error, :down}`, and a call that exceeds `call_timeout_ms`
returns `{:error, :timeout}`. A facade never raises — the instance keeps control
of the SIP response.

## Declaring a module

A module is declared by a `[module.<name>]` table. The `<name>` is the module's
registered name.

```toml
# config.toml
[module.auth_db]
database = "kamailio"
username = "kamailio"
password = "…"
```

- **Where the block lives.** Every module is configured from **`config.toml`**,
  with **one exception**: `registrar`, whose `[module.registrar]` block lives in
  **`domains.toml`** so it is hot-reloadable alongside the domains it serves. A
  `[module.registrar]` block placed in `config.toml` is ignored.
- **Which Elixir module implements it.** By default `<name>` maps to
  `Kelix.Mod.<Camelize(name)>` (`auth_db` → `Kelix.Mod.AuthDb`). Override with an
  explicit `module = "My.Custom.Module"` key.
- **Common keys.** `call_timeout_ms` (bounds a facade call; default 5000) is
  understood by every module. All other keys are module-specific — see each
  module's page.

An invalid block is **logged and skipped** at boot: the module does not start,
but the server and the other modules do (never a half-applied start).

## Loading

First-party modules (`registrar`, `auth_db`, `radius_billing`) are shipped as
separate packaging artifacts and dropped into `module_dir`
(`/usr/lib/kelixip/modules`, `server.module_dir`). A module is loaded only when a
`[module.<name>]` block declares it.

> Dynamic `.beam` loading from `module_dir` and `.beam` code-reload versioning
> land with packaging — see the roadmap. In a source checkout every module is
> already compiled into the umbrella.

## Using a module from a script

Import the facade and call it. The facade decides; the **script** composes the
SIP response (§11.1):

```elixir
import Kelix.Mod.Registrar, only: [save: 4, lookup: 1]
import Kelix.Mod.AuthDb, only: [do_registration_auth: 3]
```

## Reloading

`kelictl module reload <name>` re-reads the block: `validate_config/1` runs
first (an invalid block is rejected, the running service untouched), then the
module reconfigures in place if it supports it, else the child is cleanly
restarted. The `registrar` block additionally reloads on `kelictl reload-domains`.

## Control surface (kelictl / REST)

A module may contribute `kelictl <name> <cmd>` sub-commands and `/modules/<name>/…`
REST endpoints from a single declaration (`describe_control/0`); both frontals
derive from it. The control frontals land in P7 — see
[administration.md](../administration.md) and [rest-api.md](../rest-api.md).

## Reference

- [template.md](template.md) — the page layout every module doc follows
- [registrar.md](registrar.md)
- [auth_db.md](auth_db.md)
