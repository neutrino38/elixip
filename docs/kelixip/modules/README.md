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

First-party modules are shipped as **one package each** — `kelixip-mod-registrar`,
`kelixip-mod-auth_db` (and `kelixip-mod-radius_billing` when it exists) — which drop
their bytecode into `module_dir` (`/usr/lib/kelixip/modules`, `server.module_dir`).
**The server release contains none of them**: at boot it adds `module_dir` to its
code path and loads a module only when a `[module.<name>]` block declares it.

Two consequences worth knowing:

- **A block is what loads the code.** A script calling `Kelix.Mod.AuthDb.…` needs
  `[module.auth_db]` in `config.toml`, even if the facade would have worked
  without configuration: a release does not lazily load code on first call. With
  no block, the script raises on its first facade call and the request gets **no
  answer at all**. Boot (and `kelictl domain reload-all`) warns when a domain enables
  a function whose same-named module is not loaded.
- **Installing a new version is install + reload.** Drop the new `.beam` into
  `module_dir` and run `kelictl module reload <name>`: the code is re-read from
  disk, the block re-validated, and the service reconfigured or restarted. No
  server restart.

From a source checkout, build and install them with:

```bash
cd apps/kelix_modules && MIX_ENV=prod mix compile
cp _build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam "$MODULE_DIR"/
```

> `.beam` code-reload **versioning** (OTP `code_change`-style state migration) is
> still out of scope — a reload keeps the service's state as-is or restarts it.

## Using a module from a script

Import the facade and call it. The facade decides; the **script** composes the
SIP response (§11.1):

```elixir
import Kelix.Mod.Registrar, only: [save: 4, lookup: 1]
import Kelix.Mod.AuthDb, only: [do_registration_auth: 3]
```

### Declare what you use

A script should also **declare** the modules it calls, in its `config` block:

```elixir
config uses_modules: [:registrar, :auth_db]
```

The names are the registered ones — the `<name>` of each `[module.<name>]` block,
not the Elixir module.

kelixip then refuses to load the script when one of them is not loaded, naming the
missing module and listing those that are. Without the declaration the dependency
is written nowhere and cannot be guessed (a custom registrar script may legitimately
need no `registrar` module), so the mismatch could only ever be a boot *warning* —
and the first request to that domain would die inside the instance, answered `500`
by the reference script's rescue at best.

The declaration is **optional**: a script that declares nothing still loads, exactly
as before. Adding it turns a runtime surprise into a load-time error.

## Reloading

`kelictl module reload <name>` re-reads the block: `validate_config/1` runs
first (an invalid block is rejected, the running service untouched), then the
module reconfigures in place if it supports it, else the child is cleanly
restarted. The `registrar` block additionally reloads on `kelictl domain reload-all`.

## Control surface (kelictl / REST)

A module may contribute `kelictl <name> <cmd>` sub-commands and `/modules/<name>/…`
REST endpoints from a single declaration (`describe_control/0`); both frontals
derive from it — see [administration.md](../administration.md) and
[rest-api.md](../rest-api.md).

That declaration is also readable at runtime, so what a node serves never has to
be looked up in a module's source:

```console
$ kelictl module list          # loaded modules, their commands and facades
$ kelictl mcu help             # one module's commands, routes and arguments
$ curl localhost:8090/modules  # the same declarations as JSON
```

## Reference

- [template.md](template.md) — the page layout every module doc follows
- [registrar.md](registrar.md)
- [auth_db.md](auth_db.md)
- [mcu.md](mcu.md) — conferencing; the narrative guide is
  [docs/mcu_module_guide.md](../../mcu_module_guide.md)
