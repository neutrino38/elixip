# kelixip modules

A **module** is a loadable Elixir BEAM that extends kelixip and exposes new
functions and facades to be used in kelixip scenarios written in DSL. This
is the kelixip equivalent of kamailio modules. In details, a module can extend
kelixip by

- adding new facades / functions for scripts
- adding new admin commands
- adding new REST API endpoints for administration

The core release ships **no** SIP function on its own — a kelixip-based product
loads exactly the modules it needs.

# List of modules

| Module | Elixir module | Function | Package (RPM / deb) | Doc |
|---|---|---|---|---|
| `registrar` | `Kelix.Mod.Registrar` | Location service: REGISTER bindings, AOR lookup | `kelixip-mod-registrar` | [registrar.md](registrar.md) |
| `auth_db` | `Kelix.Mod.AuthDb` | Digest authentication against a subscriber database | `kelixip-mod-auth_db` / `kelixip-mod-auth-db` | [auth_db.md](auth_db.md) |
| `mcu` | `Kelix.Mod.Mcu` | Conferencing (medooze media server) | `kelixip-mod-mcu` | [mcu.md](mcu.md), REST endpoints [mcu-api.md](mcu-api.md), scenario guide [mcu_module_guide.md](mcu_module_guide.md) |

The module name is the one to use in a `[module.<name>]` block and in a script's
`uses_modules`; the Elixir module is what a script imports the facades from.
[template.md](template.md) is the page layout every module doc follows.

# Using modules

## Declaring a module

A module is declared by a `[module.<name>]` section in `config.toml`.
The `<name>` is the module's registered name. The section can contain
module specific parameters that are system wide e.g.

```toml
# config.toml
[module.auth_db]
database = "kamailio"
username = "kamailio"
password = "…"
```

- **One exception on where the block lives**: `registrar`, whose
  `[module.registrar]` block is in **`domains.toml`**, so it is hot-reloadable
  along with the domains it serves. A `[module.registrar]` block placed in
  `config.toml` is ignored.
- **Which Elixir module implements it**: by default `<name>` maps to
  `Kelix.Mod.<Camelize(name)>` (`auth_db` → `Kelix.Mod.AuthDb`). A third-party
  module names it explicitly with `module = "My.Custom.Module"`.
- **`call_timeout_ms`** (default 5000) bounds a facade call and is understood by
  every module. All other keys are module specific — see each module's page.

An invalid config block is **logged and skipped** at boot: the module does not start,
but the server and the other modules do (never a half-applied start).

## Packaging and loading of modules

Kelixip modules are shipped as RPM / .deb packages — one per module, listed in
the table above. They contain .beam files (compiled Elixir code) and documentation.
- .beam files are stored in `/usr/lib/kelixip/modules` (`server.module_dir`)
- doc is stored in `/usr/share/doc/<package>/`

Note that at boot, kelixip loads only those module which name has been declared
in a `[module.<name>]` block in `config.toml` (or, for `registrar`, in
`domains.toml`).

## Managing modules

If a module is upgraded or its configuration changed, the command

`kelictl module reload <name>` can be used to reload the module config and code.
Upgrading is therefore install + reload: the new `.beam` is dropped into
`module_dir` by the package, then the reload re-reads it from disk.

Behavior of module reloading depends on the module. All this can be done without
restarting kelixip and with minimal service impact.

> A reload keeps the module's state as-is or restarts the service: `.beam`
> **versioning** (OTP `code_change`-style state migration) is out of scope.

The command enables discovery of modules

```console
$ kelictl module list          # loaded modules, their commands and facades
```

## Using a module from a script

Import the facade and call it. The facade decides; the **script** composes the
SIP response (§11.1):

```elixir
import Kelix.Mod.Registrar, only: [save: 4, lookup: 1]
import Kelix.Mod.AuthDb, only: [do_registration_auth: 3]
```

A script should also **declare** its module dependencies in its `config` block:

```elixir
config uses_modules: [:registrar, :auth_db]
```
By doing so, the script ensures that it cannot be loaded if one of its dependency
modules is not loaded, instead of crashing during production time.

The names are the registered ones — the `<name>` of each `[module.<name>]` block,
not the Elixir module.


# Anatomy of a module

A module has two facets:

- **A service** — an OTP process (often a pool supervisor) that kelixip starts
  under `Kelix.ModuleSupervisor`, configured from its `[module.<name>]` block.
- **Facades** — the functions a script imports (`import Kelix.Mod.AuthDb`),
  which are stateless, resolve the running service by name, and delegate to it.

Facades are **non-blocking for the scenario instance**: if the service is down a
facade returns `{:error, :down}`, and a call that exceeds `call_timeout_ms`
returns `{:error, :timeout}`. A facade never raises — the instance keeps control
of the SIP response.

## Module administration (kelictl / REST API)

A module may add `kelictl <name> <cmd>` sub-commands and `/modules/<name>/…`
REST endpoints from a single declaration (`describe_control/0`); both frontals
derive from it — see [administration.md](../administration.md) and
[rest-api.md](../rest-api.md).


```console
$ kelictl module list          # loaded modules, their commands and facades
$ kelictl mcu help             # one module's commands, routes and arguments
$ kelictl mcu help conference.update   # one command, with its arguments' vocabulary
$ curl localhost:8090/modules  # the same declarations as JSON
```

An argument may carry its own `help:` (one line or several) for a value with a
vocabulary of its own — a mosaic name, an enum, a compact syntax. It is printed
under the command by the two `help` forms above and travels in the JSON, so the
text an operator reads sits next to the parser that enforces it.
