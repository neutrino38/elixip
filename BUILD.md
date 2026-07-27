# Building elixip / elixipp / kelixip

This repository is a **Mix umbrella** with four apps under `apps/`:

| App | Kind | Artifact | Depends on |
|-----|------|----------|------------|
| `elixip2` | library | — (shared SIP stack + DSL + media) | — |
| `elixipp` | test tool | **escript** `elixipp` | `elixip2` |
| `kelixip` | SIP server | **OTP release** `kelixip` (+ `kelictl`) | `elixip2` |
| `kelix_modules` | loadable modules | **`.beam` files** for `module_dir` | `kelixip` |

Each app pulls only its own dependencies, so the `elixipp` escript never carries
the server's HTTP/DB stack, and vice-versa. The library app is named `:elixip2`
(kept as-is to avoid churn on its many config references); its directory is
`apps/elixip2`. Design rationale: [docs/kelixip_basic_design.md](docs/kelixip_basic_design.md) §12.0.

## Prerequisites

- **Erlang/OTP** (the BEAM runtime) — required for everything.
- **Elixir** (`mix`) — required to build; **not** required at runtime for the
  `elixipp` escript (only the Erlang runtime is), and embedded in the `kelixip`
  release (ERTS is bundled).

## Common tasks (from the repo root)

All apps share the root `deps/`, `mix.lock` and `_build/`.

```bash
mix deps.get      # fetch dependencies for all apps
mix compile       # compile all apps
mix format        # format the whole tree
mix test          # run every app's test suite
```

### Running the tests

```bash
mix test                      # everything
mix test --exclude live       # skip tests needing outbound network (a real SIP proxy)
mix test apps/elixip2/test/sip_parser_test.exs        # one file
mix test apps/elixip2/test/sip_parser_test.exs:42     # one test by line
```

Notes:

- Test file paths live under `apps/<app>/test/`. In the umbrella, each app's
  tests run from **that app's directory**, so fixtures loaded with cwd-relative
  paths (`File.read("test/SIP-…")`, `scenarios/…`, `certs/…`) resolve inside the
  app.
- A few tests are **order-dependent** (named singleton processes leak state
  across test files) and the `ScenarioIntegration` **media** tests are flaky
  under load. They pass when run in isolation — so the practical bar is
  "green in isolation", not a spotless full run.
- `:live` tests require outbound network to a real SIP proxy; exclude them where
  there is none.

## elixipp — the test-tool escript

```bash
cd apps/elixipp
mix escript.build            # produces apps/elixipp/elixipp (self-contained)
./elixipp --help
./elixipp scenarios/uac_invite.exs                 # run a scenario file
./elixipp --listen udp:5060 scenarios/uas_register.exs   # server (UAS) mode
```

The escript bundles the compiled BEAM of `elixipp` + `elixip2` + their deps into
one file; it still needs an Erlang runtime (`erl`/`escript`) on the host. Install
it on your `PATH` with `mix escript.install`, or just copy the binary.

Full usage — including `--config`, `--monitor`, server (UAS) mode and the JSON
account files — is in the [README](README.md).

## kelixip — the server OTP release

```bash
cd apps/kelixip
MIX_ENV=prod mix release kelixip     # -> _build/prod/rel/kelixip/ (ERTS embedded)
```

Run it:

```bash
REL=_build/prod/rel/kelixip/bin/kelixip
$REL start        # foreground
$REL daemon       # background
$REL remote       # attach a remote shell to the running node
$REL rpc "EXPR"   # evaluate EXPR on the running node
$REL stop         # graceful stop
```

`kelictl` (the control CLI) ships **inside this release** as a `bin/` command
(it RPCs the running node) — it is not a separate escript. See
[docs/kelixip_basic_design.md](docs/kelixip_basic_design.md) §10.2, §12.

Point it at its configuration (design §2.1, §12.1):

```bash
KELIXIP_CONFIG=/etc/kelixip/config.toml \
KELIXIP_DOMAINS=/etc/kelixip/domains.toml $REL daemon
```

Both default to those FHS paths; an unreadable or invalid file aborts the boot and
says why on stderr.

> Status: the server boots, binds its `[[listen]]` ports, dispatches and answers
> (registrar). What is still missing for "basic" is the **packaging** (rpm/systemd,
> design §15 P10) and the `radius_billing` module.

## kelix_modules — the loadable modules

The release carries **no SIP function**: `registrar` and `auth_db` are installed
as `.beam` files into `server.module_dir` and loaded per `[module.<name>]` block
(design §8.3, §16.12). `apps/kelixip` does not depend on this app, which is what
keeps them out of the release.

```bash
cd apps/kelix_modules
MIX_ENV=prod mix compile
# install where the server looks (default /usr/lib/kelixip/modules)
cp _build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam "$MODULE_DIR"/
```

Check what a running node actually loaded with `kelictl status` (`modules:` line).
Installing a new version of a module is a copy plus `kelictl module reload <name>`
— no server restart.

## Development mode (no build artifact)

```bash
# run a scenario through mix (from the tool app or the umbrella root)
mix run -e "UAC.Invite.run()" apps/elixip2/scenarios/uac_invite.exs
# or via the mix task:
cd apps/elixip2 && mix scenario scenarios/uac_invite.exs
```
