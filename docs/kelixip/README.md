# kelixip — User Manual

kelixip is a scriptable SIP application server built on the Elixip SIP stack. It
serves one or more SIP domains, each routed to FSL scenario scripts, with
loadable **modules** (registrar, database auth, …) plugged in Kamailio-style.

> This is the **operator/user** manual.

## Table of contents

| Guide | What it covers |
|---|---|
| [installation.md](installation.md) | Prerequisites, RPM/deb install, FHS layout, the `kelixip` user, systemd, and the **full `config.toml` / `domains.toml` reference** |
| [running.md](running.md) | Pointing the server at its config, starting/stopping, first boot, logs |
| [administration.md](administration.md) | `kelictl` — every command, with examples |
| [rest-api.md](rest-api.md) | The core REST control API and its auth boundary |
| [modules/](modules/README.md) | The module system and the reference for each module |
| [../../BUILD.md](../../BUILD.md) | **Building the packages** — build-host toolchain (Erlang from EPEL, Elixir in `/opt/elixir`), the RPMs, install & verify |

> Installing a released package? Start at [installation.md](installation.md).
> Producing one from the sources — including how to set up an Alma Linux 9 build
> host — is [BUILD.md § Building the RPM packages](../../BUILD.md#building-the-rpm-packages-alma-linux-9).

## Modules

Each module is documented on its own page (like Kamailio's module docs):

| Module | Config lives in | Purpose |
|---|---|---|
| [registrar](modules/registrar.md) | `domains.toml` | usrloc / contact store (REGISTER) |
| [auth_db](modules/auth_db.md) | `config.toml` | MariaDB/MySQL registrar authentication |
| radius_billing *(roadmap)* | `config.toml` | RADIUS billing |

See [modules/README.md](modules/README.md) for how modules are declared, loaded
and imported by scripts, and [modules/template.md](modules/template.md) for the
page layout every module doc follows.
