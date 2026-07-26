# kelixip — User Manual

kelixip is a scriptable SIP application server built on the Elixip SIP stack. It
serves one or more SIP domains, each routed to DSL scenario scripts, with
loadable **modules** (registrar, database auth, …) plugged in Kamailio-style.

> This is the **operator/user** manual. The locked design and rationale live in
> [`../kelixip_basic.md`](../kelixip_basic.md) (spec) and
> [`../kelixip_basic_design.md`](../kelixip_basic_design.md) (design).

## Table of contents

| Guide | What it covers |
|---|---|
| [installation.md](installation.md) | Prerequisites, RPM/deb install, FHS layout, the `kelixip` user, systemd |
| [running.md](running.md) | The two config files, starting/stopping, first boot, logs |
| [administration.md](administration.md) | `kelictl` — every command, with examples |
| [rest-api.md](rest-api.md) | The core REST control API and its auth boundary |
| [modules/](modules/README.md) | The module system and the reference for each module |

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
