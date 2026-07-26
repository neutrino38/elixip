# Installation

> **Status: skeleton.** Finalized with packaging (**P10** — RPM for Alma Linux 9
> first, then deb). The layout below reflects the locked design (§12); commands
> are filled in when the packages are produced.

## Prerequisites

- Alma Linux 9 (x86_64). The release embeds its own ERTS — no system Erlang/Elixir
  required.
- A database only if you load [`auth_db`](modules/auth_db.md) (MariaDB/MySQL).

## Packages

kelixip is shipped as a **core** release plus **one package per module**, so a
deployment installs only what it uses.

- `kelixip` — the core server + `kelictl`
- `kelixip-registrar`, `kelixip-auth_db`, `kelixip-radius_billing` — modules
  (`.beam` dropped into `module_dir`)

```bash
# TODO (P10): dnf install kelixip kelixip-registrar kelixip-auth_db
```

## Filesystem layout (FHS, §12)

| Path | Contents |
|---|---|
| `/etc/kelixip/config.toml` | Infrastructure config (`%config(noreplace)`) |
| `/etc/kelixip/domains.toml` | Domains + dial-plan + registrar block (`%config(noreplace)`) |
| `/usr/share/kelixip/` | Scenario scripts (`script_dir`) |
| `/usr/lib/kelixip/modules/` | Loadable modules (`module_dir`, root-owned) |
| `/usr/sbin/kelictl` | Admin CLI (a command inside the release) |
| `/usr/lib/kelixip/` | The release itself |

## System user & service

The package creates a dedicated unprivileged `kelixip` user and a systemd unit.

```bash
# TODO (P10): systemctl enable --now kelixip
```

## Verify

```bash
# TODO (P7/P9): systemctl status kelixip
# TODO (P9):    curl -s http://127.0.0.1:<metrics>/health
```

Next: [running.md](running.md).
