# Packaging kelixip (design §12.1, §15 P10)

Produces three packages — RPM for Alma Linux 9, deb for Ubuntu/Debian — from one
`mix release`:

| Package (RPM / deb) | Contents |
|---|---|
| `kelixip` | the release (embedded ERTS) + `kelictl` + systemd unit + `/etc/kelixip` |
| `kelixip-mod-registrar` | `Kelix.Mod.Registrar` bytecode, dropped into `module_dir` |
| `kelixip-mod-auth_db` / `kelixip-mod-auth-db` | `Kelix.Mod.AuthDb` bytecode, dropped into `module_dir` |

The core ships **no SIP function**: a deployment installs only the modules it uses
(an MCU-only product installs none). See
[../docs/kelixip/installation.md](../docs/kelixip/installation.md) for the admin
side — this file is about producing the artifacts.

## Build

```bash
# RPM, on an Alma Linux 9 host:
packaging/build-rpm.sh                              # -> packaging/dist/*.rpm

# deb, on the Ubuntu/Debian release you are targeting:
packaging/build-deb.sh                              # -> packaging/dist/*.deb

# Anywhere else (needs podman or docker):
packaging/build-in-container.sh                     # RPM, almalinux:9
packaging/build-in-container.sh --target ubuntu     # deb, ubuntu:24.04
packaging/build-in-container.sh --target ubuntu --os-version 22.04
```

➡️ **[../BUILD.md § Building the RPM packages](../BUILD.md#building-the-rpm-packages-alma-linux-9)**
and **[§ Building the deb packages](../BUILD.md#building-the-deb-packages-ubuntu--debian)**
are the full guides: how to set up each build host (Erlang, Elixir, `rpmbuild` /
`dpkg-dev`), what comes out, and how to install and verify it.

Both paths run `packaging/stage.sh` first, which assembles the release + the module
`.beam` into `packaging/build/kelixip-<version>/` **and** the tarball
`packaging/build/SOURCES/kelixip-<version>.tar.gz` — `rpmbuild` consumes the tarball
(its `Source0`), `build-deb.sh` the tree. One staging step, one payload, two package
formats. The version comes from `apps/kelixip/mix.exs` and each build **fails loudly**
if its own metadata disagrees with it — `rpm/kelixip.spec`'s `Version:` for the RPM,
the first line of `deb/changelog` for the deb. Bump all three.

> **Build on the target OS.** The release embeds ERTS, which is **native code**
> dynamically linked to the build host's glibc/OpenSSL/ncurses — assemble it on
> Debian and it fails to load on AL9, and vice-versa. The `.spec`, the deb control
> files and the scriptlets are portable; the payload is not. For the deb there is a
> second reason: `dpkg-shlibdeps` computes the `Depends` from the build host, so they
> name that release's library packages (`libssl3` on Ubuntu 22.04, `libssl3t64` on
> 24.04+). One package per target release. Why, and the Erlang/Elixir source options,
> in [../docs/design/kelixip_packaging.md](../docs/design/kelixip_packaging.md).

## Files here

| Path | Role |
|---|---|
| `rpm/kelixip.spec` | the spec: `%files` on the FHS layout, `%pre` user creation, `%post` cookie, subpackages |
| `deb/control*.in` | one control template per package (`@VERSION@`, `@ARCH@`, `@DEPENDS@`, `@INSTALLED_SIZE@`) |
| `deb/postinst`, `deb/prerm`, `deb/postrm` | the maintainer scripts: user creation, ownership, cookie, systemd |
| `deb/conffiles` | what dpkg must keep on upgrade — the deb's `%config(noreplace)` |
| `deb/changelog`, `deb/copyright` | the deb version (single source for its revision) and the licence |
| `systemd/kelixip.service` | the unit — unprivileged, `ExecStop` drains, hardened |
| `sysconfig/kelixip` | the environment file: node name, cookie, TOML paths |
| `config/config.toml`, `config/domains.toml` | the shipped defaults, kept on upgrade |
| `stage.sh`, `build-rpm.sh`, `build-deb.sh` | the builds |
| `build-in-container.sh`, `Containerfile.al9`, `Containerfile.ubuntu` | the containerised builds |
| `build/`, `dist/` | outputs, git-ignored |

`sysconfig/kelixip` is the single source for the environment file: the RPM installs
it as `/etc/sysconfig/kelixip`, and `build-deb.sh` installs it as
`/etc/default/kelixip` after rewriting the path it names in its own comments — the
alternative being a second copy of the same file, drifting.

## Three things the packages do deliberately

**The cookie is generated per host.** The Erlang distribution cookie is the
credential `kelictl` authenticates with, so shipping one inside the package would
make it the same secret on every installation. `releases/COOKIE` is therefore
excluded from the payload, generated from `/dev/urandom` at install time (0640
root:kelixip), kept across upgrades and removed on erase. On the RPM it is `%ghost` +
`%post`; on the deb, `postinst` + `postrm`.

**`module_dir` is root-owned and not writable by the service.** Loading a `.beam`
is executing code: the service must not be able to plant one. `stage.sh` also
normalises the release tree to 0755/0644 root-owned, because `mix release` inherits
the developer's umask and can hand over a group-writable tree.

**The unit is enabled but not started by the install.** The shipped `config.toml` is
a template: it binds 5060 and serves no domain. Starting it before an admin has read
it would grab the port and answer 404, which is worse than nothing happening. The
RPM's `%systemd_post` and the deb's `postinst` both stop at enabling.

## Not done yet

- **`RELEASE_NODE` ↔ `server.node_name` auto-sync.** Both are set in the environment
  file, which the unit *and* `rel/env.sh` read, so there is now one place to edit
  instead of two — but nothing yet *derives* the VM node name from the TOML at boot,
  so a mismatch is still possible.
- No `%check` / no test at package time: the suite runs from the repo
  (`mix test --exclude live`), not from the staged payload.
- No repository metadata (`createrepo` / `reprepro`) and no signing: the artifacts are
  loose files today.
