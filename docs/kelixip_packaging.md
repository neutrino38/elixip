# kelixip packaging (P10) — build toolchain & RPM

Status: **design note** (2026-07-27). Records the build-environment decisions for
the P10 RPM (Alma Linux 9 first, then deb). The **what** — FHS layout, systemd
unit, subpackages, `%config(noreplace)` — is in the design doc
[§12](kelixip_basic_design.md#12-packaging); this note covers the **how to build**:
which OS, which Erlang/Elixir, and why.

## Target & golden rule

Target: **Alma Linux 9** (x86_64; match the target arch — cross-arch = qemu, slow).

The release embeds ERTS (`mix release`, `include_erts: true`, §12.1). ERTS is
**native code** — the beam VM, `erl_child_setup`, `inet_gethost`, and the **crypto
NIF linked to OpenSSL** — dynamically linked against the build host's
**glibc / OpenSSL / ncurses**. AL9 ships **glibc 2.34 + OpenSSL 3.x**.

> **Golden rule: build the release on AL9** (or an AL9 container). Assembling it on
> Debian/Ubuntu (different OpenSSL/glibc) risks runtime linkage failures on the
> target. The `.spec` / `%files` / scriptlets are portable; the **payload**
> (release + ERTS) is what must match AL9.

You do **not** need a dedicated AL9 machine — an **`almalinux:9` container in CI**
is the build host (§15 P10 already says "rpmbuild/fpm en CI"). Podman/Docker on any
host works.

## Toolchain: only Erlang is OS-sensitive

**Elixir is pure BEAM** (no native code), so it is trivial: download the
**precompiled** Elixir zip from GitHub releases, unzip, put on PATH. The only piece
that must be **AL9-native** is **Erlang/OTP**.

### Erlang/OTP on AL9 — three sources

- **A) EPEL 9** — provides `erlang` (unlike Elixir, which EPEL does **not** ship).
  As of 2026-07 EPEL AL9 gives **OTP 26.2.5-1.el9**. Simplest if that OTP suits you.
- **B) RabbitMQ "modern Erlang" RPMs for EL9** — Cloudsmith repo
  `rabbitmq/rabbitmq-erlang` (aka `rabbitmq/erlang-rpm`), current OTP, zero-dep,
  built for Alma/Rocky/RHEL 9. Use when you need a newer/pinned OTP than EPEL.
- **C) Build from source** — `asdf`/`mise` + the `erlang` plugin (kerl), or
  `./configure && make`. Max version control; needs build-deps
  (`gcc make automake autoconf ncurses-devel openssl-devel …`) and a few minutes.

Whichever you pick, the resulting ERTS is AL9-native and links AL9's OpenSSL 3.

### Elixir version — matched to the OTP major

Elixir↔OTP compatibility for **OTP 26**: Elixir **1.15 / 1.16 / 1.17 / 1.18** all
support it (1.18 covers OTP 25–27). The project requires only **`elixir: "~> 1.15"`**
(no OTP pin — checked in all three `apps/*/mix.exs`), so:

➡️ **Install Elixir 1.18.x** — ≥ the `~> 1.15` floor and the same minor used in dev.

> **Precompiled-zip pitfall:** on OTP 26 take the **`elixir-otp-26.zip`** build, NOT
> `elixir-otp-27.zip`. Elixir is bytecode, but an artifact compiled under OTP 27 can
> **fail to load** on an OTP-26 runtime. On OTP 26 → use the `otp-26` (or earlier)
> Elixir build.

## Compatibility with Elixip

**Compatible.** The project pins only `elixir: "~> 1.15"` and no OTP version; nothing
in the code requires OTP 27. OTP 26 is within Elixir 1.18's supported range, and the
current deps (jason, req, ex_sdp, xmlrpc, toml, myxql — bandit with P8) all support
OTP 26.

> **Caveat — verify once.** The dev/CI baseline is **OTP 27**; the RPM build would run
> on **OTP 26**. Before trusting the package, run the suite on the target toolchain:
>
> ```sh
> # inside the AL9 container (EPEL OTP 26 + Elixir 1.18 otp-26)
> mix deps.get && mix test --exclude live
> ```
>
> Green there ⇒ safe to freeze the package. (Building with EPEL's OTP 26 means the
> release embeds **OTP 26 ERTS, AL9-native** — exactly what we want.)

## Anti-pattern

Do **not** build the AL9 release inside the Docker Hub **`hexpm/elixir:*`** images —
they are Debian/Alpine/Ubuntu based, so the **embedded ERTS would be Debian/Alpine's**,
not AL9's → broken linkage on the target. Those images are fine for CI *tests*, not
for producing an AL9 embedded-ERTS release.

## Reference build recipe (sketch)

```dockerfile
FROM almalinux:9
# 1) Erlang native to AL9 — source A (EPEL, OTP 26.2.5)
RUN dnf install -y epel-release && dnf install -y erlang
# 2) Elixir precompiled, matched to the OTP major (otp-26!), pure BEAM
RUN curl -L .../elixir-otp-26.zip -o /tmp/e.zip \
 && unzip -d /usr/local/elixir /tmp/e.zip
ENV PATH="/usr/local/elixir/bin:$PATH"
# 3) mix release  →  AL9-native ERTS embedded  →  rpmbuild / fpm
```

> Verify the **current** versions when you build (EPEL's OTP ↔ a compatible Elixir
> `otp-XX` zip); the numbers above are the 2026-07 snapshot, not pinned forever.

## Open items (P10)

- `RELEASE_NODE` ↔ `server.node_name` auto-sync at boot (today set by hand in
  `rel/env.sh.eex` — noted in the kelictl guide).
- Module subpackages (`kelixip-mod-registrar`, …) dropping `.beam` into a
  root-owned `module_dir` (§12.1).
- deb (Ubuntu) from the same release, after the RPM.
