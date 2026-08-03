#!/usr/bin/env bash
# Build the kelixip .deb packages (core + one per module) on this host.
#
#   packaging/build-deb.sh   ->  packaging/dist/*.deb
#
# Must run on the Debian/Ubuntu release you are targeting: the release embeds an
# ERTS linked against the build host's glibc/OpenSSL, and the Depends are computed
# from that host's library packages (libssl3 on Ubuntu 22.04, libssl3t64 on 24.04+).
# One .deb per target release, therefore — same rule as one RPM per EL major. On any
# other distribution use build-in-container.sh. See packaging/README.md.
#
# No debhelper, no dpkg-buildpackage: the payload is a pre-assembled `mix release`
# tree, so there is nothing to compile at package time and `dpkg-deb --build` over
# an explicit tree is the honest shape — the same one the .spec's %install has.
set -euo pipefail

# Every directory this script creates implicitly (install -d only chmods the last
# component) must be 0755 root:root, not the developer's group-writable 0775.
umask 022

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/packaging/build"
DEBDIR="$REPO/packaging/deb"
DIST="$REPO/packaging/dist"
WORK="$BUILD/deb"

die() { echo "build-deb.sh: $*" >&2; exit 1; }

command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb not found — this needs a Debian/Ubuntu host (apt install dpkg-dev)"

# --- version ----------------------------------------------------------------
# The deb version (upstream + revision) comes from debian/changelog, as it must;
# the upstream part has to agree with apps/kelixip/mix.exs, and a silent
# disagreement would ship a mislabelled package. Bump both together.
deb_version=$(sed -n '1s/^kelixip (\([^)]*\)).*/\1/p' "$DEBDIR/changelog")
[ -n "$deb_version" ] || die "cannot read the version from packaging/deb/changelog"
upstream_version="${deb_version%%-*}"
mix_version=$(sed -n 's/^ *version: "\([0-9][^"]*\)".*/\1/p' "$REPO/apps/kelixip/mix.exs" | head -1)
[ -n "$mix_version" ] || die "cannot read the version from apps/kelixip/mix.exs"
[ "$upstream_version" = "$mix_version" ] || \
  die "version mismatch — mix.exs says $mix_version, deb/changelog says $upstream_version"

arch=$(dpkg --print-architecture)

# --- the payload ------------------------------------------------------------
# Same staging step as the RPM: one release, one set of modules, two packages.
KELIXIP_TARGET=deb "$REPO/packaging/stage.sh"
stage="$BUILD/kelixip-$mix_version"
[ -d "$stage" ] || die "$stage is missing — stage.sh did not leave its tree"

rm -rf "$WORK"
mkdir -p "$WORK" "$DIST"

# --- helpers ----------------------------------------------------------------

# render <template> <output> KEY=VALUE...   — substitute @KEY@, in bash so that
# nothing in the values (parentheses, commas, >=) needs sed escaping.
render() {
  local tpl="$1" out="$2"; shift 2
  local content kv
  content=$(cat "$tpl")
  for kv in "$@"; do
    content=${content//"@${kv%%=*}@"/"${kv#*=}"}
  done
  printf '%s\n' "$content" > "$out"
}

is_elf() {
  [ "$(dd if="$1" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]
}

# The core's Depends are computed, never hand-written. The payload's ERTS is native
# code — beam.smp, erl_child_setup, inet_gethost, the crypto NIF linked to OpenSSL —
# and dpkg-shlibdeps is the only thing that knows which package on THIS release
# provides each soname. That is also what pins the package to the release it was
# built on, which is exactly what we want given the embedded ERTS.
compute_depends() {
  local root="$1" sd="$WORK/.shlibdeps" f out
  local -a elfs=()
  while IFS= read -r f; do
    is_elf "$f" && elfs+=("$f")
  done < <(find "$root/usr/lib/kelixip" -type f \( -name '*.so' -o -perm -u+x \) | sort)

  if [ "${#elfs[@]}" -eq 0 ]; then
    die "found no ELF binary under the staged release — is include_erts still on?"
  fi

  if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    # dpkg-shlibdeps insists on being run from a source tree with debian/control;
    # a two-stanza stub is all it reads. -O prints to stdout instead of substvars.
    mkdir -p "$sd/debian"
    printf 'Source: kelixip\n\nPackage: kelixip\nArchitecture: any\n' > "$sd/debian/control"
    if out=$( cd "$sd" && dpkg-shlibdeps -O --ignore-missing-info "${elfs[@]}" 2>"$sd/warnings" ); then
      echo "${out#shlibs:Depends=}"
      return 0
    fi
    echo "WARNING: dpkg-shlibdeps failed, falling back to a hand-written Depends." >&2
    sed 's/^/         /' "$sd/warnings" >&2 || true
  else
    echo "WARNING: dpkg-shlibdeps not found (apt install dpkg-dev); using a hand-written Depends." >&2
  fi
  # Fallback: the libraries the ERTS actually links, with the alternatives that
  # cover the releases whose soname packages differ.
  echo 'libc6, libssl3 | libssl3t64, libncursesw6 | libncurses6, libtinfo6, zlib1g'
}

# finish_package <root> <control template> <package name> [KEY=VALUE...]
# Installed-Size and md5sums have to be computed on the finished tree, so the
# control file is rendered last.
finish_package() {
  local root="$1" tpl="$2" name="$3"; shift 3
  local size deb
  size=$(du -ks --exclude=DEBIAN "$root" | cut -f1)
  install -d -m 0755 "$root/DEBIAN"
  render "$tpl" "$root/DEBIAN/control" \
      VERSION="$deb_version" ARCH="$arch" INSTALLED_SIZE="$size" "$@"
  ( cd "$root" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' \
      | xargs -0 -r md5sum > DEBIAN/md5sums )
  chmod 0644 "$root/DEBIAN/control" "$root/DEBIAN/md5sums"
  deb="$DIST/${name}_${deb_version}_${arch}.deb"
  dpkg-deb --build --root-owner-group "$root" "$deb" >/dev/null
  echo "==> $deb ($(du -h "$deb" | cut -f1))"
}

# install_doc <root> <package name> — /usr/share/doc/<pkg>: copyright and the
# changelog are what dpkg-land expects of every package.
install_doc() {
  local root="$1" name="$2" docdir="$1/usr/share/doc/$2"
  install -d -m 0755 "$docdir"
  install -m 0644 "$DEBDIR/copyright" "$docdir/copyright"
  gzip -9nc "$DEBDIR/changelog" > "$docdir/changelog.Debian.gz"
  chmod 0644 "$docdir/changelog.Debian.gz"
}

# --- the core package -------------------------------------------------------
# This mirrors the .spec's %install section, path for path.
echo "==> assembling kelixip"
root="$WORK/kelixip"

# The release itself, plus the root-owned directory modules are loaded from.
install -d -m 0755 "$root/usr/lib/kelixip"
cp -a "$stage/rel/." "$root/usr/lib/kelixip/"
install -d -m 0755 "$root/usr/lib/kelixip/modules"

# kelictl is a command inside the release; kelixip is the release's own control
# script. Both resolve their own symlink, so /usr/sbin entries are enough.
install -d -m 0755 "$root/usr/sbin"
ln -s ../lib/kelixip/bin/kelictl "$root/usr/sbin/kelictl"
ln -s ../lib/kelixip/bin/kelixip "$root/usr/sbin/kelixip"

# script_dir — the reference scenario scripts.
install -d -m 0755 "$root/usr/share/kelixip"
install -m 0644 "$stage"/scripts/*.exs "$root/usr/share/kelixip/"

# Configuration. Unpacked 0640 root:root; postinst moves the group to kelixip,
# which is the one thing dpkg cannot express (the user does not exist at unpack).
# The staged copies name the RPM's /etc/sysconfig path, so rewrite the references
# instead of keeping a second, drifting copy of each file.
# Their comments also name the EL package manager and the RPM's module package
# name; an admin reading the file must find a command that works on this host.
install -d -m 0750 "$root/etc/kelixip" "$root/etc/kelixip/tls"
for toml in config domains; do
  sed -e 's,/etc/sysconfig/kelixip,/etc/default/kelixip,g' \
      -e 's,dnf install,apt install,g' \
      -e 's,kelixip-mod-auth_db,kelixip-mod-auth-db,g' \
      "$stage/config/$toml.toml" > "$root/etc/kelixip/$toml.toml"
  chmod 0640 "$root/etc/kelixip/$toml.toml"
done

install -d -m 0755 "$root/etc/default"
sed -e 's,/etc/sysconfig/kelixip,/etc/default/kelixip,g' \
    -e 's,%post generated,the postinst generated,' \
    "$stage/sysconfig/kelixip" > "$root/etc/default/kelixip"
chmod 0644 "$root/etc/default/kelixip"

# /lib/systemd/system, not /usr/lib: identical under merged-/usr and still right on
# a host without it.
install -D -m 0644 "$stage/systemd/kelixip.service" "$root/lib/systemd/system/kelixip.service"

# Mutable state (future usrloc persistence, operator-installed scripts) and the log
# directory used when stdout is redirected; postinst chowns both to the service.
install -d -m 0750 "$root/var/lib/kelixip" "$root/var/log/kelixip"

install_doc "$root" kelixip
install -m 0644 "$stage"/doc/*.md "$root/usr/share/doc/kelixip/"

# Without debhelper nothing marks a file under /etc as a conffile — DEBIAN/conffiles
# is what makes dpkg keep the admin's config.toml on upgrade (the .spec's
# %config(noreplace)).
install -d -m 0755 "$root/DEBIAN"
install -m 0644 "$DEBDIR/conffiles" "$root/DEBIAN/conffiles"
for script in postinst prerm postrm; do
  install -m 0755 "$DEBDIR/$script" "$root/DEBIAN/$script"
done

# The distribution cookie is NOT shipped: one cookie baked into the package would
# be the same secret on every installation (stage.sh already dropped it; belt and
# braces, because shipping it would be a silent security regression).
rm -f "$root/usr/lib/kelixip/releases/COOKIE"

depends=$(compute_depends "$root")
echo "==> Depends: $depends"
finish_package "$root" "$DEBDIR/control.in" kelixip DEPENDS="$depends, adduser, systemd"

# --- one package per loadable module ----------------------------------------
# The core implements no SIP function: a deployment installs only the modules it
# uses (a conferencing-only product installs kelixip-mod-mcu and nothing else).
build_module() {
  local name="$1" beam_glob="$2" tpl="$3" doc_glob="$4"
  local mroot="$WORK/$name"
  echo "==> assembling $name"
  install -d -m 0755 "$mroot/usr/lib/kelixip/modules"
  install -m 0644 "$stage"/modules/$beam_glob "$mroot/usr/lib/kelixip/modules/"
  install_doc "$mroot" "$name"
  # Its own document, alongside the copyright: what the docs on a host describe is
  # then what that host can actually do (the .spec's %doc for the same subpackage).
  install -m 0644 "$stage"/doc/modules/$doc_glob "$mroot/usr/share/doc/$name/"
  finish_package "$mroot" "$tpl" "$name"
}

# The .beam globs keep their trailing wildcard on purpose: a module is one named
# module plus its implementation (Mcu.Client, Mcu.Adapter.Conn, Registrar.Contact,
# …), and shipping only the named one installs a module whose every call fails.
build_module kelixip-mod-registrar 'Elixir.Kelix.Mod.Registrar*.beam' "$DEBDIR/control-mod-registrar.in" 'registrar.md'
build_module kelixip-mod-auth-db   'Elixir.Kelix.Mod.AuthDb*.beam'    "$DEBDIR/control-mod-auth-db.in"   'auth_db.md'
build_module kelixip-mod-mcu       'Elixir.Kelix.Mod.Mcu*.beam'       "$DEBDIR/control-mod-mcu.in"       'mcu*.md'

echo "==> packages in packaging/dist:"
ls -1 "$DIST"/*.deb
