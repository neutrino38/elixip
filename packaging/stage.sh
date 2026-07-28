#!/usr/bin/env bash
# Assemble everything the .spec needs into a single source tarball.
#
#   packaging/stage.sh  ->  packaging/build/SOURCES/kelixip-<version>.tar.gz
#
# What it stages:
#   rel/        the assembled `mix release kelixip` tree (embedded ERTS)
#   modules/    the loadable modules' .beam, compiled from apps/kelix_modules
#   scripts/    the reference scenario scripts (script_dir)
#   config/, sysconfig/, systemd/, doc/   the packaging inputs
#
# The embedded ERTS is native code linked against THIS host's glibc/OpenSSL/ncurses:
# run this on Alma Linux 9 (or in the container of packaging/Containerfile.al9),
# never in a Debian-based hexpm/elixir image. See packaging/README.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/packaging/build"
SPEC="$REPO/packaging/rpm/kelixip.spec"

# Single source of truth for the version: apps/kelixip/mix.exs. The spec has to
# agree, and a silent disagreement would ship a mislabelled package.
version=$(sed -n 's/^ *version: "\([0-9][^"]*\)".*/\1/p' "$REPO/apps/kelixip/mix.exs" | head -1)
spec_version=$(sed -n 's/^Version: *\([^ ]*\)/\1/p' "$SPEC")
if [ -z "$version" ]; then
  echo "stage.sh: cannot read the version from apps/kelixip/mix.exs" >&2
  exit 1
fi
if [ "$version" != "$spec_version" ]; then
  echo "stage.sh: version mismatch — mix.exs says $version, kelixip.spec says $spec_version" >&2
  exit 1
fi

echo "==> kelixip $version — staging on $(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release)"

if ! grep -qE '^(ID|ID_LIKE)=.*(almalinux|rhel|centos|fedora)' /etc/os-release; then
  echo "WARNING: this is not an EL host. The embedded ERTS will link this system's" >&2
  echo "         glibc/OpenSSL and may not run on Alma Linux 9 (packaging/README.md)." >&2
fi

# 1) The release, with its embedded ERTS.
echo "==> mix release kelixip"
( cd "$REPO" && mix deps.get )
( cd "$REPO/apps/kelixip" && MIX_ENV=prod mix release kelixip --overwrite --quiet )

# 2) The loadable modules. Deliberately NOT a dependency of :kelixip, so nothing
#    rebuilds them for us and nothing pulls them into the release.
echo "==> mix compile kelix_modules"
( cd "$REPO/apps/kelix_modules" && MIX_ENV=prod mix compile )

# 3) Stage.
stage="$BUILD/kelixip-$version"
rm -rf "$stage"
mkdir -p "$stage" "$BUILD/SOURCES"

cp -a "$REPO/_build/prod/rel/kelixip" "$stage/rel"
# tmp/ is the release's scratch dir (the unit points RELEASE_TMP at /run/kelixip),
# and COOKIE is generated per host by %post — neither belongs in the payload.
rm -rf "$stage/rel/tmp" "$stage/rel/releases/COOKIE"

mkdir -p "$stage/modules"
cp "$REPO"/_build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam "$stage/modules/"

mkdir -p "$stage/scripts"
cp "$REPO"/apps/kelixip/scripts/*.exs "$stage/scripts/"

cp -a "$REPO/packaging/config" "$REPO/packaging/sysconfig" "$REPO/packaging/systemd" "$stage/"

mkdir -p "$stage/doc"
cp "$REPO"/docs/kelixip/*.md "$stage/doc/"

tarball="$BUILD/SOURCES/kelixip-$version.tar.gz"
( cd "$BUILD" && tar czf "$tarball" "kelixip-$version" )
rm -rf "$stage"

echo "==> $tarball ($(du -h "$tarball" | cut -f1))"
