#!/usr/bin/env bash
# Assemble everything a package needs — the .spec and the deb build both use it.
#
#   packaging/stage.sh  ->  packaging/build/kelixip-<version>/            (the tree)
#                           packaging/build/SOURCES/kelixip-<version>.tar.gz
#
# build-rpm.sh consumes the tarball (rpmbuild's Source0), build-deb.sh the tree —
# same payload either way, which is the point: one staging step, two packages.
#
# What it stages:
#   rel/        the assembled `mix release kelixip` tree (embedded ERTS)
#   modules/    the loadable modules' .beam, compiled from apps/kelix_modules
#   scripts/    the reference scenario scripts (script_dir)
#   config/, sysconfig/, systemd/, completion/, doc/   the packaging inputs
#   doc/modules/  the per-module documents, shipped by the module subpackages
#
# The embedded ERTS is native code linked against THIS host's glibc/OpenSSL/ncurses,
# so stage on the target OS: Alma Linux 9 for the RPM, the target Ubuntu/Debian
# release for the deb (KELIXIP_TARGET=deb relaxes the host check accordingly). Never
# in an unrelated hexpm/elixir image. See packaging/README.md.
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

# Which package family this staging run feeds — it only selects the host sanity
# check below, since the payload itself is identical for both.
case "${KELIXIP_TARGET:-el}" in
  el)  os_family='almalinux|rhel|centos|fedora' ; os_label='an EL host (Alma Linux 9)' ;;
  deb) os_family='debian|ubuntu'                ; os_label='a Debian/Ubuntu host' ;;
  *)   echo "stage.sh: KELIXIP_TARGET must be 'el' or 'deb'" >&2 ; exit 1 ;;
esac

if ! grep -qE "^(ID|ID_LIKE)=.*($os_family)" /etc/os-release; then
  echo "WARNING: this is not $os_label. The embedded ERTS will link this system's" >&2
  echo "         glibc/OpenSSL and may not run on the target (packaging/README.md)." >&2
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
# and COOKIE is generated per host by the package's post-install — neither belongs
# in the payload. Neither does elixip.log: running the release from the checkout
# leaves one at the release root, and it would ship as a package file.
rm -rf "$stage/rel/tmp" "$stage/rel/releases/COOKIE"
rm -f "$stage/rel"/*.log

# `mix release` inherits the developer's umask, so the tree can arrive
# group-writable (0775/0664). Normalise it: the payload is root-owned and must not
# be writable by anything else — loading a .beam is executing code.
find "$stage/rel" -type d -exec chmod 0755 {} +
find "$stage/rel" -type f -perm -u+x -exec chmod 0755 {} +
find "$stage/rel" -type f ! -perm -u+x -exec chmod 0644 {} +

mkdir -p "$stage/modules"
cp "$REPO"/_build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam "$stage/modules/"

mkdir -p "$stage/scripts"
cp "$REPO"/apps/kelixip/scripts/*.exs "$stage/scripts/"

cp -a "$REPO/packaging/config" "$REPO/packaging/sysconfig" "$REPO/packaging/systemd" \
   "$REPO/packaging/completion" "$stage/"

mkdir -p "$stage/doc"
cp "$REPO"/docs/kelixip/*.md "$stage/doc/"

# The per-module documents travel with their own module package, not with the core:
# what a node can do depends on which subpackages are installed, and so should what
# its documentation claims.
mkdir -p "$stage/doc/modules"
cp "$REPO"/docs/kelixip/modules/*.md "$stage/doc/modules/"

tarball="$BUILD/SOURCES/kelixip-$version.tar.gz"
( cd "$BUILD" && tar czf "$tarball" "kelixip-$version" )

# The tree is kept, not just the tarball: build-deb.sh assembles its package roots
# from it directly (dpkg-deb has no Source0 to unpack). Each run starts by wiping it.
echo "==> $tarball ($(du -h "$tarball" | cut -f1))"
echo "==> $stage (staged tree, reused by build-deb.sh)"
