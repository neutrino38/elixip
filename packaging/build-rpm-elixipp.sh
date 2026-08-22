#!/usr/bin/env bash
# Build the elixipp RPM.
#
#   packaging/build-rpm-elixipp.sh   ->  packaging/dist/elixipp-*.rpm
#
# The escript is pure BEAM bytecode (see rpm/elixipp.spec), so unlike
# build-rpm.sh this can run on any host with rpmbuild and the Elixir/Erlang
# toolchain — no target-OS requirement.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/packaging/build"
DIST="$REPO/packaging/dist"

# rpmbuild never cleans its own tree: RPMS/SRPMS/SOURCES keep every past build, so
# a stale tree left over from an earlier version leaks its .rpm into this run's
# output (and stage-elixipp.sh below would add this run's tarball to the pile, not
# replace it).
rm -rf "$BUILD"

"$REPO/packaging/stage-elixipp.sh"

mkdir -p "$BUILD"/{SPECS,BUILD,BUILDROOT,RPMS,SRPMS} "$DIST"
cp "$REPO/packaging/rpm/elixipp.spec" "$BUILD/SPECS/"

echo "==> rpmbuild"
rpmbuild -bb --define "_topdir $BUILD" "$BUILD/SPECS/elixipp.spec"

# Drop this package's older builds from dist/ so it only ever holds the spec's
# current Version-Release; packages from other scripts (kelixip's RPM/deb) are
# untouched.
name="$(rpmspec -q --qf '%{name}\n' "$BUILD/SPECS/elixipp.spec" | head -1)"
rm -f "$DIST/${name}"-*.rpm
find "$BUILD/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "==> packages in packaging/dist:"
ls -1 "$DIST"
