#!/usr/bin/env bash
# Build the kelixip RPMs (core + one per module) on this host.
#
#   packaging/build-rpm.sh   ->  packaging/dist/*.rpm
#
# Must run on Alma Linux 9 — the release embeds an ERTS linked against the build
# host's glibc/OpenSSL. On any other distribution, use build-in-container.sh
# instead. See packaging/README.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/packaging/build"
DIST="$REPO/packaging/dist"

# rpmbuild never cleans its own tree: RPMS/SRPMS/SOURCES keep every past build, so
# a stale tree left over from an earlier version leaks its .rpm into this run's
# output (and stage.sh below would add this run's tarball to the pile, not replace
# it).
rm -rf "$BUILD"

"$REPO/packaging/stage.sh"

mkdir -p "$BUILD"/{SPECS,BUILD,BUILDROOT,RPMS,SRPMS} "$DIST"
cp "$REPO/packaging/rpm/kelixip.spec" "$BUILD/SPECS/"

echo "==> rpmbuild"
rpmbuild -bb --define "_topdir $BUILD" "$BUILD/SPECS/kelixip.spec"

# Likewise, drop this package's older builds from dist/ so it only ever holds the
# spec's current Version-Release; packages from other scripts (e.g. build-deb.sh's
# .deb) are untouched.
name="$(rpmspec -q --qf '%{name}\n' "$BUILD/SPECS/kelixip.spec" | head -1)"
rm -f "$DIST/${name}"-*.rpm
find "$BUILD/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "==> packages in packaging/dist:"
ls -1 "$DIST"
