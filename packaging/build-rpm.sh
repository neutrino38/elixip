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

"$REPO/packaging/stage.sh"

mkdir -p "$BUILD"/{SPECS,BUILD,BUILDROOT,RPMS,SRPMS} "$DIST"
cp "$REPO/packaging/rpm/kelixip.spec" "$BUILD/SPECS/"

echo "==> rpmbuild"
rpmbuild -bb --define "_topdir $BUILD" "$BUILD/SPECS/kelixip.spec"

find "$BUILD/RPMS" -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "==> packages in packaging/dist:"
ls -1 "$DIST"
