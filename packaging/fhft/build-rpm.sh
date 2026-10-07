#!/usr/bin/env bash
# Build bc-flexisip-http-file-transfer-server in an almalinux:9 container: the
# upstream commit the spec pins, as a tarball, plus the files of this directory.
# Output lands in packaging/dist, like the kelixip packages.
#
#   packaging/fhft/build-rpm.sh
#
# The package is noarch PHP: any AL9 image does, no toolchain is involved.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(cd "$HERE/.." && pwd)/dist"
SPEC=bc-flexisip-http-file-transfer-server.spec
UPSTREAM=https://github.com/BelledonneCommunications/flexisip-http-file-transfer-server.git
COMMIT="$(sed -n 's/^%global commit[[:space:]]*\([0-9a-f]*\).*/\1/p' "$HERE/$SPEC")"
[ -n "$COMMIT" ] || { echo "build-rpm.sh: no %global commit in $SPEC" >&2; exit 1; }

ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  for candidate in podman docker; do
    command -v "$candidate" >/dev/null 2>&1 && { ENGINE=$candidate; break; }
  done
fi
[ -n "$ENGINE" ] || { echo "build-rpm.sh: neither podman nor docker found." >&2; exit 1; }

mkdir -p "$OUT"
"$ENGINE" run --rm -v "$HERE":/fhft:ro,Z -v "$OUT":/out:Z almalinux:9 bash -euc "
  dnf install -y -q rpm-build git tar >/dev/null
  mkdir -p ~/rpmbuild/SOURCES
  git clone -q $UPSTREAM /tmp/upstream
  git -C /tmp/upstream archive --prefix=flexisip-http-file-transfer-server-$COMMIT/ \
      -o ~/rpmbuild/SOURCES/flexisip-http-file-transfer-server-$COMMIT.tar.gz $COMMIT
  cp /fhft/common-pdo.patch /fhft/flexisip-http-file-transfer-server.conf /fhft/fhft.inc \
     /fhft/zz-fhft-vhost.conf /fhft/user.ini ~/rpmbuild/SOURCES/
  rpmbuild -bb --quiet /fhft/$SPEC
  cp ~/rpmbuild/RPMS/noarch/*.rpm /out/
  chown $(id -u):$(id -g) /out/*.rpm
"
ls -1 "$OUT"/bc-flexisip-http-file-transfer-server-*.rpm
