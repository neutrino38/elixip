#!/usr/bin/env bash
# Build the kelixip packages inside a container of the target distribution — the
# portable path (CI, or a developer on the wrong OS). Output lands in packaging/dist,
# same as a native build-rpm.sh / build-deb.sh run.
#
#   packaging/build-in-container.sh                     # RPM, almalinux:9   (default)
#   packaging/build-in-container.sh --target ubuntu      # deb, ubuntu:24.04
#   packaging/build-in-container.sh --target ubuntu --os-version 22.04
#
# The distribution matters: the release embeds ERTS, so the build host's
# glibc/OpenSSL/ncurses ARE the target's. See packaging/README.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

TARGET=al9
OS_VERSION=

while [ $# -gt 0 ]; do
  case "$1" in
    --target)     TARGET="${2:?--target needs a value: al9|ubuntu}"; shift 2 ;;
    --os-version) OS_VERSION="${2:?--os-version needs a value, e.g. 22.04}"; shift 2 ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    *)            echo "build-in-container.sh: unknown argument '$1'" >&2; exit 1 ;;
  esac
done

case "$TARGET" in
  al9)
    CONTAINERFILE=Containerfile.al9
    BUILD_SCRIPT=/src/packaging/build-rpm.sh
    VERSION_ARG=            # the AL9 image is pinned in the Containerfile
    ;;
  ubuntu)
    CONTAINERFILE=Containerfile.ubuntu
    BUILD_SCRIPT=/src/packaging/build-deb.sh
    VERSION_ARG=UBUNTU_VERSION
    ;;
  *)
    echo "build-in-container.sh: --target must be al9 or ubuntu (got '$TARGET')" >&2
    exit 1
    ;;
esac

ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  for candidate in podman docker; do
    command -v "$candidate" >/dev/null 2>&1 && { ENGINE=$candidate; break; }
  done
fi
if [ -z "$ENGINE" ]; then
  echo "build-in-container.sh: neither podman nor docker found." >&2
  echo "  On a host of the target distribution you do not need a container:" >&2
  echo "  run build-rpm.sh (Alma Linux 9) or build-deb.sh (Debian/Ubuntu)." >&2
  exit 1
fi

image="kelixip-build:$TARGET${OS_VERSION:+-$OS_VERSION}"
build_args=()
if [ -n "$OS_VERSION" ]; then
  if [ -z "$VERSION_ARG" ]; then
    echo "build-in-container.sh: --os-version is not supported for --target $TARGET" >&2
    exit 1
  fi
  build_args+=(--build-arg "$VERSION_ARG=$OS_VERSION")
fi

echo "==> building the $TARGET build image with $ENGINE"
"$ENGINE" build -f "$REPO/packaging/$CONTAINERFILE" "${build_args[@]}" -t "$image" "$REPO/packaging"

# The repo is bind-mounted so the packages land on the host, but _build and deps get
# their own volumes mounted OVER the host's: the container's OTP artifacts and the
# host's must never mix (a different OTP major there would produce .beam the target
# cannot load). Only packaging/{build,dist} are written back. The volumes are named
# per target for the same reason.
echo "==> building the packages in the container"
"$ENGINE" run --rm \
  -v "$REPO":/src:z \
  -v "kelixip-build-artifacts-$TARGET":/src/_build \
  -v "kelixip-build-deps-$TARGET":/src/deps \
  -e MIX_ENV=prod \
  "$image" "$BUILD_SCRIPT"

echo "==> packages in packaging/dist:"
ls -1 "$REPO/packaging/dist"
