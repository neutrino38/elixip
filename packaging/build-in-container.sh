#!/usr/bin/env bash
# Build the kelixip RPMs inside an Alma Linux 9 container — the portable path (CI,
# or a developer on a non-EL machine). Output lands in packaging/dist, same as a
# native build-rpm.sh run.
#
#   packaging/build-in-container.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  for candidate in podman docker; do
    command -v "$candidate" >/dev/null 2>&1 && { ENGINE=$candidate; break; }
  done
fi
if [ -z "$ENGINE" ]; then
  echo "build-in-container.sh: neither podman nor docker found." >&2
  echo "  On an Alma Linux 9 host you do not need a container: run build-rpm.sh." >&2
  exit 1
fi

echo "==> building the AL9 build image with $ENGINE"
"$ENGINE" build -f "$REPO/packaging/Containerfile.al9" -t kelixip-build:al9 "$REPO/packaging"

# The repo is bind-mounted so the RPMs land on the host, but _build and deps get
# their own volumes mounted OVER the host's: the container's OTP artifacts and the
# host's must never mix (a different OTP major there would produce .beam the target
# cannot load). Only packaging/{build,dist} are written back.
echo "==> building the RPMs in the container"
"$ENGINE" run --rm \
  -v "$REPO":/src:z \
  -v kelixip-build-artifacts:/src/_build \
  -v kelixip-build-deps:/src/deps \
  -e MIX_ENV=prod \
  kelixip-build:al9 /src/packaging/build-rpm.sh

echo "==> packages in packaging/dist:"
ls -1 "$REPO/packaging/dist"
