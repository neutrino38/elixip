#!/usr/bin/env bash
# Assemble the elixipp escript for packaging.
#
#   packaging/stage-elixipp.sh  ->  packaging/build/elixipp-<version>/            (the tree)
#                                   packaging/build/SOURCES/elixipp-<version>.tar.gz
#
# Unlike kelixip's release, the escript is pure BEAM bytecode: mix.exs pulls in no
# NIF-based dependency (see BUILD.md § elixipp), so nothing here is linked against
# this host's glibc/OpenSSL — the payload can be built on any host with a matching
# Erlang/Elixir toolchain, no target-OS requirement.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/packaging/build"
SPEC="$REPO/packaging/rpm/elixipp.spec"

# Single source of truth for the version: apps/elixipp/mix.exs. The spec has to
# agree, and a silent disagreement would ship a mislabelled package.
version=$(sed -n 's/^ *version: "\([0-9][^"]*\)".*/\1/p' "$REPO/apps/elixipp/mix.exs" | head -1)
spec_version=$(sed -n 's/^Version: *\([^ ]*\)/\1/p' "$SPEC")
if [ -z "$version" ]; then
  echo "stage-elixipp.sh: cannot read the version from apps/elixipp/mix.exs" >&2
  exit 1
fi
if [ "$version" != "$spec_version" ]; then
  echo "stage-elixipp.sh: version mismatch — mix.exs says $version, elixipp.spec says $spec_version" >&2
  exit 1
fi

echo "==> elixipp $version — staging"

( cd "$REPO" && mix deps.get )
( cd "$REPO/apps/elixipp" && MIX_ENV=prod mix escript.build --force )

stage="$BUILD/elixipp-$version"
rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/doc" "$BUILD/SOURCES"

cp "$REPO/apps/elixipp/elixipp" "$stage/bin/elixipp"
chmod 0755 "$stage/bin/elixipp"

# The two docs ELIXIPP.md itself names as required reading: the tool's own usage,
# and the scenario language every .exs is written in.
cp "$REPO/ELIXIPP.md" "$REPO/FSL.md" "$stage/doc/"

tarball="$BUILD/SOURCES/elixipp-$version.tar.gz"
( cd "$BUILD" && tar czf "$tarball" "elixipp-$version" )

echo "==> $tarball ($(du -h "$tarball" | cut -f1))"
echo "==> $stage (staged tree)"
