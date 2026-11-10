#!/bin/sh
# Stable paths for compiler metadata. The application embeds its manifest path
# for development-only lab commands, which have no fixtures in the beta archive.
set -eu
compiler=$1
shift
if [ "${CARGO_PKG_NAME:-}" = rwr-package-intelligence ]; then
    export CARGO_MANIFEST_DIR=/usr/src/rwr-package-intelligence
fi
exec "$compiler" "$@" \
    "--remap-path-prefix=$RWR_BUILD_SOURCE=/usr/src" \
    "--remap-path-prefix=$RWR_BUILD_TARGET=/usr/src/rwr-target" \
    "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/usr/src/cargo"
