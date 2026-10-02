#!/usr/bin/env bash
# Builds the simplex command line from this checkout and runs the basic
# example's tests on a local Sequentia chain.
#
#   scripts/sequentia-example.sh [path/to/sequentiad]
#
# The node binary is the argument, else $SEQUENTIAD, else `sequentiad` on PATH.
# Tests run under cargo-nextest (`smplx-nextest`, `cargo-nextest`, or the binary
# named by $SIMPLEX_NEXTEST).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
node=${1:-${SEQUENTIAD:-$(command -v sequentiad || true)}}

if [ -z "$node" ] || [ ! -x "$node" ]; then
    echo "sequentiad not found: pass its path, set SEQUENTIAD, or put it on PATH" >&2
    exit 2
fi
if [ -z "${SIMPLEX_NEXTEST:-}" ] && ! command -v smplx-nextest >/dev/null && ! command -v cargo-nextest >/dev/null; then
    echo "cargo-nextest not found: install it (https://nexte.st) or set SIMPLEX_NEXTEST" >&2
    exit 2
fi

target=${CARGO_TARGET_DIR:-$root/target}
cargo build --manifest-path "$root/Cargo.toml" -p smplx-cli
simplex="$target/debug/simplex"

# The example's Simplex.toml selects the Sequentia chain; its node is found on PATH.
export PATH="$(cd "$(dirname "$node")" && pwd):$PATH"
cd "$root/examples/basic"
"$simplex" build
"$simplex" test
