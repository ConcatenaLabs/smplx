#!/usr/bin/env bash
# Checks that two lock files resolve the same versions of the Simplicity
# compiler and libraries: simplicityhl, simplicity-lang and simplicity-sys.
#
#   scripts/check-simplicity-pins.sh Cargo.lock path/to/sequentia-contracts/Cargo.lock
#
# A different compiler moves commitment roots, and with them addresses; a
# different library costs programs differently. This repository builds with
# the versions sequentia-contracts pins, and CI runs this check against them.
set -euo pipefail

ours=${1:?usage: $0 <this Cargo.lock> <sequentia-contracts Cargo.lock>}
theirs=${2:?usage: $0 <this Cargo.lock> <sequentia-contracts Cargo.lock>}

# Every version a lock file resolves for a crate, one per line, sorted.
versions() {
    awk -v name="$2" '
        $0 == "name = \"" name "\"" { found = 1; next }
        found && /^version = / { gsub(/^version = "|"$/, ""); print; found = 0 }
    ' "$1" | sort
}

status=0
for crate in simplicityhl simplicity-lang simplicity-sys; do
    a=$(versions "$ours" "$crate" | paste -sd, -)
    b=$(versions "$theirs" "$crate" | paste -sd, -)
    echo "$crate: ${a:-none} here, ${b:-none} in sequentia-contracts"
    if [ -z "$a" ] || [ "$a" != "$b" ]; then
        echo "error: $crate differs from the version sequentia-contracts pins" >&2
        status=1
    fi
done

exit $status
