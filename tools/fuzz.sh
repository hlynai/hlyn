#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Fuzz the native shim.
#
# The shim reads memory that the caller describes rather than memory it owns:
# three arrays of C string pointers and two of ports, each with a length the
# caller supplies. That is the one place in this codebase where a mistake is
# not a wrong answer but an out-of-bounds read, so it is the one place worth
# fuzzing. Built with AddressSanitizer, so a bad read is a crash rather than a
# result nobody notices.
#
#   tools/fuzz.sh              both targets, a minute each
#   tools/fuzz.sh marshal 600  one target, ten minutes
#
# Findings land in native/fuzz/artifacts/ and are reproduced with:
#   cargo +nightly fuzz run <target> <artifact-file>
# A crash worth keeping belongs in the test suite as a named case, since the
# corpus is not committed.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:-all}
seconds=${2:-60}

docker build -q -f "$root/tools/Dockerfile.rust" -t hlyn-rust "$root" >/dev/null

# Nightly only for this: libFuzzer's instrumentation is behind -Z flags. The
# library itself builds on stable, and the fuzz feature that exposes the
# ruleset-assembly path is off in every shipped build.
one() {
    echo "=== $1 ==="
    docker run --rm -v "$root/native":/native -w /native hlyn-rust \
        cargo +nightly fuzz run "$1" -- -max_total_time="$seconds" -print_final_stats=1
}

case "$target" in
    all) one marshal; one plan ;;
    marshal | plan) one "$target" ;;
    *) echo "usage: $0 [marshal|plan] [seconds]" >&2; exit 2 ;;
esac
