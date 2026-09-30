#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Mutation testing: change the code in small ways and check the suite notices.
#
# A passing suite says the code does what the tests ask. This says something
# stronger -- that the tests would catch the code doing something else. For a
# environment that matters more than usual, because the failure mode is a boundary
# that is quietly wider than intended, and a test that never checks the absence
# of a right passes just as green as one that does.
#
#   tools/mutate.sh python   the policy layer, via mutmut
#   tools/mutate.sh rust     the native shim, via cargo-mutants
#   tools/mutate.sh          both
#
# Configuration lives with each language: [tool.mutmut] in pyproject.toml and
# native/.cargo/mutants.toml. This script only arranges to run them somewhere
# reproducible.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
what=${1:-all}

run_python() {
    echo "=== policy layer ==="
    # Copied into the container rather than mutated in place: mutmut writes a
    # mutants/ tree beside the source and runs the suite from inside it.
    docker run --rm -v "$root":/work:ro python:3.13-slim sh -c '
        set -e
        pip install -q pytest hypothesis mutmut
        cp -a /work /mut
        cd /mut
        rm -rf mutants native/target .hypothesis .pytest_cache
        mutmut run --max-children 4 "hlyn.policy.*" 2>&1 | tail -5
        mutmut results
    '
}

run_rust() {
    echo "=== native shim ==="
    # Needs the image from tools/Dockerfile.rust; cargo-mutants has to compile,
    # and installing it per run would make this unusable.
    docker build -q -f "$root/tools/Dockerfile.rust" -t hlyn-rust "$root" >/dev/null
    docker run --rm -v "$root/native":/native -w /native hlyn-rust \
        cargo mutants --timeout 60
}

case "$what" in
    python) run_python ;;
    rust) run_rust ;;
    all) run_python; run_rust ;;
    *) echo "usage: $0 [python|rust]" >&2; exit 2 ;;
esac
