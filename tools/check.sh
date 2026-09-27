#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Everything that can be checked without running anything.
#
#   tools/check.sh          all of it
#   tools/check.sh python   ruff and mypy
#   tools/check.sh rust     clippy, cargo-audit, cargo-deny
#
# The tests prove the boundary holds. This proves the code around it says what
# it means: types that match reality, no accidental blind excepts, and a
# dependency tree small enough to have actually been looked at.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
what=${1:-all}

run_python() {
    echo "=== ruff and mypy ==="
    # Read-only mount, working copy elsewhere: both tools want somewhere to
    # write a cache, and neither should be able to touch the source.
    docker run --rm -v "$root":/work:ro -w /tmp python:3.13-slim sh -c '
        set -e
        pip install -q ruff mypy
        cp -a /work /w && cd /w && rm -rf native/target
        ruff check .
        mypy
    '
}

run_rust() {
    echo "=== clippy, audit, deny ==="
    docker build -q -f "$root/tools/Dockerfile.rust" -t hlyn-rust "$root" >/dev/null
    docker run --rm -v "$root/native":/native -w /native hlyn-rust sh -c '
        set -e
        cargo clippy --all-targets -- -D warnings
        cargo audit
        cargo deny check
        cd report
        cargo clippy --lib -- -D warnings
        cargo audit
        cargo deny check --config ../deny.toml
    '
}

case "$what" in
    python) run_python ;;
    rust) run_rust ;;
    all) run_python; run_rust ;;
    *) echo "usage: $0 [python|rust]" >&2; exit 2 ;;
esac
