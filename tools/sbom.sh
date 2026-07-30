#!/bin/sh
# What is in the thing you are about to trust.
#
#   tools/sbom.sh          both, into dist/
#   tools/sbom.sh rust     the shim's dependency tree only
#   tools/sbom.sh python   the package only
#
# Two SBOMs because there are two dependency trees and they are built by
# different toolchains. The Python package depends on nothing at runtime, which
# is itself the interesting fact and worth having stated in a machine-readable
# file rather than asserted in a README. The Rust shim depends on the landlock
# crate and what it pulls in, which is where the real supply chain is.
#
# CycloneDX rather than SPDX for the output: it carries dependency
# relationships and is what most scanners ingest without conversion.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
what=${1:-all}
out="$root/dist"
mkdir -p "$out"

# Pinned by digest-free tag rather than :latest, so a rebuild a year from now
# does not silently produce a different document from a different tool.
SYFT=anchore/syft:v1.18.1

run_rust() {
    echo "=== rust dependencies ==="
    docker build -q -f "$root/tools/Dockerfile.rust" -t hlyn-rust "$root" >/dev/null
    # cargo-cyclonedx reads the lockfile, so this describes what actually gets
    # compiled in rather than what the manifest permits.
    docker run --rm -v "$root/native":/native -w /native hlyn-rust sh -c '
        cargo install --quiet cargo-cyclonedx 2>/dev/null || true
        cargo cyclonedx --format json --all
    '
    find "$root/native" -name "*.cdx.json" -exec cp {} "$out/" \;
    echo "wrote $out/*.cdx.json"
}

run_python() {
    echo "=== python package ==="
    docker run --rm -v "$root":/src:ro -v "$out":/out \
        "$SYFT" scan dir:/src -o cyclonedx-json=/out/hlyn-python.cdx.json \
        --exclude './native/target' --exclude './dist' --exclude './.git'
    echo "wrote $out/hlyn-python.cdx.json"
}

case "$what" in
    rust) run_rust ;;
    python) run_python ;;
    all) run_python; run_rust ;;
    *) echo "usage: $0 [rust|python]" >&2; exit 2 ;;
esac
