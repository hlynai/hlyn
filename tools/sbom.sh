#!/bin/sh
# What is actually in the thing you are about to trust.
#
#   tools/sbom.sh            an SBOM for what ships, into dist/
#   tools/sbom.sh --all      include the development trees as well
#
# One document, not two. Syft reads `native/Cargo.lock` and the Python package
# metadata in the same pass, so a single scan covers both ecosystems and a
# second one would mostly restate the first.
#
# What is *excluded* is the part worth reading. `native/fuzz` has its own
# lockfile pulling in libFuzzer's machinery -- `arbitrary`, `derive_arbitrary`
# and their tree -- which is roughly twice the crate count of the shipped shim
# and appears in no build that leaves this repository. An SBOM listing it
# describes a supply chain nobody has, which is a worse answer than no SBOM at
# all: the whole point of the document is that its reader can act on it.
#
# CycloneDX rather than SPDX for the output: it carries dependency
# relationships and most scanners ingest it without conversion.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist"
mkdir -p "$out"

# Pinned to a version rather than :latest, so a rebuild next year does not
# quietly produce a different document from a different tool.
SYFT=anchore/syft:v1.18.1

# Build artefacts, the repository's own history, and the fuzzing harness. The
# last of these is the one that matters; see above.
skip="--exclude ./native/target --exclude ./dist --exclude ./.git"
if [ "${1:-}" = "--all" ]; then
    name=hlyn-everything
else
    name=hlyn
    skip="$skip --exclude ./native/fuzz"
fi

# shellcheck disable=SC2086 # skip is a list of flags and must word-split
docker run --rm -v "$root":/src:ro -v "$out":/out \
    "$SYFT" scan dir:/src --source-name hlyn --source-version "$(
        sed -n 's/^version = "\(.*\)"/\1/p' "$root/pyproject.toml" | head -1
    )" -o "cyclonedx-json=/out/$name.cdx.json" $skip

echo "wrote $out/$name.cdx.json"
