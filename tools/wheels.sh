#!/bin/sh
# Build the wheels PyPI accepts, and prove each one works after installing.
#
#   tools/wheels.sh            both Linux architectures, plus the sdist
#   tools/wheels.sh aarch64    one architecture
#
# Linux wheels are built inside the manylinux_2_28 images, the standard way
# to make a wheel that installs on every glibc-based distribution from 2018
# on, and `auditwheel repair` checks every shared library in them against
# that promise and stamps the tag. A plain `linux_aarch64` wheel, which is
# what `python -m build` makes anywhere else, is refused by PyPI.
#
# x86_64 is built and tested under emulation on an arm64 machine, so it is
# slow; the result is the same wheel a native build would make.
#
# The macOS wheel is pure Python and is built on a Mac with `python -m build`.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist"
arches=${1:-"aarch64 x86_64"}
mkdir -p "$out"

for arch in $arches; do
    case "$arch" in
        aarch64) platform=linux/arm64 ;;
        x86_64) platform=linux/amd64 ;;
        *) echo "unknown architecture: $arch (use aarch64 or x86_64)" >&2; exit 2 ;;
    esac

    echo "=== building for $arch"
    docker run --rm --platform "$platform" -v "$root":/work:ro -v "$out":/out \
        "quay.io/pypa/manylinux_2_28_$arch" sh -c '
        set -e
        curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal >/dev/null
        . "$HOME/.cargo/env"
        py=/opt/python/cp312-cp312/bin/python
        $py -m pip install -q build auditwheel
        cp -a /work /build && cd /build
        rm -rf dist native/target native/report/target src/hlyn/core/*.so
        $py -m build --wheel 2>&1 | tail -1
        $py -m auditwheel repair --wheel-dir /tmp/fixed dist/*.whl 2>&1 | tail -1
        cp /tmp/fixed/*.whl /out/
    '

    wheel=$(ls -t "$out"/hlyn-*manylinux*"$arch".whl | head -1)

    # Emulated programs run on this machine's kernel through a translation
    # layer that does not pass Landlock through, so the boundary cannot be
    # tested here. What can be: the wheel installs, and hlyn says it cannot
    # confine rather than pretending it did.
    native=$(docker info --format '{{.Architecture}}')
    if [ "$native" != "$arch" ]; then
        echo "=== $(basename "$wheel"): emulated here, so checking install and fail-closed only"
        docker run --rm --platform "$platform" -v "$out":/dist:ro python:3.13-slim sh -c '
            set -e
            python3 -m venv /v && /v/bin/pip install -q /dist/'"$(basename "$wheel")"' 2>/dev/null
            /v/bin/hlyn --version
            if /v/bin/hlyn probe >/dev/null; then echo "probe claimed it can confine under emulation" >&2; exit 1; fi
            /v/bin/python -c "
import hlyn
try:
    hlyn.on(log=False)
    raise SystemExit(\"sealed under emulation: that should be impossible\")
except hlyn.Error as e:
    print(\"    refuses to run unconfined:\", type(e).__name__)
"
        '
        echo "    enforcement on $arch still needs a real $arch Linux machine (CI)"
        continue
    fi

    echo "=== testing $(basename "$wheel") on three distributions"
    for image in python:3.10-slim python:3.13-slim ubuntu:24.04; do
        docker run --rm --platform "$platform" -v "$out":/dist:ro "$image" sh -c '
            set -e
            if ! command -v python3 >/dev/null; then
                apt-get update -qq && apt-get install -y -qq python3 python3-venv libseccomp2 >/dev/null
            else
                apt-get update -qq && apt-get install -y -qq libseccomp2 >/dev/null
            fi
            python3 -m venv /v && /v/bin/pip install -q /dist/'"$(basename "$wheel")"'
            cd /
            /v/bin/hlyn probe >/dev/null || { /v/bin/hlyn probe; exit 1; }
            /v/bin/python -c "
import hlyn
hlyn.on(read=[\"/etc/hostname\"], log=False)
try:
    open(\"/etc/shadow\", \"rb\").read()
    raise SystemExit(\"did not confine\")
except (PermissionError, FileNotFoundError):
    pass
"
            /v/bin/hlyn run --no-log --json -- /v/bin/python -c "open(\"/etc/shadow\")" 2>&1 >/dev/null \
                | grep -q "\"target\": \"/etc/shadow\"" || { echo "does not report" >&2; exit 1; }
            echo "    '"$image"': confines and reports"
        '
    done
done

echo "=== sdist, built from and installed from source"
docker run --rm -v "$root":/work:ro -v "$out":/out rust:1-slim-bookworm sh -c '
    set -e
    apt-get update -qq && apt-get install -y -qq python3 python3-venv libseccomp2 >/dev/null
    python3 -m venv /v && /v/bin/pip install -q build
    cp -a /work /build && cd /build && rm -rf dist native/target native/report/target src/hlyn/core/*.so
    /v/bin/python -m build --sdist 2>&1 | tail -1
    /v/bin/pip install -q dist/*.tar.gz
    cd / && /v/bin/hlyn run --no-log --json -- /v/bin/python -c "open(\"/etc/shadow\")" 2>&1 >/dev/null \
        | grep -q "\"target\": \"/etc/shadow\"" && echo "    sdist: builds, confines and reports"
    cp /build/dist/*.tar.gz /out/
'
ls -la "$out"
