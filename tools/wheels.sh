#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
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
# Everything that decides what ends up in a wheel is pinned -- the build
# images by digest, the Rust toolchain, `build` and `auditwheel` -- so the
# same commit builds the same wheel. Bump them deliberately, here.
#
# An architecture that is not this machine's is built under emulation, where
# the boundary itself cannot be exercised (emulated programs do not reach
# Landlock); for it, the wheel is checked to install and to refuse to run
# rather than pretend. Its enforcement needs a real machine of that kind.
#
# The macOS wheel is pure Python and is built on a Mac with `python -m build`.
set -eu

RUST=1.98.1
BUILD=1.6.1
AUDITWHEEL=6.8.2
IMAGE_aarch64=quay.io/pypa/manylinux_2_28_aarch64@sha256:08d390027dfe5b92f66f47bfe9d9a2703fa1c096d8c9d0f5f38771c24c3924d4
IMAGE_x86_64=quay.io/pypa/manylinux_2_28_x86_64@sha256:2394d7b597cb186bc1e9da06543ec1e2a97533a2e1a5ce739c65e755571de7bd

# Where each wheel must install, confine, report and reach HTTPS. Two C
# library generations, two package families (Debian's and Fedora's CA
# layout differ), and the oldest and newest supported Python.
DISTROS="python:3.10-slim python:3.14-slim ubuntu:24.04 fedora:42"

# The only files a wheel may contain, and the only libraries its two shared
# objects may link against. Anything else is a packaging mistake.
EXPECTED='hlyn/__init__.py hlyn/cli.py hlyn/core/__init__.py hlyn/core/landlock.py hlyn/core/libhlyn.so
hlyn/core/libhlyn_report.so hlyn/core/linux.py hlyn/core/mac.py hlyn/core/none.py hlyn/core/oslog.py
hlyn/core/preload.py hlyn/core/seccomp.py hlyn/error.py hlyn/interpreter.py hlyn/jail.py hlyn/log.py
hlyn/policy.py hlyn/py.typed hlyn/report.py hlyn/secret.py hlyn/spec.py hlyn/watch.py'
LINKS='libc.so.6 libgcc_s.so.1 libdl.so.2 libpthread.so.0 libm.so.6 librt.so.1 ld-linux-aarch64.so.1 ld-linux-x86-64.so.2'

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist"
arches=${1:-"aarch64 x86_64"}
native=$(docker info --format '{{.Architecture}}')
mkdir -p "$out"

for arch in $arches; do
    case "$arch" in
        aarch64) platform=linux/arm64; image=$IMAGE_aarch64 ;;
        x86_64) platform=linux/amd64; image=$IMAGE_x86_64 ;;
        *) echo "unknown architecture: $arch (use aarch64 or x86_64)" >&2; exit 2 ;;
    esac
    rm -f "$out"/hlyn-*"$arch".whl  # never test a wheel left over from an earlier run

    echo "=== building for $arch"
    docker run --rm --platform "$platform" -v "$root":/work:ro -v "$out":/out \
        -e RUST="$RUST" -e BUILD="$BUILD" -e AUDITWHEEL="$AUDITWHEEL" -e EXPECTED="$EXPECTED" -e LINKS="$LINKS" \
        "$image" sh -c '
        set -e
        curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$RUST" >/dev/null
        . "$HOME/.cargo/env"
        py=/opt/python/cp312-cp312/bin/python
        $py -m pip install -q "build==$BUILD" "auditwheel==$AUDITWHEEL"
        cp -a /work /build && cd /build
        rm -rf dist native/target native/report/target src/hlyn/core/*.so
        $py -m build --wheel 2>&1 | tail -1
        $py -m auditwheel repair --wheel-dir /tmp/fixed dist/*.whl 2>&1 | tail -1
        wheel=$(ls /tmp/fixed/*.whl)

        # Exactly the expected files, nothing grafted in, nothing missing.
        $py - "$wheel" <<EOF
import os, sys, zipfile
names = sorted(n for n in zipfile.ZipFile(sys.argv[1]).namelist() if not n.startswith("hlyn-") and not n.endswith("/"))
want = sorted(os.environ["EXPECTED"].split())
if names != want:
    print("unexpected wheel contents:", set(names) ^ set(want)); sys.exit(1)
print("    contents: the", len(want), "expected files")
EOF
        # And each library links only against the C library and its friends.
        mkdir /tmp/x && cd /tmp/x && $py -m zipfile -e "$wheel" . >/dev/null
        for so in hlyn/core/*.so; do
            for need in $(readelf -d "$so" | sed -n "s/.*Shared library: \[\(.*\)\]/\1/p"); do
                case " $LINKS " in *" $need "*) ;; *) echo "$so links $need, which a wheel cannot promise" >&2; exit 1 ;; esac
            done
        done
        echo "    links: glibc only"
        cp "$wheel" /out/
    '

    wheel=$(ls "$out"/hlyn-*manylinux*"$arch".whl)
    name=$(basename "$wheel")

    if [ "$native" != "$arch" ]; then
        echo "=== $name: emulated here, so checking install and fail-closed only"
        docker run --rm --platform "$platform" -v "$out":/dist:ro python:3.13-slim sh -c '
            set -e
            python3 -m venv /v && /v/bin/pip install -q /dist/'"$name"' 2>/dev/null
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
        echo "    enforcement on $arch still needs a real $arch Linux machine"
        continue
    fi

    echo "=== testing $name"
    for distro in $DISTROS; do
        docker run --rm --platform "$platform" -v "$out":/dist:ro "$distro" sh -c '
            set -e
            if command -v dnf >/dev/null; then
                dnf install -y -q python3 libseccomp >/dev/null 2>&1
            else
                apt-get update -qq >/dev/null
                apt-get install -y -qq libseccomp2 ca-certificates >/dev/null 2>&1
                command -v python3 >/dev/null || apt-get install -y -qq python3 python3-venv >/dev/null 2>&1
            fi
            python3 -m venv /v && /v/bin/pip install -q /dist/'"$name"' 2>/dev/null
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
            https="import urllib.request; print(urllib.request.urlopen(\"https://example.com\", timeout=10).status)"
            if /v/bin/python -c "$https" >/dev/null 2>&1; then
                got=$(/v/bin/hlyn run --no-log --no-report --net 443 -- /v/bin/python -c "$https" 2>&1 | tail -1)
                [ "$got" = 200 ] || { echo "HTTPS under --net 443 failed: $got" >&2; exit 1; }
                net="and reaches HTTPS on --net 443"
            else
                net="(no internet here, HTTPS not checked)"
            fi
            echo "    '"$distro"': confines, reports, $net"
        '
    done
done

echo "=== sdist, built from and installed from source"
rm -f "$out"/hlyn-*.tar.gz
docker run --rm -v "$root":/work:ro -v "$out":/out "rust:$RUST-slim-bookworm" sh -c '
    set -e
    apt-get update -qq && apt-get install -y -qq python3 python3-venv libseccomp2 >/dev/null
    python3 -m venv /v && /v/bin/pip install -q "build=='"$BUILD"'"
    cp -a /work /build && cd /build && rm -rf dist native/target native/report/target src/hlyn/core/*.so
    /v/bin/python -m build --sdist 2>&1 | tail -1
    /v/bin/pip install -q dist/*.tar.gz
    cd / && /v/bin/hlyn run --no-log --json -- /v/bin/python -c "open(\"/etc/shadow\")" 2>&1 >/dev/null \
        | grep -q "\"target\": \"/etc/shadow\"" || { echo "the sdist build does not report" >&2; exit 1; }
    echo "    sdist: builds from source, confines and reports"
    cp /build/dist/*.tar.gz /out/
'
ls -la "$out"
