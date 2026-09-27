#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build the distributable, and prove the result actually confines.
#
# Building a wheel is not the interesting part. The interesting part is that an
# *installed* copy still enforces: `landlock.py` looks for the shim beside the
# package and then falls back to a build tree, so a wheel that forgot to carry
# it works perfectly in the source directory and refuses to confine anywhere
# else. That is the failure this checks for, by installing into a clean prefix
# and running a real escape attempt from a directory with no source in it.
#
# Wheels land in dist/ and are tagged py3-none-<platform>: the shim is loaded
# through ctypes and links against nothing in libpython, so one wheel serves
# every supported Python on that platform.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

# Needs cargo for the shim and Python for the wheel, which is the rust image.
docker build -q -f "$root/tools/Dockerfile.rust" -t hlyn-rust "$root" >/dev/null

docker run --rm -v "$root":/work:ro -v "$root/dist":/out hlyn-rust sh -c '
    set -e
    apt-get update -qq && apt-get install -y -qq python3 python3-venv libseccomp2 >/dev/null 2>&1
    python3 -m venv /venv && /venv/bin/pip install -q build

    cp -a /work /build && cd /build
    rm -rf dist src/hlyn/core/libhlyn.so src/hlyn/core/libhlyn_report.so
    /venv/bin/python -m build 2>&1 | tail -2

    /venv/bin/pip install -q dist/*.whl
    cd /
    /venv/bin/python -c "
import hlyn
hlyn.on(read=[\"/etc/hostname\"])
try:
    open(\"/etc/shadow\", \"rb\").read()
    raise SystemExit(\"the installed wheel did not confine\")
except (PermissionError, FileNotFoundError):
    pass
assert open(\"/etc/hostname\").read()
" 2>/dev/null
    echo "the installed wheel confines"
    # And explains: the reporter shipped too, and `hlyn run` hears through it.
    /venv/bin/hlyn run --no-log --json -- /venv/bin/python -c "open(\"/etc/shadow\")" 2>&1 >/dev/null \
        | grep -q "\"target\": \"/etc/shadow\"" || { echo "the installed wheel cannot report" >&2; exit 1; }
    echo "the installed wheel reports what it blocked"
    cp /build/dist/* /out/
'

ls -la "$root/dist"
