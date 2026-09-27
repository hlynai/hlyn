#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run the test suite, or any command, on a real Linux kernel with both native
# crates built from this tree.
#
#   tools/linuxtest.sh                         the whole suite, verbose
#   tools/linuxtest.sh tests/test_escape.py    pytest arguments
#   tools/linuxtest.sh --sh 'CMD'              a shell command after the build
#
# The tree is copied into the container, so the run sees exactly the files as
# they are now and never writes back. Uses Docker Desktop's VM on a Mac (Linux
# 6.12, aarch64, Landlock ABI 6, no Yama). Output is printed in full.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -f "$root/tools/Dockerfile.linuxtest" -t hlyn-linuxtest "$root/tools" >/dev/null

if [ "${1:-}" = "--sh" ]; then
    shift
    run="$*"
else
    run="python3 -m pytest -vv -rA -p no:cacheprovider ${*:-tests}"
fi

exec docker run --rm --privileged --security-opt seccomp=unconfined \
    -v "$root":/work:ro -v hlyn-cargo:/usr/local/cargo/registry \
    -e PYTHONPATH=/w/src -e PYTHONDONTWRITEBYTECODE=1 hlyn-linuxtest sh -c "
set -e
cp -a /work /w && cd /w && rm -rf native/target native/report/target src/hlyn/core/*.so
(cd native && cargo build -q --release) && (cd native/report && cargo build -q --release)
echo \"== kernel \$(uname -r), \$(python3 -V)\"
$run"
