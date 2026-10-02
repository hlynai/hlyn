#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run the test suite, or any command, on a real Linux kernel with both native
# crates built from this tree.
#
#   tools/linuxtest.sh                         the whole suite, verbose
#   tools/linuxtest.sh tests/test_escape.py    pytest arguments
#   tools/linuxtest.sh --sh 'CMD'              a shell command after the build
#   tools/linuxtest.sh --stock [...]           either, in a stock container: Docker's
#                                              own seccomp profile, not privileged,
#                                              and IPv6 off (::1 included)
#
# The tree is copied into the container, so the run sees exactly the files as
# they are now and never writes back. Uses Docker Desktop's VM on a Mac (Linux
# 6.12, aarch64, Landlock ABI 6, no Yama). Output is printed in full.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -f "$root/tools/Dockerfile.linuxtest" -t hlyn-linuxtest "$root/tools" >/dev/null

box="--privileged --security-opt seccomp=unconfined"
if [ "${1:-}" = "--stock" ]; then
    shift
    box="--sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.lo.disable_ipv6=1"
fi

if [ "${1:-}" = "--sh" ]; then
    shift
    run="$*"
else
    run="python3 -m pytest -vv -rA -p no:cacheprovider ${*:-tests}"
fi

# $box is split into words on purpose.
# shellcheck disable=SC2086
exec docker run --rm $box \
    -v "$root":/work:ro -v hlyn-cargo:/usr/local/cargo/registry \
    -e PYTHONPATH=/w/src -e PYTHONDONTWRITEBYTECODE=1 hlyn-linuxtest sh -c "
set -e
mkdir /w && (cd /work && tar --exclude=./.git --exclude=./OpenAPPA-main -cf - .) | tar -xf - -C /w && cd /w && rm -rf native/target native/report/target src/hlyn/core/*.so
(cd native && cargo build -q --release) && (cd native/report && cargo build -q --release)
echo \"== kernel \$(uname -r), \$(python3 -V), seccomp \$(grep Seccomp: /proc/self/status | cut -f2), ::1 \$(ip -6 addr show lo | grep -c ::1)\"
$run"
