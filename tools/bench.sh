#!/bin/sh
# Measure what confinement costs, on a kernel that has Landlock.
#
#   tools/bench.sh          both halves
#   tools/bench.sh seal     startup cost only
#   tools/bench.sh calls    steady-state cost only
#
# See tools/bench.py for the method. The container is the same test bed the
# suite uses, so the numbers describe the same kernel the tests prove things
# about. They are not a claim about any other machine: a benchmark run on a
# laptop under a virtualised kernel is a lower bound on how good the news is,
# not a datasheet.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

docker build -q -t hlyn-test "$root/tools" >/dev/null

# One CPU, so the samples cannot be spread across cores mid-measurement, and
# --init because this forks a process per sample and someone has to reap them.
docker run --rm --init --cpuset-cpus=0 \
    -v "$root":/work -w /work hlyn-test \
    python tools/bench.py "$@"
