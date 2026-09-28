#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Fuzz each untrusted-bytes parser for SECONDS (default 60), one after another.
#
#   tools/linuxtest.sh --sh 'sh tools/fuzzproxy.sh 600'
#
# Installs atheris into a scratch venv (it builds with clang). A crash stops
# that target, prints the input, and leaves it as crash-* in the working
# folder; the script then exits non-zero. See tools/fuzzproxy.py.
set -eu
seconds=${1:-60}
if ! [ -x /tmp/fuzzvenv/bin/python ]; then
    (apt-get update -qq && apt-get install -y -qq python3-venv python3-dev clang g++) >/dev/null 2>&1
    python3 -m venv /tmp/fuzzvenv
    /tmp/fuzzvenv/bin/pip install -q atheris
fi
failed=0
for target in header head hello sockaddr; do
    echo "== $target, $seconds s"
    mkdir -p "/tmp/corpus-$target"
    status=0
    /tmp/fuzzvenv/bin/python tools/fuzzproxy.py "$target" "/tmp/corpus-$target" \
        -max_total_time="$seconds" -timeout=5 -rss_limit_mb=2048 -print_final_stats=1 \
        >"/tmp/fuzz-$target.log" 2>&1 || status=$?
    grep -E "^#[0-9]+[[:space:]]+(DONE|NEW)|stat::|ERROR|Error|crash-|Traceback|Assertion|==[0-9]+==" \
        "/tmp/fuzz-$target.log" | tail -12
    # Any way a run can end badly: a non-zero exit, a saved crash, timeout,
    # out-of-memory or leak input, or no DONE line (it never really ran).
    if [ "$status" -ne 0 ] || ls crash-* timeout-* oom-* leak-* >/dev/null 2>&1 \
            || ! grep -q "DONE" "/tmp/fuzz-$target.log"; then
        echo "!! $target failed (exit $status):"; ls crash-* timeout-* oom-* leak-* 2>/dev/null
        tail -30 "/tmp/fuzz-$target.log"; failed=1; break
    fi
done
exit $failed
