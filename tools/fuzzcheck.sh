#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Check the fuzzer can fail: plant one known bug in each parser, in a copy,
# and confirm tools/fuzzproxy.py finds it within SECONDS (default 120).
# A target that misses its planted bug has a check that can't fail.
#
#   tools/linuxtest.sh --sh 'sh tools/fuzzcheck.sh 120'
set -eu
seconds=${1:-120}
harness=${HARNESS:-tools/fuzzproxy.py}
if ! [ -x /tmp/fuzzvenv/bin/python ]; then
    (apt-get update -qq && apt-get install -y -qq python3-venv python3-dev clang g++) >/dev/null 2>&1
    python3 -m venv /tmp/fuzzvenv
    /tmp/fuzzvenv/bin/pip install -q atheris
fi
plant() {  # target file python-replace-old python-replace-new
    rm -rf /tmp/mut && cp -a . /tmp/mut
    python3 - "/tmp/mut/$2" "$3" "$4" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
assert text.count(old) == 1, f"planted bug's anchor not found once: {old!r}"
open(path, "w").write(text.replace(old, new))
PY
    mkdir -p /tmp/mutcorpus-$1 && rm -rf /tmp/mutcorpus-$1/* && cd /tmp/mut
    out=$(/tmp/fuzzvenv/bin/python "$harness" "$1" /tmp/mutcorpus-$1 -max_total_time="$seconds" \
          -timeout=5 2>&1) && status=0 || status=$?
    found=$(printf '%s\n' "$out" | grep -m1 -E "AssertionError|Uncaught Python exception" || true)
    cd - >/dev/null; rm -f /tmp/mut/crash-*
    if [ "$status" -ne 0 ] && [ -n "$found" ]; then
        echo "caught  $1: $5"; printf '%s\n' "$out" | grep -m1 -A1 "AssertionError" | sed 's/^/        /'
    else
        echo "MISSED  $1: $5 (exit $status)"; missed=1
    fi
}
missed=0
plant header src/hlyn/proxy.py '(port,) = struct.unpack("!H", block[10:12])' \
      '(port,) = struct.unpack("!H", block[8:10])' "reads the IPv4 source port, not the destination"
plant head src/hlyn/proxy.py 'raise Bad(f"request head over {limit} bytes")' \
      'return None' "waits for more forever past the limit"
plant hello src/hlyn/proxy.py 'if len(data) >= limit + 5 * (limit // 16384 + 2):' \
      'if len(data) >= 2 * limit + 5 * (limit // 16384 + 2):' "buffers twice the limit"
plant sockaddr src/hlyn/core/notify.py 'return Address(family, abstract=body[1:])' \
      'return Address(family, abstract=body[1:].rstrip(b"\0"))' "drops trailing NULs from an abstract name"
exit $missed
