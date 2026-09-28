#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Capture every packet that leaves the machine while test files run, one file
# at a time, and list where each went (REMAINING part 1 #17; DESIGN-host-
# allowlisting.md section 9: "no packet to a destination not on the list").
#
#   tools/linuxtest.sh --sh 'sh tools/capture.sh [TEST FILE ...]'
#
# Loopback is left out: that is where the agent meets the proxy. What leaves
# is the proxy's own lookups and connections, and anything that escaped.
# Prints, per test file: each DNS name asked for, and each TCP/UDP/ICMP
# destination with its packet count. Needs root (tcpdump), as in the
# linuxtest container.
set -eu
files=${*:-tests/test_escape.py tests/test_guard.py tests/test_hostmode.py tests/test_unixgate.py tests/test_seccomp.py tests/test_landlock.py tests/test_jail.py tests/test_proxy.py}
command -v tcpdump >/dev/null || (apt-get update -qq && apt-get install -y -qq tcpdump >/dev/null)
dev=$(ip -o route show default | awk '{print $5; exit}')
out=$(mktemp -d)
echo "== capturing on $dev (loopback excluded)"
for f in $files; do
    name=$(basename "$f" .py)
    tcpdump -i "$dev" -n -l -tt 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0 or udp or icmp or icmp6 or (ip6 and tcp)' \
        >"$out/$name.pcap.txt" 2>"$out/$name.err" &
    cap=$!
    sleep 1
    python3 -m pytest -q -p no:cacheprovider "$f" >"$out/$name.pytest.txt" 2>&1 || true
    sleep 1
    kill "$cap" 2>/dev/null || true
    wait "$cap" 2>/dev/null || true
    echo
    echo "== $f: $(tail -1 "$out/$name.pytest.txt")"
    echo "   DNS names asked:"
    grep -oE '(A|AAAA|HTTPS)\? [^ ]+' "$out/$name.pcap.txt" | sort | uniq -c | sed 's/^/     /' || true
    echo "   destinations (not DNS):"
    grep -vE '\.53: |\.53 >' "$out/$name.pcap.txt" | awk '{print $2, $5}' | sed 's/:$//' \
        | awk '{print $1, $2}' | sort | uniq -c | sort -rn | sed 's/^/     /' || true
done
echo
echo "== raw captures: $out"
