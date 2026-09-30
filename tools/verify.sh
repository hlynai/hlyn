#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Check that hlyn really confines on this machine, and write a report to send back.
#
# Put this script in a folder together with the two files you were given:
#     hlyn-<version>-py3-none-manylinux_2_28_<arch>.whl
#     hlyn-<version>.tar.gz
# then run, as your normal user (no sudo):
#     sh verify.sh
#
# What it does:
#   - makes a throwaway Python environment in a temporary folder
#   - installs the wheel there (nothing is installed system-wide)
#   - runs hlyn's full test suite against it: ~500 checks, most of them
#     attempts to escape the environment, each of which must fail
#   - deletes the temporary folder
#   - writes hlyn-report.txt next to this script
#
# What the report contains: the CPU type, kernel version, distribution name,
# Python version and the test results. No hostname, username, IP address,
# files or environment variables.
#
# It needs internet once, to download the test tools (pytest, hypothesis).
set -u

here=$(cd "$(dirname "$0")" && pwd)
report="$here/hlyn-report.txt"
work=$(mktemp -d "${TMPDIR:-/tmp}/hlyn-verify.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

say() { echo "$*"; echo "$*" >> "$report"; }
: > "$report"

say "hlyn verification report"
say "========================"
say "date:     $(date -u '+%Y-%m-%d %H:%M UTC')"
say "machine:  $(uname -m)"
say "kernel:   $(uname -r)"
say "distro:   $( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown)"

# -- what is needed, checked before anything is done ------------------------

fail() { say ""; say "STOPPED: $*"; exit 1; }

[ "$(uname -s)" = Linux ] || fail "this is for Linux; this machine runs $(uname -s)."

py=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        py=$(command -v "$candidate"); break
    fi
done
[ -n "$py" ] || fail "Python 3.10 or newer with the venv module is needed.
  Debian/Ubuntu: sudo apt install python3 python3-venv
  Fedora/RHEL:   sudo dnf install python3"
say "python:   $("$py" -c 'import sys; print(sys.version.split()[0])') ($py)"

arch=$(uname -m)
wheel=$(ls "$here"/hlyn-*-manylinux*_"$arch".whl 2>/dev/null | head -1)
sdist=$(ls "$here"/hlyn-*.tar.gz 2>/dev/null | head -1)
[ -n "$wheel" ] || fail "no hlyn wheel for $arch next to this script (looked for hlyn-*-manylinux*_$arch.whl)."
[ -n "$sdist" ] || fail "no hlyn source package (hlyn-*.tar.gz) next to this script; it holds the tests."
say "wheel:    $(basename "$wheel")"

"$py" -c 'import ctypes.util, sys; sys.exit(ctypes.util.find_library("seccomp") is None)' \
    || fail "libseccomp is not installed.
  Debian/Ubuntu: sudo apt install libseccomp2
  Fedora/RHEL:   sudo dnf install libseccomp"

[ "$(id -u)" = 0 ] && say "note:     running as root; a few permission tests are skipped as root"

# -- install --------------------------------------------------------------

say ""
say "installing into a temporary environment..."
"$py" -m venv "$work/venv" || fail "could not create a virtual environment."
pip="$work/venv/bin/pip"
hpy="$work/venv/bin/python"
"$pip" install -q --disable-pip-version-check "$wheel" "pytest>=8" "hypothesis>=6" >"$work/pip.log" 2>&1 \
    || { cat "$work/pip.log" >> "$report"; fail "installing failed (details above)."; }
tar xzf "$sdist" -C "$work" || fail "could not unpack $(basename "$sdist")."
src=$(ls -d "$work"/hlyn-*/ | head -1)
lib=$("$hpy" -c 'import hlyn, os; print(os.path.join(os.path.dirname(hlyn.__file__), "core"))')

# -- what the machine can do ----------------------------------------------

say ""
say "hlyn probe:"
"$work/venv/bin/hlyn" probe >> "$report" 2>&1
probe=$?
"$work/venv/bin/hlyn" probe
if [ $probe -ne 0 ]; then
    say ""
    say "RESULT: hlyn cannot confine programs on this machine (see probe above)."
    say "That is hlyn refusing correctly, not a failure -- but it means this machine cannot test it."
    exit 1
fi

# -- the checks -----------------------------------------------------------

say ""
say "a confined program, end to end:"
bad=0
# A file this user can read, which the default policy does not grant. (Not
# /etc/shadow: a normal user cannot read that anyway, and hlyn rightly does
# not report a refusal that was not its own.)
echo "not for the agent" > "$work/outside.txt"
out=$(cd "$work" && "$work/venv/bin/hlyn" run --no-log -- "$hpy" -c "open('$work/outside.txt')" 2>&1)
case "$out" in
    *"hlyn blocked"*"outside.txt"*"allow with --read"*) say "  ok    reading a file outside the policy was blocked and reported" ;;
    *) bad=1; say "  FAIL  expected the read to be blocked and reported, got:"; say "$out" ;;
esac
https='import urllib.request; print(urllib.request.urlopen("https://example.com", timeout=10).status)'
if "$hpy" -c "$https" >/dev/null 2>&1; then
    got=$(cd "$work" && "$work/venv/bin/hlyn" run --no-log --no-report --net 443 -- "$hpy" -c "$https" 2>&1 | tail -1)
    if [ "$got" = 200 ]; then say "  ok    HTTPS works under --net 443"; else bad=1; say "  FAIL  HTTPS under --net 443 gave: $got"; fi
    got=$(cd "$work" && "$work/venv/bin/hlyn" run --no-log --no-report -- "$hpy" -c "$https" 2>&1 | tail -1)
    case "$got" in 200) bad=1; say "  FAIL  HTTPS worked with the network closed" ;; *) say "  ok    the network is closed by default" ;; esac
else
    say "  skip  no internet here, so HTTPS was not checked"
fi

say ""
say "the full test suite (this takes about a minute):"
cd "$src" || fail "the source package did not unpack as expected."
HLYN_SHIM="$lib/libhlyn.so" "$hpy" -m pytest tests -q -o addopts="" -p no:cacheprovider \
    >"$work/pytest.log" 2>&1
tests=$?
tail -40 "$work/pytest.log" >> "$report"
tail -3 "$work/pytest.log"

say ""
if [ $tests -eq 0 ] && [ $bad -eq 0 ]; then
    say "RESULT: PASSED -- hlyn confines programs on this machine."
    status=0
else
    say "RESULT: FAILED -- see above."
    status=1
fi
say ""
say "Please send back: $report"
exit $status
