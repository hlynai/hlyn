#!/bin/sh
# Plant one bug in src/hlyn/procns.py, run tests/test_proc.py in the Linux test bed, restore the file.
# Usage: sh tools/hostlab/plant.sh disabled|visible|subset|forward|twice
root=$(cd "$(dirname "$0")/../.." && pwd)
f=$root/src/hlyn/procns.py
cp "$f" "$f.good"
case "$1" in
disabled) sed -i.bak 's/    if not possible():/    if True or not possible():/' "$f" ;;
visible) sed -i.bak 's/^            _hide()$/            pass/' "$f" ;;
subset) sed -i.bak 's/b"subset=pid"/None/' "$f" ;;
twice) sed -i.bak "s/info.si_code != _SI_KERNEL:/True:/" "$f" ;;
forward) sed -i.bak 's/                os.kill(command, info.si_signo)/                pass/' "$f" ;;
esac
rm -f "$f.bak"
cmp -s "$f" "$f.good" && echo "PLANT DID NOT CHANGE THE FILE"
"$root/tools/linuxtest.sh" -vv -rA -s tests/test_proc.py 2>&1 | grep -E "^(PASSED|FAILED)|passed|failed|Ctrl-C heard" | cut -c1-200
mv "$f.good" "$f"
