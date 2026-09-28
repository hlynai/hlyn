#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# `hlyn watch` on the tool calls an agent makes (REMAINING part 1 #21): each
# workload runs once unconfined under `hlyn watch`, which drafts a policy,
# then again from a clean state under `hlyn run -f` with that draft. Prints
# every draft, the confined run's result and its report.
#
#   tools/linuxtest.sh --sh 'sh tools/hostlab/watchlab.sh'
set -u
(apt-get update -qq && apt-get install -y -qq python3-venv git nodejs npm) >/dev/null 2>&1
H="python3 -m hlyn.cli"
# A project folder, not under /tmp: the draft leaves the temp folder out,
# since every policy gets a private one.
work=$HOME/watchlab; rm -rf $work; mkdir -p $work
one() {  # name, reset command, workload command...
    name=$1; reset=$2; shift 2
    echo; echo "######## $name: $*"
    sh -c "$reset"
    $H watch -- "$@" > $work/$name.toml 2>$work/$name.watch.err
    echo "-- draft ($(grep -c . $work/$name.toml) lines):"; cat $work/$name.toml
    sh -c "$reset"
    $H run --no-log -f $work/$name.toml -- "$@" > $work/$name.out 2>&1
    code=$?
    echo "-- confined run: exit $code"; tail -8 $work/$name.out
}

mkdir -p $work/proj && cd $work/proj
python3 -m venv .venv >/dev/null
one pip "rm -rf .venv/lib/python3*/site-packages/six*" .venv/bin/pip install -q --no-cache-dir six

one npm "rm -rf node_modules package-lock.json package.json" npm install --no-fund --no-audit left-pad

one git "rm -rf markupsafe" git clone -q --depth 1 https://github.com/pallets/markupsafe

mkdir -p data out && echo "hello" > data/in.txt
cat > agent.py <<'PY'
import json, pathlib, subprocess, urllib.request
text = pathlib.Path("data/in.txt").read_text()
status = urllib.request.urlopen("https://pypi.org/simple/six/", timeout=20).status
listing = subprocess.run(["ls", "data"], capture_output=True, text=True).stdout.split()
pathlib.Path("out/report.json").write_text(json.dumps({"text": text.strip(), "status": status, "files": listing}))
print("agent done:", pathlib.Path("out/report.json").read_text())
PY
one agent "rm -f out/report.json" python3 agent.py
