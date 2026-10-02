#!/bin/sh
# Lab for REMAINING #16l item 3: what a confined program reads under /proc.
# Run from the Mac:  sh tools/hostlab/proclab-run.sh '--read /proc --read /w/tools/hostlab'
#                    sh tools/hostlab/proclab-run.sh own
# $GRANT = the `hlyn run` arguments for the grant under test, or `own` for cli._own.
useradd -m -u 1000 u 2>/dev/null
chmod -R a+rX /w
cd /w
# AS= runs as root; the default is an ordinary user (uid 1000).
AS=${AS-setpriv --reuid=1000 --regid=1000 --clear-groups}
if [ "$GRANT" = ns ]; then
    $AS env SECRET_TOKEN=hunter2 sh -c "python3 /w/tools/hostlab/proclab-ns.py \$\$" 2>&1
elif [ "$GRANT" = own ]; then
    $AS env SECRET_TOKEN=hunter2 sh -c 'python3 /w/tools/hostlab/proclab-own.py $$' 2>&1
else
    $AS env SECRET_TOKEN=hunter2 sh -c "python3 -m hlyn.cli run $GRANT -- python3 /w/tools/hostlab/proclab-inner.py \$\$" 2>&1
fi
