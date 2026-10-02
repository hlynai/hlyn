#!/bin/sh
# On the Mac: run the /proc lab in the Linux test bed. $1 = the grant under test
# (`hlyn run` arguments, or `own` for cli._own, or `ns` for the namespace sketch);
# $2 = `root` to run as root instead of uid 1000.
root=$(cd "$(dirname "$0")/../.." && pwd)
who=
[ "${2:-}" = root ] && who="AS= "
exec "$root/tools/linuxtest.sh" --sh "${who}GRANT='$1' sh tools/hostlab/proclab.sh"
