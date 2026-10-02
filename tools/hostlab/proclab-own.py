# Option (b) of the /proc lab: the command's own /proc/PID only (cli._own), as `hlyn claude` grants it.
# Usage (in the Linux test bed, as uid 1000): python3 proclab-own.py LAUNCHER_PID
import os
import sys

from hlyn import cli
from hlyn.policy import Policy

plan = Policy(read=("/w/tools/hostlab",))
sys.exit(cli._launch(["python3", "/w/tools/hostlab/proclab-inner.py", sys.argv[1]], plan, own=True))
