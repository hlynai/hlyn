# SPDX-License-Identifier: Apache-2.0
"""`hlyn.on()` with a thread already running.

Linux (Landlock) confines one thread at a time, so a thread started earlier
would keep its access: hlyn refuses to seal. macOS (Seatbelt) confines the whole
process, so a running thread is confined too: hlyn seals, and the thread's own
read after the seal is denied. Each platform's promise is pinned here.
"""

from __future__ import annotations

import sys

import pytest
from conftest import boot, enforces

pytestmark = pytest.mark.skipif(not enforces(), reason="this machine can't seal (see hlyn probe)")

PROGRAM = """
import os, tempfile, threading, time
import hlyn

secret = os.path.join(tempfile.mkdtemp(), "secret.txt")
open(secret, "w").write("SECRET")
seen = {}

def worker():
    time.sleep(1)  # reads only after the seal attempt
    try:
        open(secret).read()
        seen["thread"] = "READ"
    except OSError as exc:
        seen["thread"] = f"blocked errno={exc.errno}"

thread = threading.Thread(target=worker)
thread.start()
try:
    hlyn.on(read=[], log=False)
    seen["seal"] = "sealed"
except hlyn.Error as exc:
    seen["seal"] = "refused"
thread.join()
print(seen)
"""


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt")
def test_macos_confines_a_thread_that_was_already_running():
    done = boot(PROGRAM)
    print(done.stdout, done.stderr)
    assert "'seal': 'sealed'" in done.stdout and "'thread': 'blocked" in done.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock")
def test_linux_refuses_to_seal_with_a_thread_running_so_none_keeps_its_access():
    done = boot(PROGRAM)
    print(done.stdout, done.stderr)
    assert "'seal': 'refused'" in done.stdout and "'thread': 'READ'" in done.stdout  # nothing was sealed
