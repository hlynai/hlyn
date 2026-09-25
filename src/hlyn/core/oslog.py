"""Hearing refusals on macOS: the sandbox's own reports, from the system log.

Seatbelt writes every refusal to the unified log, from the kernel, naming the
process, the operation and the path:

    Sandbox: python3(4211) deny(1) file-read-data /Users/k/.ssh/id_ed25519

Four things about reading it were found by measurement, not documentation
(see FINDINGS.md):

- **Only a live stream has them.** `log show` never returns these entries;
  `log stream` does, without root. So the stream is started before the
  command and read while it runs.
- **The stream says it is ready before it is.** It prints its header and then
  misses whatever happens in the next moments. So readiness is proven by
  writing a marker to the log and waiting to see it come back; the same
  marker, written after the command exits, proves the stream has caught up.
- **Every refusal carries our tag.** The profile's `(deny default)` is given
  `(with message TAG)`, and Seatbelt appends TAG to each report it makes --
  for the command and for every process it starts, since they inherit the
  sandbox. That scopes the stream to this run exactly, with no process-tree
  bookkeeping, and the tag is written by the kernel: the agent cannot forge a
  report from the `Sandbox` sender.
- **It is best-effort.** A few percent of reports never arrive, more when the
  log daemon is busy. When the end marker is late, the report says the list
  may be incomplete; a report that simply went missing cannot be detected.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import select
import subprocess
import time
from collections.abc import Mapping

from ..policy import Policy
from ..report import Denial

__all__ = ["Listener", "parse"]

LOG = "/usr/bin/log"
LOGGER = "/usr/bin/logger"

READY = 3.0  # seconds to wait for the stream to prove it is connected
CAUGHT = 2.0  # seconds to wait for it to catch up after the command exits

LINE = re.compile(
    r"^(?:(?P<times>\d+) duplicate reports for )?Sandbox: (?P<name>.+)\((?P<pid>\d+)\) "
    r"deny\(\d+\) (?P<op>\S+)(?: (?P<target>.*))?$"
)
ADDRESS = re.compile(r"^(?:remote|local):(?P<host>.*):(?P<port>\d+)$")

# Seatbelt reports paths after resolving them, so /etc arrives as
# /private/etc. People type the short form, and it is what they should see.
PRIVATE = ("/private/etc", "/private/tmp", "/private/var")


def short(path: str) -> str:
    """`/private/etc/hosts` as `/etc/hosts`. On macOS those are the same file."""
    for item in PRIVATE:
        if path == item or path.startswith(item + "/"):
            return path[len("/private"):]
    return path


def kind(op: str) -> str:
    """The policy field a Seatbelt operation belongs to."""
    if op.startswith("file-read"):
        return "read"
    if op.startswith("file-write"):
        return "write"
    if op.startswith("process-exec"):
        return "exec"
    if op == "network-outbound":
        return "net"
    if op in ("network-bind", "network-inbound"):
        return "bind"
    # Mach services, sysctl, shared memory, IOKit, preferences: the operating
    # system's own plumbing, which no policy field grants.
    return "system"


def parse(line: str, tag: str) -> Denial | None:
    """One refusal from one line of `log stream --style ndjson`, or None."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    message = event.get("eventMessage")
    sender = event.get("senderImagePath")
    if not isinstance(message, str) or not isinstance(sender, str):
        return None
    # Only the sandbox itself, never a process that wrote something similar.
    if not sender.endswith("/Sandbox") or event.get("processImagePath") != "/kernel":
        return None
    body, _, last = message.rpartition("\n")
    if last != tag:
        return None
    found = LINE.match(body)
    if not found:
        return None
    op = found["op"]
    target = found["target"] or ""
    what = kind(op)
    if what in ("read", "write", "exec"):
        target = short(target)
    elif what in ("net", "bind"):
        address = ADDRESS.match(target)
        if address:
            host = address["host"]
            target = address["port"] + ("" if host in ("*", "") else f" {host}")
        elif target.startswith("/"):
            target = "unix:" + short(target)
    return Denial(
        kind=what,
        target=target,
        op=op,
        by=found["name"],
        pid=int(found["pid"]),
        count=int(found["times"] or 1),
        source="kernel",
    )


class Listener:
    """Streams the sandbox's reports for one tagged run."""

    source = "kernel"

    def __init__(self) -> None:
        self.tag: str | None = "hlyn-" + secrets.token_hex(12)
        self.why: str | None = None
        self._mark = f"{self.tag}-mark"
        self._stream: subprocess.Popen[bytes] | None = None
        self._rest = b""
        self._held: list[Denial] = []
        if not (os.access(LOG, os.X_OK) and os.access(LOGGER, os.X_OK)):
            self.why = "the system log tools are missing"
            self.tag = None

    def grant(self, plan: Policy) -> Policy:
        return plan  # nothing the command has to reach: the kernel reports for it

    def env(self, keep: Mapping[str, str]) -> dict[str, str]:
        return {}

    def start(self) -> None:
        if self.tag is None:
            return
        predicate = (
            f'(sender == "Sandbox" AND eventMessage CONTAINS "{self.tag}") '
            f'OR eventMessage CONTAINS "{self._mark}"'
        )
        try:
            self._stream = subprocess.Popen(  # noqa: S603 - fixed program, fixed arguments
                [LOG, "stream", "--style", "ndjson", "--predicate", predicate],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self._fail(f"the system log could not be read ({exc.strerror})")
            return
        if self._stream.stdout is None:  # cannot happen with stdout=PIPE; typed as optional
            self._fail("the system log could not be read")
            return
        os.set_blocking(self._stream.stdout.fileno(), False)
        if not self._wait("start", READY, again=True):
            self._fail("the system log did not respond in time")

    def _fail(self, why: str) -> None:
        self.why = why
        self.tag = None  # no tag in the profile: nothing would read it
        self._kill()

    def _say(self, word: str) -> None:
        """Writes our marker into the system log.

        Through the C library's `syslog` rather than by running `logger`:
        the same log, measured equally reliable, without starting a process
        each time -- which is most of what waiting for the stream used to cost.
        """
        text = f"{self._mark} {word}"
        try:
            import syslog

            syslog.syslog(syslog.LOG_NOTICE, text)
            syslog.closelog()  # nothing of ours left open for the command to inherit
        except Exception:  # noqa: BLE001 - fall back to the program that does the same
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run(  # noqa: S603 - fixed program; the marker is our own hex
                    [LOGGER, text],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=2, check=False,
                )

    def _wait(self, word: str, limit: float, again: bool) -> bool:
        """Reads until our marker `word` comes back, holding any refusals seen.

        With `again`, the marker is repeated until it arrives: a stream that
        is not connected yet drops it, which is the whole point of waiting.
        """
        want = f"{self._mark} {word}"
        end = time.monotonic() + limit
        next_say = 0.0
        if not again:
            self._say(word)
        while time.monotonic() < end:
            if again and time.monotonic() >= next_say:
                self._say(word)
                next_say = time.monotonic() + 0.03
            for line in self._lines(0.01):
                if want in line:
                    return True
                found = parse(line, self.tag or "")
                if found is not None:
                    self._held.append(found)
        return False

    def _lines(self, timeout: float) -> list[str]:
        stream = self._stream
        if stream is None or stream.stdout is None:
            return []
        fd = stream.stdout.fileno()
        try:
            ready, _, _ = select.select([fd], [], [], timeout)
        except (OSError, ValueError):
            return []
        if not ready:
            return []
        try:
            chunk = os.read(fd, 1 << 16)
        except BlockingIOError:
            return []
        except OSError:
            return []
        if not chunk:
            return []
        *lines, self._rest = (self._rest + chunk).split(b"\n")
        if len(self._rest) > 1 << 16:
            self._rest = b""
        return [line.decode("utf-8", "replace") for line in lines]

    def fileno(self) -> int | None:
        stream = self._stream
        if stream is None or stream.stdout is None:
            return None
        return stream.stdout.fileno()

    def read(self) -> list[Denial]:
        out, self._held = self._held, []
        for line in self._lines(0):
            found = parse(line, self.tag or "")
            if found is not None:
                out.append(found)
        return out

    def finish(self) -> list[Denial]:
        if self._stream is None:
            return self.read()
        out = self.read()
        if not self._wait("end", CAUGHT, again=False):
            self.why = "the system log fell behind"
        out.extend(self._held)
        self._held = []
        self._kill()
        return out

    def _kill(self) -> None:
        stream, self._stream = self._stream, None
        if stream is None:
            return
        with contextlib.suppress(OSError):
            stream.kill()
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            stream.wait(timeout=2)
        if stream.stdout is not None:
            with contextlib.suppress(OSError):
                stream.stdout.close()

    def close(self) -> None:
        self._kill()
