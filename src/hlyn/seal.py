# SPDX-License-Identifier: Apache-2.0
"""A log that shows when it has been edited.

`hlyn run --log FILE` appends one JSON record per line, from several processes
(this one, the gate, the proxy). When a run ends, `seal` appends one more
record that commits to everything written so far:

    {"kind": "log-seal", "from": 0, "bytes": 4096, "records": 31,
     "prev": "", "sha256": "..."}

`sha256` covers `prev` (the previous seal's `sha256`, empty for the first) and
the `bytes` bytes of the file from offset `from`. Each seal starts where the
last one's covered bytes ended, so the previous seal line is itself covered by
the next, and every byte before the last seal is covered by exactly one. Then
`verify` finds:

- an edited, inserted or removed record or byte: that seal's hash differs;
- a seal removed from the middle: the next one no longer starts where the
  last ended;
- records after the last seal: reported as unsealed (a run that was killed
  looks like this), not as an edit.

What this does not do, said plainly: someone who can rewrite the whole file and
knows this format can rebuild every seal. The seal's hash is for keeping
elsewhere: `hlyn log verify FILE --anchor HASH` fails when the last seal is not
that one, which also catches the last seal being cut off. The agent can't touch
the file (it must sit outside every `--write` grant, see `log.record`).

Standard library only: `hashlib` and `fcntl`.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from typing import Any

__all__ = ["KIND", "seal", "verify"]

KIND = "log-seal"
_CHUNK = 1 << 20
_LINE = 4096  # a seal line is far shorter; anything longer is not one


def _lines(fd: int, size: int) -> list[tuple[int, int, bytes]]:
    """(start, end, text) of every line in the file that could be a seal,
    reading in chunks, so a very long record is never held in memory.

    `end` is the offset just after the newline; a final line with no newline is
    not a record yet and is left out.
    """
    out: list[tuple[int, int, bytes]] = []
    offset = 0
    start = 0
    held = bytearray()
    over = False  # the current line is longer than `_LINE`: keep only where it ends
    while offset < size:
        block = os.pread(fd, min(_CHUNK, size - offset), offset)
        if not block:
            break
        base = 0
        while True:
            cut = block.find(b"\n", base)
            if cut < 0:
                if not over:
                    held += block[base:]
                    if len(held) > _LINE:
                        over, held = True, bytearray()
                break
            if not over:
                held += block[base:cut]
                if len(held) <= _LINE and held.startswith(b"{") and KIND.encode() in held:
                    out.append((start, offset + cut + 1, bytes(held)))
            start = offset + cut + 1
            held, over, base = bytearray(), False, cut + 1
        offset += len(block)
    return out


def _digest(fd: int, begin: int, length: int, prev: str) -> str:
    h = hashlib.sha256()
    h.update(prev.encode() + b"\n")
    end = begin + length
    while begin < end:
        block = os.pread(fd, min(_CHUNK, end - begin), begin)
        if not block:
            raise OSError("the log is shorter than a seal says")
        h.update(block)
        begin += len(block)
    return h.hexdigest()


def _seals(fd: int, size: int) -> list[dict[str, Any]]:
    """The seal records in the file, in order, each with where its line is."""
    found: list[dict[str, Any]] = []
    for start, end, text in _lines(fd, size):
        try:
            row = json.loads(text)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("kind") == KIND:
            row["_at"], row["_end"] = start, end
            found.append(row)
    return found


def _fields(row: dict[str, Any]) -> bool:
    return (isinstance(row.get("from"), int) and isinstance(row.get("bytes"), int)
            and isinstance(row.get("sha256"), str) and isinstance(row.get("prev"), str)
            and not isinstance(row.get("from"), bool) and not isinstance(row.get("bytes"), bool)
            and row["from"] >= 0 and row["bytes"] >= 0)


def seal(fd: int) -> str:
    """Append a seal to the log open on `fd` (read and append) and return its
    hash. Takes the file's lock, so two runs sealing one file take turns; a
    record another process writes meanwhile lands after the seal and is
    covered by the next one."""
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        size = os.fstat(fd).st_size
        marks = _seals(fd, size)
        last = marks[-1] if marks and _fields(marks[-1]) else None
        begin = last["from"] + last["bytes"] if last else 0
        prev = last["sha256"] if last else ""
        length = size - begin
        records = 0
        offset = begin
        while offset < size:
            block = os.pread(fd, min(_CHUNK, size - offset), offset)
            records += block.count(b"\n")
            offset += len(block)
        digest = _digest(fd, begin, length, prev)
        row = {"t": round(time.time(), 3), "kind": KIND, "pid": os.getpid(), "from": begin,
               "bytes": length, "records": records, "prev": prev, "sha256": digest}
        os.write(fd, (json.dumps(row) + "\n").encode())
        return digest
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def verify(path: str, anchor: str | None = None) -> dict[str, Any]:
    """Check the log at `path`. Returns a dict with `ok`, `state` (`sealed`,
    `unsealed` or `edited`), the seals found, what is wrong, and the hash of the
    last seal. `anchor`, a prefix of the hash you kept, must match the last
    seal."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        size = info.st_size
        marks = _seals(fd, size)
        problems: list[str] = []
        covered = 0
        prev = ""
        good = 0
        for number, row in enumerate(marks, 1):
            if not _fields(row):
                problems.append(f"seal {number} at byte {row['_at']} is malformed")
                continue
            if row["from"] != covered:
                problems.append(
                    f"seal {number} starts at byte {row['from']}, not {covered}: a seal or a record "
                    f"before it was removed or added"
                )
            if row["prev"] != prev:
                problems.append(f"seal {number} does not follow the seal before it")
            end = row["from"] + row["bytes"]
            if end > row["_at"] or end > size:
                problems.append(f"seal {number} claims bytes it does not follow")
            else:
                try:
                    same = _digest(fd, row["from"], row["bytes"], row["prev"]) == row["sha256"]
                except OSError:
                    same = False
                if not same:
                    problems.append(f"seal {number}: the bytes {row['from']} to {end} were changed")
                else:
                    good += 1
            covered, prev = end, row["sha256"]
        last = marks[-1] if marks else None
        # Bytes no seal covers: after the last seal's own line, and any written between
        # what it covered and its line (a record that landed during sealing).
        if last and _fields(last):
            loose = max(0, size - (last["from"] + last["bytes"]) - (last["_end"] - last["_at"]))
        else:
            loose = size - last["_end"] if last else size
        if anchor and (not last or not str(last.get("sha256", "")).startswith(anchor.lower())):
            problems.append("the last seal is not the one you kept: the log was rewritten or cut short")
        if problems:
            state = "edited"
        elif not marks or loose > 0:
            state = "unsealed"
        else:
            state = "sealed"
        return {
            "ok": not problems and state == "sealed",
            "state": state,
            "seals": len(marks),
            "intact": good,
            "after_last_seal": loose,
            "last": last["sha256"] if last and isinstance(last.get("sha256"), str) else None,
            "problems": problems,
        }
    finally:
        os.close(fd)
