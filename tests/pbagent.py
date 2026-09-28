# SPDX-License-Identifier: Apache-2.0
"""A pasteboard of the test's own, used by tests/test_mach.py.

    python3 pbagent.py new -        make a uniquely named pasteboard, print its name
    python3 pbagent.py write NAME   put a value on it
    python3 pbagent.py read NAME    print what is on it
    python3 pbagent.py clear NAME   empty it
    python3 pbagent.py done NAME    release it

Only ever a pasteboard this test made (`pasteboardWithUniqueName`): never
the user's clipboard. Through the Objective-C runtime with ctypes, since
PyObjC isn't a test dependency. Each call is its own process: CoreFoundation
can't be used across a plain fork.
"""

from __future__ import annotations

import ctypes
import sys

objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
ctypes.CDLL("/System/Library/Frameworks/AppKit.framework/AppKit")
objc.objc_getClass.restype = ctypes.c_void_p
objc.sel_registerName.restype = ctypes.c_void_p
send = objc.objc_msgSend
PTR = ctypes.c_void_p


def msg(obj: object, sel: str, *args: object, restype: object = PTR, argtypes: tuple = ()) -> object:
    send.restype = restype
    send.argtypes = [PTR, PTR, *argtypes]
    return send(obj, objc.sel_registerName(sel.encode()), *args)


def text(value: str) -> object:
    cls = objc.objc_getClass(b"NSString")
    return msg(cls, "stringWithUTF8String:", value.encode(), argtypes=(ctypes.c_char_p,))


def plain(ns: object) -> str | None:
    return None if not ns else msg(ns, "UTF8String", restype=ctypes.c_char_p).decode()  # type: ignore[union-attr]


def board(name: str) -> object:
    return msg(objc.objc_getClass(b"NSPasteboard"), "pasteboardWithName:", text(name), argtypes=(PTR,))


def main() -> None:
    what, name = sys.argv[1], sys.argv[2]
    kind = text("public.utf8-plain-text")
    if what == "new":
        print(plain(msg(msg(objc.objc_getClass(b"NSPasteboard"), "pasteboardWithUniqueName"), "name")))
    elif what == "write":
        pb = board(name)
        msg(pb, "clearContents", restype=ctypes.c_long)
        done = msg(pb, "setString:forType:", text("secret-4242"), kind, restype=ctypes.c_bool,
                   argtypes=(PTR, PTR))
        print("wrote", bool(done))
    elif what == "read":
        print("read", plain(msg(board(name), "stringForType:", kind, argtypes=(PTR,))))
    elif what == "clear":
        msg(board(name), "clearContents", restype=ctypes.c_long)
        print("cleared")
    elif what == "done":
        msg(board(name), "releaseGlobally")


if __name__ == "__main__":
    main()
