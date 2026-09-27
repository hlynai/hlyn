# SPDX-License-Identifier: Apache-2.0
import socket
dst = ("127.0.0.1", 47002)
s = socket.socket()
try: s.connect(dst); print("  agent connect(): connected")
except OSError as e: print("  agent connect():", e.strerror)
s = socket.socket()
try: print("  agent sendto(MSG_FASTOPEN): sent", s.sendto(b"leak-via-tfo", socket.MSG_FASTOPEN, dst), "bytes")
except OSError as e: print("  agent sendto(MSG_FASTOPEN):", e.strerror)
