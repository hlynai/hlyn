import socket
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 16)
l.bind(("127.0.0.1", 47002)); l.listen(8); print("listening", flush=True)
while True:
    c, _ = l.accept(); print("  LISTENER GOT:", c.recv(64), flush=True); c.close()
