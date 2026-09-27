import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): print("LISTENER GOT GET", self.path, "from", self.client_address[0], "UA:", self.headers.get("User-Agent"), flush=True); self.send_response(404); self.end_headers()
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 47010), H).serve_forever()
