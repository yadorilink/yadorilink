#!/usr/bin/env python3
"""Tiny fixture server for the installer tests: serves ROOT over plain HTTP on
127.0.0.1 (random port, written to PORTFILE). A request counter is kept in
ROOT/../requests.log. A directory containing a file named `.truncate` serves
its .zip files cut in half (declared length intact), to model an interrupted
download."""
import http.server
import os
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
portfile = Path(sys.argv[2])
log = root.parent / "requests.log"


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(root), **k)

    def log_message(self, fmt, *args):
        with open(log, "a") as f:
            f.write(self.path + "\n")

    def do_GET(self):
        if self.path.startswith("/redir/"):
            self.send_response(302)
            self.send_header("Location", self.path[len("/redir"):])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = Path(self.translate_path(self.path))
        if path.suffix == ".zip" and path.is_file() and (path.parent.parent.parent / ".truncate").exists():
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data[: len(data) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        super().do_GET()


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
portfile.write_text(str(srv.server_address[1]))
srv.serve_forever()
