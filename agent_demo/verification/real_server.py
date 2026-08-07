"""A real, local HTTP server for empirical verification -- not a mock.

Every prior demo used `responses.RequestsMock()`, which fakes the network
layer entirely inside the `requests` library before any real socket ever
opens. That's fine for repeatable testing, but it means no prior demo has
ever actually watched a real request either get sent or genuinely fail to
leave the process -- "a block means zero bytes leave" was proven by
reading rules.py's code (check_sink raises before the wrapped function is
ever called), not by observing it happen.

This is a genuine socket, a genuine HTTP server, receiving genuine bytes
over a genuine (loopback) network connection. The only thing making it
safe to run is that we own both ends -- nothing here talks to a real
third party.
"""

from __future__ import annotations

import http.server
import threading
from dataclasses import dataclass, field


@dataclass
class RecordedRequest:
    method: str
    path: str
    body: bytes


class RecordingHTTPServer:
    """Starts a real HTTP server on a free localhost port, in a background
    thread, recording every request it genuinely receives."""

    def __init__(self) -> None:
        self.requests: list[RecordedRequest] = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                server.requests.append(RecordedRequest(self.command, self.path, body))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def log_message(self, format: str, *args: object) -> None:
                pass  # keep test/demo output clean -- we already record requests ourselves

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_port
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> "RecordingHTTPServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
