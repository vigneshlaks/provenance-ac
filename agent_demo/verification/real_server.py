"""A genuine, local HTTP server for verification. This is not a mock.

Every other demo uses responses.RequestsMock(), which fakes the network
layer inside the requests library before any socket actually opens. That's
fine for repeatable testing, but it means no other demo actually observes
a request get sent or genuinely fail to leave the process. The claim that
a block means zero bytes leave is a property of rules.py's code, since
check_sink raises before the wrapped function runs, but it isn't something
watched happening.

This is a genuine socket and a genuine HTTP server on loopback. It's safe
to run because we own both ends. Nothing here talks to an actual third
party.
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
    """Starts a genuine HTTP server on a free localhost port, in a
    background thread, recording every request it genuinely receives."""

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
                pass  # Requests are already recorded above, so this suppresses the default stderr logging.

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
