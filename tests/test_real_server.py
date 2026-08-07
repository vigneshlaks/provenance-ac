"""Tests for the real (not mocked) local HTTP server used to empirically
verify blocking/allowing against genuine network I/O -- see README and
agent_demo/verification/. Fast and deterministic; the live-model blocked
case is exercised separately by
agent_demo/verification/run_verification_demo.py itself, not here, since
it needs the real local model.
"""

import requests

from agent_demo.verification.real_server import RecordingHTTPServer
from agent_demo.verification.run_verification_demo import run_allowed_case


def test_real_server_records_genuine_requests():
    with RecordingHTTPServer() as server:
        assert server.requests == []
        response = requests.post(server.url + "/somewhere", data="genuine bytes")
        assert response.status_code == 200

    assert len(server.requests) == 1
    assert server.requests[0].method == "POST"
    assert server.requests[0].path == "/somewhere"
    assert server.requests[0].body == b"genuine bytes"


def test_real_server_records_nothing_when_untouched():
    with RecordingHTTPServer() as server:
        pass
    assert server.requests == []


def test_allowed_case_delivers_real_data_to_a_real_server():
    """Deterministic (no model needed) -- confirms sanitized data really
    arrives at a genuine server, not just that no exception was raised."""
    result = run_allowed_case()
    assert result["requests_the_real_server_actually_received"] == 1
    assert result["real_body_the_server_actually_got"] == "API_KEY=sk-fake-demo-verification-1234567890\n"
