"""Tests for the genuine, not mocked, local HTTP server used to verify
blocking and allowing against genuine network I/O empirically. See the
README and agent_demo/verification/. These are fast and deterministic. The
live model blocked case is exercised separately, by
agent_demo/verification/run_verification_demo.py itself rather than here,
since it needs the local model actually running.
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


def test_allowed_case_delivers_actual_data_to_a_genuine_server():
    """Deterministic, no model needed. Confirms sanitized data genuinely
    arrives at a server, not just that no exception was raised."""
    result = run_allowed_case()
    assert result["requests_the_server_actually_received"] == 1
    assert result["body_the_server_actually_got"] == "API_KEY=sk-fake-demo-verification-1234567890\n"
