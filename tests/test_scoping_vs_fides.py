"""FIDES, "Securing AI Agents with Information-Flow Control," by Costa and
Köpf at Microsoft, names its own fundamental limitation: tainting happens
per session, so once any untrusted data enters, the entire downstream
conversation becomes over restricted, even for tool calls that never touch
that data.

    "when a tool returns untrusted or confidential data, this data
    immediately taints the conversation history, restricting the tools
    that can be called later without violating security policies"

Our design tracks provenance per object, through ProvenanceStr and the
side table keyed by id, not per conversation or session. check_sink() and
find_flagged() only ever inspect the actual arguments passed to the
specific call being made. This tests that directly: an unrelated sink call
using only clean data, made in the same rules.installed() session as an
earlier flagged read, should not be restricted by that earlier read at
all.
"""

import responses

from provenance import rules
from provenance.storage import is_flagged


def test_unrelated_clean_call_not_restricted_by_earlier_flagged_read(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-secret-value")

    with rules.installed():
        # Reading flagged data. In FIDES's design, this is where their
        # conversation history would get tainted.
        with open(secret_file) as f:
            secret = f.read()
        assert is_flagged(secret), "sanity check: the read really was tagged"

        # An unrelated sink call, later in the same session, using data
        # never derived from secret. This must not be blocked just because
        # some flagged data exists elsewhere in this session.
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://safe.example/status", status=200)
            import requests
            response = requests.post("https://safe.example/status", data="ordinary status update")

    assert response.status_code == 200


def test_multiple_earlier_flagged_reads_still_dont_restrict_unrelated_call(tmp_path):
    """The same property, with several accumulated flagged reads instead
    of just one, to rule out this being an artifact of the single taint
    case."""
    files = [tmp_path / f"secret{i}.txt" for i in range(5)]
    for f in files:
        f.write_text("sk-another-secret")

    with rules.installed():
        for f in files:
            with open(f) as fh:
                value = fh.read()
            assert is_flagged(value)

        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://safe.example/status", status=200)
            import requests
            response = requests.post("https://safe.example/status", data="still just an ordinary update")

    assert response.status_code == 200


def test_the_actual_flagged_value_is_still_correctly_blocked_in_the_same_session(tmp_path):
    """Confirms the tests above pass because per-object tracking works,
    not because enforcement is accidentally disabled. Within the same
    session, a call that does use the flagged value must still be
    blocked."""
    from provenance.exceptions import ProvenanceViolation
    import pytest

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-secret-value")

    with rules.installed():
        with open(secret_file) as f:
            secret = f.read()

        # An unrelated clean call first, to prove scoping.
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://safe.example/status", status=200)
            import requests
            requests.post("https://safe.example/status", data="clean")

        # Now actually using the flagged value. This must still be
        # blocked.
        with pytest.raises(ProvenanceViolation):
            requests.post("https://safe.example/status", data=secret)
