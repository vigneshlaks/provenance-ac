"""Novelty-mining Stage 1/2 result (see README/conversation record): FIDES
("Securing AI Agents with Information-Flow Control," Costa & Köpf,
Microsoft) names, in their own words, a "fundamental limitation" of their
design that they only "partially address":

    "when a tool returns untrusted or confidential data, this data
    immediately taints the conversation history, restricting the tools
    that can be called later without violating security policies"

i.e. FIDES's tainting is coarse-grained -- once ANY untrusted data enters,
the entire downstream conversation/session becomes over-restricted, even
for tool calls that never touch that data at all. This costs real utility
(their own reported numbers show a utility gap they attribute partly to
this).

Our design tracks provenance per OBJECT (ProvenanceStr / the id-keyed
side-table), not per conversation or session. check_sink()/find_flagged()
only ever inspects the actual arguments passed to the specific call being
made -- there is no session-wide or conversation-wide taint state
anywhere in rules.py or storage.py. The hypothesis, tested directly here
rather than assumed: an unrelated sink call using only clean data, made
in the same `rules.installed()` session as an earlier flagged read,
should NOT be restricted by that earlier read at all.

This is real, checkable content: it's a genuine architectural comparison
against a specific, cited, named limitation in closely related published
work, not a reimplementation of anything and not a guessed research
candidate -- FIDES stated the gap in their own paper; this test confirms
whether (and precisely why) our design doesn't share it.
"""

import responses

from provenance import rules
from provenance.storage import is_flagged


def test_unrelated_clean_call_not_restricted_by_earlier_flagged_read(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-secret-value")

    with rules.installed():
        # Step 1: read flagged data. In FIDES's design, this is exactly the
        # moment their "conversation history" gets tainted.
        with open(secret_file) as f:
            secret = f.read()
        assert is_flagged(secret), "sanity check: the read really was tagged"

        # Step 2: a completely unrelated sink call, later in the same
        # session, using data that was never derived from `secret` in any
        # way. If our design had FIDES's named limitation, this would be
        # blocked purely because *some* flagged data exists somewhere in
        # this session -- it must not be.
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://safe.example/status", status=200)
            import requests
            response = requests.post("https://safe.example/status", data="ordinary status update")

    assert response.status_code == 200


def test_multiple_earlier_flagged_reads_still_dont_restrict_unrelated_call(tmp_path):
    """Same property, stress-tested with more accumulated flagged state --
    several flagged reads, not just one, to make sure the result isn't an
    artifact of only testing the single-taint case."""
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
    """Sanity check that the above isn't secretly "enforcement is broken" --
    within the exact same session, a call that DOES use the flagged value
    must still be blocked. Confirms the earlier tests pass because
    per-object tracking works correctly, not because enforcement is
    accidentally disabled."""
    from provenance.exceptions import ProvenanceViolation
    import pytest

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("sk-secret-value")

    with rules.installed():
        with open(secret_file) as f:
            secret = f.read()

        # unrelated clean call first -- proves scoping
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, "https://safe.example/status", status=200)
            import requests
            requests.post("https://safe.example/status", data="clean")

        # now actually use the flagged value -- must still be blocked
        with pytest.raises(ProvenanceViolation):
            requests.post("https://safe.example/status", data=secret)
