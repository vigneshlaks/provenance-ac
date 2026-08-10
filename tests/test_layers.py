"""Tests for layer 8, human oversight, and layer 9, audit logging. Layer 4,
sandboxing, is a subprocess level OS demo, not something to unit test the
same way. See layers/sandbox_demo.py, which verifies itself by asserting
on its own before and after behavior.
"""

import pytest

from provenance import audit_log, rules
from provenance.exceptions import ProvenanceViolation
from provenance.rules import check_sink
from provenance.storage import ProvenanceRecord, ProvenanceStr


def make_flagged(value: str, origin: str = "file:/tmp/x.txt") -> ProvenanceStr:
    return ProvenanceStr(value, ProvenanceRecord(origins=(origin,)))


def test_check_sink_allows_unflagged_without_hook():
    check_sink("test.sink", "plain value")  # should not raise


def test_check_sink_blocks_flagged_without_hook():
    with pytest.raises(ProvenanceViolation):
        check_sink("test.sink", make_flagged("secret"))


def test_approval_hook_can_approve_a_call():
    rules.set_approval_hook(lambda sink, value, record: True)
    try:
        check_sink("test.sink", make_flagged("secret"))  # should not raise
    finally:
        rules.set_approval_hook(None)


def test_approval_hook_can_still_deny():
    rules.set_approval_hook(lambda sink, value, record: False)
    try:
        with pytest.raises(ProvenanceViolation):
            check_sink("test.sink", make_flagged("secret"))
    finally:
        rules.set_approval_hook(None)


def test_approval_hook_receives_sink_name_and_record():
    seen = {}

    def hook(sink, value, record):
        seen["sink"] = sink
        seen["origins"] = record.origins
        return True

    rules.set_approval_hook(hook)
    try:
        check_sink("my.sink", make_flagged("secret", origin="file:/tmp/y.txt"))
    finally:
        rules.set_approval_hook(None)

    assert seen["sink"] == "my.sink"
    assert seen["origins"] == ("file:/tmp/y.txt",)


def test_no_hook_registered_is_the_default():
    # After any test above unregisters its hook, behavior must be back to a
    # flat block, confirming the hook is opt in, not sticky.
    with pytest.raises(ProvenanceViolation):
        check_sink("test.sink", make_flagged("secret"))


def test_audit_log_disabled_by_default(tmp_path):
    log_path = tmp_path / "should_not_exist.jsonl"
    check_sink("sink.d", "plain")
    assert not log_path.exists()


def test_audit_log_records_allowed_and_blocked(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit_log.set_log_path(log_path)
    try:
        check_sink("sink.a", "plain")
        with pytest.raises(ProvenanceViolation):
            check_sink("sink.b", make_flagged("secret"))
    finally:
        audit_log.set_log_path(None)

    records = audit_log.read_records(log_path)
    assert len(records) == 2
    assert records[0].sink == "sink.a" and records[0].decision == "allowed"
    assert records[1].sink == "sink.b" and records[1].decision == "blocked"
    assert records[1].origins == ("file:/tmp/x.txt",)


def test_audit_log_records_approved_decision(tmp_path):
    log_path = tmp_path / "audit2.jsonl"
    audit_log.set_log_path(log_path)
    rules.set_approval_hook(lambda sink, value, record: True)
    try:
        check_sink("sink.c", make_flagged("secret"))
    finally:
        audit_log.set_log_path(None)
        rules.set_approval_hook(None)

    records = audit_log.read_records(log_path)
    assert len(records) == 1
    assert records[0].sink == "sink.c"
    assert records[0].decision == "approved"
