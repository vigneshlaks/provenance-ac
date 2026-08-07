"""Phase 1 milestone (spec §11): a flagged string remains flagged after
being assigned to a new variable and after concatenation with another
string."""

import sys

from provenance.instrument import register_call_hook, start, stop
from provenance.storage import ProvenanceRecord, ProvenanceStr, get_provenance, is_flagged


def make_flagged(value: str, origin: str = "file:/tmp/secret.txt") -> ProvenanceStr:
    return ProvenanceStr(value, ProvenanceRecord(origins=(origin,)))


def test_flagged_string_is_flagged():
    s = make_flagged("hello")
    assert is_flagged(s)


def test_survives_assignment():
    a = make_flagged("hello")
    b = a
    assert b is a
    assert is_flagged(b)
    assert get_provenance(b).origins == ("file:/tmp/secret.txt",)


def test_survives_concatenation_flagged_plus_plain():
    a = make_flagged("hello ")
    result = a + "world"
    assert isinstance(result, ProvenanceStr)
    assert result == "hello world"
    assert is_flagged(result)
    assert "concat(+)" in get_provenance(result).chain


def test_survives_concatenation_plain_plus_flagged():
    a = make_flagged("world")
    result = "hello " + a
    assert isinstance(result, ProvenanceStr)
    assert result == "hello world"
    assert is_flagged(result)


def test_survives_concatenation_flagged_plus_flagged_merges_origins():
    a = make_flagged("hello ", origin="file:/tmp/a.txt")
    b = make_flagged("world", origin="network:https://evil.example/x")
    result = a + b
    assert isinstance(result, ProvenanceStr)
    assert is_flagged(result)
    origins = get_provenance(result).origins
    assert "file:/tmp/a.txt" in origins
    assert "network:https://evil.example/x" in origins


def test_chained_assignment_and_concat():
    a = make_flagged("secret=")
    b = a
    c = b + "abc123"
    d = c
    assert is_flagged(d)
    assert d == "secret=abc123"


def test_unflagged_string_is_not_flagged():
    plain = "just a normal string"
    assert not is_flagged(plain)
    assert get_provenance(plain) is None


def test_plain_plus_plain_stays_plain():
    result = "hello " + "world"
    assert type(result) is str
    assert not is_flagged(result)


def test_sanitize_clears_flag():
    a = make_flagged("hello")
    record = get_provenance(a)
    sanitized_record = record.sanitize("strip_html")
    sanitized = ProvenanceStr(str(a), sanitized_record)
    assert not is_flagged(sanitized)
    assert "sanitized:strip_html" in get_provenance(sanitized).chain


def test_side_table_tracks_plain_primitives():
    from provenance.storage import side_table

    plain = "untracked but sensitive"
    side_table.attach(plain, ProvenanceRecord(origins=("env:API_KEY",)))
    assert is_flagged(plain)
    side_table.clear(plain)
    assert not is_flagged(plain)


def test_side_table_clear_all():
    """ADR-006: uninstall() does not clear the side-table -- it accumulates
    for the whole process lifetime by default. clear_all() exists so
    independent runs (e.g. benchmark repetitions) can reset it, closing the
    id()-reuse window between them."""
    from provenance.storage import side_table

    a = "first value"
    b = "second value"
    side_table.attach(a, ProvenanceRecord(origins=("file:a.txt",)))
    side_table.attach(b, ProvenanceRecord(origins=("file:b.txt",)))
    assert len(side_table) >= 2

    side_table.clear_all()
    assert len(side_table) == 0
    assert not is_flagged(a)
    assert not is_flagged(b)


def test_call_event_hook_fires():
    seen = []

    def hook(code, instruction_offset, callable_, arg0):
        if callable_ is target:
            seen.append(arg0)

    def target(x):
        return x + 1

    register_call_hook(hook)
    start()
    try:
        target(41)
    finally:
        stop()

    assert seen == [41]


def test_str_call_registers_result_in_side_table():
    """str(x) always constructs a genuinely new plain str object (confirmed
    empirically: `str.__str__(subclass_instance) is subclass_instance` is
    False), so it can't just "not strip" the flag -- there's no way to
    return self and still honor str's own contract of returning a plain
    str. Found this biting for real in target/: GitPython's own
    Git._unpack_args() calls str(arg) on every command-line argument
    before building a subprocess call. The fix is registering the new
    result in the side-table rather than trying to avoid creating one."""
    a = make_flagged("hello")
    result = str(a)
    assert type(result) is str
    assert is_flagged(result)
    assert get_provenance(result).origins == ("file:/tmp/secret.txt",)
