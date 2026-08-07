"""Provenance storage: side-table for immutable primitives, plus wrapper
types (ProvenanceStr, ProvenanceDict) for values that can hold real
attributes.

Architecture note (ADR-001, see README):

CPython's built-in str methods do not preserve subclasses -- verified
empirically: `S("x").upper()`, `.split()`, slicing, and `str(x)` all return
plain `str`, not `S`, even when `S` subclasses `str`. Plain str/int/float/
bytes instances also do not support weak references. So the "side-table"
below is a plain dict keyed by id(value), not a true WeakValueDictionary:
there is no way to be notified when an untracked plain primitive is garbage
collected, so a stale id() can in principle be reused by an unrelated new
object, producing a false provenance flag. This is a real, documented
correctness risk (see README limitations) that we do not fully eliminate.

Where the type is under our control, we sidestep the side-table's id-reuse
risk entirely by using a wrapper (ProvenanceStr, ProvenanceDict) that holds
its ProvenanceRecord as a real attribute on the object itself. The side-table
remains as the fallback for the cases wrapping can't reach: values crossing
an opaque boundary (an unwrapped result from a C extension or a builtin
method we have not explicitly overridden -- e.g. `.upper()` on a
ProvenanceStr silently returns a plain, unflagged `str` unless the caller
re-wraps it; that gap is tracked in propagation.py, Phase 2).
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class ProvenanceRecord:
    """Metadata describing where a value came from and its sanitization state."""

    origins: tuple[str, ...]
    chain: tuple[str, ...] = ()
    sanitized: bool = False

    def flagged(self) -> bool:
        return bool(self.origins) and not self.sanitized

    def extend(self, step: str) -> "ProvenanceRecord":
        return dataclasses.replace(self, chain=self.chain + (step,))

    def merge(self, other: "ProvenanceRecord | None", step: str) -> "ProvenanceRecord":
        """Combine this record with another value's record (e.g. for a+b),
        recording the operation in the chain. `other` may be None if the
        other operand carries no provenance at all."""
        if other is None:
            return self.extend(step)
        origins = tuple(dict.fromkeys(self.origins + other.origins))
        chain = self.chain + other.chain + (step,)
        sanitized = self.sanitized and other.sanitized
        return ProvenanceRecord(origins=origins, chain=chain, sanitized=sanitized)

    def sanitize(self, sanitizer_name: str) -> "ProvenanceRecord":
        return dataclasses.replace(
            self, sanitized=True, chain=self.chain + (f"sanitized:{sanitizer_name}",)
        )


class _IdSideTable:
    """id()-keyed provenance table for plain immutable primitives that were
    not created through a wrapper type. See ADR-001 above for why this is a
    plain dict rather than a real WeakValueDictionary, and the id-reuse risk
    that follows from that.
    """

    def __init__(self) -> None:
        self._table: dict[int, ProvenanceRecord] = {}

    def attach(self, value: Any, record: ProvenanceRecord) -> None:
        self._table[id(value)] = record

    def get(self, value: Any) -> "ProvenanceRecord | None":
        return self._table.get(id(value))

    def clear(self, value: Any) -> None:
        self._table.pop(id(value), None)

    def __len__(self) -> int:
        return len(self._table)


side_table = _IdSideTable()


def get_provenance(value: Any) -> "ProvenanceRecord | None":
    """Look up provenance for any value, whether it's a wrapper type or a
    plain primitive registered in the side-table."""
    if isinstance(value, (ProvenanceStr, ProvenanceDict)):
        return value._provenance
    return side_table.get(value)


def is_flagged(value: Any) -> bool:
    record = get_provenance(value)
    return record is not None and record.flagged()


class ProvenanceStr(str):
    """A str subclass carrying a real ProvenanceRecord attribute.

    Only operations explicitly overridden here (__add__, __radd__) propagate
    provenance automatically. Every other str method (.upper(), .split(),
    slicing, str(), f-string embedding via BUILD_STRING, ...) returns a
    plain, unflagged str -- a documented gap closed incrementally in
    propagation.py (Phase 2, §6 of the spec).
    """

    _provenance: ProvenanceRecord

    def __new__(cls, value: str, provenance: ProvenanceRecord) -> "ProvenanceStr":
        obj = str.__new__(cls, value)
        obj._provenance = provenance
        return obj

    def __add__(self, other: Any) -> "ProvenanceStr":
        result = str.__add__(self, other)
        merged = self._provenance.merge(get_provenance(other), step="concat(+)")
        return ProvenanceStr(result, merged)

    def __radd__(self, other: Any) -> "ProvenanceStr":
        result = other + str(self)
        merged = self._provenance.merge(get_provenance(other), step="concat(+)")
        return ProvenanceStr(result, merged)

    def __str__(self) -> str:
        # str(x) always calls type(x).__str__(x) per the data model, and it
        # genuinely constructs a *new* plain str object -- confirmed
        # empirically, `str.__str__(subclass_instance) is subclass_instance`
        # is False. That's the exact mechanism that lets a flag silently
        # vanish through code we don't control: found for real in
        # GitPython's Git._unpack_args(), which does `str(arg)` on every
        # command-line argument before building the subprocess call (see
        # target/ in the README). Registering the new plain string in the
        # side-table -- rather than trying to avoid creating one, which
        # isn't possible, str's own contract requires returning a plain
        # str -- closes this specific gap without changing what str(x)
        # returns to unrelated callers.
        result = str.__str__(self)
        side_table.attach(result, self._provenance)
        return result

    def __repr__(self) -> str:
        return (
            f"ProvenanceStr({str.__str__(self)!r}, "
            f"origins={self._provenance.origins}, sanitized={self._provenance.sanitized})"
        )


class ProvenanceDict(dict):
    """A dict subclass tracking per-key ProvenanceRecords for values that
    don't carry their own (e.g. plain ints/floats). Values that are already
    ProvenanceStr/ProvenanceDict keep their own record; get_item_provenance
    checks both.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._item_provenance: dict[Any, ProvenanceRecord] = {}

    def set_provenance(self, key: Any, record: ProvenanceRecord) -> None:
        self._item_provenance[key] = record

    def get_item_provenance(self, key: Any) -> "ProvenanceRecord | None":
        if key in self._item_provenance:
            return self._item_provenance[key]
        return get_provenance(super().__getitem__(key))

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        record = get_provenance(value)
        if record is not None:
            self._item_provenance[key] = record
        else:
            self._item_provenance.pop(key, None)

    def __repr__(self) -> str:
        flagged_keys = [k for k in self if self.get_item_provenance(k) and self.get_item_provenance(k).flagged()]
        return f"ProvenanceDict({dict.__repr__(self)}, flagged_keys={flagged_keys})"
