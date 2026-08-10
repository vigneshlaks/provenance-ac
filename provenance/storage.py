"""Provenance storage. There is a side table for immutable primitives, and
there are wrapper types, ProvenanceStr and ProvenanceDict, for values that
can hold attributes of their own.

Where the type is under our control, ProvenanceStr and ProvenanceDict hold
their ProvenanceRecord as an actual attribute, so provenance travels with
the object itself. Plain primitives such as bytes, int, and float can't carry an
attribute and don't support weak references, so those fall back to the side
table below, which is a plain dict keyed by id(value). That means there is
no garbage collection notification when an untracked primitive is
collected, so a stale id() can in principle be reused by an unrelated
object and produce a false provenance flag. See the limitations section of
the README.

The side table is also the fallback for values crossing an opaque boundary
that wrapping can't reach. For example, calling .upper() on a ProvenanceStr
returns a plain, unflagged str unless the caller re-wraps it, since
CPython's str methods don't preserve subclasses.
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
        """Combines this record with another value's record, as for a + b,
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
    """A provenance table, keyed by id(), for plain immutable primitives
    that were not created through a wrapper type. It is a plain dict rather
    than a WeakValueDictionary, so it carries the id reuse risk described
    above.

    Calling rules.uninstall() does not clear this table, it only restores
    the patched functions, so entries accumulate for the process lifetime
    across installed() and uninstall() cycles. In a tight loop of short
    lived operations, a later object's id() can collide with an earlier,
    already deleted one and produce a false positive. This happened in
    practice in benchmarks/overhead_measurement.py. clear_all() resets the
    table between independent runs to avoid that.
    """

    def __init__(self) -> None:
        self._table: dict[int, ProvenanceRecord] = {}

    def attach(self, value: Any, record: ProvenanceRecord) -> None:
        self._table[id(value)] = record

    def get(self, value: Any) -> "ProvenanceRecord | None":
        return self._table.get(id(value))

    def clear(self, value: Any) -> None:
        self._table.pop(id(value), None)

    def clear_all(self) -> None:
        self._table.clear()

    def __len__(self) -> int:
        return len(self._table)


side_table = _IdSideTable()


def get_provenance(value: Any) -> "ProvenanceRecord | None":
    """Looks up provenance for any value, whether it is a wrapper type or a
    plain primitive registered in the side table."""
    if isinstance(value, (ProvenanceStr, ProvenanceDict)):
        return value._provenance
    return side_table.get(value)


def is_flagged(value: Any) -> bool:
    record = get_provenance(value)
    return record is not None and record.flagged()


class ProvenanceStr(str):
    """A str subclass carrying an actual ProvenanceRecord attribute.

    Only the operations explicitly overridden here, __add__ and __radd__,
    propagate provenance automatically. Every other str method, such as
    .upper(), .split(), slicing, str(), or f-string embedding, returns a
    plain, unflagged str.
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
        # Calling str(x) constructs a new plain str object, not self, so a
        # flag would silently vanish through any code that calls str() on
        # us. This happens, not just hypothetically, inside GitPython's
        # Git._unpack_args(), see the target directory referenced in the
        # README. Registering the new string in the side table keeps it
        # tracked.
        result = str.__str__(self)
        side_table.attach(result, self._provenance)
        return result

    def __repr__(self) -> str:
        return (
            f"ProvenanceStr({str.__str__(self)!r}, "
            f"origins={self._provenance.origins}, sanitized={self._provenance.sanitized})"
        )


class ProvenanceDict(dict):
    """A dict subclass tracking a ProvenanceRecord per key for values that
    don't carry their own, such as plain ints or floats. Values that are
    already a ProvenanceStr or ProvenanceDict keep their own record, and
    get_item_provenance checks both.
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
