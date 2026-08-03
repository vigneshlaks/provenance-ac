"""Exceptions raised by enforcement (rules.py)."""

from __future__ import annotations

from typing import Sequence


class ProvenanceViolation(Exception):
    """Raised when a sink call receives an argument that traces to an
    untrusted origin and has not passed through a @sanitizer."""

    def __init__(self, sink_name: str, origins: Sequence[str], chain: Sequence[str]):
        self.sink_name = sink_name
        self.origins = tuple(origins)
        self.chain = tuple(chain)
        path = " -> ".join(self.chain) if self.chain else "(direct)"
        super().__init__(
            f"blocked call to {sink_name!r}: argument traces to untrusted "
            f"origin(s) {self.origins!r} via propagation path [{path}]"
        )
