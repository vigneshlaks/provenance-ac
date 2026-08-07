"""Structured audit logging for sink decisions (layer 9: detection, per the
defense-in-depth discussion in the README -- this is a record of what
happened, not a mechanism that changes what happens; rules.py still
blocks/allows entirely on its own regardless of whether logging is on).

Deliberately uses a pristine, pre-patch reference to open() (captured at
this module's own import time, before rules.install() ever runs) rather
than whatever open() happens to be bound to at call time. Reason: rules.py
patches builtins.open when installed, and check_sink() (which calls into
this module) runs *during* a sink call -- if this module's own housekeeping
write went through the patched open(), and the log file's path happened to
be outside the configured workspace, that write would itself trigger
another check_sink() call (the workspace-boundary write sink), which would
try to audit-log *that* decision too. Same reentrancy-guard reasoning as
instrument.py's ADR-002: infrastructure that logs about the system must not
itself be subject to the system it's logging.
"""

from __future__ import annotations

import builtins
import dataclasses
import json
import time
from pathlib import Path
from typing import Any

_real_open = builtins.open

_log_path: Path | None = None


@dataclasses.dataclass
class AuditRecord:
    timestamp: float
    sink: str
    decision: str  # "allowed" | "blocked" | "approved"
    origins: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))


def set_log_path(path: Any) -> None:
    """Enable logging to `path` (JSON Lines, one AuditRecord per line), or
    pass None to disable. Disabled by default -- logging is opt-in."""
    global _log_path
    _log_path = Path(path) if path is not None else None


def is_enabled() -> bool:
    return _log_path is not None


def record(sink: str, decision: str, origins: tuple[str, ...] = (), chain: tuple[str, ...] = ()) -> None:
    if _log_path is None:
        return
    entry = AuditRecord(timestamp=time.time(), sink=sink, decision=decision, origins=tuple(origins), chain=tuple(chain))
    with _real_open(_log_path, "a") as f:
        f.write(entry.to_json() + "\n")


def read_records(path: Any) -> list[AuditRecord]:
    """Convenience for tests/inspection -- not used by the enforcement path."""
    records = []
    with _real_open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            raw["origins"] = tuple(raw["origins"])
            raw["chain"] = tuple(raw["chain"])
            records.append(AuditRecord(**raw))
    return records
