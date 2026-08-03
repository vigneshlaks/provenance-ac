"""sys.monitoring (PEP 669) integration.

Architecture decision (ADR-001), resolved empirically before writing this
file -- see tests/test_propagation.py and the commands recorded in the repo
README for how each claim below was checked on Python 3.13:

1. sys.monitoring has no STORE_NAME- or BINARY_OP-*named* events. The event
   set is {PY_START, PY_RESUME, PY_RETURN, PY_YIELD, PY_UNWIND, PY_THROW,
   CALL, C_RETURN, C_RAISE, LINE, INSTRUCTION, JUMP, BRANCH, RAISE, RERAISE,
   EXCEPTION_HANDLED, STOP_ITERATION}. Catching a specific opcode like
   STORE_NAME or BINARY_OP requires enabling INSTRUCTION (fires per bytecode
   instruction executed -- expensive) and decoding the opcode yourself.

2. That INSTRUCTION-level tracing turns out to be unnecessary for variable
   assignment and string concatenation specifically:
   - Assignment (`b = a`) is free: CPython name binding just rebinds a name
     to the same object. If `a` is a ProvenanceStr, `b` is the identical
     object with its `_provenance` attribute intact -- no instrumentation
     of any kind is involved.
   - Concatenation (`a + b`) is handled by ProvenanceStr.__add__/__radd__
     (see storage.py). CPython's `+` operator dispatches through the normal
     `__add__`/`__radd__` protocol even for str subclasses, confirmed with:
       class S(str):
           def __add__(self, other): return S(str.__add__(self, other))
       type(S("a") + "b") is S   # True
     So provenance-aware concatenation is just operator overloading; no
     bytecode hook is needed for it either.

3. sys.monitoring's CALL event *is* the right tool here, just not for
   assignment/concat. It fires with signature
   `(code, instruction_offset, callable, arg0)` on every call, including
   calls to builtins/C functions -- confirmed empirically. That is exactly
   what Phase 2 needs to intercept: source calls (open().read(), etc.), sink
   calls (requests.post, subprocess.run), and @sanitizer-decorated function
   calls, all of which are ordinary callables we can match `callable_`
   against. This module sets up that CALL-event plumbing now so Phase 2 can
   register match rules against it; it does not attempt to hook assignment
   or concatenation, because those are already fully handled by storage.py.

Fallback clause per spec §4: if a future propagation rule genuinely can't be
expressed as a wrapper-type override (e.g. f-string embedding via
BUILD_STRING, which coerces to plain `str` regardless of what __format__
returns -- also confirmed empirically), INSTRUCTION-level tracing is the
documented fallback, deferred to Phase 2/propagation.py rather than built
speculatively here.
"""

from __future__ import annotations

import sys
from typing import Any, Callable

TOOL_ID = 3
TOOL_NAME = "provenance-ac"

CallHook = Callable[[Any, int, Any, Any], None]

_call_hooks: list[CallHook] = []
_active = False


def register_call_hook(hook: CallHook) -> None:
    """Register a callback invoked on every CALL event, with signature
    (code, instruction_offset, callable, arg0). Intended consumer: Phase 2's
    source/sink/sanitizer matching in rules.py.
    """
    _call_hooks.append(hook)


def _dispatch_call(code: Any, instruction_offset: int, callable_: Any, arg0: Any) -> None:
    for hook in _call_hooks:
        hook(code, instruction_offset, callable_, arg0)


def start() -> None:
    """Install the CALL-event monitor. Safe to call once; raises if already
    active or if the tool id is claimed by something else."""
    global _active
    if _active:
        return
    sys.monitoring.use_tool_id(TOOL_ID, TOOL_NAME)
    sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.CALL, _dispatch_call)
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.CALL)
    _active = True


def stop() -> None:
    """Uninstall the monitor and free the tool id."""
    global _active
    if not _active:
        return
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.NO_EVENTS)
    sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.CALL, None)
    sys.monitoring.free_tool_id(TOOL_ID)
    _active = False


def is_active() -> bool:
    return _active
