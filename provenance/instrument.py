"""sys.monitoring (PEP 669) integration.

Why this module doesn't do more than it does:

Assignment, as in b = a, needs no instrumentation at all. CPython name
binding just rebinds a name to the same object, so a ProvenanceStr's
_provenance attribute survives automatically. Concatenation, as in a + b, is
handled by ProvenanceStr.__add__ and __radd__ in storage.py, since
CPython's + dispatches through the normal operator protocol even for str
subclasses. Neither one needs bytecode level tracing.

sys.monitoring's CALL event isn't used for sink and source enforcement,
even though it looks like a natural fit. Its callback signature is
(code, instruction_offset, callable, arg0), which only exposes the first
positional argument, and for bound methods that argument is self, so it
isn't enough to inspect every argument at a sink call. It is also
reentrant: a callback that does actual work, such as a print call, a dict
lookup, or string formatting, is itself a call, which re-triggers CALL and
can cascade into monitoring the interpreter's own internal calls. The
reentrancy guard in _dispatch_call below handles the cascade, but it
doesn't fix the missing arguments problem.

rules.py enforces sinks and sources instead by directly wrapping the target
callables, monkey patching requests.post, subprocess.run, builtins.open,
and so on, so the wrapper gets the actual positional and keyword arguments
straight from the call site. The CALL event plumbing below is kept as
working infrastructure for coverage and observability, for example
answering "did we see a call to something with no source or sink rule", but
it isn't the enforcement mechanism.

If a future propagation rule can't be expressed as a wrapper type override,
for example f-string embedding, which coerces to a plain str regardless of
what __format__ returns, INSTRUCTION level tracing is the fallback. It
isn't needed yet for anything currently propagated.
"""

from __future__ import annotations

import sys
from typing import Any, Callable

TOOL_ID = 3
TOOL_NAME = "provenance-ac"

CallHook = Callable[[Any, int, Any, Any], None]

_call_hooks: list[CallHook] = []
_active = False
_dispatching = False


def register_call_hook(hook: CallHook) -> None:
    """Registers a callback invoked on every CALL event, with the signature
    (code, instruction_offset, callable, arg0). This is not used for sink
    or source enforcement, see the module docstring, but it is available
    for coverage and observability tooling.
    """
    _call_hooks.append(hook)


def _dispatch_call(code: Any, instruction_offset: int, callable_: Any, arg0: Any) -> None:
    # Reentrancy guard. A hook that itself makes a call, such as a print or
    # a dict lookup, would otherwise re-trigger this same CALL event and
    # cascade into monitoring the interpreter's own internal calls.
    global _dispatching
    if _dispatching:
        return
    _dispatching = True
    try:
        for hook in _call_hooks:
            hook(code, instruction_offset, callable_, arg0)
    finally:
        _dispatching = False


def start() -> None:
    """Installs the CALL event monitor. Safe to call once. Raises if it is
    already active, or if the tool id is claimed by something else."""
    global _active
    if _active:
        return
    sys.monitoring.use_tool_id(TOOL_ID, TOOL_NAME)
    sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.CALL, _dispatch_call)
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.CALL)
    _active = True


def stop() -> None:
    """Uninstalls the monitor and frees the tool id."""
    global _active
    if not _active:
        return
    sys.monitoring.set_events(TOOL_ID, sys.monitoring.events.NO_EVENTS)
    sys.monitoring.register_callback(TOOL_ID, sys.monitoring.events.CALL, None)
    sys.monitoring.free_tool_id(TOOL_ID)
    _active = False


def is_active() -> bool:
    return _active
