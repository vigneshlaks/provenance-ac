# provenance-ac

Status: **Phase 1 and Phase 2 complete** (instrumentation core; rules and
enforcement). Phases 3-4 not started. Full project claim, demos, and
limitations section land in Phase 4 per the spec — this README currently
documents the architecture decisions made so far.

## ADR-001: instrumentation approach for assignment & concatenation

The spec (§4) requires `sys.monitoring` (PEP 669) as the primary
instrumentation mechanism, with a documented fallback if it "proves too
limited for a needed granularity."

Before writing `provenance/instrument.py`, I checked what `sys.monitoring`
actually exposes on Python 3.13:

```pycon
>>> import sys
>>> [e for e in dir(sys.monitoring.events) if not e.startswith('_')]
['BRANCH', 'CALL', 'C_RAISE', 'C_RETURN', 'EXCEPTION_HANDLED', 'INSTRUCTION',
 'JUMP', 'LINE', 'NO_EVENTS', 'PY_RESUME', 'PY_RETURN', 'PY_START',
 'PY_THROW', 'PY_UNWIND', 'RAISE', 'RERAISE', 'STOP_ITERATION']
```

There is no `STORE_NAME` or `BINARY_OP` event. Catching a specific opcode at
that granularity requires enabling `INSTRUCTION` (fires on *every* bytecode
instruction) and decoding the opcode by hand — the expensive path §4
anticipated.

That path turns out to be unnecessary for the two operations Phase 1 needs:

- **Assignment** (`b = a`) requires no instrumentation at all. CPython name
  binding just rebinds a name to the same object; if `a` is a
  `ProvenanceStr`, `b` is that identical object, attribute and all.
- **Concatenation** (`a + b`) is handled by operator overloading.
  Confirmed empirically that CPython's `+` still dispatches to
  `__add__`/`__radd__` on a `str` subclass (unlike most other `str`
  methods — see below), so `ProvenanceStr.__add__`/`__radd__` propagate
  provenance correctly without any bytecode hook:

  ```pycon
  >>> class S(str):
  ...     def __add__(self, other): return S(str.__add__(self, other))
  >>> type(S("a") + "b")
  <class '__main__.S'>
  ```

So `provenance/storage.py` (wrapper types) does the actual work for
Phase 1's milestone, not `provenance/instrument.py`.

`sys.monitoring` earns its place at a different point: the **`CALL`** event
fires on every call — including calls into builtins/C functions — with
signature `(code, instruction_offset, callable, arg0)`, confirmed by a
smoke test in `tests/test_propagation.py::test_call_event_hook_fires`. That
is the right mechanism for Phase 2: matching `callable_` against
`requests.post`, `subprocess.run`, `open(...).read`, and `@sanitizer`-
decorated functions to intercept sources/sinks/sanitizers. `instrument.py`
sets up that `CALL`-event plumbing now (tool id `3`, via
`sys.monitoring.use_tool_id`) so Phase 2's `rules.py` has something to
register against.

**Known gap, deferred to Phase 2:** f-string interpolation (`f"{s}"`)
compiles to `BUILD_STRING`, which always produces a plain `str` regardless
of what `__format__` returns — confirmed empirically. Propagating through
f-strings will need either `INSTRUCTION`-level tracing on `BUILD_STRING` or
an AST-level rewrite; not attempted in Phase 1 since the milestone only
requires assignment and `+` concatenation.

## Storage design (§4.1)

- **`ProvenanceStr(str)`** — used for strings we create ourselves (at
  sources). Holds a real `_provenance: ProvenanceRecord` attribute. Note
  most `str` methods (`.upper()`, `.split()`, slicing, `str(x)`) silently
  return a plain `str` and drop the subclass — confirmed empirically. Only
  `__add__`/`__radd__` are overridden so far; re-wrapping after other string
  methods is Phase 2 work (§6 item 5).
- **`ProvenanceDict(dict)`** — per-key `ProvenanceRecord`s in
  `_item_provenance`, auto-populated in `__setitem__` when the assigned
  value already carries provenance.
- **id-keyed side-table** (`storage.side_table`) — fallback for plain
  primitives that were never wrapped (e.g. a value crossing an
  uninstrumented C-extension boundary). This is a plain `dict`, **not** a
  real `WeakValueDictionary`: `str`/`int`/`float`/`bytes` instances don't
  support weak references in CPython (confirmed empirically — a
  custom-class instance does, a plain `str` doesn't), so there's no GC
  notification to expire stale entries. A reused `id()` after garbage
  collection can theoretically produce a false-positive flag. Documented,
  accepted risk — not eliminated. Wrapper types are preferred wherever
  possible specifically to avoid this class of bug for the common path.

## ADR-002: sink/source enforcement uses direct wrapping, not CALL events

Phase 1's plan (end of ADR-001) was to enforce sinks/sources via
`sys.monitoring`'s `CALL` event. Before writing `rules.py`, I tested that
plan directly and it doesn't hold up, for two independent reasons:

1. **`CALL`'s signature is `(code, instruction_offset, callable, arg0)` —
   only the first positional argument.** Confirmed empirically:
   `target(1, 2, c=3, d=4)` only exposes `arg0=1`; a bound method call
   exposes `self` as `arg0`, not the caller's real first argument. §5
   requires inspecting *all* arguments recursively — structurally
   impossible from this event alone.
2. **A `CALL` callback that does real work re-triggers itself.** A callback
   that called `print()` cascaded into monitoring every call the
   interpreter made internally (import machinery, module locks, ...) until
   the process crashed. A reentrancy guard (module-level flag in
   `instrument.py::_dispatch_call`) fixes the crash but not problem 1.

So `rules.py` enforces sinks/sources by **directly wrapping the target
callables** — `requests.get`/`post`, `subprocess.run`/`Popen`,
`builtins.open` — via `install()`/`uninstall()` (monkey-patching). The
wrapper receives the real `*args, **kwargs` from the call site directly, no
event system involved. `instrument.py`'s `CALL`-event plumbing from Phase 1
is kept — it's real, tested infrastructure — but repurposed as available
groundwork for later coverage/observability use, not the enforcement path.

## Phase 2: rules and enforcement (§5-6)

- `provenance/exceptions.py` — `ProvenanceViolation`, carrying the sink
  name, origins, and propagation chain.
- `provenance/rules.py` — the v1 source/sink/sanitizer list from §5:
  - Sinks: `requests.get`/`post`, `subprocess.run`/`Popen`,
    `open(path, 'w').write(...)` when `path` resolves outside the declared
    workspace (`set_workspace()`). Each sink calls `find_flagged()`, which
    recursively walks args/kwargs through dict/list/tuple/set, and raises
    `ProvenanceViolation` if it finds a flagged, unsanitized value.
  - Sources: `open(...).read()`/`.readlines()`, `requests` response
    `.text`/`.json()` (patched at the class level, since `.text` is a
    property — a data descriptor, so it can't be shadowed by a plain
    instance attribute), `subprocess.run(...).stdout`. `tag_source()`
    handles str (wraps in `ProvenanceStr`), dict/list (recurses per §6
    item 4), and falls back to the side-table for bytes/int/float.
  - `@sanitizer` — clears the flag on a function's return value, trusted
    by declaration per §5.
- `install()`/`uninstall()`/`installed()` (context manager) apply and
  revert all the monkey-patches together.

## Running tests

```bash
.venv/bin/pytest tests/ -v
```

20/20 passing:
- `test_propagation.py` (11) — Phase 1: a flagged string survives
  assignment and both directions of `+` concatenation, with origins
  merging correctly.
- `test_enforcement.py` (9) — Phase 2 milestone: a hand-written script
  (file read → concat → `requests.post`) is blocked; the same script with
  an explicit `@sanitizer` step is allowed. Also covers `subprocess.run`
  as a sink and a source, and the workspace-boundary file-write sink both
  ways.

## Next: Phase 3

Select a real, small, open-source Python project and run instrumentation
against it without crashing; reconstruct the two Anthropic incidents
concretely.
