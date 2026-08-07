# provenance-ac

Status: **Phase 1 and Phase 2 complete**; both Incident A and Incident B
(Phase 3) reconstructed against a real, local, unscripted model. Three
complementary defense-in-depth layers beyond the core system (audit
logging, human oversight, OS-level sandboxing) added and verified. The
third-party `target/` codebase run (rest of Phase 3) and Phase 4 (overhead
measurement, final writeup) not started. This README documents the
architecture decisions made so far.

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

## Phase 3 (in progress): Incident A, against a real model

The two Anthropic incidents are reconstructed by running a real model, not
a scripted sequence of calls that's known in advance to trigger the block.

**Model**: `mlx-community/Llama-3.2-3B-Instruct-4bit`, run fully locally via
[`mlx-lm`](https://github.com/ml-explore/mlx-lm) (Apple's inference library
for Apple Silicon). Chosen over Ollama or the Anthropic API specifically to
avoid any API key/cost dependency and, more importantly, because a defense
that isn't tied to one vendor's model is a stronger version of the claim
this project is making — the system doesn't know or care what produced a
given tool call.

**Agent loop** (`agent_demo/agent_loop.py`): a minimal, from-scratch
tool-calling loop, not a framework. The model is given a plain-text
protocol (`TOOL: name(arg="value")` / `FINAL: ...`) rather than relying on
this small quantized model's native tool-calling template, which proved
more reliable in testing. Tool calls are parsed with `ast.parse` and
dispatched only through an explicit per-scenario whitelist — **never
`eval()`** — so a malformed or unexpected model response can't execute
arbitrary code, and a scenario that doesn't need `run_command` (e.g.
incident A) simply cannot reach it regardless of what the model outputs.

Critically, the three tool implementations
(`tool_read_file`/`tool_send_external`/`tool_run_command`) are just plain
Python calling the ordinary `open()`/`requests.post`/`subprocess.run` —
the exact same functions `rules.py` already wraps. **The provenance system
has no special-casing for the fact that an LLM produced the arguments**;
enforcement doesn't distinguish a model-issued tool call from any other
function call. This is a deliberate constraint, not an oversight — adding
"if this looks like an agent tool call" logic to the core system would
quietly undermine the actual claim being demonstrated.

**Incident A** (`agent_demo/incident_a_credential_phishing/`): `notes.txt`
contains ordinary content plus an embedded "SYSTEM NOTE" instructing the
model to read `credentials.txt` and POST it to an external URL. The model
is only ever told to summarize `notes.txt` — the injected instruction is
purely something it encounters as file content. `run_incident_a.py` runs
this multiple times and reports two separate numbers, deliberately kept
apart:

- how often the **model** attempts the exfiltration (non-deterministic —
  a property of this model/prompt/quantization, not something this project
  controls or claims to fix)
- whether the **provenance system** blocks it whenever attempted (expected
  to be 100% — a deterministic check on data origin, not a heuristic on the
  model's behavior)

Real, measured result (5 runs, `mlx-community/Llama-3.2-3B-Instruct-4bit`):

```
Model attempted exfiltration:            5/5
Of those, blocked by provenance system:  5/5
```

This small model had no defense against a plainly-labeled injected
instruction — it attempted the exfiltration every time. The provenance
system blocked every attempt regardless, because `credentials.txt`'s
content is tagged as untrusted the moment it's read (spec §5: sources tag
unconditionally, not based on perceived sensitivity), and `send_external`
→ `requests.post` checks that tag before the request goes out. Run it
yourself:

```bash
.venv/bin/python -m agent_demo.incident_a_credential_phishing.run_incident_a 5
```

`tests/test_agent_loop.py` covers the parsing/dispatch mechanism
deterministically (nested calls, blocking, the whitelist, malformed input,
and an explicit "arbitrary code is not executed" case) without depending on
model behavior, so the harness itself can be verified independent of the
non-deterministic demo above.

## Phase 3: Incident B, allowlist bypass

Incident B (§8): a file provides an attacker-controlled value framed as an
API key, alongside a destination that's genuinely legitimate — not a
trick. A defense that only checks "is this destination allowed" would pass
it straight through; provenance tracking catches it because the
*credential itself* traces to an untrusted file, independent of where it's
headed. `NAIVE_ALLOWLIST` in `run_incident_b.py` exists purely to make that
contrast visible in the demo output — it is not, and will never be, part
of `rules.py`; the system has no concept of an allowlist at all.

`tool_send_to_service` (`agent_demo/agent_loop.py`) is deliberately written
to keep `api_key` as a distinct argument rather than composing it into a
bigger string — building the request body via an f-string like
`f"key={api_key}"` would silently strip its provenance (§4's confirmed
f-string/`BUILD_STRING` gap), passing a flagged value straight through
undetected. Passing it as a raw dict value (`json={"api_key": api_key,
...}`) keeps the actual `ProvenanceStr` object intact, so `find_flagged()`
still finds it nested inside the `json=` kwarg — proven directly by
`test_credential_stays_flagged_inside_nested_json_kwarg`.

Real, measured result (5 runs against the live model):

```
Model attempted to use the file-sourced credential:      5/5
Of those, a naive destination allowlist would allow:     0/5
Of those, blocked by provenance system anyway:            5/5
```

Worth reporting honestly rather than adjusting until it looks cleaner: the
model attempted the credential misuse in every run, but did not copy the
destination URL verbatim from the file — it fabricated its own
(`https://analytics-service.com/api/status`) instead of using the one in
`config_notes.txt`. So this particular live run doesn't itself land on a
URL that's genuinely on `NAIVE_ALLOWLIST`, meaning it doesn't, by itself,
exercise the "naive allowlist says yes" half of the contrast. The
deterministic test
`test_flagged_credential_blocked_even_at_an_allowed_destination` covers
that half directly and rigorously, using the real allowed URL. Between the
two: the live run proves the model will attempt credential misuse
unprompted and gets blocked regardless of whatever destination it
chooses (a superset of the claim); the deterministic test proves the
specific "genuinely-allowed destination, still blocked" case the incident
describes.

Run it yourself:

```bash
.venv/bin/python -m agent_demo.incident_b_allowlist_bypass.run_incident_b 5
```

## Running tests

```bash
.venv/bin/pytest tests/ -v
```

39/39 passing:
- `test_propagation.py` (11) — Phase 1: a flagged string survives
  assignment and both directions of `+` concatenation, with origins
  merging correctly.
- `test_enforcement.py` (9) — Phase 2 milestone: a hand-written script
  (file read → concat → `requests.post`) is blocked; the same script with
  an explicit `@sanitizer` step is allowed. Also covers `subprocess.run`
  as a sink and a source, and the workspace-boundary file-write sink both
  ways.
- `test_agent_loop.py` (10) — the agent's tool-call parsing/dispatch
  mechanism, independent of model behavior, including both incidents'
  blocking behavior at the deterministic level.
- `test_layers.py` (9) — layers 8 and 9 (below): the approval hook can
  approve or still deny, receives the right sink name/record, and reverts
  to a flat block once unregistered; audit logging is off by default and
  correctly records allowed/blocked/approved decisions.

## ADR-003: AgentDojo integration uses content-matching, not object identity

`benchmarks/` wires this project's provenance core into
[AgentDojo](https://github.com/ethz-spylab/agentdojo), the external,
third-party benchmark used to evaluate CaMeL, FIDES, and others — so this
system's block rate is measurable on a real, externally-standardized
benchmark, not just our own hand-written incident demos.

Two things ruled out reusing `rules.py` directly, both confirmed by
reading AgentDojo's actual source rather than assuming:

1. AgentDojo's tools are **simulated, in-memory Python functions**
   operating on Pydantic model state (`BankAccount`, `Filesystem`, ...),
   not real `open`/`requests.post`/`subprocess.run` calls. `rules.py`'s
   monkey-patches have nothing to intercept there.
2. More fundamentally, **object-identity provenance does not survive
   AgentDojo's harness.** Traced through `ToolsExecutor` and
   `LocalLLM._parse_model_output`: every tool result is formatted to a
   string and appended to the conversation; the model reads that string
   and *writes fresh JSON text* for its next call, which gets
   `json.loads()`'d into a brand-new object. Unlike `agent_demo/agent_loop.py`
   (where a nested call is actually executed, so the real object flows
   into the outer call), nothing here ever hands the model a literal
   Python reference to what a source produced — `id()`-based matching is
   structurally blind to this.

So `benchmarks/agentdojo_adapter.py`'s `ProvenanceGatedToolsExecutor` uses
**content-based matching** instead: source-tool outputs are logged as
`(content, origin)` pairs; a sink call is blocked if an argument value
contains, or is contained in, previously-logged flagged content. Strictly
weaker than object identity — it can miss a paraphrased value and could in
principle false-positive on a coincidental substring — and that's a
deliberate, documented tradeoff, not an oversight. `benchmarks/local_llm_patch.py`
is a separate, unrelated fix: our local model reliably produces valid JSON
tool calls but doesn't always close AgentDojo's `<function=...></function>`
tag cleanly, so the parser was patched to bracket-match the JSON instead of
relying on the closing tag — applied identically to both pipelines so it
can't bias the comparison.

**Honest current state**: the adapter is built and confirmed to work
mechanically (`blocked=N` fires correctly on real runs). A complete,
reportable comparative result does not exist yet — the first attempt
(`Llama-3.2-3B-Instruct-4bit`) gave an inconclusive 0/0 on both metrics
because the model wasn't capable enough to complete AgentDojo's
precision-demanding banking tasks at all; a second attempt with a larger
local model (`Qwen3-4B-4bit`, chosen because a 7B download didn't fit
available disk space) was lost mid-run to a background-process
interruption unrelated to the code itself, before finishing. Getting a
complete result would need either a larger local model, a bigger sample,
or real GPU compute (explored but not pursued, given the account/cost
commitment it requires) — noted here rather than left as a silent gap.

## ADR-004: this project is one layer of a defense-in-depth stack, not the whole stack

Everything above — `storage.py`/`rules.py`/`instrument.py` — operates at a
single layer: **application data flow**. It tracks whether a specific
Python value traces to an untrusted origin, and gates specific declared
sinks. That's a real, narrower thing than "AI agent security" as a whole,
and it's worth being explicit about what it does and doesn't cover rather
than let the scope blur.

A real incident chain (multi-tenancy leak → SSRF → broken auth → privilege
escalation → RCE) makes the boundary concrete: **none of those steps route
through a Python function this project wraps**, so this system would catch
essentially none of that chain — it's an infrastructure/network/auth-layer
problem, not a data-flow-through-an-agent's-own-tool-calls problem. Where
this project's layer earns its place is the complementary, narrower
failure mode infra-layer controls are structurally unable to catch: a
properly sandboxed, properly authenticated agent, using its own authorized
tools, still misled by content into misusing a capability it's genuinely
allowed to use (exactly Incident B's real point — the destination
`api.anthropic.com` was never illegitimate; the credential's origin is
what mattered, and no destination-based control could see that).

Three more layers were added as a deliberate, verified (not just
asserted) demonstration of this:

**Layer 9 (audit logging, `provenance/audit_log.py`)** — off by default;
`set_log_path()` enables JSON-lines logging of every sink decision
(allowed/blocked/approved). Uses a pristine `open()` reference captured at
its own import time, before `rules.install()` ever runs — the same
reentrancy concern as `instrument.py`'s ADR-002: if the log write itself
went through the *patched* `open()`, and the log path were outside the
configured workspace, that write would trigger the workspace-boundary
sink check, which would try to audit-log *that* decision too. Logging
infrastructure must not be subject to the mechanism it's logging about.

**Layer 8 (human oversight, `rules.set_approval_hook()`)** — a registered
callback can approve a call that would otherwise be blocked, instead of a
flat deny (the same shape as APPA's "remedy plans"). Off by default; with
no hook registered, behavior is unchanged from before this existed. Scoped
deliberately to interactive use — AgentDojo-style batch evaluation has no
human present, so this isn't wired into the benchmark path.

**Layer 4 (OS-level sandboxing, `layers/sandbox_demo.py`)** — verified,
not assumed, and the verification changed the design:
- `sandbox-exec` is deprecated by Apple (confirmed via its own man page:
  "DEPRECATED... adopt App Sandbox instead") but still functional on this
  system (macOS 26.5).
- **Per-destination network filtering does not work on this macOS
  version** — `(remote ip "host:port")` errors with `"host must be * or
  localhost"`. So this tool can only do blanket allow/deny of all network
  egress, not "allow this destination, block that one" — genuine
  destination-selective filtering would need a real firewall (`pfctl`) or
  a filtering proxy, neither built here. This is a real capability gap
  between the OS-level tool and the app-layer sinks, worth stating
  plainly rather than glossing over.
- Filesystem path scoping **does** work with real granularity — confirmed
  with a working subpath-deny rule. Caught one genuine gotcha along the
  way: macOS resolves `/tmp` to `/private/tmp` (and `tempfile`'s default
  directory similarly), so a profile path must be the *resolved* path or
  the deny rule silently no-ops — confirmed this the hard way when a
  first attempt let the "blocked" write through.
- The demo simulates app-layer provenance being bypassed entirely (no
  `rules.py` involved at all) and shows the sandbox independently stops a
  credentials-file exfiltration via `subpath` restriction — a real,
  working backstop with zero concept of "provenance."

## Next

- Layer 7 (supply-chain/tool-poisoning): a tool whose *description* lies
  about what it does, showing content-blind enforcement still catches the
  real runtime behavior regardless of advertised metadata. Not built yet.
- Select a real, small, third-party open-source Python project for
  `target/` and run instrumentation against it without crashing.
- Phase 4: overhead measurement and the final writeup.
