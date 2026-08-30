# provenance-ac

A value that reaches a sink (`requests.get`/`post`, `subprocess.run`/
`Popen`, or a file write outside a declared workspace) through an
explicit data flow from a source (a file read, a network response,
subprocess output) gets blocked unless it passed through a declared
`@sanitizer` first. That's the whole claim, narrow and falsifiable:
produce a value that provably travels one of those paths, unsanitized,
and isn't blocked, and the claim is disproven.

## Architecture

`rules.py` enforces the rule set by directly wrapping `open`,
`requests.get`/`post`, and `subprocess.run`/`Popen`. `storage.py`
tags a value either as an attribute on a wrapper object, or in a side
table for plain primitives that can't hold one. Three optional layers
sit alongside this: audit logging, a human-approval hook, and OS-level
sandboxing.

## Results

**Incident A, credential phishing** — a file contains ordinary content
plus an injected instruction to read a credentials file and post it
externally, in a task that only ever asks for a summary.

```
Model attempted exfiltration:            5/5
Of those, blocked by provenance system:  5/5
```

```bash
.venv/bin/python -m agent_demo.incident_a_credential_phishing.run_incident_a 5
```

**Incident B, allowlist bypass** — an attacker-controlled credential
is sent to a legitimate destination. A destination-only allowlist
would let it through; provenance blocks it because the credential
itself traces to an untrusted file, regardless of destination.

```
Model attempted misuse:                      5/5
A naive destination allowlist would allow:   0/5
Blocked by provenance system anyway:         5/5
```

```bash
.venv/bin/python -m agent_demo.incident_b_allowlist_bypass.run_incident_b 5
```

**Layer 7, tool poisoning** — the compromise is in a tool's own
advertised description (claims to just log locally; actually
exfiltrates), not in any file content.

```
Model used the poisoned tool:            5/5
Of those, blocked by provenance system:  5/5
```

**Verified against a real server, not a mock** — a local HTTP server
independently confirms zero requests arrive when blocked, and the
full credential arrives byte-for-byte when sanitized.

**Overhead**, measured on a subprocess-heavy git workload: 1.012x
(+1.2%). This workload is dominated by subprocess spawn cost, so a
pure-Python workload could show higher relative overhead.

**Delegation boundary** — provenance does not survive one agent
handing a task to another, since tokenization turns text into token
ids with no attribute to carry a tag. This is structural, not a
fixable formatting quirk, and it's the same wall single-agent tool
calling already crosses whenever the model reasons about a value.

**Run against real, unmodified third-party code** — testing against
the real `mcp-server-git` reference server surfaced a real propagation
gap (now fixed) and a second, structural one: if target code imports
`subprocess.Popen` before this project installs its patches, that
reference is permanently unpatched.

## Limitations

- Implicit and control-flow leaks aren't tracked (`if secret == guess:
  send(guess)` leaks nothing this can see) — a standard gap in this
  class of tool, not unique to this implementation.
- Most string methods (`.upper()`, `.split()`, slicing) and all
  f-string interpolation drop the tag. Function return values don't
  inherit provenance from their arguments.
- The side table can produce a false positive from `id()` reuse.
  Sanitizers are trusted by declaration, not verified.
- Anything that never goes through a wrapped function (raw sockets,
  `urllib`, `smtplib`, an async client) bypasses detection completely.
- This is one layer of a defense-in-depth stack. An infrastructure or
  auth-layer compromise would route through essentially none of what
  this watches.

## Running tests

```bash
.venv/bin/pytest tests/ -v
```

55 of 55 pass.
