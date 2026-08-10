"""Source, sink, and sanitizer rules, and the enforcement built on top of them.

The target callables are wrapped directly (requests.get and requests.post,
subprocess.run and subprocess.Popen, builtins.open) rather than going
through sys.monitoring's CALL event. The reasoning for that choice lives in
instrument.py. Sources tag their return values with a ProvenanceRecord, and
sinks call find_flagged() on their arguments, raising ProvenanceViolation if
anything flagged and unsanitized turns up.
"""

from __future__ import annotations

import builtins
import contextlib
import functools
import pathlib
import subprocess
from typing import Any, Callable, Iterator

from . import audit_log
from .exceptions import ProvenanceViolation
from .storage import ProvenanceDict, ProvenanceRecord, ProvenanceStr, get_provenance, side_table

try:
    import requests
except ImportError:  # pragma: no cover; requests is a demo dependency, not core
    requests = None


# --------------------------------------------------------------------------
# Sanitizer
# --------------------------------------------------------------------------

def sanitizer(func: Callable) -> Callable:
    """A decorator. Calling the wrapped function clears the provenance flag
    on whatever it returns. This is trusted by declaration, since nothing
    checks that the function actually sanitized anything."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = func(*args, **kwargs)
        record = get_provenance(result)
        if record is None:
            return result
        sanitized = record.sanitize(func.__name__)
        if isinstance(result, ProvenanceStr):
            return ProvenanceStr(str.__str__(result), sanitized)
        side_table.attach(result, sanitized)
        return result

    return wrapper


# --------------------------------------------------------------------------
# Recursive scan for flagged values, walking arguments through basic
# containers
# --------------------------------------------------------------------------

def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _walk(v)


def find_flagged(*args: Any, **kwargs: Any) -> tuple[Any, "ProvenanceRecord | None"]:
    """Returns the first value found in args or kwargs that is flagged and
    not sanitized, along with its record, or (None, None) if nothing
    matches."""
    for value in _walk(args):
        record = get_provenance(value)
        if record is not None and record.flagged():
            return value, record
    for value in _walk(kwargs):
        record = get_provenance(value)
        if record is not None and record.flagged():
            return value, record
    return None, None


ApprovalHook = Callable[[str, Any, ProvenanceRecord], bool]

_approval_hook: "ApprovalHook | None" = None


def set_approval_hook(hook: "ApprovalHook | None") -> None:
    """Registers a callback invoked when a sink call would otherwise be
    blocked, so a human, or some other policy, can approve it instead of a
    flat denial. The hook takes the sink name, the value, and the record,
    and returns True to approve the call or False to deny it, the same as
    if no hook were registered. No hook is registered by default. Passing
    None removes it."""
    global _approval_hook
    _approval_hook = hook


def check_sink(sink_name: str, *args: Any, **kwargs: Any) -> None:
    value, record = find_flagged(*args, **kwargs)
    if value is None:
        audit_log.record(sink_name, "allowed")
        return
    if _approval_hook is not None and _approval_hook(sink_name, value, record):
        audit_log.record(sink_name, "approved", record.origins, record.chain)
        return
    audit_log.record(sink_name, "blocked", record.origins, record.chain)
    raise ProvenanceViolation(sink_name, record.origins, record.chain)


# --------------------------------------------------------------------------
# Source tagging
# --------------------------------------------------------------------------

def tag_source(value: Any, origin: str) -> Any:
    """Tags a plain value (a string, bytes, int, float, dict, or list) as
    coming from the given origin. Strings get wrapped in a ProvenanceStr.
    Dicts and lists get walked recursively. Everything else falls back to
    the side table."""
    if isinstance(value, str):
        return ProvenanceStr(value, ProvenanceRecord(origins=(origin,)))
    if isinstance(value, dict):
        tagged = ProvenanceDict()
        for k, v in value.items():
            tagged[k] = tag_source(v, origin)
        return tagged
    if isinstance(value, list):
        return [tag_source(v, origin) for v in value]
    if isinstance(value, (bytes, int, float)):
        side_table.attach(value, ProvenanceRecord(origins=(origin,)))
        return value
    return value


# --------------------------------------------------------------------------
# Workspace boundary (for the open(...).write() sink)
# --------------------------------------------------------------------------

_workspace = pathlib.Path.cwd().resolve()


def set_workspace(path: Any) -> None:
    global _workspace
    _workspace = pathlib.Path(path).resolve()


def _inside_workspace(path: Any) -> bool:
    try:
        resolved = pathlib.Path(path).resolve()
    except OSError:
        return False
    try:
        resolved.relative_to(_workspace)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Sink and source: subprocess.run and subprocess.Popen
# --------------------------------------------------------------------------

_original_run = subprocess.run
_original_popen = subprocess.Popen


def _run_wrapper(*args: Any, **kwargs: Any) -> Any:
    check_sink("subprocess.run", *args, **kwargs)
    result = _original_run(*args, **kwargs)
    if result.stdout is not None:
        cmd = args[0] if args else kwargs.get("args")
        result.stdout = tag_source(result.stdout, f"subprocess:{cmd!r}")
    return result


class _PopenWrapper(_original_popen):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        check_sink("subprocess.Popen", *args, **kwargs)
        super().__init__(*args, **kwargs)


# --------------------------------------------------------------------------
# Sink and source: requests.get and requests.post
# --------------------------------------------------------------------------

if requests is not None:
    _original_requests_get = requests.get
    _original_requests_post = requests.post
    _original_response_text = requests.models.Response.text
    _original_response_json = requests.models.Response.json

    def _tagged_text(self: Any) -> Any:
        value = _original_response_text.fget(self)
        origin = getattr(self, "_provenance_origin", f"network:{getattr(self, 'url', '?')}")
        return tag_source(value, origin)

    def _tagged_json(self: Any, *args: Any, **kwargs: Any) -> Any:
        value = _original_response_json(self, *args, **kwargs)
        origin = getattr(self, "_provenance_origin", f"network:{getattr(self, 'url', '?')}")
        return tag_source(value, origin)

    def _make_requests_wrapper(name: str, original: Callable) -> Callable:
        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check_sink(name, *args, **kwargs)
            response = original(*args, **kwargs)
            url = args[0] if args else kwargs.get("url")
            response._provenance_origin = f"network:{url}"
            return response
        return wrapper

    _requests_get_wrapper = _make_requests_wrapper("requests.get", _original_requests_get)
    _requests_post_wrapper = _make_requests_wrapper("requests.post", _original_requests_post)


# --------------------------------------------------------------------------
# Source and sink: open(...).read() and open(path, 'w').write()
# --------------------------------------------------------------------------

_original_open = builtins.open


class _TrackedFile:
    def __init__(self, fileobj: Any, path: Any):
        object.__setattr__(self, "_fileobj", fileobj)
        object.__setattr__(self, "_path", path)

    def read(self, *args: Any, **kwargs: Any) -> Any:
        return tag_source(self._fileobj.read(*args, **kwargs), f"file:{self._path}")

    def readlines(self, *args: Any, **kwargs: Any) -> Any:
        return [tag_source(line, f"file:{self._path}") for line in self._fileobj.readlines(*args, **kwargs)]

    def write(self, data: Any) -> Any:
        if not _inside_workspace(self._path):
            check_sink(f"open({self._path!r}, write mode).write, outside the workspace", data)
        return self._fileobj.write(data)

    def __enter__(self) -> "_TrackedFile":
        self._fileobj.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        return self._fileobj.__exit__(*exc)

    def __iter__(self) -> Iterator[Any]:
        for line in self._fileobj:
            yield tag_source(line, f"file:{self._path}")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fileobj, name)


def _open_wrapper(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> _TrackedFile:
    fileobj = _original_open(file, mode, *args, **kwargs)
    return _TrackedFile(fileobj, file)


# --------------------------------------------------------------------------
# Install and uninstall
# --------------------------------------------------------------------------

_installed = False


def install() -> None:
    global _installed
    if _installed:
        return
    subprocess.run = _run_wrapper
    subprocess.Popen = _PopenWrapper
    builtins.open = _open_wrapper
    if requests is not None:
        requests.get = _requests_get_wrapper
        requests.post = _requests_post_wrapper
        requests.models.Response.text = property(_tagged_text)
        requests.models.Response.json = _tagged_json
    _installed = True


def uninstall() -> None:
    global _installed
    if not _installed:
        return
    subprocess.run = _original_run
    subprocess.Popen = _original_popen
    builtins.open = _original_open
    if requests is not None:
        requests.get = _original_requests_get
        requests.post = _original_requests_post
        requests.models.Response.text = _original_response_text
        requests.models.Response.json = _original_response_json
    _installed = False


@contextlib.contextmanager
def installed() -> Iterator[None]:
    install()
    try:
        yield
    finally:
        uninstall()
