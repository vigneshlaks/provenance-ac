"""v1 source/sink/sanitizer rules (spec §5) and enforcement.

See instrument.py's ADR-002 for why this uses direct wrapping of the target
callables (requests.get/post, subprocess.run/Popen, builtins.open) rather
than sys.monitoring's CALL event: CALL only exposes the first positional
argument, and a CALL callback that does real work risks a reentrant crash.
Wrapping gets the real *args/**kwargs directly from the call site, with
neither problem.

Sources tag return values with a ProvenanceRecord. Sinks call find_flagged()
on their arguments and raise ProvenanceViolation if anything flagged and
unsanitized is found.
"""

from __future__ import annotations

import builtins
import contextlib
import functools
import pathlib
import subprocess
from typing import Any, Callable, Iterator

from .exceptions import ProvenanceViolation
from .storage import ProvenanceDict, ProvenanceRecord, ProvenanceStr, get_provenance, side_table

try:
    import requests
except ImportError:  # pragma: no cover - requests is a demo dependency, not core
    requests = None


# --------------------------------------------------------------------------
# Sanitizer
# --------------------------------------------------------------------------

def sanitizer(func: Callable) -> Callable:
    """Decorator: calling `func` clears the provenance flag on its return
    value. v1 does not verify the function actually does anything -- the
    sanitizer is trusted by declaration (spec §5, a documented limitation).
    """

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
# Recursive flagged-value scan (spec §5: "inspect all arguments, recursively
# through basic containers")
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
    """Return (value, record) for the first flagged-and-unsanitized value
    found in args/kwargs, or (None, None) if none found."""
    for value in _walk(args):
        record = get_provenance(value)
        if record is not None and record.flagged():
            return value, record
    for value in _walk(kwargs):
        record = get_provenance(value)
        if record is not None and record.flagged():
            return value, record
    return None, None


def check_sink(sink_name: str, *args: Any, **kwargs: Any) -> None:
    value, record = find_flagged(*args, **kwargs)
    if value is not None:
        raise ProvenanceViolation(sink_name, record.origins, record.chain)


# --------------------------------------------------------------------------
# Source tagging
# --------------------------------------------------------------------------

def tag_source(value: Any, origin: str) -> Any:
    """Tag a plain value (str, bytes, int, float, dict, list) as coming from
    `origin`. Strings get wrapped in ProvenanceStr; dict/list get walked
    recursively (§6 item 4); other primitives fall back to the side-table."""
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
# Sink/source: subprocess.run / subprocess.Popen
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
# Sink/source: requests.get / requests.post
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
# Source/sink: open(...).read() / open(path, 'w').write()
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
            check_sink(f"open({self._path!r}, write-mode).write [outside workspace]", data)
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
# Install / uninstall
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
