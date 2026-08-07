"""Phase 3 target/ milestone (spec §8): run instrumentation against a real,
unmodified, third-party Python project (not written by us) without
crashing, and find/fix propagation gaps real code patterns surface.

Target: mcp-server-git (vendored from modelcontextprotocol/servers,
unmodified) -- a real MCP server using GitPython, which shells out to the
real `git` binary via subprocess.Popen internally. Chosen specifically
because it's a real third-party library calling a function we already
wrap, rather than a fully async/httpx-only server (like mcp-server-fetch)
we'd have zero coverage on.

Two real, distinct gaps were found here, not one -- worth keeping
separate since they have different fixes:

1. `Git._unpack_args()` (GitPython's own argument-normalization code)
   calls `str(arg)` on every command-line argument before building the
   git command line. `str()` on a `ProvenanceStr` returns a plain,
   unflagged `str` -- confirmed empirically all the way back in Phase 1,
   now confirmed biting in real code. FIXED: `ProvenanceStr.__str__` now
   registers the resulting plain string in the side-table before
   returning it (storage.py).

2. `git/cmd.py` does `from subprocess import Popen` at its own import
   time; on non-Windows, `safer_popen = Popen` aliases that captured
   reference directly. If `git` gets imported before `rules.install()`
   ever runs, `git.cmd.Popen` stays bound to the *original* class
   forever -- reassigning `subprocess.Popen` afterward does not affect
   it. NOT fixable in our own code in general (Python's `from X import Y`
   copies a reference, decoupled from the source module after that
   point). The one real mitigation is operational: call `rules.install()`
   before importing any target code, not after.

Each scenario below runs in its own fresh subprocess, deliberately --
Python caches imports in sys.modules, so testing "import order" within a
single process risks the second scenario silently running against an
already-cached module from the first, which would test a false premise.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import textwrap

HERE = pathlib.Path(__file__).parent
PROJECT_ROOT = HERE.parent
TARGET_SRC = HERE / "mcp-server-git" / "src"

_COMMON_SETUP = f"""
import sys
sys.path.insert(0, {str(PROJECT_ROOT)!r})
sys.path.insert(0, {str(TARGET_SRC)!r})
import pathlib, tempfile
from provenance.exceptions import ProvenanceViolation
from provenance.storage import ProvenanceRecord, ProvenanceStr

def make_repo(tmp):
    import git as gitmodule
    repo_path = pathlib.Path(tmp) / "repo"
    repo_path.mkdir()
    repo = gitmodule.Repo.init(repo_path)
    (repo_path / "hello.txt").write_text("hello world\\n")
    return repo
"""

_STATUS_SCRIPT = _COMMON_SETUP + """
from provenance import rules
from mcp_server_git.server import git_status
with tempfile.TemporaryDirectory() as tmp:
    repo = make_repo(tmp)
    with rules.installed():
        output = git_status(repo)
        print("RESULT:", len(output))
"""

_INSTALL_BEFORE_IMPORT_SCRIPT = _COMMON_SETUP + """
from provenance import rules
rules.install()
from mcp_server_git.server import git_add
with tempfile.TemporaryDirectory() as tmp:
    repo = make_repo(tmp)
    flagged = ProvenanceStr("hello.txt", ProvenanceRecord(origins=("file:untrusted.txt",)))
    try:
        git_add(repo, [flagged])
        print("RESULT:blocked=False")
    except ProvenanceViolation:
        print("RESULT:blocked=True")
"""

_INSTALL_AFTER_IMPORT_SCRIPT = _COMMON_SETUP + """
import git as gitmodule  # noqa: F401 -- imported before install(), like most real programs
from mcp_server_git.server import git_add
from provenance import rules
with tempfile.TemporaryDirectory() as tmp:
    repo = make_repo(tmp)
    flagged = ProvenanceStr("hello.txt", ProvenanceRecord(origins=("file:untrusted.txt",)))
    with rules.installed():
        try:
            git_add(repo, [flagged])
            print("RESULT:blocked=False")
        except ProvenanceViolation:
            print("RESULT:blocked=True")
"""


def _run(script: str) -> str:
    result = subprocess.run([sys.executable, "-c", textwrap.dedent(script)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"subprocess failed:\n{result.stderr}")
    for line in result.stdout.splitlines():
        if line.startswith("RESULT:"):
            return line[len("RESULT:") :]
    raise RuntimeError(f"no RESULT line in output:\n{result.stdout}\n{result.stderr}")


def main() -> None:
    print("target/ milestone: instrumentation against real, unmodified third-party code\n")

    status_result = _run(_STATUS_SCRIPT)
    print(f"Runs without crashing: git_status() returned real output ({status_result} chars)")

    print()
    before = _run(_INSTALL_BEFORE_IMPORT_SCRIPT)
    print(f"install() before importing target code -> {before}  (expected: blocked=True, gap 1 fixed)")

    after = _run(_INSTALL_AFTER_IMPORT_SCRIPT)
    print(f"install() after importing target code  -> {after}  (expected: blocked=False, gap 2 unfixed)")

    print()
    if before == "blocked=True" and after == "blocked=False":
        print("Confirmed: gap 1 (str() stripping the flag in GitPython's own arg-normalization")
        print("code) is genuinely fixed. Gap 2 (import-time capture of Popen bypassing a later")
        print("patch) is real, distinct, and not fixable in our own code -- only mitigated by")
        print("installing before importing target code, which is documented, not silently assumed.")
    else:
        print("WARNING: unexpected result -- see README before trusting this.")


if __name__ == "__main__":
    main()
