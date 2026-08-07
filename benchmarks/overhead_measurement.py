"""Phase 4 (spec §8): real, measured runtime overhead of instrumentation --
not an estimate. Runs a representative workload against the real,
unmodified target/mcp-server-git code, with and without
provenance.rules.installed(), and reports the actual multiplier.

Methodology, matching the standard practice for this kind of measurement
(the sys.settrace/sys.monitoring benchmarking literature reviewed earlier
in this project uses repeated runs, not a single sample, to average out
OS-level scheduling noise): run the same fixed workload cycle N times per
condition, take the median across repetitions (robust to occasional
outliers a mean isn't), report median-with-instrumentation /
median-without as the real multiplier.

Each repetition uses a *fresh* temp repo, and does the same fixed number
of operations within it -- so repo growth (more commits => slower log/
status) affects both conditions identically, and the comparison isolates
instrumentation overhead specifically rather than being confounded by
repo size drifting differently between conditions.
"""

from __future__ import annotations

import pathlib
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "target" / "mcp-server-git" / "src"))

import git as gitmodule
from mcp_server_git.server import git_add, git_commit, git_diff_unstaged, git_log, git_status

from provenance import rules
from provenance.storage import side_table

CYCLES_PER_RUN = 20
REPETITIONS = 11  # odd number -> clean median


def workload_cycle(repo: "gitmodule.Repo", i: int) -> None:
    fname = f"file_{i}.txt"
    path = pathlib.Path(repo.working_dir) / fname
    path.write_text(f"content {i}\n")
    git_add(repo, [fname])
    git_commit(repo, f"add {fname}")
    path.write_text(f"content {i} v2\n")
    git_diff_unstaged(repo)
    git_add(repo, [fname])
    git_commit(repo, f"update {fname}")
    git_status(repo)
    git_log(repo, max_count=5)


def run_once(instrumented: bool) -> float:
    with tempfile.TemporaryDirectory() as tmp:
        repo = gitmodule.Repo.init(pathlib.Path(tmp) / "repo")

        if instrumented:
            # ADR-006: the side-table is process-global and never cleared
            # by uninstall() -- reset it between independent repetitions so
            # a stale id()-keyed entry from an earlier, already-deleted
            # temp repo can't collide with a new object in this one (this
            # is exactly what happened the first time this benchmark ran).
            side_table.clear_all()
            # Workspace defaults to CWD, not this run's temp repo -- set it
            # explicitly so git's own internal bookkeeping writes
            # (.git/COMMIT_EDITMSG, etc.) are correctly treated as inside
            # the intended operating area, not flagged as "outside
            # workspace" writes.
            rules.set_workspace(repo.working_dir)
            rules.install()
        try:
            start = time.perf_counter()
            for i in range(CYCLES_PER_RUN):
                workload_cycle(repo, i)
            elapsed = time.perf_counter() - start
        finally:
            if instrumented:
                rules.uninstall()
        return elapsed


def main() -> None:
    print(f"Overhead measurement: {REPETITIONS} repetitions x {CYCLES_PER_RUN} cycles/run")
    print(f"Workload/cycle: write file, add, commit, diff, add, commit, status, log\n")

    baseline_times = [run_once(instrumented=False) for _ in range(REPETITIONS)]
    instrumented_times = [run_once(instrumented=True) for _ in range(REPETITIONS)]

    baseline_median = statistics.median(baseline_times)
    instrumented_median = statistics.median(instrumented_times)
    multiplier = instrumented_median / baseline_median

    print(f"Baseline (no instrumentation):     median={baseline_median:.4f}s  "
          f"min={min(baseline_times):.4f}s  max={max(baseline_times):.4f}s")
    print(f"Instrumented (rules.installed()):  median={instrumented_median:.4f}s  "
          f"min={min(instrumented_times):.4f}s  max={max(instrumented_times):.4f}s")
    print()
    print(f"Real measured overhead multiplier: {multiplier:.3f}x  ({(multiplier - 1) * 100:+.1f}%)")
    print(
        "\nCaveat: this workload is subprocess-dominated (6 real git command "
        "spawns per cycle) -- the git binary's own execution cost swamps our "
        "per-call Python-level check. A workload with many pure-Python "
        "operations and few real subprocess/network calls would have less "
        "real work to amortize the check against, and could show higher "
        "relative overhead than this number suggests."
    )


if __name__ == "__main__":
    main()
