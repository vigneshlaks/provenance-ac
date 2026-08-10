"""Measured runtime overhead of instrumentation. This runs a representative
workload against the unmodified target/mcp-server-git code, with and
without provenance.rules.installed(), and reports the actual multiplier.

It runs the same fixed workload cycle N times per condition and takes the
median across repetitions, which is robust to occasional outliers in a way
a mean isn't, and reports the median with instrumentation divided by the
median without as the multiplier.

Each repetition uses a fresh temp repo and does the same fixed number of
operations within it, so repo growth, meaning more commits leading to a
slower log or status, affects both conditions identically. This isolates
the instrumentation overhead rather than confounding it with repo size
drifting differently between conditions.
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
REPETITIONS = 11  # An odd number gives a clean median.


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
            # The side table is global to the process and never cleared by
            # uninstall(), so it's reset between repetitions here. Without
            # that, a stale id() keyed entry from an earlier, already
            # deleted temp repo could collide with a new object in this
            # one.
            side_table.clear_all()
            # The workspace defaults to the current working directory, not
            # this run's temp repo, so it's set explicitly here. That way
            # git's own bookkeeping writes, such as .git/COMMIT_EDITMSG,
            # are treated as inside the operating area rather than flagged
            # as writes outside the workspace.
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
    print(f"Overhead measurement: {REPETITIONS} repetitions of {CYCLES_PER_RUN} cycles each")
    print("Workload per cycle: write file, add, commit, diff, add, commit, status, log\n")

    baseline_times = [run_once(instrumented=False) for _ in range(REPETITIONS)]
    instrumented_times = [run_once(instrumented=True) for _ in range(REPETITIONS)]

    baseline_median = statistics.median(baseline_times)
    instrumented_median = statistics.median(instrumented_times)
    multiplier = instrumented_median / baseline_median

    print(f"Baseline, no instrumentation:     median={baseline_median:.4f}s  "
          f"min={min(baseline_times):.4f}s  max={max(baseline_times):.4f}s")
    print(f"Instrumented, rules.installed():  median={instrumented_median:.4f}s  "
          f"min={min(instrumented_times):.4f}s  max={max(instrumented_times):.4f}s")
    print()
    print(f"Measured overhead multiplier: {multiplier:.3f}x  ({(multiplier - 1) * 100:+.1f}%)")
    print(
        "\nCaveat: this workload is dominated by subprocess calls, with six "
        "actual git command spawns per cycle, so the git binary's own execution "
        "cost swamps our per-call Python level check. A workload with many pure "
        "Python operations and few subprocess or network calls actually made "
        "would have less work to amortize the check against, and could show "
        "higher relative overhead than this number suggests."
    )


if __name__ == "__main__":
    main()
