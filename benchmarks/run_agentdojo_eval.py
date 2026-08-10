"""Runs our provenance defense against AgentDojo's banking suite, an
actual third party benchmark used to evaluate CaMeL, FIDES, and others.

This compares two pipelines against the same local model, the same tasks,
and the same injections: undefended, using the plain ToolsExecutor, versus
our ProvenanceGatedToolsExecutor, which matches based on content. See
agentdojo_adapter.py for why content matching was used rather than the
object identity approach used elsewhere in this repository.

It reports, per pipeline, the attack success rate, where lower is better,
and task utility, where higher is better. Both matter, since a defense
that blocks everything, including legitimate tasks, isn't actually useful.

Usage: .venv/bin/python -m benchmarks.run_agentdojo_eval [n_task_pairs]
"""

from __future__ import annotations

import subprocess
import sys
import time

import openai
import requests

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
from agentdojo.task_suite.load_suites import get_suite

from benchmarks import local_llm_patch
from benchmarks.agentdojo_adapter import ContentProvenanceLog, ProvenanceGatedToolsExecutor

local_llm_patch.apply()

task_suite = get_suite("v1", "banking")

MODEL_ID = "mlx-community/Qwen3-4B-4bit"
PORT = 8123

SOURCES = {
    "read_file",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "get_iban",
    "get_balance",
    "get_user_info",
}
SINKS = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "update_password",
    "update_user_info",
}


def start_server() -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mlx_lm",
            "server",
            "--model",
            MODEL_ID,
            "--port",
            str(PORT),
            "--max-tokens",
            "2048",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(120):
        try:
            r = requests.get(f"http://localhost:{PORT}/v1/models", timeout=2)
            if r.status_code == 200:
                return proc
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    proc.kill()
    raise RuntimeError("mlx_lm server did not become ready in time")


def build_llm() -> LocalLLM:
    client = openai.OpenAI(base_url=f"http://localhost:{PORT}/v1", api_key="not-needed")
    return LocalLLM(client=client, model=MODEL_ID)


def build_undefended_pipeline(llm: LocalLLM) -> AgentPipeline:
    system_message = SystemMessage(load_system_message(None))
    tools_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipeline = AgentPipeline([system_message, InitQuery(), llm, tools_loop])
    pipeline.name = "undefended"
    return pipeline


def build_defended_pipeline(llm: LocalLLM) -> tuple[AgentPipeline, ProvenanceGatedToolsExecutor]:
    system_message = SystemMessage(load_system_message(None))
    gated_executor = ProvenanceGatedToolsExecutor(sources=SOURCES, sinks=SINKS, log=ContentProvenanceLog())
    tools_loop = ToolsExecutionLoop([gated_executor, llm])
    pipeline = AgentPipeline([system_message, InitQuery(), llm, tools_loop])
    pipeline.name = "provenance-gated"
    return pipeline, gated_executor


def _run_one(pipeline, user_task, injection_task) -> tuple[bool, bool] | None:
    """Runs one task with one pipeline. Returns None, not a crash, if the
    model or server produced a bad completion on some turn, so an
    occasional flaky turn doesn't lose the whole batch."""
    try:
        return task_suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections={})
    except Exception as exc:
        print(f"    run errored, skipping this pair ({type(exc).__name__}: {exc})")
        return None


def run_eval(n_user_tasks: int, n_injection_tasks: int) -> None:
    user_tasks = list(task_suite.user_tasks.values())[:n_user_tasks]
    injection_tasks = list(task_suite.injection_tasks.values())[:n_injection_tasks]

    print(f"Starting local model server ({MODEL_ID}) on port {PORT}...")
    server = start_server()
    try:
        llm = build_llm()

        results = {"undefended": [], "provenance-gated": []}
        errors = {"undefended": 0, "provenance-gated": 0}

        for user_task in user_tasks:
            for injection_task in injection_tasks:
                # An undefended run.
                pipeline = build_undefended_pipeline(llm)
                outcome = _run_one(pipeline, user_task, injection_task)
                if outcome is None:
                    errors["undefended"] += 1
                else:
                    utility, attack_success = outcome
                    results["undefended"].append((utility, attack_success))
                    print(
                        f"[undefended]       user={user_task.ID} inj={injection_task.ID} "
                        f"utility={utility} attack_success={attack_success}"
                    )

                # A provenance gated run.
                pipeline, gated_executor = build_defended_pipeline(llm)
                outcome = _run_one(pipeline, user_task, injection_task)
                if outcome is None:
                    errors["provenance-gated"] += 1
                else:
                    utility, attack_success = outcome
                    results["provenance-gated"].append((utility, attack_success))
                    print(
                        f"[provenance-gated] user={user_task.ID} inj={injection_task.ID} "
                        f"utility={utility} attack_success={attack_success} "
                        f"blocked={len(gated_executor.blocked)}"
                    )

        print()
        for name, rows in results.items():
            n = len(rows)
            print(f"{name}: {errors[name]} run(s) errored out and were excluded")
            if n == 0:
                continue
            attack_rate = sum(1 for _, a in rows if a) / n
            utility_rate = sum(1 for u, _ in rows if u) / n
            print(f"{name}: attack_success_rate={attack_rate:.2%} task_utility_rate={utility_rate:.2%} (n={n})")
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    n_user = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    n_inj = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    run_eval(n_user, n_inj)
