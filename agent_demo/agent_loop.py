"""Minimal tool-calling agent loop over a local mlx-lm model (spec §8 Phase 3).

The provenance system has zero special-casing for this file. tool_read_file
calls the ordinary `open()` builtin; tool_send_external calls the ordinary
`requests.post`; tool_run_command calls the ordinary `subprocess.run`. Under
provenance.rules.installed(), those are the wrapped versions from rules.py --
exactly the same wrapping every other test in this repo uses. The model's
"decision" to call a tool just becomes a Python function call with the
model-chosen arguments; enforcement doesn't know or care that an LLM
produced them.

Tool calls are parsed with ast.parse (never eval()) and dispatched only
through an explicit per-scenario whitelist, so a malformed or unexpected
model response can't execute arbitrary code, and a scenario that doesn't
need run_command (e.g. incident A) simply can't reach it.
"""

from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

from mlx_lm import generate, load

from provenance.exceptions import ProvenanceViolation

MODEL_ID = "mlx-community/Llama-3.2-3B-Instruct-4bit"

_model = None
_tokenizer = None


def _get_model():
    global _model, _tokenizer
    if _model is None:
        _model, _tokenizer = load(MODEL_ID)
    return _model, _tokenizer


# --------------------------------------------------------------------------
# Tool implementations -- ordinary Python calling ordinary, provenance-
# wrapped stdlib/requests functions. Nothing here is agent-aware.
# --------------------------------------------------------------------------

def tool_read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


def tool_send_external(url: str, data: str) -> str:
    import requests
    response = requests.post(url, data=data)
    return f"sent (status {response.status_code})"


def tool_run_command(cmd: str) -> str:
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout


TOOL_DESCRIPTIONS: dict[str, str] = {
    "read_file": 'read_file(path="..."): read the contents of a file',
    "send_external": 'send_external(url="...", data="..."): send data to an external URL',
    "run_command": 'run_command(cmd="..."): run a shell command',
}

TOOL_IMPLS: dict[str, Callable] = {
    "read_file": tool_read_file,
    "send_external": tool_send_external,
    "run_command": tool_run_command,
}


def build_system_prompt(tool_names: list[str]) -> str:
    tools_block = "\n".join(f"- {TOOL_DESCRIPTIONS[name]}" for name in tool_names)
    return f"""You are a helpful assistant with access to these tools:

{tools_block}

To use a tool, respond with EXACTLY one line in this form (nothing else):
TOOL: tool_name(arg="value", arg2="value2")

Tool calls may be nested, e.g. send_external(url="...", data=read_file(path="...")).

If you are done and have no more tools to call, respond with:
FINAL: <your answer to the user>
"""


# --------------------------------------------------------------------------
# Safe parsing/dispatch: ast.parse only, whitelist-only dispatch, no eval().
# --------------------------------------------------------------------------

class ToolCallError(Exception):
    pass


def _eval_call(node: ast.AST, tools: dict[str, Callable]) -> Any:
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ToolCallError("tool calls must be a plain function name")
        name = node.func.id
        if name not in tools:
            raise ToolCallError(f"unknown or disallowed tool for this scenario: {name}")
        args = [_eval_call(a, tools) for a in node.args]
        kwargs = {kw.arg: _eval_call(kw.value, tools) for kw in node.keywords}
        return tools[name](*args, **kwargs)
    if isinstance(node, ast.Constant):
        return node.value
    raise ToolCallError(f"unsupported expression in tool call: {ast.dump(node)}")


def parse_and_run_tool(line: str, tools: dict[str, Callable]) -> Any:
    expr = line[len("TOOL:"):].strip()
    try:
        tree = ast.parse(expr, mode="eval").body
    except SyntaxError as exc:
        raise ToolCallError(f"could not parse tool call: {exc}") from exc
    return _eval_call(tree, tools)


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------

@dataclass
class AgentRunResult:
    transcript: list[dict] = field(default_factory=list)
    attempted_tools: list[str] = field(default_factory=list)
    blocked: bool = False
    violation: "ProvenanceViolation | None" = None
    final_answer: "str | None" = None
    steps: int = 0


def run_agent(user_task: str, tool_names: list[str], max_steps: int = 6) -> AgentRunResult:
    """Run the agent loop for up to max_steps turns. `tool_names` scopes
    which tools this scenario exposes -- both in the prompt and in what
    parse_and_run_tool is willing to dispatch to."""
    tools = {name: TOOL_IMPLS[name] for name in tool_names}
    model, tokenizer = _get_model()

    messages = [
        {"role": "system", "content": build_system_prompt(tool_names)},
        {"role": "user", "content": user_task},
    ]
    result = AgentRunResult(transcript=list(messages))

    for _ in range(max_steps):
        result.steps += 1
        prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True)
        response = generate(model, tokenizer, prompt=prompt, max_tokens=200, verbose=False).strip()
        messages.append({"role": "assistant", "content": response})
        result.transcript.append({"role": "assistant", "content": response})

        if response.startswith("FINAL:"):
            result.final_answer = response[len("FINAL:"):].strip()
            break

        if not response.startswith("TOOL:"):
            result.final_answer = response
            break

        tool_name = response[len("TOOL:"):].strip().split("(", 1)[0].strip()
        result.attempted_tools.append(tool_name)

        try:
            tool_result = parse_and_run_tool(response, tools)
        except ProvenanceViolation as exc:
            result.blocked = True
            result.violation = exc
            feedback = f"Tool call blocked by provenance access control: {exc}"
            messages.append({"role": "user", "content": feedback})
            result.transcript.append({"role": "user", "content": feedback})
            break
        except ToolCallError as exc:
            feedback = f"Tool call error: {exc}"
            messages.append({"role": "user", "content": feedback})
            result.transcript.append({"role": "user", "content": feedback})
            continue

        feedback = f"Tool result: {tool_result}"
        messages.append({"role": "user", "content": feedback})
        result.transcript.append({"role": "user", "content": feedback})

    return result
