"""Adapter wiring our provenance approach into AgentDojo, an external,
third-party benchmark (used to evaluate CaMeL, FIDES, and others) for
prompt-injection attacks/defenses on tool-using LLM agents.

ADR-003 (see README): two things ruled out reusing rules.py directly.

1. AgentDojo's tools are simulated, in-memory Python functions operating
   on Pydantic model state (BankAccount, Filesystem, ...), not real
   stdlib/requests/subprocess calls. rules.py's monkey-patches of
   open/requests.post/subprocess.run have nothing to intercept here.

2. More fundamentally: object-identity provenance (storage.py's entire
   design, and the thing that made Phase 1's milestone trivial -- "b = a"
   needs no propagation code because it's the same object) does not
   survive AgentDojo's harness. Traced through ToolsExecutor and
   LocalLLM._parse_model_output: every tool result gets formatted to a
   string and appended to the message history; the LLM reads that string
   and *generates fresh JSON text* for its next tool call's arguments,
   which gets json.loads()'d into a brand-new object. The string that
   reaches a sink argument is never the same object a source tagged --
   there is no nested-call evaluation here the way agent_demo/agent_loop.py
   has, where an inner tool call is actually executed and its real return
   object flows into the outer call. id()-based matching would just never
   fire.

So this adapter uses content-based matching instead: source-tool outputs
are logged as (content, origin) pairs; a sink call is blocked if any of
its argument values contains, or is contained in, a sufficiently long
piece of previously-logged content. This is strictly weaker than
object-identity tracking -- it can miss a value the model paraphrased
rather than copied, and can in principle false-positive on a coincidental
substring match -- and that tradeoff is deliberate and documented, not
hidden. MIN_MATCH_LENGTH exists specifically to suppress trivial
short-string false positives (a bare "a" or "the" matching everything).
"""

from __future__ import annotations

import dataclasses
from ast import literal_eval
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

MIN_MATCH_LENGTH = 6


@dataclasses.dataclass
class ContentProvenanceLog:
    """Per-run registry of (content, origin-tool-name) pairs tagged from
    source tool outputs. Deliberately a fresh instance per task run --
    unlike storage.side_table, this is not global state, so independent
    benchmark tasks can't leak flagged content into each other."""

    entries: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    def tag(self, content: str, origin: str) -> None:
        content = content.strip()
        if len(content) >= MIN_MATCH_LENGTH:
            self.entries.append((content, origin))

    def find_match(self, value: Any) -> tuple[str, str] | None:
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        if len(value) < MIN_MATCH_LENGTH:
            return None
        for content, origin in self.entries:
            if content in value or value in content:
                return content, origin
        return None


@dataclasses.dataclass
class BlockedCall:
    function: str
    matched_content: str
    origin: str


class ProvenanceGatedToolsExecutor(BasePipelineElement):
    """Drop-in replacement for agentdojo.agent_pipeline.ToolsExecutor.
    Structurally mirrors it (same message-handling logic), adding one
    thing: sink tool calls get their arguments checked against a
    ContentProvenanceLog before execution; source tool calls have their
    formatted output logged after execution.
    """

    def __init__(
        self,
        sources: set[str],
        sinks: set[str],
        log: ContentProvenanceLog,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.sources = sources
        self.sinks = sinks
        self.log = log
        self.output_formatter = tool_output_formatter
        self.blocked: list[BlockedCall] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue
            if tool_call.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=f"Invalid tool {tool_call.function} provided.",
                    )
                )
                continue

            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            if tool_call.function in self.sinks:
                match = None
                for arg_v in tool_call.args.values():
                    match = self.log.find_match(arg_v)
                    if match:
                        break
                if match:
                    content, origin = match
                    self.blocked.append(BlockedCall(tool_call.function, content, origin))
                    tool_call_results.append(
                        ChatToolResultMessage(
                            role="tool",
                            content=[text_content_block_from_string("")],
                            tool_call_id=tool_call.id,
                            tool_call=tool_call,
                            error=(
                                f"Blocked by provenance access control: an argument to "
                                f"{tool_call.function!r} traces to untrusted content read "
                                f"earlier from {origin!r}."
                            ),
                        )
                    )
                    continue

            tool_call_result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            if tool_call.function in self.sources:
                self.log.tag(self.output_formatter(tool_call_result), tool_call.function)

            formatted_tool_call_result = self.output_formatter(tool_call_result)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted_tool_call_result)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args
