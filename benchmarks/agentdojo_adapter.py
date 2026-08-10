"""An adapter wiring our provenance approach into AgentDojo, an external,
third party benchmark used to evaluate CaMeL, FIDES, and others, for prompt
injection attacks and defenses on tool using language model agents.

This doesn't reuse rules.py directly, for two reasons.

First, AgentDojo's tools are simulated, in memory Python functions
operating on Pydantic model state, such as BankAccount and Filesystem, not
actual stdlib, requests, or subprocess calls, so rules.py's monkey patches
have nothing to intercept.

Second, and more fundamentally, the object identity approach to
provenance, which is storage.py's whole design, doesn't survive AgentDojo's
harness. Every tool result gets formatted to a string and appended to the
message history. The model reads that string and generates fresh JSON text
for its next tool call's arguments, which gets parsed by json.loads() into
a brand new object. The string reaching a sink argument is never the same
object a source tagged. Unlike agent_demo/agent_loop.py, there is no nested
call evaluation here where an inner tool call's own return object flows
into the outer call, so matching based on id() would never fire.

So this adapter matches based on content instead. Source tool outputs are
logged as pairs of content and origin, and a sink call is blocked if any
argument contains, or is contained in, a sufficiently long piece of
previously logged content. This is strictly weaker than tracking based on
object identity. It can miss a value the model paraphrased rather than
copied, and it can produce a false positive on a coincidental substring
match. MIN_MATCH_LENGTH suppresses trivial false positives from short
strings, such as a bare "a" or "the" matching everything.
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
    """A per run registry of content and origin pairs, where origin is the
    name of the source tool that produced the content. This is a fresh
    instance for each task run, unlike storage.side_table, so independent
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
    """A direct replacement for agentdojo.agent_pipeline.ToolsExecutor. It
    mirrors the same message handling logic structurally, and adds one
    thing: sink tool calls get their arguments checked against a
    ContentProvenanceLog before execution, and source tool calls have their
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
