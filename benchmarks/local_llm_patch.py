"""Compatibility patch for agentdojo's LocalLLM output parser, not a
provenance-logic change -- applied identically regardless of which
pipeline (undefended or provenance-gated) is running, so it doesn't bias
the comparison.

AgentDojo's default parser (_parse_model_output) takes everything between
`<function=name>` and the next `</function>` (or end of string if that
tag never appears) and json.loads()s it verbatim. Our small local model
reliably produces valid JSON but then trails off into prose afterward
without closing the tag cleanly (observed directly: a real completion
was `{"file_path": "bill-december-2023.txt"}>\n\`\`\`\n\nPlease note
that I'm assuming...`) -- valid JSON followed by junk, which the
tag-boundary search captures as one blob and fails to parse. This patch
finds the first balanced {...} object after the opening tag instead of
relying on the closing tag being present, and ignores anything after it.
"""

from __future__ import annotations

import json
import re

from agentdojo.agent_pipeline.llms import local_llm
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string


def _extract_balanced_json(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
    return None


def _lenient_parse_model_output(completion: str) -> ChatAssistantMessage:
    default_message = ChatAssistantMessage(
        role="assistant", content=[text_content_block_from_string(completion.strip())], tool_calls=[]
    )
    open_tag_pattern = re.compile(r"<function\s*=\s*([^>]+)>")
    open_match = open_tag_pattern.search(completion)
    if not open_match:
        return default_message

    function_name = open_match.group(1).strip()
    raw_json = _extract_balanced_json(completion[open_match.end() :])
    if raw_json is None:
        return default_message

    try:
        params_dict = json.loads(raw_json)
        tool_calls = [FunctionCall(function=function_name, args=params_dict)]
    except Exception:
        return default_message

    return ChatAssistantMessage(
        role="assistant", content=[text_content_block_from_string(completion.strip())], tool_calls=tool_calls
    )


def apply() -> None:
    local_llm._parse_model_output = _lenient_parse_model_output
