"""Model backends.

BedrockModel is the real thing. ScriptedModel is an adversary model for offline
verification: it stands in for an LLM that has been fully compromised and does
whatever an injection asks, provided the injection actually reached it. Running
the hardened controls against that worst case shows what they guarantee
independently of how well any given model resists manipulation.
"""
from __future__ import annotations

import json
import re
import uuid

# Nova (and other models) can wrap their chain of thought in <thinking> tags in
# the text of a reply. That is model plumbing, not an answer: it must never reach
# the customer, in either posture.
_REASONING_BLOCK = re.compile(r"<\s*thinking\b[^>]*>.*?<\s*/\s*thinking\s*>", re.IGNORECASE | re.DOTALL)
_REASONING_OPEN = re.compile(r"<\s*thinking\b[^>]*>", re.IGNORECASE)
_REASONING_CLOSE = re.compile(r"<\s*/\s*thinking\s*>", re.IGNORECASE)

# What ScriptedModel says in its reasoning, so a leak is easy to spot in a report.
SCRIPTED_REASONING = "IB-SCRIPTED-REASONING planning the next step for the customer."


def strip_reasoning(text: str) -> str:
    """Remove reasoning blocks from a model reply.

    Closed blocks are removed. An unclosed opening tag means the rest of the
    text is reasoning (typically a reply cut off by the token limit), so it is
    dropped. An orphan closing tag means everything before it was reasoning.
    Fails closed: when in doubt, text is removed rather than shown.
    """
    text = _REASONING_BLOCK.sub("", text)
    opened = _REASONING_OPEN.search(text)
    if opened:
        text = text[:opened.start()]
    closes = list(_REASONING_CLOSE.finditer(text))
    if closes:
        text = text[closes[-1].end():]
    return text.strip()


class BedrockModel:
    def __init__(self, client, model_id: str):
        self.client = client
        self.model_id = model_id

    def converse(self, system: str, messages: list, tool_specs: list) -> dict:
        resp = self.client.converse(
            modelId=self.model_id,
            system=[{"text": system}],
            messages=messages,
            toolConfig={"tools": [{"toolSpec": s} for s in tool_specs]},
            inferenceConfig={"maxTokens": 1024, "temperature": 0},
        )
        return resp["output"]["message"]


def context_text(system: str, messages: list) -> str:
    """Everything the model can see, flattened."""
    parts = [system]
    for m in messages:
        for block in m.get("content", []):
            if "text" in block:
                parts.append(block["text"])
            elif "toolResult" in block:
                for c in block["toolResult"].get("content", []):
                    parts.append(c.get("text") or json.dumps(c.get("json", {})))
    return "\n".join(parts)


def tool_results_text(messages: list) -> str:
    parts = []
    for m in messages:
        for block in m.get("content", []):
            if "toolResult" in block:
                for c in block["toolResult"].get("content", []):
                    parts.append(c.get("text") or json.dumps(c.get("json", {})))
    return "\n".join(parts)


class ScriptedModel:
    """Follows a list of steps, each optionally conditioned on what it can see.

    Step forms:
      {tool: name, args: {...}, repeat: n, if_context_contains: "marker"}
      {say: "text", if_context_contains: "marker"}
    In `say`, {system_prompt} and {tool_results} expand to what the model was
    actually given, so it can only leak what really reached it.

    With reasoning=True every reply also carries a <thinking> block, the way
    Nova formats its replies, so the offline bench exercises reasoning removal.
    """

    def __init__(self, steps: list[dict], reasoning: bool = False):
        self._reasoning = reasoning
        self._queue: list[dict] = []
        for step in steps:
            self._queue.extend([step] * int(step.get("repeat", 1)))

    def _thinking(self) -> list[dict]:
        return [{"text": f"<thinking>{SCRIPTED_REASONING}</thinking>"}] if self._reasoning else []

    def _say(self, text: str) -> dict:
        prefix = f"<thinking>{SCRIPTED_REASONING}</thinking>\n" if self._reasoning else ""
        return {"role": "assistant", "content": [{"text": prefix + text}]}

    def converse(self, system: str, messages: list, tool_specs: list) -> dict:
        seen = context_text(system, messages)
        while self._queue:
            step = self._queue.pop(0)
            marker = step.get("if_context_contains")
            if marker and marker not in seen:
                continue
            if "tool" in step:
                return {"role": "assistant", "content": self._thinking() + [{"toolUse": {
                    "toolUseId": "tu_" + uuid.uuid4().hex[:12], "name": step["tool"],
                    "input": dict(step.get("args", {}))}}]}
            text = (step["say"].replace("{system_prompt}", system)
                    .replace("{tool_results}", tool_results_text(messages)))
            return self._say(text)
        return self._say("I'm sorry, I can't help with that.")
