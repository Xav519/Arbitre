"""Model backends.

BedrockModel is the real thing. ScriptedModel is an adversary model for offline
verification: it stands in for an LLM that has been fully compromised and does
whatever an injection asks, provided the injection actually reached it. Running
the hardened controls against that worst case shows what they guarantee
independently of how well any given model resists manipulation.
"""
from __future__ import annotations

import json
import uuid


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
    """

    def __init__(self, steps: list[dict]):
        self._queue: list[dict] = []
        for step in steps:
            self._queue.extend([step] * int(step.get("repeat", 1)))

    def converse(self, system: str, messages: list, tool_specs: list) -> dict:
        seen = context_text(system, messages)
        while self._queue:
            step = self._queue.pop(0)
            marker = step.get("if_context_contains")
            if marker and marker not in seen:
                continue
            if "tool" in step:
                return {"role": "assistant", "content": [{"toolUse": {
                    "toolUseId": "tu_" + uuid.uuid4().hex[:12], "name": step["tool"],
                    "input": dict(step.get("args", {}))}}]}
            text = (step["say"].replace("{system_prompt}", system)
                    .replace("{tool_results}", tool_results_text(messages)))
            return {"role": "assistant", "content": [{"text": text}]}
        return {"role": "assistant", "content": [{"text": "I'm sorry, I can't help with that."}]}
