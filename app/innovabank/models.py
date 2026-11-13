# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# Inno, the banking chatbot, needs a "brain": a language model that reads
# the conversation and decides what to say or which tool to use (check a
# balance, send money, search the knowledge base...). This file provides
# that brain, in two interchangeable versions:
#
#   1. BedrockModel - the real AI model (Amazon Nova) running in AWS. Used
#      when the lab is deployed for real. Costs money, needs an AWS account.
#
#   2. ScriptedModel - a fake model that just follows a script written in
#      the attack YAML files. Used for tests and the offline bench. It is
#      free, instant, and always gives the same result.
#
# The important twist: ScriptedModel plays the WORST possible model. It
# behaves like an AI that has been completely tricked and obeys any
# malicious instruction, but only if that instruction really reached it.
# If the hardened bank still stops the attack against such a model, we know
# the protections work on their own, without relying on the AI being smart
# enough to say no.
#
# Both versions answer the same question in the same format ("here is my
# reply" or "please run this tool"), so the rest of the code never needs to
# know which one it is talking to.
#
# The file also contains strip_reasoning(), which cleans up the model's
# reply before the customer sees it. Some models write down their private
# "thinking" inside the reply; that must be removed, it is not an answer.
#
# =============================================================================

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
# Three patterns are needed because replies are not always well formed: a full
# <thinking>...</thinking> block, an opening tag with no end (reply cut off),
# or a closing tag with no start. The patterns tolerate extra spaces and
# attributes inside the tags, since models are not strict about formatting.
_REASONING_BLOCK = re.compile(r"<\s*thinking\b[^>]*>.*?<\s*/\s*thinking\s*>", re.IGNORECASE | re.DOTALL)
_REASONING_OPEN = re.compile(r"<\s*thinking\b[^>]*>", re.IGNORECASE)
_REASONING_CLOSE = re.compile(r"<\s*/\s*thinking\s*>", re.IGNORECASE)
# Nova also sometimes wraps the answer itself in <response> tags. The tags are
# plumbing, the text inside them is the answer: unwrap, keep the text.
_RESPONSE_TAG = re.compile(r"<\s*/?\s*response\b[^>]*>", re.IGNORECASE)

# What ScriptedModel says in its reasoning, so a leak is easy to spot in a report.
# It is a unique marker: if it ever shows up in a customer reply, we know the
# reasoning removal failed, and a simple text search proves it.
SCRIPTED_REASONING = "IB-SCRIPTED-REASONING planning the next step for the customer."


# This is reply cleanup, not a security control: it runs in BOTH postures and
# does not log security events. Even the vulnerable bank should not show the
# model's private notes to customers, otherwise every test result would be
# polluted by noise that has nothing to do with the attacks.
def strip_reasoning(text: str) -> str:
    """Remove reasoning blocks from a model reply.

    Closed blocks are removed. An unclosed opening tag means the rest of the
    text is reasoning (typically a reply cut off by the token limit), so it is
    dropped. An orphan closing tag means everything before it was reasoning.
    Fails closed: when in doubt, text is removed rather than shown.
    Then <response> wrapper tags are removed and their content kept.
    """
    # Step 1: remove every complete <thinking>...</thinking> block.
    text = _REASONING_BLOCK.sub("", text)
    # Step 2: an opening tag that was never closed. Everything after it is
    # unfinished thinking, so cut the text there. Showing a half-sentence of
    # reasoning is worse than showing a shorter answer.
    opened = _REASONING_OPEN.search(text)
    if opened:
        text = text[:opened.start()]
    # Step 3: a closing tag with no opening tag. Everything before the last
    # one was thinking, so keep only what comes after it.
    closes = list(_REASONING_CLOSE.finditer(text))
    if closes:
        text = text[closes[-1].end():]
    # Step 4: drop <response> tags but keep the words inside them, since
    # those words are the actual answer.
    text = _RESPONSE_TAG.sub("", text)
    return text.strip()


# The real model, used when the lab runs in AWS. It is a thin wrapper on
# purpose: all the security logic lives in the agent and the policy code, not
# here, so swapping in ScriptedModel changes nothing else in the system.
class BedrockModel:
    def __init__(self, client, model_id: str):
        # The client is passed in (not created here) so tests can hand in a
        # fake one. The model id comes from supplychain/model-lock.yaml, so
        # the exact model version is pinned and reviewed, never picked ad hoc.
        self.client = client
        self.model_id = model_id

    def converse(self, system: str, messages: list, tool_specs: list) -> dict:
        # One round trip to Bedrock: send the rules (system prompt), the
        # conversation so far, and the list of tools the model may ask for.
        # The model replies with text, a tool request, or both.
        resp = self.client.converse(
            modelId=self.model_id,
            system=[{"text": system}],
            messages=messages,
            toolConfig={"tools": [{"toolSpec": s} for s in tool_specs]},
            # temperature 0 makes the model as predictable as possible, so the
            # same attack gives the same result from one run to the next.
            # maxTokens caps the reply length (and the cost of each call).
            inferenceConfig={"maxTokens": 1024, "temperature": 0},
        )
        return resp["output"]["message"]


# Joins together every piece of text the model was given: the system prompt,
# the messages, and the tool results. ScriptedModel uses it to check whether
# an attacker's instruction really made it into the model's view. If a
# control removed or blocked that text, the fake model never "sees" it and
# so cannot obey it, exactly like a real model.
def context_text(system: str, messages: list) -> str:
    """Everything the model can see, flattened."""
    parts = [system]
    for m in messages:
        for block in m.get("content", []):
            if "text" in block:
                parts.append(block["text"])
            elif "toolResult" in block:
                # Tool results can be plain text or structured JSON; turn the
                # JSON into text too so a hidden instruction inside it counts.
                for c in block["toolResult"].get("content", []):
                    parts.append(c.get("text") or json.dumps(c.get("json", {})))
    return "\n".join(parts)


# Same idea as context_text, but only the tool results (what the tools sent
# back, such as documents or account data). Used to fill in the
# {tool_results} placeholder, so a "leak" attack can only leak data that a
# tool actually returned, never data the fake model invented.
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
        # Expand "repeat: n" up front into n copies of the step, so the main
        # loop only has to take steps off the front of a simple list. This is
        # how attacks that spam a tool (to test the budget control) are written.
        self._queue: list[dict] = []
        for step in steps:
            self._queue.extend([step] * int(step.get("repeat", 1)))

    # A fake <thinking> block placed before a tool request, so tool-calling
    # replies look like real Nova replies too.
    def _thinking(self) -> list[dict]:
        return [{"text": f"<thinking>{SCRIPTED_REASONING}</thinking>"}] if self._reasoning else []

    # Builds a text reply in the same shape Bedrock returns, optionally with
    # the fake <thinking> block in front, so strip_reasoning gets tested.
    def _say(self, text: str) -> dict:
        prefix = f"<thinking>{SCRIPTED_REASONING}</thinking>\n" if self._reasoning else ""
        return {"role": "assistant", "content": [{"text": prefix + text}]}

    # Same signature as BedrockModel.converse, so the agent can use either one
    # without knowing the difference. Each call plays the next usable step.
    def converse(self, system: str, messages: list, tool_specs: list) -> dict:
        seen = context_text(system, messages)
        while self._queue:
            step = self._queue.pop(0)
            # A conditional step only fires if its marker (for example a
            # phrase planted in a poisoned document) is in what the model can
            # see. If a control kept the marker out, the step is skipped for
            # good: the attack failed because the defence worked, not by luck.
            marker = step.get("if_context_contains")
            if marker and marker not in seen:
                continue
            if "tool" in step:
                # Ask the agent to run a tool. The id is random, like a real
                # model's, and args are copied so a repeated step cannot be
                # altered by later code changing a shared dict.
                return {"role": "assistant", "content": self._thinking() + [{"toolUse": {
                    "toolUseId": "tu_" + uuid.uuid4().hex[:12], "name": step["tool"],
                    "input": dict(step.get("args", {}))}}]}
            # A text reply. Placeholders are replaced with what the model was
            # really given, so a leak only succeeds if the secret truly
            # reached the model (and survived the output filters afterwards).
            text = (step["say"].replace("{system_prompt}", system)
                    .replace("{tool_results}", tool_results_text(messages)))
            return self._say(text)
        # Script finished (or every remaining step was skipped): give a
        # harmless refusal, like a model with nothing left to do.
        return self._say("I'm sorry, I can't help with that.")
