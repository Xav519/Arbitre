# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file is Inno's security diary. Every time a safety check notices
# something suspicious (a prompt injection, a tool call that breaks the
# rules, a secret about to leak in a reply), it writes one line here.
#
# Each line is a small JSON record that says:
#
#   - what happened        (for example "prompt_injection")
#   - which check saw it   (for example "input_scan")
#   - what was done        "blocked" if the check was switched on and
#                          stopped it, "observed" if the check was switched
#                          off and only watched it happen
#   - who and when         customer, request id, timestamp
#   - what kind of attack  its MITRE ATLAS and OWASP LLM Top 10 labels
#
# Where the lines go: they are printed to stdout. On AWS Lambda anything
# printed ends up in CloudWatch Logs, and CloudWatch has alarms that count
# lines by their "ib_event" name (see infra/modules/stack/detections.tf).
# So printing one line here is all it takes to light up a dashboard.
#
# Why "observed" matters: the vulnerable stack runs the very same checks as
# the hardened one, it just does not act on them. That way the vulnerable
# stack still records every attack it lets through, and you can compare
# "what was seen" with "what was stopped" side by side.
#
# The file has two parts:
#
#   1. EVENTS: the list of every allowed event name, each tied to its
#              attack labels. An unknown name fails loudly on purpose.
#
#   2. Trace:  a notebook for one customer request. It keeps the security
#              events and every tool call Inno tried, so tests, the attack
#              harness and the Lambda response can all read them afterwards.
#
# Adding a new event name means updating three places together: EVENTS
# below, the CloudWatch filters in detections.tf, and docs/controls.md.
#
# =============================================================================

"""Structured security events.

Every control decision becomes one JSON line on stdout. In Lambda that lands in
CloudWatch Logs, where metric filters keyed on `ib_event` drive alarms. Each
event carries its MITRE ATLAS technique and OWASP LLM category so a detection
is already mapped when it fires.

Checks run in both postures. A control that is switched off still evaluates and
logs with action "observed"; a control that is on logs "blocked". The vulnerable
stack therefore detects what it does not prevent.
"""
from __future__ import annotations

import json
import time

# ib_event -> (ATLAS technique id, ATLAS technique name, OWASP LLM Top 10 2025)
#
# Why a fixed table: the labels are attached here, once, instead of at every
# place that logs an event. That keeps the labels consistent, and it means a
# security analyst reading an alarm already knows which known attack family
# it belongs to without looking anything up.
#
# Why it is a closed list: Trace.event() looks the name up with EVENTS[...],
# so a typo in an event name crashes in the tests instead of silently writing
# a line that no CloudWatch alarm is listening for.

# How an attack gets its ATLAS label:
#   1. A check spots something with plain code rules (for example guards.scan
#      finds "ignore previous instructions", or policy.py denies a transfer
#      to an unknown payee).
#   2. That check always logs the same event name, picked for what it looks
#      for (the input scanner logs "prompt_injection", the tool policy logs
#      "tool_call_denied").
#   3. Trace.event() finds that name in this table and copies the matching
#      ATLAS and OWASP labels onto the log line.
# Nothing classifies the attack on the fly. A person filled in this table
# once from the ATLAS and OWASP lists, so an attack that no check catches
# gets no label at all.
EVENTS = {
    # Someone typed instructions meant to override Inno's rules.
    "prompt_injection": ("AML.T0051.000", "LLM Prompt Injection: Direct", "LLM01"),
    # Same idea, but hidden with tricks like base64 or odd characters.
    "prompt_obfuscation": ("AML.T0068", "LLM Prompt Obfuscation", "LLM01"),
    # Instructions hidden inside data Inno reads (a document, a search result).
    "indirect_injection": ("AML.T0051.001", "LLM Prompt Injection: Indirect", "LLM01"),
    # A knowledge base document was refused at ingest (unsigned or dirty).
    "rag_document_rejected": ("AML.T0070", "RAG Poisoning", "LLM04"),
    # The tool policy said no (wrong account, unknown payee, over limit...).
    "tool_call_denied": ("AML.T0053", "AI Agent Tool Invocation", "LLM06"),
    # A tool call looked like an attempt to send data out to an attacker.
    "exfiltration_attempt": ("AML.T0086", "Exfiltration via AI Agent Tool Invocation", "LLM06"),
    # The reply contained a piece of Inno's hidden system prompt.
    "system_prompt_leak": ("AML.T0056", "Extract LLM System Prompt", "LLM07"),
    # The reply contained personal or secret data it should not show.
    "sensitive_data_in_output": ("AML.T0057", "LLM Data Leakage", "LLM02"),
    # The reply contained links or markup that could do harm when displayed.
    "unsafe_output_rendering": ("AML.T0077", "LLM Response Rendering", "LLM05"),
    # Text from a poisoned document made it all the way into the reply.
    "poisoned_content_in_output": ("AML.T0070", "RAG Poisoning", "LLM04"),
    # Too many tool calls or too much input: a way to burn money or time.
    "resource_budget_exceeded": ("AML.T0029", "Denial of AI Service", "LLM10"),
    # Amazon Bedrock Guardrails stepped in on the input or the reply.
    "guardrail_intervened": ("AML.T0054", "LLM Jailbreak", "LLM01"),
    # A tool's own IAM role refused the AWS call. Logged with control "iam": not an app switch.
    # Why it exists: this is the last line of defence, enforced by AWS itself
    # rather than by our Python code, so it is worth seeing when it fires.
    "tool_access_denied": ("AML.T0053", "AI Agent Tool Invocation", "LLM06"),
}


class Trace:
    """Collects the security events and tool calls of one agent turn."""

    # One Trace is created per customer request and thrown away afterwards.
    # Keeping everything about one request in one object makes it easy to
    # hand the full story to the tests, the attack harness and the reports.
    def __init__(self, mode: str, customer_id: str = "", request_id: str = "", quiet: bool = False):
        # "vulnerable" or "hardened": stamped on every event so alarms can
        # tell the two stacks apart.
        self.mode = mode
        # Who was talking and which request this was, so an analyst can tie
        # an alarm back to one exact conversation.
        self.customer_id = customer_id
        self.request_id = request_id
        # quiet=True skips printing. The offline harness runs hundreds of
        # requests and only needs the records in memory, not a flood of
        # JSON lines in the terminal.
        self.quiet = quiet
        self.events: list[dict] = []
        self.tool_calls: list[dict] = []
        # Counted by the agent loop. The harness uses it to spot attacks
        # that make the model spin many rounds.
        self.model_calls = 0

    def event(self, ib_event: str, control: str, enforced: bool, detail: str = "") -> None:
        # Fails with KeyError on an unknown name on purpose (see EVENTS).
        atlas_id, atlas_name, owasp = EVENTS[ib_event]
        record = {
            "ib_event": ib_event,
            "control": control,
            # The caller passes whether its control is switched on. This one
            # word is what lets the vulnerable stack log attacks it does not
            # stop: "observed" there, "blocked" on the hardened stack.
            "action": "blocked" if enforced else "observed",
            "atlas_technique": atlas_id,
            "atlas_name": atlas_name,
            "owasp": owasp,
            "mode": self.mode,
            "customer_id": self.customer_id,
            "request_id": self.request_id,
            # Cut to 300 characters so an attacker cannot stuff huge text
            # into the logs (log cost, noise), while keeping enough to
            # understand what triggered the event.
            "detail": detail[:300],
            "ts": int(time.time()),
        }
        self.events.append(record)
        if not self.quiet:
            # One line per event, keys sorted so the output is stable and
            # easy to diff. CloudWatch metric filters match on these lines.
            print(json.dumps(record, sort_keys=True))

    def tool(self, name: str, args: dict, status: str, reason: str = "") -> None:
        # Records every tool Inno tried to use, allowed or not. status is
        # "executed" or "denied"; reason says why it was denied. The harness
        # checks this list to decide whether an attack really did damage.
        self.tool_calls.append({"name": name, "args": args, "status": status, "reason": reason})

    @property
    def executed(self) -> list[dict]:
        # Only the tool calls that actually ran. A denied transfer did no
        # harm, so success checks care about this list, not all attempts.
        return [t for t in self.tool_calls if t["status"] == "executed"]

    def as_dict(self) -> dict:
        # Plain dictionary version, sent back in the agent's response so the
        # harness and the Lambda caller can read the trace as JSON.
        return {
            "mode": self.mode,
            "events": self.events,
            "tool_calls": self.tool_calls,
            "model_calls": self.model_calls,
        }
