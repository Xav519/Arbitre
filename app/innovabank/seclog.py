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
EVENTS = {
    "prompt_injection": ("AML.T0051.000", "LLM Prompt Injection: Direct", "LLM01"),
    "prompt_obfuscation": ("AML.T0068", "LLM Prompt Obfuscation", "LLM01"),
    "indirect_injection": ("AML.T0051.001", "LLM Prompt Injection: Indirect", "LLM01"),
    "rag_document_rejected": ("AML.T0070", "RAG Poisoning", "LLM04"),
    "tool_call_denied": ("AML.T0053", "AI Agent Tool Invocation", "LLM06"),
    "exfiltration_attempt": ("AML.T0086", "Exfiltration via AI Agent Tool Invocation", "LLM06"),
    "system_prompt_leak": ("AML.T0056", "Extract LLM System Prompt", "LLM07"),
    "sensitive_data_in_output": ("AML.T0057", "LLM Data Leakage", "LLM02"),
    "unsafe_output_rendering": ("AML.T0077", "LLM Response Rendering", "LLM05"),
    "poisoned_content_in_output": ("AML.T0070", "RAG Poisoning", "LLM04"),
    "resource_budget_exceeded": ("AML.T0029", "Denial of AI Service", "LLM10"),
    "guardrail_intervened": ("AML.T0054", "LLM Jailbreak", "LLM01"),
}


class Trace:
    """Collects the security events and tool calls of one agent turn."""

    def __init__(self, mode: str, customer_id: str = "", request_id: str = "", quiet: bool = False):
        self.mode = mode
        self.customer_id = customer_id
        self.request_id = request_id
        self.quiet = quiet
        self.events: list[dict] = []
        self.tool_calls: list[dict] = []
        self.model_calls = 0

    def event(self, ib_event: str, control: str, enforced: bool, detail: str = "") -> None:
        atlas_id, atlas_name, owasp = EVENTS[ib_event]
        record = {
            "ib_event": ib_event,
            "control": control,
            "action": "blocked" if enforced else "observed",
            "atlas_technique": atlas_id,
            "atlas_name": atlas_name,
            "owasp": owasp,
            "mode": self.mode,
            "customer_id": self.customer_id,
            "request_id": self.request_id,
            "detail": detail[:300],
            "ts": int(time.time()),
        }
        self.events.append(record)
        if not self.quiet:
            print(json.dumps(record, sort_keys=True))

    def tool(self, name: str, args: dict, status: str, reason: str = "") -> None:
        self.tool_calls.append({"name": name, "args": args, "status": status, "reason": reason})

    @property
    def executed(self) -> list[dict]:
        return [t for t in self.tool_calls if t["status"] == "executed"]

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "events": self.events,
            "tool_calls": self.tool_calls,
            "model_calls": self.model_calls,
        }
