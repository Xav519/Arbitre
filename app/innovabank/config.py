"""Runtime configuration.

A posture ("mode") is nothing more than a preset of named controls. Every
control can also be toggled on its own through IB_CONTROLS, which is what makes
control ablation possible: run the hardened stack minus one control and see
which attacks come back.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

ALL_CONTROLS = (
    "prompt_hygiene",    # no secrets in the system prompt, leak canary instead
    "input_filter",      # normalisation + injection heuristics on user input
    "guardrail",         # Amazon Bedrock Guardrails on input, retrieved content, output
    "spotlight",         # retrieved content is delimited and marked as data
    "retrieval_scan",    # injection heuristics on retrieved content at query time
    "taint_lock",        # state-changing tools are locked once untrusted content is in context
    "tool_policy",       # ownership binding, payee allowlist, limits, argument validation
    "budget",            # hard cap on tool calls and input size per turn
    "output_filter",     # canary, PII, link and markup controls on the final answer
    "data_minimisation", # tools return only the fields the task needs
    "ingest_integrity",  # only signed documents are indexed
    "ingest_scan",       # injection heuristics at ingestion, quarantine on hit
)

PRESETS = {
    "vulnerable": frozenset(),
    "hardened": frozenset(ALL_CONTROLS),
}

TOOL_NAMES = (
    "search_knowledge_base",
    "read_document",
    "get_account_summary",
    "transfer_funds",
    "send_secure_message",
)


def resolve_controls(mode: str, override: str | None = None) -> frozenset[str]:
    """Return the active control set for a mode, with an optional override.

    Override syntax: "all", "none", an explicit comma list, or a delta against
    the preset such as "-taint_lock,-tool_policy" or "+output_filter".
    """
    if mode not in PRESETS:
        raise ValueError(f"unknown mode {mode!r}, expected one of {sorted(PRESETS)}")
    base = set(PRESETS[mode])
    if not override:
        return frozenset(base)
    items = [i.strip() for i in override.split(",") if i.strip()]
    if items == ["all"]:
        return frozenset(ALL_CONTROLS)
    if items == ["none"]:
        return frozenset()
    if all(i[0] in "+-" for i in items):
        for i in items:
            name = i[1:]
            _check(name)
            (base.add if i[0] == "+" else base.discard)(name)
        return frozenset(base)
    for name in items:
        _check(name)
    return frozenset(items)


def _check(name: str) -> None:
    if name not in ALL_CONTROLS:
        raise ValueError(f"unknown control {name!r}")


@dataclass(frozen=True)
class Config:
    mode: str = "vulnerable"
    controls: frozenset = frozenset()
    model_id: str = "us.amazon.nova-lite-v1:0"
    embed_model_id: str = "amazon.titan-embed-text-v2:0"
    guardrail_id: str = ""
    guardrail_version: str = ""
    # Model rounds per turn are max_tool_calls + 2. With the budget control off the
    # loop gets far more rounds, so a runaway tool loop can actually happen. The
    # budget checks themselves (policy.HARDENED_TOOL_BUDGET, HARDENED_INPUT_BUDGET)
    # run with fixed limits in both postures, so they still log when off.
    max_tool_calls: int = 6
    transfer_limit: float = 1000.0
    retrieval_k: int = 3
    # AWS resource names, empty when running in process.
    customers_table: str = ""
    transfers_table: str = ""
    outbox_table: str = ""
    kb_table: str = ""
    bucket: str = ""
    signing_key_id: str = ""
    tool_functions: dict = field(default_factory=dict)

    def on(self, control: str) -> bool:
        return control in self.controls

    @classmethod
    def for_mode(cls, mode: str, controls_override: str | None = None, **kw) -> Config:
        controls = resolve_controls(mode, controls_override)
        if "budget" not in controls:
            kw.setdefault("max_tool_calls", 40)
        return cls(mode=mode, controls=controls, **kw)

    @classmethod
    def from_env(cls) -> Config:
        e = os.environ
        return cls.for_mode(
            e.get("IB_MODE", "vulnerable"),
            e.get("IB_CONTROLS") or None,
            model_id=e.get("IB_MODEL_ID", cls.model_id),
            embed_model_id=e.get("IB_EMBED_MODEL_ID", cls.embed_model_id),
            guardrail_id=e.get("IB_GUARDRAIL_ID", ""),
            guardrail_version=e.get("IB_GUARDRAIL_VERSION", ""),
            customers_table=e.get("IB_CUSTOMERS_TABLE", ""),
            transfers_table=e.get("IB_TRANSFERS_TABLE", ""),
            outbox_table=e.get("IB_OUTBOX_TABLE", ""),
            kb_table=e.get("IB_KB_TABLE", ""),
            bucket=e.get("IB_BUCKET", ""),
            signing_key_id=e.get("IB_SIGNING_KEY_ID", ""),
            tool_functions=json.loads(e.get("IB_TOOL_FUNCTIONS", "{}")),
        )
