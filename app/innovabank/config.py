# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file holds the settings that decide how Inno, the fictional InnovaBank
# chatbot, behaves. Think of it as the control panel for the whole lab.
#
# The most important idea here: the "vulnerable" bank and the "hardened" bank
# run exactly the same code. The only thing that differs is a list of named
# safety checks ("controls") that are switched on or off.
#
#   - vulnerable = every safety check switched off
#   - hardened   = every safety check switched on
#
# You can also flip single checks on or off (for example "hardened, but
# without the taint lock"). This lets the lab answer a useful question:
# "if we removed just this one protection, which attacks would succeed again?"
#
# Settings can come from two places:
#
#   1. Directly in Python (tests and the offline harness call for_mode()).
#   2. From environment variables starting with IB_ (the AWS Lambda functions
#      call from_env(), and Terraform sets those variables at deploy time).
#
# Both paths end in the same Config object, so the rest of the code never has
# to care whether it is running on a laptop or in AWS.
#
# =============================================================================

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

# The full list of safety checks the lab knows about. Each one is a short name
# so it can be typed on a command line or in an environment variable.
# Keeping them in one place means a typo in a control name is caught early
# (see _check below) instead of silently doing nothing.
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

# The two ready-made postures. A posture is just a named set of controls, so
# adding a new posture later would only mean adding one line here.
# frozenset is used so nobody can accidentally change a preset at runtime.
PRESETS = {
    "vulnerable": frozenset(),
    "hardened": frozenset(ALL_CONTROLS),
}

# The five tools Inno can use. Two of them (transfer_funds and
# send_secure_message) change things in the real world, which is why the
# policy code treats them more strictly than the read-only ones.
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
    # Fail loudly on an unknown mode. Silently falling back to a default could
    # deploy a vulnerable bank when someone meant to deploy a hardened one.
    if mode not in PRESETS:
        raise ValueError(f"unknown mode {mode!r}, expected one of {sorted(PRESETS)}")
    # Start from a mutable copy of the preset so deltas can add or remove items.
    base = set(PRESETS[mode])
    # No override given: just use the preset as is.
    if not override:
        return frozenset(base)
    # Split "a, b ,c" into ["a", "b", "c"], ignoring stray spaces and empty bits.
    items = [i.strip() for i in override.split(",") if i.strip()]
    # Shortcuts: "all" and "none" ignore the preset entirely.
    if items == ["all"]:
        return frozenset(ALL_CONTROLS)
    if items == ["none"]:
        return frozenset()
    # Delta form: every item starts with + or -, so adjust the preset.
    # This is what ablation uses, e.g. "hardened" with "-taint_lock".
    if all(i[0] in "+-" for i in items):
        for i in items:
            name = i[1:]
            _check(name)
            # "+" adds the control, "-" removes it (discard does not fail if
            # the control was already absent).
            (base.add if i[0] == "+" else base.discard)(name)
        return frozenset(base)
    # Explicit list form: the given names replace the preset completely.
    for name in items:
        _check(name)
    return frozenset(items)


def _check(name: str) -> None:
    # Reject misspelled control names. Without this, "-taint_lok" would quietly
    # remove nothing and an experiment would give misleading results.
    if name not in ALL_CONTROLS:
        raise ValueError(f"unknown control {name!r}")


# All settings for one run of the agent, bundled together.
# frozen=True makes it read-only after creation, so no part of the code can
# switch a safety check off halfway through a request.
@dataclass(frozen=True)
class Config:
    mode: str = "vulnerable"
    controls: frozenset = frozenset()
    # Which Bedrock models to call. The real pinned versions are tracked in
    # supplychain/model-lock.yaml; these are the defaults.
    model_id: str = "us.amazon.nova-lite-v1:0"
    embed_model_id: str = "amazon.titan-embed-text-v2:0"
    # Bedrock Guardrail to use, empty when no guardrail is deployed.
    guardrail_id: str = ""
    guardrail_version: str = ""
    # Model rounds per turn are max_tool_calls + 2. With the budget control off the
    # loop gets far more rounds, so a runaway tool loop can actually happen. The
    # budget checks themselves (policy.HARDENED_TOOL_BUDGET, HARDENED_INPUT_BUDGET)
    # run with fixed limits in both postures, so they still log when off.
    max_tool_calls: int = 6
    # Largest single transfer allowed when tool_policy is on.
    transfer_limit: float = 1000.0
    # How many knowledge base documents to fetch per search.
    retrieval_k: int = 3
    # AWS resource names, empty when running in process.
    customers_table: str = ""
    transfers_table: str = ""
    outbox_table: str = ""
    kb_table: str = ""
    bucket: str = ""
    signing_key_id: str = ""
    # Maps each tool name to the Lambda function that runs it in AWS.
    # default_factory gives each Config its own empty dict instead of one
    # shared dict, which is a classic Python pitfall with mutable defaults.
    tool_functions: dict = field(default_factory=dict)

    def on(self, control: str) -> bool:
        # The one question the rest of the code asks: "is this check enforced?"
        # Checks still run when this returns False; they just log "observed"
        # instead of blocking.
        return control in self.controls

    @classmethod
    def for_mode(cls, mode: str, controls_override: str | None = None, **kw) -> Config:
        # Build a Config from a mode name plus optional control tweaks.
        # Used directly by tests and the offline harness.
        controls = resolve_controls(mode, controls_override)
        # Without the budget control, give the model many more rounds so the
        # lab can show what a runaway tool loop looks like. setdefault keeps
        # any value the caller passed explicitly.
        if "budget" not in controls:
            kw.setdefault("max_tool_calls", 40)
        return cls(mode=mode, controls=controls, **kw)

    @classmethod
    def from_env(cls) -> Config:
        # Build a Config from IB_* environment variables. This is how the AWS
        # Lambda functions get their settings: Terraform writes the variables,
        # this method reads them. Missing variables fall back to safe empty
        # values or the class defaults above.
        e = os.environ
        return cls.for_mode(
            e.get("IB_MODE", "vulnerable"),
            # "or None" turns an empty string into None, meaning "no override".
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
            # Environment variables are plain text, so the tool-to-Lambda map
            # arrives as a JSON string and is decoded here.
            tool_functions=json.loads(e.get("IB_TOOL_FUNCTIONS", "{}")),
        )
