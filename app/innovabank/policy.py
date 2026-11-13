"""Tool authorisation.

This is the control the design leans on most. It runs in the orchestrator,
outside the model, and decides from facts the model cannot change: who is
authenticated, what that customer has registered, and whether untrusted
content has entered the context. A fully compromised model can ask for
anything. It can only get what this file allows.
"""
from __future__ import annotations

from dataclasses import dataclass

HIGH_RISK_TOOLS = {"transfer_funds", "send_secure_message"}
UNTRUSTED_SOURCE_TOOLS = {"search_knowledge_base", "read_document"}
HARDENED_TOOL_BUDGET = 6
HARDENED_INPUT_BUDGET = 4000  # characters per message
PUBLIC_DOC_PREFIX = "kb/public/"

_SCHEMAS = {
    "search_knowledge_base": {"query": str},
    "read_document": {"key": str},
    "get_account_summary": {"customer_id": str},
    "transfer_funds": {"from_customer_id": str, "to_account": str, "amount": (int, float)},
    "send_secure_message": {"to_email": str, "subject": str, "body": str},
}


@dataclass
class Violation:
    control: str
    ib_event: str
    reason: str


@dataclass
class TurnState:
    tainted: bool = False
    tool_count: int = 0


def evaluate(name: str, args: dict, customer: dict, state: TurnState, transfer_limit: float) -> list[Violation]:
    """Return every rule this tool call breaks. An empty list means allowed.

    Each violation names the control that owns it, so the caller can enforce
    only the controls that are switched on and log the rest as observed.
    """
    v: list[Violation] = []
    schema = _SCHEMAS.get(name)
    if schema is None:
        return [Violation("tool_policy", "tool_call_denied", f"unknown tool {name}")]

    for key, typ in schema.items():
        val = args.get(key)
        if not isinstance(val, typ) or isinstance(val, bool):
            v.append(Violation("tool_policy", "tool_call_denied", f"{name}: bad or missing argument {key}"))
        elif isinstance(val, str) and len(val) > 2000:
            v.append(Violation("tool_policy", "tool_call_denied", f"{name}: argument {key} too long"))
    if v:
        return v

    if state.tool_count >= HARDENED_TOOL_BUDGET:
        v.append(Violation("budget", "resource_budget_exceeded",
                           f"tool budget of {HARDENED_TOOL_BUDGET} calls per turn exceeded"))

    if state.tainted and name in HIGH_RISK_TOOLS:
        v.append(Violation("taint_lock", "tool_call_denied",
                           f"{name} locked: untrusted content entered the context this turn"))

    me = customer.get("customer_id")
    if name == "get_account_summary" and args["customer_id"] != me:
        v.append(Violation("tool_policy", "tool_call_denied",
                           f"cross-customer read: {args['customer_id']} is not the authenticated customer"))

    if name == "transfer_funds":
        if args["from_customer_id"] != me:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"transfer from {args['from_customer_id']}, not the authenticated customer"))
        if not 0 < args["amount"] <= transfer_limit:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"amount {args['amount']} outside 0 to {transfer_limit}"))
        if args["to_account"] not in customer.get("payees", []):
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"payee {args['to_account']} is not registered, step-up required"))

    if name == "send_secure_message" and args["to_email"].lower() != customer.get("email", "").lower():
        v.append(Violation("tool_policy", "exfiltration_attempt",
                           f"recipient {args['to_email']} is not the address on file"))

    if name == "read_document":
        key = args["key"]
        if not key.startswith(PUBLIC_DOC_PREFIX) or ".." in key:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"document {key} is outside {PUBLIC_DOC_PREFIX}"))
    return v
