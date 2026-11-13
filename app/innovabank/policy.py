# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# Inno, the banking chatbot, can use five tools: look up a balance, send
# money, send a secure message, search the knowledge base, and read a
# document. The AI model decides WHEN to use a tool and WITH WHICH values.
# But the AI can be tricked (for example by a hidden instruction inside a
# document), so we never let it have the final word.
#
# This file is the final word. Every time the AI asks to use a tool, the
# request is checked here first, like a bank teller checking an ID before
# handing over cash. The checks are simple, fixed rules written in normal
# code, so no clever wording can talk them out of anything:
#
#   - Is the tool real, and are the values sensible (right type, not huge)?
#   - Has the AI already used too many tools in this one message?
#   - Is the customer only looking at THEIR OWN account?
#   - Is money only leaving THEIR OWN account, within the limit, and only
#     going to a payee they registered themselves?
#   - Is a secure message only going to THEIR OWN email address?
#   - Is the document being read a public one, not a private file?
#   - Taint lock: if the AI has read outside content (knowledge base or a
#     document) during this message, it may no longer send money or
#     messages. Outside content might contain a hidden attack, so the
#     dangerous tools are switched off until the next message.
#
# The answer is a list of broken rules. An empty list means "allowed".
# Each broken rule says which protection it belongs to, so the caller can
# block it (hardened bank) or just record it (vulnerable bank).
#
# =============================================================================

"""Tool authorisation.

This is the control the design leans on most. It runs in the orchestrator,
outside the model, and decides from facts the model cannot change: who is
authenticated, what that customer has registered, and whether untrusted
content has entered the context. A fully compromised model can ask for
anything. It can only get what this file allows.
"""
from __future__ import annotations

from dataclasses import dataclass

# Tools that can cause real harm if misused: moving money out, or sending
# data to someone outside. These are the ones the taint lock switches off.
HIGH_RISK_TOOLS = {"transfer_funds", "send_secure_message"}
# Tools that bring outside text into the conversation. That text is not
# written by the customer or the bank, so it may hide an attack.
UNTRUSTED_SOURCE_TOOLS = {"search_knowledge_base", "read_document"}
# A normal request needs only a few tool calls. A runaway loop (or an attack
# trying to burn money or hammer the backend) needs many, so we cap it.
HARDENED_TOOL_BUDGET = 6
# Very long messages are a common way to bury an attack or run up costs.
HARDENED_INPUT_BUDGET = 4000  # characters per message
# Only documents under this folder are meant for customers to read. Anything
# else in the bucket (internal files, quarantined uploads) stays off limits.
PUBLIC_DOC_PREFIX = "kb/public/"

# The exact arguments each tool expects, and their types. We check these
# ourselves instead of trusting the model, because a tricked model may send
# missing, wrongly typed, or extra values to confuse the tool behind it.
_SCHEMAS = {
    "search_knowledge_base": {"query": str},
    "read_document": {"key": str},
    "get_account_summary": {"customer_id": str},
    "transfer_funds": {"from_customer_id": str, "to_account": str, "amount": (int, float)},
    "send_secure_message": {"to_email": str, "subject": str, "body": str},
}


@dataclass
class Violation:
    """One broken rule.

    control: which protection owns this rule (for example "taint_lock"),
             so the caller can tell whether it is switched on.
    ib_event: the security event name to log, used by the CloudWatch alarms.
    reason: a plain explanation, for logs and for people reading them.
    """
    control: str
    ib_event: str
    reason: str


@dataclass
class TurnState:
    """What has happened so far while answering the current message.

    It is reset for every new customer message, so the taint lock and the
    tool budget only ever apply within a single turn.
    """
    # True once outside content (knowledge base or document) has been read.
    tainted: bool = False
    # How many tools have already been called in this turn.
    tool_count: int = 0


def evaluate(name: str, args: dict, customer: dict, state: TurnState, transfer_limit: float) -> list[Violation]:
    """Return every rule this tool call breaks. An empty list means allowed.

    Each violation names the control that owns it, so the caller can enforce
    only the controls that are switched on and log the rest as observed.
    """
    v: list[Violation] = []
    schema = _SCHEMAS.get(name)
    # A tool we do not know about is refused outright: there is no rule we
    # could check it against, so allowing it would mean trusting the model.
    if schema is None:
        return [Violation("tool_policy", "tool_call_denied", f"unknown tool {name}")]

    # Check every expected argument is present and of the right type.
    # bool is rejected on purpose: in Python True counts as the number 1, so
    # without this check "amount": true would pass as a 1 unit transfer.
    # Very long strings are rejected because they are a cheap way to smuggle
    # a large hidden payload into a tool.
    for key, typ in schema.items():
        val = args.get(key)
        if not isinstance(val, typ) or isinstance(val, bool):
            v.append(Violation("tool_policy", "tool_call_denied", f"{name}: bad or missing argument {key}"))
        elif isinstance(val, str) and len(val) > 2000:
            v.append(Violation("tool_policy", "tool_call_denied", f"{name}: argument {key} too long"))
    # Stop here if the arguments are malformed. The checks below read the
    # arguments directly and would crash or give misleading results on bad
    # input.
    if v:
        return v

    # Budget: too many tool calls in one turn. A fixed limit is used even
    # when the budget control is off, so the vulnerable bank still logs it.
    if state.tool_count >= HARDENED_TOOL_BUDGET:
        v.append(Violation("budget", "resource_budget_exceeded",
                           f"tool budget of {HARDENED_TOOL_BUDGET} calls per turn exceeded"))

    # Taint lock: once outside content has been read this turn, the risky
    # tools are off. This works even if we fail to spot the hidden attack in
    # that content, because it does not try to detect the attack at all. It
    # just removes the power the attack would need.
    if state.tainted and name in HIGH_RISK_TOOLS:
        v.append(Violation("taint_lock", "tool_call_denied",
                           f"{name} locked: untrusted content entered the context this turn"))

    # "me" is the customer who actually logged in. It comes from the session,
    # never from the chat, so the model cannot change who it is acting for.
    me = customer.get("customer_id")
    # Customers may only see their own account, never someone else's.
    if name == "get_account_summary" and args["customer_id"] != me:
        v.append(Violation("tool_policy", "tool_call_denied",
                           f"cross-customer read: {args['customer_id']} is not the authenticated customer"))

    if name == "transfer_funds":
        # Money can only leave the logged-in customer's own account.
        if args["from_customer_id"] != me:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"transfer from {args['from_customer_id']}, not the authenticated customer"))
        # The amount must be positive and under the per-transfer limit. A
        # negative amount is refused here too, rather than relying on the
        # tool behind it, because a negative debit would add money instead.
        if not 0 < args["amount"] <= transfer_limit:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"amount {args['amount']} outside 0 to {transfer_limit}"))
        # Money can only go to a payee the customer registered beforehand.
        # Adding a new payee needs extra verification (step-up) outside the
        # chat, so an attacker cannot just name their own account.
        if args["to_account"] not in customer.get("payees", []):
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"payee {args['to_account']} is not registered, step-up required"))

    # Secure messages may only go to the customer's own email on file.
    # Otherwise a tricked model could mail private data to an attacker, so
    # this is logged as an exfiltration attempt, not just a denied call.
    # The comparison ignores upper/lower case, as email addresses do.
    if name == "send_secure_message" and args["to_email"].lower() != customer.get("email", "").lower():
        v.append(Violation("tool_policy", "exfiltration_attempt",
                           f"recipient {args['to_email']} is not the address on file"))

    # Documents must be inside the public folder. ".." is refused as well,
    # because "kb/public/../private/x" starts with the right prefix but
    # actually points outside it (a path traversal trick).
    if name == "read_document":
        key = args["key"]
        if not key.startswith(PUBLIC_DOC_PREFIX) or ".." in key:
            v.append(Violation("tool_policy", "tool_call_denied",
                               f"document {key} is outside {PUBLIC_DOC_PREFIX}"))
    return v
