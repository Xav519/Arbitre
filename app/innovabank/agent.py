# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file is the "brain" of Inno, the fictional InnovaBank chatbot.
# It does not contain the AI model itself. Instead it runs the conversation
# around the model and decides what the model is allowed to do.
#
# Every customer message goes through the same five steps:
#
#   1. Check the message coming in (too long? looks like a prompt injection?).
#   2. Ask the AI model what to do. The model can answer directly or ask to
#      use a tool (check a balance, move money, search documents, ...).
#   3. Before any tool runs, check it against the bank's rules (is this the
#      customer's own account? is the payee approved? is the amount too big?).
#   4. If a tool returns text from documents, treat that text as untrusted,
#      because a document could contain hidden instructions for the model.
#   5. Check the final answer going out (no leaked secrets, no personal data,
#      no suspicious links) before it reaches the customer.
#
# The same code runs for both the "vulnerable" and "hardened" versions of the
# bank. The only difference is which safety checks are switched on. When a
# check is off, it still runs and still records what it saw ("observed"), it
# just does not stop anything. That way the lab can show exactly which attacks
# a weak setup would have caught but let through.
#
# =============================================================================

"""The orchestrator.

One loop serves both postures. What differs is which controls are enforced.
Every check is evaluated either way, so an attack against the vulnerable stack
still produces a security event, it just is not stopped.
"""
from __future__ import annotations

import json
import uuid

from . import guards, policy
from .models import strip_reasoning
from .prompts import system_prompt
from .seclog import Trace
from .tools import tool_specs


class Agent:
    # The agent receives all of its moving parts from outside (model, tool
    # runner, data store, guardrail). This is why the exact same class can run
    # in tests with fake parts and in AWS with real Bedrock, Lambda and DynamoDB.
    def __init__(self, cfg, model, dispatcher, store, guardrail=None):
        self.cfg = cfg                # which controls are on (the "posture")
        self.model = model            # the AI model, real or scripted
        self.dispatcher = dispatcher  # runs the actual tools
        self.store = store            # customer data
        # No guardrail given means "use one that never intervenes", so the rest
        # of the code never has to check for None.
        self.guardrail = guardrail or guards.NullGuardrail()

    # ------------------------------------------------------------------ public

    def handle(self, message: str, customer_id: str, request_id: str = "", quiet: bool = False) -> dict:
        """Answer one customer message from start to finish."""
        cfg = self.cfg
        # The trace collects every security event and tool call for this
        # request, so the harness and CloudWatch can see what happened.
        trace = Trace(cfg.mode, customer_id, request_id or uuid.uuid4().hex, quiet=quiet)
        customer = self.store.get_customer(customer_id)
        if not customer:
            return self._reply("Unknown customer.", trace, blocked=True)

        # Step 1: stop bad input before it ever reaches the model. This is the
        # cheapest place to refuse, since no model call has been paid for yet.
        refusal = self._screen_input(message, trace)
        if refusal:
            return self._reply(refusal, trace, blocked=True)

        # With prompt_hygiene on, the system prompt leaves out secrets, so there
        # is nothing for an attacker to trick the model into revealing.
        system = system_prompt(cfg.on("prompt_hygiene"), customer)
        messages = [{"role": "user", "content": [{"text": message}]}]
        # TurnState remembers things across tool calls in this one request,
        # such as how many tools ran and whether untrusted text was read.
        state = policy.TurnState()
        # Fallback reply in case the loop ends without the model answering.
        answer = "I wasn't able to complete that request."
        # With tool_policy on, the model is not even offered a "recipient" field
        # for secure messages, so it cannot be talked into emailing a stranger.
        specs = tool_specs(bind_recipient=cfg.on("tool_policy"))

        # Step 2: let the model think and use tools, but only for a limited
        # number of rounds, so a confused or hijacked model cannot loop forever.
        # The "+ 2" leaves room for a final answer after the last tool call.
        for _ in range(cfg.max_tool_calls + 2):
            reply = self.model.converse(system, messages, specs)
            trace.model_calls += 1
            messages.append(reply)
            uses = [b["toolUse"] for b in reply.get("content", []) if "toolUse" in b]
            if not uses:
                # No tool requested means the model is giving its final answer.
                text = "".join(b.get("text", "") for b in reply.get("content", []))
                # Some models wrap private reasoning in <thinking> tags. That is
                # not meant for the customer, so it is removed here.
                answer = strip_reasoning(text) or answer
                break
            # Step 3 and 4 happen inside _run_tool. Results are fed back to the
            # model so it can decide its next move.
            results = [self._run_tool(use, customer, state, trace) for use in uses]
            messages.append({"role": "user", "content": results})

        # Step 5: check the answer before the customer sees it.
        answer, blocked = self._screen_output(answer, customer, trace)
        return self._reply(answer, trace, blocked=blocked)

    # ------------------------------------------------------------------ input

    def _screen_input(self, message: str, trace: Trace) -> str | None:
        """Return a refusal message if the input should be blocked, else None."""
        cfg = self.cfg
        # Very long messages are a common way to bury attacks and run up cost.
        if len(message) > policy.HARDENED_INPUT_BUDGET:
            enforced = cfg.on("budget")
            # Log first, then block only if the control is on. This pattern
            # repeats everywhere so the vulnerable posture still records events.
            trace.event("resource_budget_exceeded", "budget", enforced, f"input of {len(message)} characters")
            if enforced:
                return guards.REFUSAL

        # Look for known injection phrases, including ones hidden with encoding
        # tricks (base64, odd Unicode, and so on).
        verdict = guards.scan(message)
        if verdict.flagged:
            enforced = cfg.on("input_filter")
            # Hidden (obfuscated) attacks get their own event name because they
            # signal a more deliberate attacker.
            event = "prompt_obfuscation" if verdict.obfuscated else "prompt_injection"
            trace.event(event, "input_filter", enforced, f"patterns {sorted(set(verdict.hits))}")
            if enforced:
                return guards.REFUSAL

        # The AWS Bedrock Guardrail is a second, managed opinion. It is only
        # called when switched on, because unlike our own checks it costs money
        # and does not exist offline.
        if cfg.on("guardrail") and self.guardrail.available:
            intervened, text = self.guardrail.apply(message, "INPUT")
            if intervened:
                trace.event("guardrail_intervened", "guardrail", True, "input blocked by Bedrock Guardrails")
                return text
        return None

    # ------------------------------------------------------------------ tools

    def _run_tool(self, use: dict, customer: dict, state: policy.TurnState, trace: Trace) -> dict:
        """Check one tool request against the rules, run it if allowed, and package the result."""
        cfg = self.cfg
        # Copy the arguments so changes here never affect the model's own record.
        name, args = use["name"], dict(use.get("input") or {})
        if name == "send_secure_message" and cfg.on("tool_policy"):
            # Fill in the recipient from the bank's records, not from the model.
            args = self._bind_recipient(args, customer)

        # The rules live in plain code (policy.py), outside the model. A clever
        # prompt can fool a model, but it cannot rewrite this code.
        denied = []
        for v in policy.evaluate(name, args, customer, state, cfg.transfer_limit):
            enforced = cfg.on(v.control)
            trace.event(v.ib_event, v.control, enforced, v.reason)
            if enforced:
                denied.append(v.reason)
        # Count the attempt even if denied, so repeated denied calls still use
        # up the budget and cannot be spammed.
        state.tool_count += 1
        if denied:
            trace.tool(name, args, "denied", denied[0])
            # Tell the model why it was denied so it can explain to the customer
            # instead of retrying blindly.
            return self._tool_result(use, {"error": "denied by policy", "reason": denied[0]}, error=True)

        result = self.dispatcher.call(name, args)
        if result.get("access_denied"):
            # Enforced by AWS whatever the posture, so always "blocked".
            # Each tool runs with its own narrow AWS permissions, a last line of
            # defense if everything above was bypassed.
            trace.event("tool_access_denied", "iam", True, f"{name}: {result.get('detail', '')}")
            trace.tool(name, args, "denied", "denied by the tool's IAM role")
            return self._tool_result(use, {"error": result["error"]}, error=True)
        trace.tool(name, args, "executed")

        # Searching documents brings in text written by someone other than the
        # customer, which could hide instructions. Mark the turn as "tainted" so
        # the policy refuses money transfers and messages for the rest of it.
        if name in policy.UNTRUSTED_SOURCE_TOOLS and "error" not in result:
            state.tainted = True
            return self._tool_result(use, text=self._prepare_untrusted(name, result, trace))
        return self._tool_result(use, result, error="error" in result)

    @staticmethod
    def _bind_recipient(args: dict, customer: dict) -> dict:
        """Address the message to the customer's email on file, from the session, not from the model.

        The hardened tool schema has no recipient, so a model that follows it never
        supplies one. If a recipient is supplied anyway it is left in place for the
        policy to judge: a foreign address is denied and logged as an exfiltration
        attempt. With no email on file nothing is filled in and the schema check denies.
        """
        if "to_email" not in args and customer.get("email"):
            return {**args, "to_email": customer["email"]}
        return args

    def _prepare_untrusted(self, name: str, result: dict, trace: Trace) -> str:
        """Scan, optionally withhold, and optionally spotlight retrieved content."""
        cfg = self.cfg
        # The two document tools return different shapes. Turn both into the
        # same list of {source, text} items so the checks below handle them alike.
        items = result.get("results") if name == "search_knowledge_base" else [
            {"source": result.get("key", ""), "text": result.get("text", "")}]
        # A random marker for this request only. An attacker writing a document
        # in advance cannot guess it, so they cannot fake the "end of data" line.
        nonce = uuid.uuid4().hex[:10]
        rendered = []
        for item in items or []:
            text, source = item.get("text", ""), item.get("source", "")
            withheld = False

            # Scan the document for hidden instructions aimed at the model.
            verdict = guards.scan(text, document=True)
            if verdict.flagged:
                enforced = cfg.on("retrieval_scan")
                trace.event("indirect_injection", "retrieval_scan", enforced,
                            f"{source}: patterns {sorted(set(verdict.hits))}")
                withheld = enforced

            # Skip the paid guardrail call if our own scan already withheld it.
            if not withheld and cfg.on("guardrail") and self.guardrail.available:
                intervened, _ = self.guardrail.apply(text, "INPUT")
                if intervened:
                    trace.event("indirect_injection", "guardrail", True,
                                f"{source}: retrieved content blocked by Bedrock Guardrails")
                    withheld = True

            # Replace dangerous text with a short notice rather than dropping it,
            # so the model knows a document existed but was not safe to show.
            if withheld:
                text = guards.WITHHELD
            body = f"source: {source}\n{text}"
            # "Spotlighting" wraps the text in clear markers that say "this is
            # data, not instructions", which helps the model ignore commands in it.
            rendered.append(guards.spotlight(body, nonce) if cfg.on("spotlight") else body)
        return "\n\n".join(rendered) if rendered else "No matching documents."

    @staticmethod
    def _tool_result(use: dict, payload: dict | None = None, text: str | None = None, error: bool = False) -> dict:
        """Wrap a tool's output in the format the Bedrock Converse API expects."""
        # The dumps/loads round trip turns values JSON cannot hold (dates,
        # decimals from DynamoDB) into strings, so the model call never fails.
        content = [{"text": text}] if text is not None else [{"json": json.loads(json.dumps(payload, default=str))}]
        return {"toolResult": {"toolUseId": use["toolUseId"], "content": content,
                               "status": "error" if error else "success"}}

    # ------------------------------------------------------------------ output

    def _screen_output(self, answer: str, customer: dict, trace: Trace) -> tuple[str, bool]:
        """Clean the final answer and say whether it had to be blocked."""
        cfg = self.cfg
        enforced = cfg.on("output_filter")
        # Look for leaked secrets, other people's personal data, and risky links
        # or markup. The customer's own email is passed in so it is not flagged.
        cleaned, findings = guards.check_output(answer, customer.get("email", ""))
        for f in findings:
            trace.event(f.ib_event, "output_filter", enforced, f.detail)
        blocked = False
        if enforced:
            answer = cleaned
            # Some findings are fixed by redacting; others are serious enough
            # that the whole answer is treated as blocked.
            blocked = any(f.block for f in findings)

        # No point paying for a guardrail check on an answer already blocked.
        if not blocked and cfg.on("guardrail") and self.guardrail.available:
            intervened, text = self.guardrail.apply(answer, "OUTPUT")
            if intervened:
                trace.event("guardrail_intervened", "guardrail", True, "output modified by Bedrock Guardrails")
                answer = text
        return answer, blocked

    @staticmethod
    def _reply(text: str, trace: Trace, blocked: bool) -> dict:
        # One reply shape for every exit path, so callers (Lambda handler,
        # harness, tests) never need special cases.
        return {"response": text, "blocked": blocked, "trace": trace.as_dict()}
