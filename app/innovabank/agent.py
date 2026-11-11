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
    def __init__(self, cfg, model, dispatcher, store, guardrail=None):
        self.cfg = cfg
        self.model = model
        self.dispatcher = dispatcher
        self.store = store
        self.guardrail = guardrail or guards.NullGuardrail()

    # ------------------------------------------------------------------ public

    def handle(self, message: str, customer_id: str, request_id: str = "", quiet: bool = False) -> dict:
        cfg = self.cfg
        trace = Trace(cfg.mode, customer_id, request_id or uuid.uuid4().hex, quiet=quiet)
        customer = self.store.get_customer(customer_id)
        if not customer:
            return self._reply("Unknown customer.", trace, blocked=True)

        refusal = self._screen_input(message, trace)
        if refusal:
            return self._reply(refusal, trace, blocked=True)

        system = system_prompt(cfg.on("prompt_hygiene"), customer)
        messages = [{"role": "user", "content": [{"text": message}]}]
        state = policy.TurnState()
        answer = "I wasn't able to complete that request."
        specs = tool_specs(bind_recipient=cfg.on("tool_policy"))

        for _ in range(cfg.max_tool_calls + 2):
            reply = self.model.converse(system, messages, specs)
            trace.model_calls += 1
            messages.append(reply)
            uses = [b["toolUse"] for b in reply.get("content", []) if "toolUse" in b]
            if not uses:
                text = "".join(b.get("text", "") for b in reply.get("content", []))
                answer = strip_reasoning(text) or answer
                break
            results = [self._run_tool(use, customer, state, trace) for use in uses]
            messages.append({"role": "user", "content": results})

        answer, blocked = self._screen_output(answer, customer, trace)
        return self._reply(answer, trace, blocked=blocked)

    # ------------------------------------------------------------------ input

    def _screen_input(self, message: str, trace: Trace) -> str | None:
        cfg = self.cfg
        if len(message) > 4000:
            enforced = cfg.on("budget")
            trace.event("resource_budget_exceeded", "budget", enforced, f"input of {len(message)} characters")
            if enforced:
                return guards.REFUSAL

        verdict = guards.scan(message)
        if verdict.flagged:
            enforced = cfg.on("input_filter")
            event = "prompt_obfuscation" if verdict.obfuscated else "prompt_injection"
            trace.event(event, "input_filter", enforced, f"patterns {sorted(set(verdict.hits))}")
            if enforced:
                return guards.REFUSAL

        if cfg.on("guardrail") and self.guardrail.available:
            intervened, text = self.guardrail.apply(message, "INPUT")
            if intervened:
                trace.event("guardrail_intervened", "guardrail", True, "input blocked by Bedrock Guardrails")
                return text
        return None

    # ------------------------------------------------------------------ tools

    def _run_tool(self, use: dict, customer: dict, state: policy.TurnState, trace: Trace) -> dict:
        cfg = self.cfg
        name, args = use["name"], dict(use.get("input") or {})
        if name == "send_secure_message" and cfg.on("tool_policy"):
            args = self._bind_recipient(args, customer)

        denied = []
        for v in policy.evaluate(name, args, customer, state, cfg.transfer_limit):
            enforced = cfg.on(v.control)
            trace.event(v.ib_event, v.control, enforced, v.reason)
            if enforced:
                denied.append(v.reason)
        state.tool_count += 1
        if denied:
            trace.tool(name, args, "denied", denied[0])
            return self._tool_result(use, {"error": "denied by policy", "reason": denied[0]}, error=True)

        result = self.dispatcher.call(name, args)
        if result.get("access_denied"):
            # Enforced by AWS whatever the posture, so always "blocked".
            trace.event("tool_access_denied", "iam", True, f"{name}: {result.get('detail', '')}")
            trace.tool(name, args, "denied", "denied by the tool's IAM role")
            return self._tool_result(use, {"error": result["error"]}, error=True)
        trace.tool(name, args, "executed")

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
        items = result.get("results") if name == "search_knowledge_base" else [
            {"source": result.get("key", ""), "text": result.get("text", "")}]
        nonce = uuid.uuid4().hex[:10]
        rendered = []
        for item in items or []:
            text, source = item.get("text", ""), item.get("source", "")
            withheld = False

            verdict = guards.scan(text, document=True)
            if verdict.flagged:
                enforced = cfg.on("retrieval_scan")
                trace.event("indirect_injection", "retrieval_scan", enforced,
                            f"{source}: patterns {sorted(set(verdict.hits))}")
                withheld = enforced

            if not withheld and cfg.on("guardrail") and self.guardrail.available:
                intervened, _ = self.guardrail.apply(text, "INPUT")
                if intervened:
                    trace.event("indirect_injection", "guardrail", True,
                                f"{source}: retrieved content blocked by Bedrock Guardrails")
                    withheld = True

            if withheld:
                text = guards.WITHHELD
            body = f"source: {source}\n{text}"
            rendered.append(guards.spotlight(body, nonce) if cfg.on("spotlight") else body)
        return "\n\n".join(rendered) if rendered else "No matching documents."

    @staticmethod
    def _tool_result(use: dict, payload: dict | None = None, text: str | None = None, error: bool = False) -> dict:
        content = [{"text": text}] if text is not None else [{"json": json.loads(json.dumps(payload, default=str))}]
        return {"toolResult": {"toolUseId": use["toolUseId"], "content": content,
                               "status": "error" if error else "success"}}

    # ------------------------------------------------------------------ output

    def _screen_output(self, answer: str, customer: dict, trace: Trace) -> tuple[str, bool]:
        cfg = self.cfg
        enforced = cfg.on("output_filter")
        cleaned, findings = guards.check_output(answer, customer.get("email", ""))
        for f in findings:
            trace.event(f.ib_event, "output_filter", enforced, f.detail)
        blocked = False
        if enforced:
            answer = cleaned
            blocked = any(f.block for f in findings)

        if not blocked and cfg.on("guardrail") and self.guardrail.available:
            intervened, text = self.guardrail.apply(answer, "OUTPUT")
            if intervened:
                trace.event("guardrail_intervened", "guardrail", True, "output modified by Bedrock Guardrails")
                answer = text
        return answer, blocked

    @staticmethod
    def _reply(text: str, trace: Trace, blocked: bool) -> dict:
        return {"response": text, "blocked": blocked, "trace": trace.as_dict()}
