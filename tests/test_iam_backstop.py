"""An IAM deny from a tool's own role is logged and attributed, not swallowed as a generic failure.

Before this, a tool Lambda whose role refused the AWS call crashed with an unhandled
ClientError, the dispatcher returned "tool execution failed", no security event was
logged, and the harness could not say which control had stopped the request.
"""
import io
import json

import pytest
from botocore.exceptions import ClientError

from innovabank import handlers
from innovabank.agent import Agent
from innovabank.config import Config
from innovabank.models import ScriptedModel
from innovabank.tools import LambdaDispatcher, access_denied_code
from innovabank_harness import report, runner
from innovabank_harness.targets import LocalTarget

S3_DENY = "An error occurred (AccessDenied) when calling the GetObject operation: Access Denied"


def client_error(code, op="GetObject"):
    return ClientError({"Error": {"Code": code, "Message": "denied"}}, op)


# ------------------------------------------------------------------ agent


class DenyingDispatcher:
    def call(self, name, args):
        return {"error": "access denied by the tool's IAM role", "access_denied": True,
                "detail": "GetObject AccessDenied"}


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_agent_logs_an_iam_deny_as_blocked_by_iam_in_both_postures(mode):
    t = LocalTarget(mode)
    t.reset()
    model = ScriptedModel([{"tool": "read_document", "args": {"key": "kb/public/fees.md"}},
                           {"say": "{tool_results}"}])
    out = Agent(t.cfg, model, DenyingDispatcher(), t.store).handle("open it", "C-1001", quiet=True)
    events = out["trace"]["events"]
    assert [(e["ib_event"], e["control"], e["action"]) for e in events] == [("tool_access_denied", "iam", "blocked")]
    assert events[0]["atlas_technique"] == "AML.T0053" and events[0]["owasp"] == "LLM06"
    assert "read_document" in events[0]["detail"]
    call = out["trace"]["tool_calls"][0]
    assert (call["status"], call["reason"]) == ("denied", "denied by the tool's IAM role")
    assert runner._controls(events, "blocked") == ["iam"]


def test_report_names_the_iam_backstop():
    assert report._labels(["iam"]) == "per-tool IAM"
    assert report._outcome({"succeeded": False, "blocked_by": ["iam"]}, {"succeeded": True}) == "blocked by per-tool IAM"


# ------------------------------------------------------------------ dispatcher


class FakeLambda:
    def __init__(self, payload=None, function_error=None, raises=None):
        self.payload, self.function_error, self.raises = payload or {}, function_error, raises

    def invoke(self, FunctionName, Payload):
        if self.raises:
            raise self.raises
        resp = {"Payload": io.BytesIO(json.dumps(self.payload).encode())}
        if self.function_error:
            resp["FunctionError"] = self.function_error
        return resp


def dispatcher(client):
    return LambdaDispatcher(Config.for_mode("hardened", tool_functions={"read_document": "fn-read"}), client)


def test_dispatcher_reports_an_unhandled_iam_deny_inside_the_tool():
    out = dispatcher(FakeLambda({"errorType": "ClientError", "errorMessage": S3_DENY}, "Unhandled")).call(
        "read_document", {"key": "internal/ops-runbook.md"})
    assert out["access_denied"] is True and out["detail"] == "AccessDenied"


def test_dispatcher_reports_the_agent_role_being_denied_invoke():
    out = dispatcher(FakeLambda(raises=client_error("AccessDeniedException", "Invoke"))).call("read_document", {})
    assert out["access_denied"] is True and "AccessDeniedException" in out["detail"]


def test_dispatcher_keeps_other_failures_generic_and_reraises_other_errors():
    out = dispatcher(FakeLambda({"errorType": "Timeout", "errorMessage": "Task timed out"}, "Unhandled")).call(
        "read_document", {})
    assert out == {"error": "tool execution failed", "detail": "Timeout"}
    with pytest.raises(ClientError):
        dispatcher(FakeLambda(raises=client_error("ThrottlingException", "Invoke"))).call("read_document", {})


@pytest.mark.parametrize("code, denied", [
    ("AccessDenied", True), ("AccessDeniedException", True), ("UnauthorizedOperation", True),
    ("NoSuchKey", False), ("ThrottlingException", False), ("ResourceNotFoundException", False),
])
def test_access_denied_codes(code, denied):
    assert (access_denied_code(client_error(code)) is not None) is denied
    assert access_denied_code(ValueError("not an AWS error")) is None


# ------------------------------------------------------------------ tool handler


class FakeBoto3:
    @staticmethod
    def client(name):
        return object()


def test_tool_handler_returns_an_iam_deny_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(handlers, "_runtime", lambda: (Config.for_mode("hardened"), FakeBoto3, None))

    def deny(*a, **k):
        raise client_error("AccessDenied", "GetObject")

    monkeypatch.setattr(handlers, "run_tool", deny)
    out = handlers.tool_handler({"tool": "read_document", "args": {"key": "internal/ops-runbook.md"}}, None)
    assert out["access_denied"] is True and out["detail"] == "GetObject AccessDenied"


def test_tool_handler_still_raises_other_errors(monkeypatch):
    monkeypatch.setattr(handlers, "_runtime", lambda: (Config.for_mode("hardened"), FakeBoto3, None))

    def boom(*a, **k):
        raise client_error("ProvisionedThroughputExceededException", "GetItem")

    monkeypatch.setattr(handlers, "run_tool", boom)
    with pytest.raises(ClientError):
        handlers.tool_handler({"tool": "get_account_summary", "args": {}}, None)
