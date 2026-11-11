"""The model's <thinking> blocks never reach the customer, in either posture.

Found in the first live run: Nova Lite wraps its reasoning in <thinking> tags.
The vulnerable stack returned them verbatim, and the hardened output filter
stripped the tags as markup but kept the reasoning, and logged every reply as
an unsafe-rendering event.
"""
import json
import pathlib

import pytest

from innovabank.models import SCRIPTED_REASONING, ScriptedModel, strip_reasoning
from innovabank_harness import runner
from innovabank_harness.targets import LocalTarget

REPLIES = json.loads((pathlib.Path(__file__).parent / "fixtures" / "nova_lite_replies.json").read_text())["replies"]


@pytest.mark.parametrize("reply", REPLIES, ids=[r["id"] for r in REPLIES])
def test_recorded_nova_replies_lose_their_reasoning(reply):
    out = strip_reasoning(reply["raw"])
    assert out == reply["expected"]
    assert "thinking" not in out.lower()


@pytest.mark.parametrize("text, expected", [
    ("<thinking>plan</thinking>Answer.", "Answer."),
    ("<THINKING >plan</ Thinking>\n\nAnswer.", "Answer."),
    ("<thinking>a</thinking> One. <thinking>b</thinking> Two.", "One.  Two."),
    ("Answer first. <thinking>then a reply cut off by the token limit", "Answer first."),
    ("<thinking>only reasoning, never closed", ""),
    ("reasoning whose opening tag was lost</thinking> Answer.", "Answer."),
    ("No reasoning here.", "No reasoning here."),
])
def test_closed_unclosed_and_orphan_tags(text, expected):
    assert strip_reasoning(text) == expected


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_reasoning_is_removed_in_both_postures_without_security_events(mode):
    t = LocalTarget(mode)
    t.reset()
    out = t.invoke("What's my balance?", "C-1001", [
        {"tool": "get_account_summary", "args": {"customer_id": "C-1001"}},
        {"say": "Your balance is 2500.00 dollars."}])
    assert out["response"] == "Your balance is 2500.00 dollars."
    assert out["trace"]["events"] == []


def test_answer_that_is_only_reasoning_falls_back_to_a_safe_message():
    t = LocalTarget("hardened")
    t.reset()
    out = t.invoke("hi", "C-1001", [{"say": "<thinking>internal plan, never closed"}])
    assert "internal plan" not in out["response"] and out["response"]


def test_scripted_model_formats_replies_like_nova():
    reply = ScriptedModel([{"tool": "get_account_summary", "args": {"customer_id": "C-1001"}}],
                          reasoning=True).converse("sys", [], [])
    assert reply["content"][0]["text"] == f"<thinking>{SCRIPTED_REASONING}</thinking>"
    assert "toolUse" in reply["content"][1]


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_no_response_in_the_bench_contains_reasoning(mode):
    record = runner.run(LocalTarget(mode))
    leaks = [r["id"] for r in record["attacks"] + record["benign"] if "IB-SCRIPTED-REASONING" in r["response"]]
    assert leaks == []
