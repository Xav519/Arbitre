"""Run the catalog against a target and record what actually happened."""
from __future__ import annotations

import datetime
import pathlib

import yaml

from . import detectors

HARNESS_DIR = pathlib.Path(__file__).resolve().parents[1]


def load_catalog() -> list[dict]:
    attacks = []
    for path in sorted((HARNESS_DIR / "attacks").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for a in doc["attacks"]:
            attacks.append({**a, "category": doc["category"], "owasp": doc["owasp"],
                            "owasp_name": doc["owasp_name"], "path_module": doc["path_module"]})
    return attacks


def load_benign() -> list[dict]:
    return yaml.safe_load((HARNESS_DIR / "benign.yaml").read_text(encoding="utf-8"))["cases"]


def _execute(target, case: dict) -> tuple[dict, dict, list[dict]]:
    target.reset()
    events: list[dict] = []
    for doc in (case.get("setup") or {}).get("documents", []):
        outcome = target.plant(doc["key"], doc["body"], bool(doc.get("signed")))
        events.extend(outcome.get("events", []))
    prompt = case["prompt"]
    if case.get("pad_chars"):
        prompt = ("Please read carefully. " * (int(case["pad_chars"]) // 23 + 1))[: int(case["pad_chars"])] + "\n" + prompt
    result = target.invoke(prompt, case["session"], case.get("compromised_model", []))
    events.extend(result.get("trace", {}).get("events", []))
    return result, target.observe(), events


def _controls(events: list[dict], action: str) -> list[str]:
    seen: list[str] = []
    for e in events:
        if e.get("action") == action and e["control"] not in seen:
            seen.append(e["control"])
    return seen


def run(target, only: set[str] | None = None) -> dict:
    """Execute every attack and benign case. Returns a JSON-serialisable record."""
    attacks, benign = [], []
    for case in load_catalog():
        if only and case["id"] not in only:
            continue
        result, observed, events = _execute(target, case)
        attacks.append({
            "id": case["id"], "name": case["name"], "category": case["category"],
            "owasp": case["owasp"], "owasp_name": case["owasp_name"], "atlas": case["atlas"],
            "path_module": case["path_module"],
            "succeeded": detectors.any_of(case["success"], result, observed),
            "blocked_by": _controls(events, "blocked"),
            "detected_by": sorted({e["ib_event"] for e in events}),
            "response": result.get("response", "")[:400],
            "tool_calls": result.get("trace", {}).get("tool_calls", [])[:12],
        })
    for case in load_benign():
        if only and case["id"] not in only:
            continue
        result, observed, events = _execute(target, case)
        benign.append({
            "id": case["id"], "name": case["name"],
            "passed": detectors.all_of(case["expect"], result, observed),
            "blocked_by": _controls(events, "blocked"),
            "detected_by": sorted({e["ib_event"] for e in events}),
            "response": result.get("response", "")[:400],
        })
    target.reset()
    return {
        "meta": {**target.describe(),
                 "run_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "attacks": attacks,
        "benign": benign,
    }
