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


def _trial(target, case: dict, verdict) -> dict:
    """One execution of a case: what happened, judged by `verdict(result, observed)`."""
    result, observed, events = _execute(target, case)
    return {
        "ok": verdict(result, observed),
        "blocked_by": _controls(events, "blocked"),
        "detected_by": sorted({e["ib_event"] for e in events}),
        "response": result.get("response", "")[:400],
        "tool_calls": result.get("trace", {}).get("tool_calls", [])[:12],
    }


def _union(lists) -> list[str]:
    seen: list[str] = []
    for items in lists:
        seen.extend(i for i in items if i not in seen)
    return seen


def _aggregate(trials: list[dict], show: dict, key: str) -> dict:
    """Summary fields over every trial. Events and blocks are the union, so one noisy trial shows.

    `show` is the trial whose response and tool calls are kept at the top level, the most
    telling one: a trial where the attack got through, or where the legitimate request broke.
    """
    return {
        "trials": len(trials),
        "blocked_by": _union(t["blocked_by"] for t in trials),
        "detected_by": sorted(set(_union(t["detected_by"] for t in trials))),
        "response": show["response"],
        "tool_calls": show["tool_calls"],
        "runs": [{key: t["ok"], **{k: v for k, v in t.items() if k != "ok"}} for t in trials],
    }


def run(target, only: set[str] | None = None, trials: int = 1) -> dict:
    """Execute every attack and benign case `trials` times. Returns a JSON-serialisable record.

    A live model is not deterministic even at temperature 0, so one trial can flip either way.
    An attack counts as succeeded if it succeeded in any trial (worst case). A legitimate request
    counts as passed only if it passed in every trial; `passes` says how many did, and the
    regression guard decides how many it needs.
    """
    if trials < 1:
        raise ValueError("trials must be at least 1")
    attacks, benign = [], []
    for case in load_catalog():
        if only and case["id"] not in only:
            continue
        runs = [_trial(target, case, lambda r, o: detectors.any_of(case["success"], r, o)) for _ in range(trials)]
        hits = sum(t["ok"] for t in runs)
        show = next((t for t in runs if t["ok"]), runs[0])
        attacks.append({
            "id": case["id"], "name": case["name"], "category": case["category"],
            "owasp": case["owasp"], "owasp_name": case["owasp_name"], "atlas": case["atlas"],
            "path_module": case["path_module"],
            "succeeded": hits > 0, "successes": hits,
            **_aggregate(runs, show, "succeeded"),
        })
    for case in load_benign():
        if only and case["id"] not in only:
            continue
        runs = [_trial(target, case, lambda r, o: detectors.all_of(case["expect"], r, o)) for _ in range(trials)]
        passes = sum(t["ok"] for t in runs)
        show = next((t for t in runs if not t["ok"]), runs[0])
        benign.append({
            "id": case["id"], "name": case["name"],
            "passed": passes == trials, "passes": passes,
            **_aggregate(runs, show, "passed"),
        })
    target.reset()
    return {
        "meta": {**target.describe(), "trials": trials,
                 "run_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "attacks": attacks,
        "benign": benign,
    }
