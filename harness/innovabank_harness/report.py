"""Turn two runs into the before and after table."""
from __future__ import annotations

import re

CONTROL_LABELS = {
    "prompt_hygiene": "prompt hygiene", "input_filter": "input filter", "guardrail": "Bedrock Guardrails",
    "spotlight": "spotlighting", "retrieval_scan": "retrieval scan", "taint_lock": "taint lock",
    "tool_policy": "tool policy", "budget": "budget", "output_filter": "output filter",
    "data_minimisation": "data minimisation", "ingest_integrity": "signed ingestion",
    "ingest_scan": "ingestion scan",
}


def _pct(n: int, d: int) -> str:
    return f"{n}/{d} ({round(100 * n / d)}%)" if d else "n/a"


def _by_category(run: dict) -> dict:
    out: dict = {}
    for a in run["attacks"]:
        row = out.setdefault(a["category"], {"owasp": a["owasp"], "total": 0, "succeeded": 0})
        row["total"] += 1
        row["succeeded"] += int(a["succeeded"])
    return out


def _stopped(attack: dict) -> str:
    if attack["succeeded"]:
        return "**not stopped**"
    if attack["blocked_by"]:
        return ", ".join(CONTROL_LABELS.get(c, c) for c in attack["blocked_by"])
    return "no control fired (payload never reached the model, or the model declined)"


def summary_table(vuln: dict, hard: dict) -> str:
    v, h = _by_category(vuln), _by_category(hard)
    lines = ["| OWASP LLM | Category | Vulnerable | Hardened |", "|---|---|---|---|"]
    tv = th = tn = 0
    for cat, row in v.items():
        hr = h.get(cat, {"succeeded": 0, "total": 0})
        lines.append(f"| {row['owasp']} | {cat} | {_pct(row['succeeded'], row['total'])} "
                     f"| {_pct(hr['succeeded'], hr['total'])} |")
        tv, th, tn = tv + row["succeeded"], th + hr["succeeded"], tn + row["total"]
    lines.append(f"| | **All attacks** | **{_pct(tv, tn)}** | **{_pct(th, tn)}** |")
    bv = sum(b["passed"] for b in vuln["benign"])
    bh = sum(b["passed"] for b in hard["benign"])
    lines.append(f"| | Legitimate requests completed | {_pct(bv, len(vuln['benign']))} "
                 f"| {_pct(bh, len(hard['benign']))} |")
    return "\n".join(lines)


def detail_table(vuln: dict, hard: dict) -> str:
    hv = {a["id"]: a for a in hard["attacks"]}
    lines = ["| ID | Attack | ATLAS | Vulnerable | Hardened | Stopped by |", "|---|---|---|---|---|---|"]
    for a in vuln["attacks"]:
        h = hv.get(a["id"])
        if not h:
            continue
        lines.append(f"| {a['id']} | {a['name']} | {', '.join(a['atlas'])} "
                     f"| {'succeeded' if a['succeeded'] else 'failed'} "
                     f"| {'succeeded' if h['succeeded'] else 'failed'} | {_stopped(h)} |")
    return "\n".join(lines)


def benign_table(vuln: dict, hard: dict) -> str:
    hb = {b["id"]: b for b in hard["benign"]}
    lines = ["| ID | Legitimate request | Vulnerable | Hardened |", "|---|---|---|---|"]
    for b in vuln["benign"]:
        h = hb.get(b["id"], {"passed": False, "blocked_by": []})
        note = "" if h["passed"] else f" (blocked by {', '.join(h['blocked_by']) or 'unknown'})"
        lines.append(f"| {b['id']} | {b['name']} | {'ok' if b['passed'] else 'FAILED'} "
                     f"| {'ok' if h['passed'] else 'FAILED'}{note} |")
    return "\n".join(lines)


def provenance(vuln: dict, hard: dict) -> str:
    m = hard["meta"]
    if m["target"] == "offline":
        return (f"Source: offline control verification, run {m['run_at']}. Real orchestrator and controls, "
                "in process, against a scripted model that obeys every injection that reaches it. "
                "Bedrock Guardrails is not exercised. The vulnerable column is 100% by construction: "
                "with no controls, a model that obeys everything loses to everything.")
    return (f"Source: live run against deployed stacks in {m.get('region', 'AWS')}, {m['run_at']}. "
            f"Model `{m['model']}`, guardrail `{m['guardrail']}`. One trial per attack at temperature 0.")


def render(vuln: dict, hard: dict, title: str) -> str:
    return "\n\n".join([
        f"# {title}", provenance(vuln, hard),
        "## Attack success rate by category", summary_table(vuln, hard),
        "## Every attack", detail_table(vuln, hard),
        "## Legitimate requests", benign_table(vuln, hard),
    ]) + "\n"


def inject(readme_text: str, block: str, content: str) -> str:
    """Replace the text between <!-- IB:{block}:START --> and <!-- IB:{block}:END -->."""
    pattern = re.compile(rf"(<!-- IB:{block}:START -->).*?(<!-- IB:{block}:END -->)", re.DOTALL)
    if not pattern.search(readme_text):
        raise ValueError(f"README has no IB:{block} markers")
    return pattern.sub(lambda m: f"{m.group(1)}\n{content}\n{m.group(2)}", readme_text)
