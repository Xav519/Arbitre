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


ATTRIBUTION_NOTE = (
    "How to read the last column. Controls are listed when they blocked something during the attack. "
    "When several are listed, any one of them may have been enough; the ablation report measures which "
    "control an attack actually depends on. When an attack also failed against the vulnerable stack, the "
    "model declined on its own, so the hardened controls that fired are shown but not credited with stopping it."
)


def _labels(controls: list[str]) -> str:
    return ", ".join(CONTROL_LABELS.get(c, c) for c in controls)


def _outcome(hard: dict, vuln: dict) -> str:
    """Explain a hardened result without crediting controls for what the model refused anyway."""
    if hard["succeeded"]:
        return "**not stopped**"
    fired = _labels(hard["blocked_by"])
    if not vuln["succeeded"]:
        return "model declined (also failed on vulnerable)" + (f"; controls also fired: {fired}" if fired else "")
    return f"blocked by {fired}" if fired else "no control fired (the model declined)"


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
    lines = ["| ID | Attack | ATLAS | Vulnerable | Hardened | Why it failed on hardened |",
             "|---|---|---|---|---|---|"]
    for a in vuln["attacks"]:
        h = hv.get(a["id"])
        if not h:
            continue
        lines.append(f"| {a['id']} | {a['name']} | {', '.join(a['atlas'])} "
                     f"| {'succeeded' if a['succeeded'] else 'failed'} "
                     f"| {'succeeded' if h['succeeded'] else 'failed'} | {_outcome(h, a)} |")
    return "\n".join(lines)


def _benign_cell(b: dict | None) -> str:
    """A legitimate request's outcome. A failure names the controls that blocked it, or says none did."""
    if b is None:
        return "not run"
    if b["passed"]:
        return "ok"
    if b.get("response", "").startswith("[harness]"):
        return "FAILED (harness error, see results JSON)"
    fired = _labels(b.get("blocked_by", []))
    return f"FAILED (blocked by {fired})" if fired else "FAILED (no control fired; the model did not complete it)"


def benign_table(vuln: dict, hard: dict) -> str:
    hb = {b["id"]: b for b in hard["benign"]}
    lines = ["| ID | Legitimate request | Vulnerable | Hardened |", "|---|---|---|---|"]
    for b in vuln["benign"]:
        lines.append(f"| {b['id']} | {b['name']} | {_benign_cell(b)} | {_benign_cell(hb.get(b['id']))} |")
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
        "## Every attack", ATTRIBUTION_NOTE, detail_table(vuln, hard),
        "## Legitimate requests", benign_table(vuln, hard),
    ]) + "\n"


def inject(readme_text: str, block: str, content: str) -> str:
    """Replace the text between <!-- IB:{block}:START --> and <!-- IB:{block}:END -->."""
    pattern = re.compile(rf"(<!-- IB:{block}:START -->).*?(<!-- IB:{block}:END -->)", re.DOTALL)
    if not pattern.search(readme_text):
        raise ValueError(f"README has no IB:{block} markers")
    return pattern.sub(lambda m: f"{m.group(1)}\n{content}\n{m.group(2)}", readme_text)
