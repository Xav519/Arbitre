"""Command line entry point.

  python -m innovabank_harness run --target offline --mode hardened --out results/offline-hardened.json
  python -m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials 3 --out results/live-hardened.json
  python -m innovabank_harness report --vulnerable a.json --hardened b.json --out docs/results/offline.md
  python -m innovabank_harness ablation
  python -m innovabank_harness seed --outputs infra/envs/hardened/outputs.json
  python -m innovabank_harness ask --outputs infra/envs/hardened/outputs.json --customer C-1001 "What is my balance?"
"""
from __future__ import annotations

import argparse
import json
import pathlib

from . import report, runner
from .targets import ROOT, AwsTarget, LocalTarget


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _target(args):
    if args.target == "aws":
        if not args.outputs:
            raise SystemExit("--outputs <terraform outputs json> is required with --target aws")
        return AwsTarget(args.outputs)
    return LocalTarget(args.mode, args.controls)


def cmd_run(args) -> int:
    record = runner.run(_target(args), set(args.only.split(",")) if args.only else None, trials=args.trials)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n")
    hit = sum(a["succeeded"] for a in record["attacks"])
    ok = sum(b["passed"] for b in record["benign"])
    print(f"{record['meta']['target']}/{record['meta']['mode']}: {hit}/{len(record['attacks'])} attacks succeeded, "
          f"{ok}/{len(record['benign'])} legitimate requests completed"
          f"{f' (over {args.trials} trials)' if args.trials > 1 else ''} -> {out}")
    return 0


def cmd_report(args) -> int:
    vuln = json.loads(pathlib.Path(args.vulnerable).read_text())
    hard = json.loads(pathlib.Path(args.hardened).read_text())
    live = hard["meta"]["target"] == "aws"
    title = "InnovaBank results: live Bedrock run" if live else "InnovaBank results: offline control verification"
    text = report.render(vuln, hard, title)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"wrote {out}")
    if args.readme:
        readme = pathlib.Path(args.readme)
        block = "LIVE-RESULTS" if live else "OFFLINE-RESULTS"
        content = report.provenance(vuln, hard) + "\n\n" + report.summary_table(vuln, hard)
        readme.write_text(report.inject(readme.read_text(), block, content))
        print(f"updated {block} block in {readme}")
    return 0


def cmd_ablation(args) -> int:
    """Remove one control at a time from the hardened posture and see what comes back."""
    from innovabank.config import ALL_CONTROLS

    baseline = {a["id"] for a in runner.run(LocalTarget("hardened"))["attacks"] if a["succeeded"]}
    lines = ["# Control ablation (offline)", "",
             "Each row is the hardened posture with one control removed, against the scripted adversary model. "
             "An attack listed here is one that this control alone was holding back. A control with no "
             "attacks listed is not redundant: it means another layer also covers those attacks.", "",
             f"Baseline, all controls on: {', '.join(sorted(baseline)) or 'none'} succeed.", "",
             "| Control removed | Attacks that now succeed | Legitimate requests |", "|---|---|---|"]
    for control in ALL_CONTROLS:
        if control == "guardrail":
            lines.append("| Bedrock Guardrails | not measurable offline. Live, on the deployed stack (3 trials): "
                         "PI-06 succeeds 3/3 without it, 0/3 with it. See docs/controls.md | n/a offline |")
            continue
        rec = runner.run(LocalTarget("hardened", f"-{control}"))
        back = sorted({a["id"] for a in rec["attacks"] if a["succeeded"]} - baseline)
        ok = sum(b["passed"] for b in rec["benign"])
        lines.append(f"| {report.CONTROL_LABELS[control]} | {', '.join(back) or 'none'} | {ok}/{len(rec['benign'])} |")
    text = "\n".join(lines) + "\n"
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(text)
    return 0


def cmd_seed(args) -> int:
    target = AwsTarget(args.outputs)
    target.reset()
    print(f"seeded {target.out['bucket']}: customers restored, corpus signed and indexed")
    return 0


def format_turn(result: dict) -> str:
    """Human-readable view of one agent turn: the answer, the tool calls, the security events."""
    trace = result.get("trace") or {}
    lines = ["", "ANSWER", "  " + (result.get("response") or "").replace("\n", "\n  "), ""]
    calls = trace.get("tool_calls") or []
    lines.append("TOOL CALLS" + ("" if calls else "  (none)"))
    for t in calls:
        reason = f"  <- {t['reason']}" if t.get("reason") else ""
        lines.append(f"  {t['status']:<9} {t['name']} {json.dumps(t['args'])}{reason}")
    events = trace.get("events") or []
    lines.append("")
    lines.append("SECURITY EVENTS" + ("" if events else "  (none)"))
    for e in events:
        lines.append(f"  {e['action']:<9} {e['control']:<16} {e['atlas_technique']} {e['atlas_name']} ({e['owasp']})")
        if e.get("detail"):
            lines.append(f"            {e['detail']}")
    return "\n".join(lines) + "\n"


def cmd_ask(args) -> int:
    target = AwsTarget(args.outputs)
    result = target._call(target.out["agent_function"],
                          {"message": args.message, "session": {"customer_id": args.customer}})
    print(f"[{target.out['mode']} stack, customer {args.customer}]")
    print(format_turn(result))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="innovabank_harness", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the attack catalog")
    r.add_argument("--target", choices=["offline", "aws"], default="offline")
    r.add_argument("--mode", choices=["vulnerable", "hardened"], default="hardened")
    r.add_argument("--controls", help='offline only. Use the = form for removals, for example --controls=-taint_lock,-tool_policy')
    r.add_argument("--outputs", help="terraform outputs json of the stack to attack")
    r.add_argument("--only", help="comma separated attack ids")
    r.add_argument("--trials", type=_positive_int, default=1,
                   help="run each case N times and record how many trials each one won (default 1)")
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="render the before and after tables")
    rp.add_argument("--vulnerable", required=True)
    rp.add_argument("--hardened", required=True)
    rp.add_argument("--out", required=True)
    rp.add_argument("--readme", help="also update the results block in this README")
    rp.set_defaults(fn=cmd_report)

    ab = sub.add_parser("ablation", help="measure what each control is holding back")
    ab.add_argument("--out", default=str(ROOT / "docs" / "results" / "ablation.md"))
    ab.set_defaults(fn=cmd_ablation)

    sd = sub.add_parser("seed", help="seed a deployed stack")
    sd.add_argument("--outputs", required=True)
    sd.set_defaults(fn=cmd_seed)

    ak = sub.add_parser("ask", help="send one message to a deployed stack and show what happened")
    ak.add_argument("--outputs", required=True)
    ak.add_argument("--customer", default="C-1001")
    ak.add_argument("message")
    ak.set_defaults(fn=cmd_ask)

    args = p.parse_args(argv)
    return args.fn(args)
