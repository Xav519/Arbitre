"""Supply chain gate.

  python -m ib_supplychain gate            fail the build on any violation, write the ML-BOM
  python -m ib_supplychain scan <path>     scan a file or directory of model artifacts
"""
from __future__ import annotations

import argparse
import json
import pathlib

import yaml

from . import mlbom, provenance, scan

ROOT = pathlib.Path(__file__).resolve().parents[2]
BLOCKING = {"CRITICAL", "HIGH", "MEDIUM"}


def _print_findings(scans: list[dict]) -> int:
    blocking = 0
    for s in scans:
        print(f"  {s['file']}  format={s['format']}  sha256={s['sha256'][:16]}...")
        for f in s["findings"]:
            print(f"    [{f['severity']}] {f['rule']}: {f['detail']}")
            blocking += f["severity"] in BLOCKING
    return blocking


def cmd_scan(args) -> int:
    scans = scan.scan_path(pathlib.Path(args.path))
    print(f"scanned {len(scans)} artifact(s) under {args.path}")
    blocking = _print_findings(scans)
    print("RESULT: " + ("REJECTED" if blocking else "clean"))
    return 1 if blocking else 0


def cmd_gate(args) -> int:
    lock = yaml.safe_load(pathlib.Path(args.lock).read_text())
    scans = scan.scan_path(pathlib.Path(args.artifacts))
    print(f"model lock: {len(lock.get('models', []))} managed model(s), {len(lock.get('artifacts', []))} artifact(s)")
    blocking = _print_findings(scans)

    problems = provenance.check_lock(lock, scans)
    problems += provenance.check_references(lock, [ROOT / "app", ROOT / "infra"])
    for p in problems:
        print(f"  [PROVENANCE] {p}")

    if blocking or problems:
        print(f"GATE FAILED: {blocking} scan finding(s), {len(problems)} provenance violation(s)")
        return 1

    bom = mlbom.build(lock, scans, ROOT)
    out = pathlib.Path(args.bom)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"GATE PASSED: wrote ML-BOM with {len(bom['components'])} component(s) to {out}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ib_supplychain", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--lock", default=str(ROOT / "supplychain" / "model-lock.yaml"))
    g.add_argument("--artifacts", default=str(ROOT / "supplychain" / "artifacts"))
    g.add_argument("--bom", default=str(ROOT / "sbom" / "ml-bom.cdx.json"))
    g.set_defaults(fn=cmd_gate)
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.set_defaults(fn=cmd_scan)
    args = p.parse_args(argv)
    return args.fn(args)
