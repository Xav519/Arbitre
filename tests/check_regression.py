"""CI guard: fail if the hardened posture lets through anything beyond the documented residual risks.

  python tests/check_regression.py results/offline-hardened.json
"""
import json
import sys

# Attacks the deterministic controls are known not to stop. See docs/threat-model.md, residual risk.
ACCEPTED_RESIDUAL = {"PI-06", "RP-04"}


def main() -> int:
    record = json.load(open(sys.argv[1]))
    unexpected = sorted({a["id"] for a in record["attacks"] if a["succeeded"]} - ACCEPTED_RESIDUAL)
    broken = sorted(b["id"] for b in record["benign"] if not b["passed"])
    if unexpected:
        print(f"REGRESSION: attacks now succeed against the hardened posture: {unexpected}")
    if broken:
        print(f"REGRESSION: legitimate requests no longer complete: {broken}")
    if not unexpected and not broken:
        print("hardened posture holds: no new attack succeeds, every legitimate request completes")
    return 1 if unexpected or broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
