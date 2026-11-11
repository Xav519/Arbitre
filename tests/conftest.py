import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for sub in ("app", "harness", "supplychain"):
    sys.path.insert(0, str(ROOT / sub))
