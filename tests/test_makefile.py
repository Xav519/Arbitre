"""The documented make targets expand to the harness calls the docs promise."""
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")


def dry_run(*args: str) -> str:
    return subprocess.run(["make", "-n", "-s", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def test_attack_live_one_targets_one_stack_with_trials_filter_and_output():
    cmd = " ".join(dry_run("attack-live-one", "MODE=hardened", "TRIALS=3", "ONLY=SD-02",
                           "OUT=results/iam-backstop.json").split())
    assert "-m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials 3" in cmd
    assert "--only SD-02" in cmd and "--out results/iam-backstop.json" in cmd


def test_attack_live_one_defaults():
    cmd = " ".join(dry_run("attack-live-one", "MODE=vulnerable").split())
    assert "--outputs infra/envs/vulnerable/outputs.json --trials 1" in cmd
    assert "--only" not in cmd and "--out results/live-vulnerable.json" in cmd


def test_docs_never_call_the_harness_without_pythonpath():
    """A bare `python3 -m innovabank_harness` fails outside make, which sets PYTHONPATH."""
    bare = re.compile(r"^(?!.*PYTHONPATH=)\s*python3? -m innovabank_harness", re.M)
    offenders = [str(p.relative_to(ROOT)) for p in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]
                 if bare.search(p.read_text(encoding="utf-8"))]
    assert offenders == []
