"""The offline bench itself is a test: these are the claims the README makes."""
import pathlib
import re

import pytest

from innovabank.config import ALL_CONTROLS, resolve_controls
from innovabank.seclog import EVENTS
from innovabank_harness import report, runner
from innovabank_harness.targets import LocalTarget

ROOT = pathlib.Path(__file__).resolve().parents[1]
RESIDUAL = {"PI-06", "RP-04"}
ATLAS_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")


@pytest.fixture(scope="module")
def runs():
    return runner.run(LocalTarget("vulnerable")), runner.run(LocalTarget("hardened"))


def test_catalog_is_well_formed():
    catalog = runner.load_catalog()
    ids = [a["id"] for a in catalog]
    assert len(ids) == len(set(ids)) == 26
    for a in catalog:
        assert a["success"] and a["prompt"] and a["session"]
        assert all(ATLAS_ID.match(t) for t in a["atlas"]), a["id"]
        assert re.match(r"^LLM\d{2}$", a["owasp"])


def test_every_attack_succeeds_against_the_vulnerable_posture(runs):
    vuln, _ = runs
    assert [a["id"] for a in vuln["attacks"] if not a["succeeded"]] == []


def test_every_attack_is_at_least_detected_in_the_vulnerable_posture(runs):
    vuln, _ = runs
    undetected = {a["id"] for a in vuln["attacks"] if not a["detected_by"]}
    assert undetected == RESIDUAL  # the two residual risks are also the two blind spots


def test_hardened_posture_stops_everything_except_documented_residual_risk(runs):
    _, hard = runs
    assert {a["id"] for a in hard["attacks"] if a["succeeded"]} == RESIDUAL


def test_hardening_does_not_break_legitimate_requests(runs):
    for run in runs:
        assert [b["id"] for b in run["benign"] if not b["passed"]] == []


def test_report_renders_and_injects(runs):
    text = report.render(*runs, "t")
    assert "26/26 (100%)" in text and "2/26 (8%)" in text and "7/7 (100%)" in text
    readme = "a\n<!-- IB:OFFLINE-RESULTS:START -->\nold\n<!-- IB:OFFLINE-RESULTS:END -->\nb"
    out = report.inject(readme, "OFFLINE-RESULTS", "new")
    assert "old" not in out and "new" in out and out.startswith("a\n") and out.endswith("\nb")


def test_control_override_syntax():
    assert resolve_controls("hardened") == frozenset(ALL_CONTROLS)
    assert resolve_controls("vulnerable") == frozenset()
    assert "taint_lock" not in resolve_controls("hardened", "-taint_lock")
    assert resolve_controls("vulnerable", "+tool_policy") == {"tool_policy"}
    assert resolve_controls("vulnerable", "tool_policy,budget") == {"tool_policy", "budget"}
    with pytest.raises(ValueError):
        resolve_controls("hardened", "-nope")


def test_terraform_detections_match_application_events():
    """Every event the app can emit has an alarm, with the same ATLAS and OWASP mapping."""
    tf = (ROOT / "infra/modules/stack/detections.tf").read_text()
    rows = re.findall(r'^\s+(\w+)\s+= \{ atlas = "([^"]+)", technique = "([^"]+)", owasp = "([^"]+)"', tf, re.M)
    assert {name: (atlas, tech, owasp) for name, atlas, tech, owasp in rows} == EVENTS
