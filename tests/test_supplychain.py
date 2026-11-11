import json
import os
import pathlib
import pickle
import struct
import zipfile

import yaml

from ib_supplychain import cli, mlbom, provenance, scan

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK = yaml.safe_load((ROOT / "supplychain/model-lock.yaml").read_text())


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo never-runs",))


def _safetensors(path):
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 4)


def severities(result):
    return {f["severity"] for f in result["findings"]}


def test_malicious_pickle_is_critical_without_being_loaded(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps({"w": [1.0], "hook": _Evil()}))
    result = scan.scan_file(p)
    assert result["format"] == "pickle" and "CRITICAL" in severities(result)
    assert any("system" in f["detail"] for f in result["findings"])


def test_every_pickle_protocol_is_caught(tmp_path):
    for proto in range(0, pickle.HIGHEST_PROTOCOL + 1):
        p = tmp_path / f"m{proto}.pkl"
        p.write_bytes(pickle.dumps(_Evil(), protocol=proto))
        assert "CRITICAL" in severities(scan.scan_file(p)), f"protocol {proto}"


def test_pickle_hidden_in_a_torch_style_zip_is_caught(tmp_path):
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(_Evil()))
    assert "CRITICAL" in severities(scan.scan_file(p))


def test_data_only_pickle_is_still_rejected_as_a_format(tmp_path):
    p = tmp_path / "weights.pkl"
    p.write_bytes(pickle.dumps({"w": [1.0, 2.0]}))
    assert severities(scan.scan_file(p)) == {"MEDIUM"}


def test_safetensors_is_clean_and_malformed_header_is_not(tmp_path):
    good, bad = tmp_path / "model.safetensors", tmp_path / "bad.safetensors"
    _safetensors(good)
    bad.write_bytes(struct.pack("<Q", 10**12) + b"{}")
    assert scan.scan_file(good)["findings"] == []
    assert severities(scan.scan_file(bad)) == {"HIGH"}


def test_repository_lock_is_consistent_with_code_and_terraform():
    assert provenance.check_lock(LOCK, []) == []
    assert provenance.check_references(LOCK, [ROOT / "app", ROOT / "infra"]) == []


def test_unapproved_model_reference_is_caught(tmp_path):
    (tmp_path / "main.tf").write_text('model = "us.anthropic.claude-3-5-haiku-20241022-v1:0"\n')
    problems = provenance.check_references(LOCK, [tmp_path])
    assert len(problems) == 1 and "not in the model lock" in problems[0]


def test_artifact_rules(tmp_path):
    f = tmp_path / "model.safetensors"
    _safetensors(f)
    scans = scan.scan_path(tmp_path)
    good = {"name": "m", "source": "huggingface", "publisher": "acme", "repo": "acme/m",
            "revision": "a" * 40, "file": "model.safetensors", "sha256": scans[0]["sha256"],
            "format": "safetensors", "license": "apache-2.0"}
    policy = {"allowed_sources": {"huggingface": ["acme"]}, "allowed_artifact_formats": ["safetensors"]}

    assert provenance.check_lock({"policy": policy, "artifacts": [good]}, scans) == []
    for change, expect in [({"revision": "main"}, "full commit hash"), ({"sha256": "0" * 64}, "sha256 mismatch"),
                           ({"publisher": "stranger"}, "not approved"), ({"format": "pickle"}, "not allowed")]:
        problems = provenance.check_lock({"policy": policy, "artifacts": [{**good, **change}]}, scans)
        assert any(expect in p for p in problems), (change, problems)
    assert any("not declared" in p for p in provenance.check_lock({"policy": policy, "artifacts": []}, scans))


def test_mlbom_is_valid_shape_and_deterministic(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1794182400")
    a, b = mlbom.build(LOCK, [], ROOT), mlbom.build(LOCK, [], ROOT)
    assert a == b and a["bomFormat"] == "CycloneDX" and a["specVersion"] == "1.6"
    types = [c["type"] for c in a["components"]]
    assert types.count("machine-learning-model") == 2 and types.count("data") == 1
    assert a["dependencies"][0]["dependsOn"] == [c["bom-ref"] for c in a["components"]]


def test_gate_passes_on_the_repository_and_fails_on_a_bad_artifact(tmp_path, capsys):
    bom = tmp_path / "bom.json"
    assert cli.main(["gate", "--bom", str(bom)]) == 0 and bom.exists()
    bad = tmp_path / "artifacts"
    bad.mkdir()
    (bad / "model.bin").write_bytes(pickle.dumps(_Evil()))
    assert cli.main(["gate", "--artifacts", str(bad), "--bom", str(tmp_path / "x.json")]) == 1
    assert not (tmp_path / "x.json").exists()
    assert "GATE FAILED" in capsys.readouterr().out
