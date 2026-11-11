"""CycloneDX 1.6 ML-BOM generation.

The BOM lists what the assistant is made of from an AI point of view: the
models it calls, any weights it ships, and the corpus it retrieves from, each
with enough identity to answer "what exactly was running" after an incident.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import uuid


def _props(pairs: dict) -> list[dict]:
    return [{"name": f"innovabank:{k}", "value": str(v)} for k, v in pairs.items() if v not in (None, "")]


def _dataset_hash(path: pathlib.Path) -> tuple[str, int]:
    """One digest over the sorted (name, content hash) pairs of a directory."""
    h, count = hashlib.sha256(), 0
    for p in sorted(path.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(path).as_posix().encode())
            h.update(hashlib.sha256(p.read_bytes()).digest())
            count += 1
    return h.hexdigest(), count


def build(lock: dict, scans: list[dict], repo_root: pathlib.Path, version: str = "1.0.0") -> dict:
    components = []
    for m in lock.get("models", []):
        components.append({
            "type": "machine-learning-model",
            "bom-ref": f"model:{m['name']}",
            "name": m["model_id"],
            "supplier": {"name": m["publisher"]},
            "description": m.get("role", ""),
            "licenses": [{"license": {"name": m.get("license", "unknown")}}],
            "properties": _props({"source": m["source"], "role": m.get("role"),
                                  "inference_profile": m.get("inference_profile"), "hosting": "managed"}),
        })
    by_file = {s["file"]: s for s in scans}
    for a in lock.get("artifacts", []):
        scan = by_file.get(a.get("file", ""), {})
        components.append({
            "type": "machine-learning-model",
            "bom-ref": f"artifact:{a['name']}",
            "name": a.get("repo", a["name"]),
            "version": a.get("revision", ""),
            "supplier": {"name": a.get("publisher", "")},
            "purl": f"pkg:huggingface/{a.get('repo', a['name'])}@{a.get('revision', '')}",
            "hashes": [{"alg": "SHA-256", "content": a.get("sha256", "")}],
            "licenses": [{"license": {"name": a.get("license", "unknown")}}],
            "properties": _props({"source": a.get("source"), "format": a.get("format"), "file": a.get("file"),
                                  "scan_findings": len(scan.get("findings", [])), "hosting": "self-hosted"}),
        })
    for d in lock.get("datasets", []):
        digest, count = _dataset_hash(repo_root / d["path"])
        components.append({
            "type": "data",
            "bom-ref": f"dataset:{d['name']}",
            "name": d["name"],
            "description": d.get("role", ""),
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": _props({"path": d["path"], "documents": count}),
        })

    # Deterministic serial and timestamp so the committed BOM only changes when its content does.
    fingerprint = hashlib.sha256(json.dumps(components, sort_keys=True).encode()).hexdigest()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0")) or int(time.time())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'innovabank:' + fingerprint)}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            "component": {"type": "application", "bom-ref": "app:innovabank", "name": "innovabank", "version": version},
            "tools": {"components": [{"type": "application", "name": "ib_supplychain", "version": version}]},
        },
        "components": components,
        "dependencies": [{"ref": "app:innovabank", "dependsOn": [c["bom-ref"] for c in components]}],
    }
