"""Provenance checks against the model lock file."""
from __future__ import annotations

import pathlib
import re

# Bedrock model and inference profile identifiers as they appear in code and Terraform.
_MODEL_REF = re.compile(
    r"\b(?:(?:us|eu|apac|global|us-gov)\.)?"
    r"(?:amazon|anthropic|meta|mistral|cohere|ai21|deepseek|openai|writer|stability|twelvelabs|qwen)"
    r"\.[a-z][a-z0-9-]*(?:[.-][a-z0-9]+)*-v\d+(?::\d+)?\b")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def approved_ids(lock: dict) -> set[str]:
    ids = set()
    for m in lock.get("models", []):
        ids.add(m["model_id"])
        if m.get("inference_profile"):
            ids.add(m["inference_profile"])
    return ids


def check_lock(lock: dict, scans: list[dict]) -> list[str]:
    """Violations in the lock file itself, and between the lock and the artifacts on disk."""
    problems = []
    policy = lock.get("policy", {})
    sources = policy.get("allowed_sources", {})
    formats = set(policy.get("allowed_artifact_formats", []))
    by_file = {s["file"]: s for s in scans}

    for m in lock.get("models", []) + lock.get("artifacts", []):
        src, pub = m.get("source"), m.get("publisher")
        if src not in sources:
            problems.append(f"{m.get('name')}: source {src!r} is not allowed")
        elif pub not in (sources[src] or []):
            problems.append(f"{m.get('name')}: publisher {pub!r} is not approved for {src}")

    declared = set()
    for a in lock.get("artifacts", []):
        name, declared_file = a.get("name"), a.get("file", "")
        declared.add(declared_file)
        if policy.get("require_pinned_revision", True) and not _COMMIT.match(str(a.get("revision", ""))):
            problems.append(f"{name}: revision must be a full commit hash, got {a.get('revision')!r}")
        if not _SHA256.match(str(a.get("sha256", ""))):
            problems.append(f"{name}: missing or malformed sha256")
        if a.get("format") not in formats:
            problems.append(f"{name}: format {a.get('format')!r} is not allowed")
        scanned = by_file.get(declared_file)
        if not scanned:
            problems.append(f"{name}: declared file {declared_file!r} is not present")
        else:
            if scanned["sha256"] != a.get("sha256"):
                problems.append(f"{name}: sha256 mismatch, file does not match the lock")
            if scanned["format"] != a.get("format"):
                problems.append(f"{name}: file is {scanned['format']}, lock says {a.get('format')}")

    for s in scans:
        if s["file"] not in declared:
            problems.append(f"{s['file']}: artifact is not declared in the lock file")
    return problems


def check_references(lock: dict, roots: list[pathlib.Path]) -> list[str]:
    """Every model identifier referenced in code or Terraform must be in the lock."""
    approved = approved_ids(lock)
    problems = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.suffix not in {".py", ".tf", ".tfvars"} or ".terraform" in path.parts:
                continue
            for ref in sorted(set(_MODEL_REF.findall(path.read_text(encoding="utf-8", errors="ignore")))):
                if ref not in approved:
                    problems.append(f"{path.as_posix()}: references {ref}, which is not in the model lock")
    return problems
