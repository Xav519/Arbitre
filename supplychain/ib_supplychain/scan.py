"""Static scanning of model artifacts.

Pickle-based model formats run code when they are loaded. This scanner never
loads anything. It walks the pickle opcode stream with pickletools, collects
every import the file would perform, and judges those imports. Formats that
cannot carry code (safetensors, GGUF) only get a structural sanity check.
"""
from __future__ import annotations

import hashlib
import io
import json
import pathlib
import pickletools
import struct
import zipfile
from dataclasses import asdict, dataclass

PICKLE_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".npy", ".npz"}

# Imports that give code execution, file or network access.
DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "builtins", "__builtin__", "runpy", "importlib",
    "socket", "shutil", "pty", "commands", "webbrowser", "ctypes", "multiprocessing", "threading",
    "http", "urllib", "requests", "pickle", "_pickle", "marshal", "code", "codeop", "pip", "tempfile",
    "asyncio", "operator", "functools", "types", "base64", "zlib", "bdb", "pdb", "timeit", "torch.hub",
}

# Imports a plain tensor checkpoint legitimately needs.
SAFE_GLOBALS = {
    "collections.OrderedDict",
    "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_parameter",
    "torch.FloatStorage", "torch.HalfStorage", "torch.LongStorage", "torch.IntStorage",
    "torch.DoubleStorage", "torch.BoolStorage", "torch.ByteStorage",
    "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.ndarray", "numpy.dtype",
}


@dataclass
class Finding:
    severity: str   # CRITICAL, HIGH, MEDIUM
    file: str
    rule: str
    detail: str


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pickle_imports(data: bytes) -> list[str]:
    """Every module.name a pickle stream would import, without unpickling it."""
    imports, strings = [], []
    for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
        if opcode.name in ("GLOBAL", "INST"):
            imports.append(str(arg).replace(" ", "."))
        elif opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING",
                             "BINSTRING", "SHORT_BINSTRING"):
            strings.append(str(arg))
        elif opcode.name == "STACK_GLOBAL" and len(strings) >= 2:
            imports.append(f"{strings[-2]}.{strings[-1]}")
    return imports


def _judge_imports(name: str, imports: list[str]) -> list[Finding]:
    findings = []
    for imp in sorted(set(imports)):
        module = imp.rsplit(".", 1)[0]
        root = module.split(".")[0]
        if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES:
            findings.append(Finding("CRITICAL", name, "dangerous-import",
                                    f"loading this file would import {imp}"))
        elif imp not in SAFE_GLOBALS:
            findings.append(Finding("HIGH", name, "unexpected-import",
                                    f"{imp} is not on the allowlist for tensor checkpoints"))
    return findings


def detect_format(path: pathlib.Path, head: bytes) -> str:
    ext = path.suffix.lower()
    if head[:4] == b"GGUF":
        return "gguf"
    if ext == ".safetensors":
        return "safetensors"
    if ext == ".onnx":
        return "onnx"
    if head[:2] == b"PK":
        return "zip"
    if ext in PICKLE_EXTENSIONS or (head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05")):
        return "pickle"
    return "unknown"


def _check_safetensors(path: pathlib.Path, name: str) -> list[Finding]:
    size = path.stat().st_size
    with path.open("rb") as fh:
        raw = fh.read(8)
        if len(raw) < 8:
            return [Finding("HIGH", name, "malformed-safetensors", "file shorter than its header")]
        (n,) = struct.unpack("<Q", raw)
        if n > min(size - 8, 100 * 1024 * 1024):
            return [Finding("HIGH", name, "malformed-safetensors", "header length exceeds file size")]
        try:
            header = json.loads(fh.read(n))
        except (ValueError, UnicodeDecodeError):
            return [Finding("HIGH", name, "malformed-safetensors", "header is not valid JSON")]
    return [] if isinstance(header, dict) else [Finding("HIGH", name, "malformed-safetensors", "header is not an object")]


def scan_file(path: pathlib.Path, root: pathlib.Path | None = None) -> dict:
    name = path.relative_to(root).as_posix() if root else path.name
    with path.open("rb") as fh:
        head = fh.read(8)
    fmt = detect_format(path, head)
    findings: list[Finding] = []

    if fmt == "pickle":
        findings.append(Finding("MEDIUM", name, "pickle-format",
                                "pickle-based format can execute code on load, convert to safetensors"))
        try:
            findings += _judge_imports(name, pickle_imports(path.read_bytes()))
        except Exception as exc:  # truncated or deliberately malformed stream
            findings.append(Finding("HIGH", name, "unparseable-pickle", f"opcode stream could not be read: {exc}"))
    elif fmt == "zip":
        try:
            with zipfile.ZipFile(path) as zf:
                members = [m for m in zf.namelist() if m.endswith((".pkl", ".pickle"))]
                if members:
                    findings.append(Finding("MEDIUM", name, "pickle-format",
                                            "archive contains pickle data, convert to safetensors"))
                for m in members:
                    findings += _judge_imports(f"{name}!{m}", pickle_imports(zf.read(m)))
        except zipfile.BadZipFile:
            findings.append(Finding("HIGH", name, "malformed-archive", "not a readable zip archive"))
    elif fmt == "safetensors":
        findings += _check_safetensors(path, name)
    elif fmt == "unknown":
        findings.append(Finding("HIGH", name, "unknown-format", "unrecognised artifact format"))

    return {"file": name, "format": fmt, "sha256": sha256(path), "size": path.stat().st_size,
            "findings": [asdict(f) for f in findings]}


def scan_path(root: pathlib.Path) -> list[dict]:
    skip = {"README.md", ".gitkeep"}
    if root.is_file():
        return [scan_file(root)]
    return [scan_file(p, root) for p in sorted(root.rglob("*")) if p.is_file() and p.name not in skip]
