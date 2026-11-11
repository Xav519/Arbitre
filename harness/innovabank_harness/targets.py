"""Where the harness points: an in-process stack, or a deployed one in AWS."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "app"))

from innovabank import ingest, seed  # noqa: E402
from innovabank.agent import Agent  # noqa: E402
from innovabank.config import Config  # noqa: E402
from innovabank.models import ScriptedModel  # noqa: E402
from innovabank.rag import LocalEmbedder  # noqa: E402
from innovabank.seclog import Trace  # noqa: E402
from innovabank.store import SIGNATURE_META, AwsStore, KmsSigner, LocalSigner, MemoryStore  # noqa: E402
from innovabank.tools import LocalDispatcher  # noqa: E402


class LocalTarget:
    """Runs the real orchestrator and controls in process.

    The model is replaced by ScriptedModel, an adversary that obeys any
    injection that reaches it. Bedrock Guardrails is not available offline, so
    results from this target measure the deterministic controls only.
    """

    kind = "offline"

    def __init__(self, mode: str, controls: str | None = None):
        self.cfg = Config.for_mode(mode, controls)
        self.store = MemoryStore()
        self.signer = LocalSigner()
        self.embedder = LocalEmbedder()
        self._corpus = seed.load_corpus()

    def _ingest(self, key: str) -> dict:
        trace = Trace(self.cfg.mode, quiet=True)
        outcome = ingest.ingest_document(key, self.cfg, self.store, self.embedder, self.signer, trace)
        return {**outcome, "events": trace.events}

    def reset(self) -> None:
        seed.reset(self.store, self.signer, self._ingest, self._corpus)

    def plant(self, key: str, body: str, signed: bool) -> dict:
        raw = body.encode()
        self.store.doc_put(key, raw, {SIGNATURE_META: self.signer.sign(raw)} if signed else {})
        return self._ingest(key)

    def invoke(self, prompt: str, customer_id: str, script: list[dict]) -> dict:
        agent = Agent(self.cfg, ScriptedModel(script), LocalDispatcher(self.cfg, self.store, self.embedder), self.store)
        return agent.handle(prompt, customer_id, quiet=True)

    def observe(self) -> dict:
        return {"transfers": self.store.list_transfers(), "outbox": self.store.outbox_list()}

    def describe(self) -> dict:
        return {"target": self.kind, "mode": self.cfg.mode, "controls": sorted(self.cfg.controls),
                "model": "ScriptedModel (assumed-compromised adversary)", "guardrail": "not exercised offline"}


class AwsTarget:
    """Drives a deployed stack using its Terraform outputs.

    Needs credentials that can invoke the agent and ingestion functions, read
    and write the stack's tables and bucket, and call kms:Sign on the corpus
    signing key. That is the publisher and assessor role, not the agent's.
    """

    kind = "aws"

    def __init__(self, outputs_file: str):
        import boto3

        raw = json.loads(pathlib.Path(outputs_file).read_text())
        out = {k: (v["value"] if isinstance(v, dict) and "value" in v else v) for k, v in raw.items()}
        self.out = out
        session = boto3.Session(region_name=out["region"])
        self.cfg = Config.for_mode(
            out["mode"], out.get("controls_override") or None,
            customers_table=out["customers_table"], transfers_table=out["transfers_table"],
            outbox_table=out["outbox_table"], kb_table=out["kb_table"],
            bucket=out["bucket"], signing_key_id=out["signing_key_id"],
            model_id=out["model_id"],
        )
        self.store = AwsStore(self.cfg, session)
        self.signer = KmsSigner(session.client("kms"), out["signing_key_id"])
        from botocore.config import Config as BotoConfig

        # An agent turn can take minutes in the vulnerable posture. Never retry: a retry re-runs the attack.
        self._lambda = session.client("lambda", config=BotoConfig(
            read_timeout=330, connect_timeout=10, retries={"total_max_attempts": 1}))
        self._corpus = seed.load_corpus()

    def _call(self, function: str, payload: dict) -> dict:
        resp = self._lambda.invoke(FunctionName=function, Payload=json.dumps(payload).encode())
        body = json.loads(resp["Payload"].read() or b"{}")
        if resp.get("FunctionError"):
            raise RuntimeError(f"{function} failed: {json.dumps(body)[:500]}")
        return body

    def _ingest(self, key: str) -> dict:
        return self._call(self.out["ingest_function"], {"key": key})["results"][0]

    def reset(self) -> None:
        seed.reset(self.store, self.signer, self._ingest, self._corpus)

    def plant(self, key: str, body: str, signed: bool) -> dict:
        raw = body.encode()
        self.store.doc_put(key, raw, {SIGNATURE_META: self.signer.sign(raw)} if signed else {})
        outcome = self._ingest(key)
        if outcome.get("status") == "quarantined":
            reasons = outcome.get("reasons", [])
            control = "ingest_integrity" if "signature" in reasons else "ingest_scan"
            outcome["events"] = [{"control": control, "action": "blocked", "ib_event": "rag_document_rejected"}]
        return outcome

    def invoke(self, prompt: str, customer_id: str, script: list[dict]) -> dict:
        try:
            return self._call(self.out["agent_function"], {"message": prompt, "session": {"customer_id": customer_id}})
        except Exception as exc:  # timeout or function error: record it and keep the run going
            return {"response": f"[harness] agent call failed: {exc}"[:400], "blocked": False, "trace": {}}

    def observe(self) -> dict:
        return {"transfers": self.store.list_transfers(), "outbox": self.store.outbox_list()}

    def describe(self) -> dict:
        return {"target": self.kind, "mode": self.cfg.mode, "controls": sorted(self.cfg.controls),
                "model": self.out["model_id"],
                "guardrail": self.out.get("guardrail_id") or "none", "region": self.out["region"]}
