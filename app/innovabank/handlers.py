"""AWS Lambda entry points: the agent, the tools, and knowledge base ingestion."""
from __future__ import annotations

import functools
import urllib.parse

from . import ingest
from .agent import Agent
from .config import Config
from .guards import BedrockGuardrail, NullGuardrail
from .models import BedrockModel
from .rag import BedrockEmbedder
from .seclog import Trace
from .store import AwsStore, KmsSigner
from .tools import LambdaDispatcher, run_tool


@functools.lru_cache(maxsize=1)
def _runtime():
    import boto3

    cfg = Config.from_env()
    return cfg, boto3, AwsStore(cfg)


@functools.lru_cache(maxsize=1)
def _agent() -> Agent:
    from botocore.config import Config as BotoConfig

    cfg, boto3, store = _runtime()
    bedrock = boto3.client("bedrock-runtime", config=BotoConfig(
        read_timeout=90, retries={"mode": "standard", "max_attempts": 3}))
    # Tool invocations are never retried: a retried transfer would move money twice.
    lambda_client = boto3.client("lambda", config=BotoConfig(read_timeout=45, retries={"total_max_attempts": 1}))
    guardrail = (BedrockGuardrail(bedrock, cfg.guardrail_id, cfg.guardrail_version)
                 if cfg.guardrail_id else NullGuardrail())
    return Agent(cfg, BedrockModel(bedrock, cfg.model_id),
                 LambdaDispatcher(cfg, lambda_client), store, guardrail)


def agent_handler(event, context):
    """Event: {"message": str, "session": {"customer_id": str}}.

    The session comes from the caller, which is IAM authenticated. In a real
    deployment it would be derived from the customer's verified token.
    """
    message = str(event.get("message", ""))
    customer_id = str((event.get("session") or {}).get("customer_id", ""))
    return _agent().handle(message, customer_id, getattr(context, "aws_request_id", ""))


def tool_handler(event, context):
    """Event: {"tool": str, "args": dict}. One function per tool, one role per function."""
    cfg, boto3, store = _runtime()
    embedder = BedrockEmbedder(boto3.client("bedrock-runtime"), cfg.embed_model_id)
    return run_tool(str(event.get("tool", "")), dict(event.get("args") or {}), cfg, store, embedder)


def ingest_handler(event, context):
    """Triggered by S3 object events, or invoked directly with {"key": str}."""
    cfg, boto3, store = _runtime()
    embedder = BedrockEmbedder(boto3.client("bedrock-runtime"), cfg.embed_model_id)
    signer = KmsSigner(boto3.client("kms"), cfg.signing_key_id)
    keys = [event["key"]] if "key" in event else [
        urllib.parse.unquote_plus(r["s3"]["object"]["key"]) for r in event.get("Records", [])]
    trace = Trace(cfg.mode, request_id=getattr(context, "aws_request_id", ""))
    return {"results": [ingest.ingest_document(k, cfg, store, embedder, signer, trace) for k in keys]}
