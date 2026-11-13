# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file is the front door between AWS and the InnovaBank code. When the
# lab is deployed to AWS, every Lambda function starts by calling one of the
# three functions at the bottom of this file:
#
#   1. agent_handler   - a customer sends a chat message to Inno, the banking
#                        chatbot. This runs the full agent (model, safety
#                        checks, tool calls) and returns the reply.
#   2. tool_handler    - the agent wants to use one tool (for example "move
#                        money" or "search the knowledge base"). Each tool
#                        runs in its own Lambda with its own narrow
#                        permissions, and this is the code it runs.
#   3. ingest_handler  - a new document lands in the S3 bucket. This checks
#                        that it is signed and clean before adding it to the
#                        knowledge base, or puts it in quarantine otherwise.
#
# The key idea: this file contains almost no logic of its own. It only
# plugs the real AWS pieces (Bedrock, DynamoDB, S3, KMS, Lambda) into the
# same Agent and tool code that the offline tests use with fake pieces.
# That way the vulnerable and hardened postures behave the same on a laptop
# and in AWS, and the tests really test what gets deployed.
#
# =============================================================================

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
from .tools import LambdaDispatcher, access_denied_code, access_denied_result, run_tool


# Shared setup used by all three handlers: read the settings and connect to
# the data store. lru_cache makes this run only once per Lambda container, so
# later requests reuse the same connections instead of rebuilding them each
# time (faster and cheaper on warm starts).
# boto3 is imported here, not at the top, so the offline tests can import this
# module without needing the AWS SDK to be set up.
@functools.lru_cache(maxsize=1)
def _runtime():
    import boto3

    # Settings come from IB_* environment variables that Terraform sets on
    # each Lambda, so one zip file can run as vulnerable or hardened.
    cfg = Config.from_env()
    return cfg, boto3, AwsStore(cfg)


# Builds the agent once per Lambda container, wired to the real AWS services.
# Like _runtime, it is cached so warm requests skip all of this setup.
@functools.lru_cache(maxsize=1)
def _agent() -> Agent:
    from botocore.config import Config as BotoConfig

    cfg, boto3, store = _runtime()
    # Model calls can be slow, so allow a long read timeout. Retrying a model
    # call is safe (it only produces text), so a few retries are allowed.
    bedrock = boto3.client("bedrock-runtime", config=BotoConfig(
        read_timeout=90, retries={"mode": "standard", "max_attempts": 3}))
    # Tool invocations are never retried: a retried transfer would move money twice.
    lambda_client = boto3.client("lambda", config=BotoConfig(read_timeout=45, retries={"total_max_attempts": 1}))
    # Use the Bedrock Guardrail only if one was deployed. Otherwise plug in a
    # do-nothing stand-in, so the agent code never has to check "is there one?".
    guardrail = (BedrockGuardrail(bedrock, cfg.guardrail_id, cfg.guardrail_version)
                 if cfg.guardrail_id else NullGuardrail())
    # Same Agent class as offline. Only the plug-in parts are swapped for AWS
    # versions: real model, tools running in separate Lambdas, real store.
    return Agent(cfg, BedrockModel(bedrock, cfg.model_id),
                 LambdaDispatcher(cfg, lambda_client), store, guardrail)


def agent_handler(event, context):
    """Event: {"message": str, "session": {"customer_id": str}}.

    The session comes from the caller, which is IAM authenticated. In a real
    deployment it would be derived from the customer's verified token.
    """
    # Convert to plain strings and default to empty values, so a malformed
    # event cannot crash the handler or sneak in an unexpected type.
    message = str(event.get("message", ""))
    customer_id = str((event.get("session") or {}).get("customer_id", ""))
    # The AWS request id ties every security log line for this request
    # together, which makes it easy to trace one attack in CloudWatch.
    return _agent().handle(message, customer_id, getattr(context, "aws_request_id", ""))


def tool_handler(event, context):
    """Event: {"tool": str, "args": dict}. One function per tool, one role per function."""
    # By the time we get here the agent has already decided this call is
    # allowed (policy checks run before the tool is invoked). This Lambda
    # just does the work, limited by its own IAM role.
    cfg, boto3, store = _runtime()
    embedder = BedrockEmbedder(boto3.client("bedrock-runtime"), cfg.embed_model_id)
    try:
        return run_tool(str(event.get("tool", "")), dict(event.get("args") or {}), cfg, store, embedder)
    except Exception as exc:
        # If AWS refused the action because this tool's IAM role is too
        # narrow, that is the least-privilege control doing its job. Return a
        # clear "access denied" result instead of crashing, so the agent can
        # log it as a security event. Any other error is a real bug and is
        # raised as normal.
        code = access_denied_code(exc)
        if code:  # this tool's role does not allow what was asked: report it, the agent logs it
            operation = getattr(exc, "operation_name", "") or "AWS call"
            return access_denied_result(f"{operation} {code}")
        raise


def ingest_handler(event, context):
    """Triggered by S3 object events, or invoked directly with {"key": str}."""
    cfg, boto3, store = _runtime()
    embedder = BedrockEmbedder(boto3.client("bedrock-runtime"), cfg.embed_model_id)
    # The KMS signer is used to verify that a document was signed by the
    # trusted publisher. Unsigned or tampered documents get quarantined, which
    # stops attackers from slipping poisoned text into the knowledge base.
    signer = KmsSigner(boto3.client("kms"), cfg.signing_key_id)
    # Two ways to be called: directly with one key (handy for seeding and
    # tests), or by S3 with a batch of records. S3 URL-encodes object keys
    # (spaces become "+"), so they are decoded back to the real file name.
    keys = [event["key"]] if "key" in event else [
        urllib.parse.unquote_plus(r["s3"]["object"]["key"]) for r in event.get("Records", [])]
    # One trace for the whole batch, so all ingestion security events share
    # the same request id in the logs.
    trace = Trace(cfg.mode, request_id=getattr(context, "aws_request_id", ""))
    return {"results": [ingest.ingest_document(k, cfg, store, embedder, signer, trace) for k in keys]}
