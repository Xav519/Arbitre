# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file is where the bank keeps its data, and how it proves a document
# is genuine.
#
# The agent and its tools need somewhere to read and write: customer
# balances, money transfers, outgoing secure messages, the knowledge base
# search index and the raw documents. This file provides that "somewhere"
# in two interchangeable versions:
#
#   1. MemoryStore: everything lives in plain Python dicts and lists. Used by
#      the unit tests and the offline harness, so the whole lab runs on a
#      laptop with no AWS account and no cost.
#
#   2. AwsStore: the same methods, backed by real DynamoDB tables and an S3
#      bucket. Used by the Lambda functions in a deployed stack.
#
# Both classes have exactly the same method names and behaviour. That is the
# whole point: the agent, the tools, ingestion and the harness call
# store.execute_transfer(...) or store.doc_get(...) without ever knowing or
# caring which one they got. An attack that works offline should work the
# same way live, and vice versa.
#
# The file also holds two "signers", again one offline and one AWS:
#
#   - LocalSigner: a simple secret-key signature (HMAC) for offline runs.
#   - KmsSigner: a real public-key signature from AWS KMS for live runs.
#
# Signatures matter because of knowledge base poisoning attacks. A document
# only gets indexed (made searchable by Inno) if it carries a valid
# signature. Someone who can drop a file in the bucket, but cannot sign,
# cannot get their content in front of the model.
#
# One more important piece: execute_transfer() moves money "all or nothing".
# The balance is debited and the transfer is recorded together, or not at
# all, so a failure halfway can never make money vanish.
#
# =============================================================================

"""Persistence and signing backends.

MemoryStore runs the whole system in process for tests and the offline harness.
AwsStore maps the same interface onto DynamoDB and S3. Both expose identical
methods so the agent, tools, ingestion and harness never branch on backend.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import os
from decimal import Decimal

# Documents that fail the signature or content checks during ingestion are
# moved under this folder instead of being deleted. They stay available for
# investigation but are never indexed, so Inno can never see them.
QUARANTINE_PREFIX = "quarantine/"
# Name of the metadata field (an S3 object tag in AWS) that carries a
# document's signature. Publishers write it, ingestion checks it.
SIGNATURE_META = "ib-signature"


# --------------------------------------------------------------------------- signing
# A signer has two jobs: sign(body) when a trusted publisher uploads a
# document, and verify(body, signature) when ingestion decides whether that
# document may be indexed. Both signers return the signature as base64 text so
# it fits in object metadata.

class LocalSigner:
    """HMAC signer for offline runs. The key never leaves the process."""

    def __init__(self, key: bytes | None = None):
        # A fresh random key per run if none is given. Nothing outside this
        # process can know it, so nothing outside can forge a signature,
        # which mirrors the "only the publisher can sign" rule in AWS.
        self._key = key or os.urandom(32)

    def sign(self, body: bytes) -> str:
        return base64.b64encode(hmac.new(self._key, body, hashlib.sha256).digest()).decode()

    def verify(self, body: bytes, signature: str) -> bool:
        # HMAC verification is just "sign it again and compare". compare_digest
        # takes the same time whether the first or last character differs, so
        # an attacker cannot guess the signature byte by byte from timing.
        # A missing or malformed signature simply means "not valid", never a crash.
        try:
            return hmac.compare_digest(self.sign(body), signature or "")
        except (TypeError, ValueError):
            return False


class KmsSigner:
    """ECDSA P-256 signatures from an asymmetric KMS key.

    Publishing a document needs kms:Sign. The ingestion function only holds
    kms:Verify, so write access to the bucket is not enough to get content
    into the index.
    """

    ALGORITHM = "ECDSA_SHA_256"

    def __init__(self, kms_client, key_id: str):
        self.kms = kms_client
        self.key_id = key_id

    def sign(self, body: bytes) -> str:
        # We send KMS only the SHA-256 hash of the document, not the document
        # itself. KMS caps message size at 4 KB, and the hash is enough to bind
        # the signature to every byte of the content.
        resp = self.kms.sign(KeyId=self.key_id, Message=hashlib.sha256(body).digest(),
                             MessageType="DIGEST", SigningAlgorithm=self.ALGORITHM)
        return base64.b64encode(resp["Signature"]).decode()

    def verify(self, body: bytes, signature: str) -> bool:
        # No signature at all: reject straight away, no need to call KMS.
        if not signature:
            return False
        # Imported here, not at the top, so offline code never needs the AWS
        # SDK loaded just to import this module.
        from botocore.exceptions import ClientError

        # Garbage that is not even valid base64 is treated as a bad signature,
        # not as an error. An attacker controls this value, so it must never
        # be able to crash ingestion.
        try:
            raw = base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError):
            return False
        try:
            resp = self.kms.verify(KeyId=self.key_id, Message=hashlib.sha256(body).digest(),
                                   MessageType="DIGEST", Signature=raw,
                                   SigningAlgorithm=self.ALGORITHM)
        except ClientError as exc:
            # An invalid signature is an answer. Anything else (access, throttling) is a fault
            # and must surface, otherwise a broken role would silently quarantine everything.
            if exc.response.get("Error", {}).get("Code") == "KMSInvalidSignatureException":
                return False
            raise
        return bool(resp.get("SignatureValid"))


# --------------------------------------------------------------------------- memory

class InsufficientFunds(Exception):
    """The sender does not exist or cannot cover the amount. Nothing was changed."""
    # Both stores raise this same exception, so the transfer tool can handle
    # "not enough money" one way without knowing which backend is in use.


class MemoryStore:
    # In-memory twin of AwsStore. Each attribute plays the role of one
    # DynamoDB table or the S3 bucket.
    #
    # Most methods store and return deep copies. A real database hands you a
    # copy of the data, so editing what you got back changes nothing until you
    # write it again. Copying here gives the same behaviour, so code that
    # accidentally edits a returned dict acts the same offline and live.
    def __init__(self):
        self.customers: dict[str, dict] = {}         # customers table, keyed by customer_id
        self.transfers: list[dict] = []              # transfers table
        self.outbox: list[dict] = []                 # outbox table (sent secure messages)
        self.kb: dict[str, dict] = {}                # knowledge base index, keyed by chunk_id
        self.docs: dict[str, tuple[bytes, dict]] = {}  # S3 bucket: key -> (body, metadata)

    # customers
    def get_customer(self, customer_id: str) -> dict | None:
        c = self.customers.get(customer_id)
        return copy.deepcopy(c) if c else None

    def put_customer(self, item: dict) -> None:
        self.customers[item["customer_id"]] = copy.deepcopy(item)

    # transfers and outbox
    def execute_transfer(self, item: dict) -> None:
        """Debit the sender and record the transfer, both or neither."""
        # Check first, change second. If the check fails we raise before
        # touching anything, so there is never a half-done transfer. This is
        # the offline equivalent of the DynamoDB transaction in AwsStore.
        sender = self.customers.get(item["from_customer_id"])
        if not sender or sender["balance"] < item["amount"]:
            raise InsufficientFunds(item["from_customer_id"])
        # Round to cents so repeated float maths does not drift into values
        # like 99.99999999.
        sender["balance"] = round(sender["balance"] - item["amount"], 2)
        self.transfers.append(copy.deepcopy(item))

    def list_transfers(self) -> list[dict]:
        return copy.deepcopy(self.transfers)

    # The clear_* helpers exist for the lab reset between attacks, not for
    # the agent. A real bank would never wipe its transfer history.
    def clear_transfers(self) -> None:
        self.transfers.clear()

    def outbox_put(self, item: dict) -> None:
        self.outbox.append(copy.deepcopy(item))

    def outbox_list(self) -> list[dict]:
        return copy.deepcopy(self.outbox)

    def outbox_clear(self) -> None:
        self.outbox.clear()

    # knowledge base index
    # A document is split into chunks for search. kb_replace_doc first removes
    # every old chunk of that document, so re-ingesting an edited document
    # never leaves stale (possibly poisoned) chunks behind.
    def kb_replace_doc(self, doc_key: str, chunks: list[dict]) -> None:
        self.kb_delete_doc(doc_key)
        for c in chunks:
            self.kb[c["chunk_id"]] = copy.deepcopy(c)

    def kb_delete_doc(self, doc_key: str) -> None:
        # Build the list of ids first, then delete. Deleting from a dict while
        # looping over it directly would raise an error.
        for cid in [k for k, c in self.kb.items() if c["doc_key"] == doc_key]:
            del self.kb[cid]

    def kb_all_chunks(self) -> list[dict]:
        # Search reads every chunk and ranks them itself (see rag.py). Fine for
        # a small lab corpus; a real system would use a vector index.
        return list(self.kb.values())

    # documents
    def doc_put(self, key: str, body: bytes, metadata: dict | None = None) -> None:
        self.docs[key] = (body, dict(metadata or {}))

    def doc_get(self, key: str) -> tuple[bytes, dict]:
        # Raise KeyError for a missing document, the same error AwsStore
        # raises, so callers handle "not found" one way for both backends.
        if key not in self.docs:
            raise KeyError(key)
        return self.docs[key]

    def doc_delete(self, key: str) -> None:
        # Deleting something that is already gone is not an error, same as S3.
        self.docs.pop(key, None)

    def doc_list(self, prefix: str = "") -> list[str]:
        # Sorted so results are the same order on every run, which keeps tests
        # and reports stable.
        return sorted(k for k in self.docs if k.startswith(prefix))

    def doc_quarantine(self, key: str) -> None:
        # "Move" the document under quarantine/: same body and metadata, new key.
        if key in self.docs:
            self.docs[QUARANTINE_PREFIX + key] = self.docs.pop(key)


# --------------------------------------------------------------------------- aws
# DynamoDB refuses Python floats (it wants Decimal to avoid rounding errors)
# and gives every number back as a Decimal. These two helpers translate on the
# way in and on the way out, so the rest of the code works with ordinary int
# and float values, exactly like MemoryStore.

def _to_ddb(value):
    # Going through str() keeps the number as written (12.5 stays 12.5)
    # instead of exposing the float's tiny binary rounding error.
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_ddb(v) for v in value]
    return value


def _from_ddb(value):
    # Whole numbers come back as int (500, not 500.0), everything else as float.
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() and value.as_tuple().exponent >= 0 else float(value)
    if isinstance(value, dict):
        return {k: _from_ddb(v) for k, v in value.items()}
    # DynamoDB can return sets; turn them into lists to match what the
    # in-memory store returns.
    if isinstance(value, (list, set)):
        return [_from_ddb(v) for v in value]
    return value


class AwsStore:
    # Same interface as MemoryStore, backed by DynamoDB (customers, transfers,
    # outbox, kb) and one S3 bucket (documents). Table and bucket names come
    # from the config, which reads them from the Lambda's environment.
    def __init__(self, cfg, session=None):
        # Imported here so the offline path never needs boto3 loaded.
        import boto3

        # An explicit session can be passed in, so the harness can act with
        # specific credentials (for example the publisher role) instead of the
        # default ones.
        self._session = session or boto3.Session()
        self._ddb = self._session.resource("dynamodb")
        self._s3 = self._session.client("s3")
        self.bucket = cfg.bucket
        self._names = {
            "customers": cfg.customers_table, "transfers": cfg.transfers_table,
            "outbox": cfg.outbox_table, "kb": cfg.kb_table,
        }

    def _table(self, name: str):
        return self._ddb.Table(self._names[name])

    def _scan(self, name: str, **kw) -> list[dict]:
        # DynamoDB returns at most 1 MB per scan call. Keep asking for the next
        # page until there is none, otherwise large tables would be silently
        # cut short.
        table, items = self._table(name), []
        resp = table.scan(**kw)
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], **kw)
            items.extend(resp.get("Items", []))
        return [_from_ddb(i) for i in items]

    def _clear(self, name: str, key: str) -> None:
        # Empty a table for the lab reset. We only fetch each item's key
        # (ProjectionExpression), since that is all a delete needs, and use a
        # batch writer to send deletes in groups instead of one call each.
        # "#k" is a placeholder so key names that clash with DynamoDB reserved
        # words still work.
        table = self._table(name)
        with table.batch_writer() as batch:
            for item in self._scan(name, ProjectionExpression="#k", ExpressionAttributeNames={"#k": key}):
                batch.delete_item(Key={key: item[key]})

    # customers
    def get_customer(self, customer_id: str) -> dict | None:
        item = self._table("customers").get_item(Key={"customer_id": customer_id}).get("Item")
        return _from_ddb(item) if item else None

    def put_customer(self, item: dict) -> None:
        self._table("customers").put_item(Item=_to_ddb(item))

    # transfers and outbox
    def execute_transfer(self, item: dict) -> None:
        """Debit the sender and record the transfer in one DynamoDB transaction.

        Either both writes land or neither does: an IAM deny on the transfers table,
        a throttle or a crash cannot leave a debit without its transfer record. The
        balance check is a condition inside the transaction, so two concurrent
        transfers cannot both spend the same money. The transfer id is the
        idempotency token, so a retried call cannot debit twice.

        IAM: TransactWriteItems has no action of its own. Each item is authorised as
        the action it performs (dynamodb:UpdateItem on customers, dynamodb:PutItem
        on transfers), which the transfer tool's role already holds.
        """
        from botocore.exceptions import ClientError

        amount = Decimal(str(item["amount"]))
        try:
            # The resource's client takes plain Python values, like the Table API.
            self._ddb.meta.client.transact_write_items(
                # DynamoDB limits this token to 36 characters, hence the cut.
                ClientRequestToken=str(item["transfer_id"])[:36],
                TransactItems=[
                    # Step 1: take the money from the sender, but only if the
                    # customer exists and has enough. DynamoDB checks and
                    # writes in one go, so no other request can sneak in between.
                    {"Update": {
                        "TableName": self._names["customers"],
                        "Key": {"customer_id": item["from_customer_id"]},
                        "UpdateExpression": "SET balance = balance - :a",
                        "ConditionExpression": "attribute_exists(customer_id) AND balance >= :a",
                        "ExpressionAttributeValues": {":a": amount},
                    }},
                    # Step 2: write the transfer record, refusing to overwrite
                    # an existing transfer with the same id.
                    {"Put": {
                        "TableName": self._names["transfers"],
                        "Item": _to_ddb(item),
                        "ConditionExpression": "attribute_not_exists(transfer_id)",
                    }},
                ],
            )
        except ClientError as exc:
            # DynamoDB says which step's condition failed, in the same order as
            # TransactItems. If step 1 (the balance check) failed, that is a
            # normal business answer: not enough money. Any other failure
            # (duplicate id, permissions, throttling) is a real fault and is
            # passed on unchanged.
            reasons = [r.get("Code") for r in exc.response.get("CancellationReasons", [])]
            if exc.response["Error"]["Code"] == "TransactionCanceledException" and reasons[:1] == ["ConditionalCheckFailed"]:
                raise InsufficientFunds(item["from_customer_id"]) from None
            raise

    def list_transfers(self) -> list[dict]:
        return self._scan("transfers")

    def clear_transfers(self) -> None:
        self._clear("transfers", "transfer_id")

    def outbox_put(self, item: dict) -> None:
        self._table("outbox").put_item(Item=_to_ddb(item))

    def outbox_list(self) -> list[dict]:
        return self._scan("outbox")

    def outbox_clear(self) -> None:
        self._clear("outbox", "message_id")

    # knowledge base index
    def kb_replace_doc(self, doc_key: str, chunks: list[dict]) -> None:
        # Same "remove old chunks, then add new ones" rule as MemoryStore.
        self.kb_delete_doc(doc_key)
        with self._table("kb").batch_writer() as batch:
            for c in chunks:
                # The embedding is a long list of floats. Storing it as one
                # JSON string avoids converting hundreds of numbers to Decimal
                # and back, and keeps the item compact.
                batch.put_item(Item={**c, "embedding": json.dumps(c["embedding"])})

    def kb_delete_doc(self, doc_key: str) -> None:
        # Imported here for the same reason as boto3 above.
        from boto3.dynamodb.conditions import Attr

        # Find every chunk that belongs to this document (fetching only its
        # id), then delete them all in one batch.
        stale = self._scan("kb", FilterExpression=Attr("doc_key").eq(doc_key), ProjectionExpression="chunk_id")
        with self._table("kb").batch_writer() as batch:
            for item in stale:
                batch.delete_item(Key={"chunk_id": item["chunk_id"]})

    def kb_all_chunks(self) -> list[dict]:
        # Turn the stored JSON string back into a list of floats for search.
        return [{**c, "embedding": json.loads(c["embedding"])} for c in self._scan("kb")]

    # documents
    def doc_put(self, key: str, body: bytes, metadata: dict | None = None) -> None:
        # Metadata (including the signature) travels with the S3 object, so the
        # document and its proof of origin can never get separated.
        self._s3.put_object(Bucket=self.bucket, Key=key, Body=body, Metadata=dict(metadata or {}))

    def doc_get(self, key: str) -> tuple[bytes, dict]:
        # Translate S3's own "no such key" error into a plain KeyError so
        # callers see the same error as with MemoryStore.
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=key)
        except self._s3.exceptions.NoSuchKey:
            raise KeyError(key) from None
        return obj["Body"].read(), obj.get("Metadata", {})

    def doc_delete(self, key: str) -> None:
        self._s3.delete_object(Bucket=self.bucket, Key=key)

    def doc_list(self, prefix: str = "") -> list[str]:
        # S3 lists at most 1000 keys per call; the paginator fetches every page.
        keys = []
        for page in self._s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return sorted(keys)

    def doc_quarantine(self, key: str) -> None:
        # S3 has no "move" operation, so quarantine is copy then delete. The
        # copy comes first: if the delete fails, the document is duplicated,
        # never lost.
        self._s3.copy_object(Bucket=self.bucket, Key=QUARANTINE_PREFIX + key,
                             CopySource={"Bucket": self.bucket, "Key": key})
        self._s3.delete_object(Bucket=self.bucket, Key=key)
