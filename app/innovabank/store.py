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

QUARANTINE_PREFIX = "quarantine/"
SIGNATURE_META = "ib-signature"


# --------------------------------------------------------------------------- signing

class LocalSigner:
    """HMAC signer for offline runs. The key never leaves the process."""

    def __init__(self, key: bytes | None = None):
        self._key = key or os.urandom(32)

    def sign(self, body: bytes) -> str:
        return base64.b64encode(hmac.new(self._key, body, hashlib.sha256).digest()).decode()

    def verify(self, body: bytes, signature: str) -> bool:
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
        resp = self.kms.sign(KeyId=self.key_id, Message=hashlib.sha256(body).digest(),
                             MessageType="DIGEST", SigningAlgorithm=self.ALGORITHM)
        return base64.b64encode(resp["Signature"]).decode()

    def verify(self, body: bytes, signature: str) -> bool:
        if not signature:
            return False
        from botocore.exceptions import ClientError

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


class MemoryStore:
    def __init__(self):
        self.customers: dict[str, dict] = {}
        self.transfers: list[dict] = []
        self.outbox: list[dict] = []
        self.kb: dict[str, dict] = {}
        self.docs: dict[str, tuple[bytes, dict]] = {}

    # customers
    def get_customer(self, customer_id: str) -> dict | None:
        c = self.customers.get(customer_id)
        return copy.deepcopy(c) if c else None

    def put_customer(self, item: dict) -> None:
        self.customers[item["customer_id"]] = copy.deepcopy(item)

    # transfers and outbox
    def execute_transfer(self, item: dict) -> None:
        """Debit the sender and record the transfer, both or neither."""
        sender = self.customers.get(item["from_customer_id"])
        if not sender or sender["balance"] < item["amount"]:
            raise InsufficientFunds(item["from_customer_id"])
        sender["balance"] = round(sender["balance"] - item["amount"], 2)
        self.transfers.append(copy.deepcopy(item))

    def list_transfers(self) -> list[dict]:
        return copy.deepcopy(self.transfers)

    def clear_transfers(self) -> None:
        self.transfers.clear()

    def outbox_put(self, item: dict) -> None:
        self.outbox.append(copy.deepcopy(item))

    def outbox_list(self) -> list[dict]:
        return copy.deepcopy(self.outbox)

    def outbox_clear(self) -> None:
        self.outbox.clear()

    # knowledge base index
    def kb_replace_doc(self, doc_key: str, chunks: list[dict]) -> None:
        self.kb_delete_doc(doc_key)
        for c in chunks:
            self.kb[c["chunk_id"]] = copy.deepcopy(c)

    def kb_delete_doc(self, doc_key: str) -> None:
        for cid in [k for k, c in self.kb.items() if c["doc_key"] == doc_key]:
            del self.kb[cid]

    def kb_all_chunks(self) -> list[dict]:
        return list(self.kb.values())

    # documents
    def doc_put(self, key: str, body: bytes, metadata: dict | None = None) -> None:
        self.docs[key] = (body, dict(metadata or {}))

    def doc_get(self, key: str) -> tuple[bytes, dict]:
        if key not in self.docs:
            raise KeyError(key)
        return self.docs[key]

    def doc_delete(self, key: str) -> None:
        self.docs.pop(key, None)

    def doc_list(self, prefix: str = "") -> list[str]:
        return sorted(k for k in self.docs if k.startswith(prefix))

    def doc_quarantine(self, key: str) -> None:
        if key in self.docs:
            self.docs[QUARANTINE_PREFIX + key] = self.docs.pop(key)


# --------------------------------------------------------------------------- aws

def _to_ddb(value):
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_ddb(v) for v in value]
    return value


def _from_ddb(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() and value.as_tuple().exponent >= 0 else float(value)
    if isinstance(value, dict):
        return {k: _from_ddb(v) for k, v in value.items()}
    if isinstance(value, (list, set)):
        return [_from_ddb(v) for v in value]
    return value


class AwsStore:
    def __init__(self, cfg, session=None):
        import boto3

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
        table, items = self._table(name), []
        resp = table.scan(**kw)
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], **kw)
            items.extend(resp.get("Items", []))
        return [_from_ddb(i) for i in items]

    def _clear(self, name: str, key: str) -> None:
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
                ClientRequestToken=str(item["transfer_id"])[:36],
                TransactItems=[
                    {"Update": {
                        "TableName": self._names["customers"],
                        "Key": {"customer_id": item["from_customer_id"]},
                        "UpdateExpression": "SET balance = balance - :a",
                        "ConditionExpression": "attribute_exists(customer_id) AND balance >= :a",
                        "ExpressionAttributeValues": {":a": amount},
                    }},
                    {"Put": {
                        "TableName": self._names["transfers"],
                        "Item": _to_ddb(item),
                        "ConditionExpression": "attribute_not_exists(transfer_id)",
                    }},
                ],
            )
        except ClientError as exc:
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
        self.kb_delete_doc(doc_key)
        with self._table("kb").batch_writer() as batch:
            for c in chunks:
                batch.put_item(Item={**c, "embedding": json.dumps(c["embedding"])})

    def kb_delete_doc(self, doc_key: str) -> None:
        from boto3.dynamodb.conditions import Attr

        stale = self._scan("kb", FilterExpression=Attr("doc_key").eq(doc_key), ProjectionExpression="chunk_id")
        with self._table("kb").batch_writer() as batch:
            for item in stale:
                batch.delete_item(Key={"chunk_id": item["chunk_id"]})

    def kb_all_chunks(self) -> list[dict]:
        return [{**c, "embedding": json.loads(c["embedding"])} for c in self._scan("kb")]

    # documents
    def doc_put(self, key: str, body: bytes, metadata: dict | None = None) -> None:
        self._s3.put_object(Bucket=self.bucket, Key=key, Body=body, Metadata=dict(metadata or {}))

    def doc_get(self, key: str) -> tuple[bytes, dict]:
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=key)
        except self._s3.exceptions.NoSuchKey:
            raise KeyError(key) from None
        return obj["Body"].read(), obj.get("Metadata", {})

    def doc_delete(self, key: str) -> None:
        self._s3.delete_object(Bucket=self.bucket, Key=key)

    def doc_list(self, prefix: str = "") -> list[str]:
        keys = []
        for page in self._s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return sorted(keys)

    def doc_quarantine(self, key: str) -> None:
        self._s3.copy_object(Bucket=self.bucket, Key=QUARANTINE_PREFIX + key,
                             CopySource={"Bucket": self.bucket, "Key": key})
        self._s3.delete_object(Bucket=self.bucket, Key=key)
