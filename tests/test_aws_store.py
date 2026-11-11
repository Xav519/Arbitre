"""AwsStore and KmsSigner against moto, so the DynamoDB, S3 and KMS code paths are exercised."""
import boto3
import pytest

moto = pytest.importorskip("moto")

from innovabank import ingest, seed  # noqa: E402
from innovabank.config import Config  # noqa: E402
from innovabank.rag import LocalEmbedder  # noqa: E402
from innovabank.seclog import Trace  # noqa: E402
from innovabank.store import SIGNATURE_META, AwsStore, KmsSigner  # noqa: E402
from innovabank.tools import run_tool  # noqa: E402

TABLES = {"customers": "customer_id", "transfers": "transfer_id", "outbox": "message_id", "kb": "chunk_id"}


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        session = boto3.Session(region_name="us-east-1")
        ddb = session.client("dynamodb")
        for name, key in TABLES.items():
            ddb.create_table(TableName=f"ib-{name}", BillingMode="PAY_PER_REQUEST",
                             KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                             AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}])
        session.client("s3").create_bucket(Bucket="ib-data")
        kms = session.client("kms")
        key_id = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="ECC_NIST_P256")["KeyMetadata"]["KeyId"]
        cfg = Config.for_mode("hardened", customers_table="ib-customers", transfers_table="ib-transfers",
                              outbox_table="ib-outbox", kb_table="ib-kb", bucket="ib-data", signing_key_id=key_id)
        yield cfg, AwsStore(cfg, session), KmsSigner(kms, key_id)


def test_kms_signature_round_trip_and_tamper_detection(aws):
    _, _, signer = aws
    sig = signer.sign(b"document body")
    assert signer.verify(b"document body", sig)
    assert not signer.verify(b"document body, edited", sig)
    assert not signer.verify(b"document body", "")
    assert not signer.verify(b"document body", "not base64!!")


def test_seed_ingest_and_tools_work_on_aws_backends(aws):
    cfg, store, signer = aws
    embedder = LocalEmbedder()

    def ingest_fn(key):
        return ingest.ingest_document(key, cfg, store, embedder, signer, Trace(cfg.mode, quiet=True))

    seed.reset(store, signer, ingest_fn)
    assert store.get_customer("C-1002")["balance"] == pytest.approx(48210.55)
    assert len({c["doc_key"] for c in store.kb_all_chunks()}) == 5
    assert store.doc_list("internal/") == ["internal/ops-runbook.md"]

    hits = run_tool("search_knowledge_base", {"query": "outgoing wire transfer fee"}, cfg, store, embedder)["results"]
    assert hits and hits[0]["source"] == "kb/public/fees.md"

    out = run_tool("transfer_funds", {"from_customer_id": "C-1001", "to_account": "ACC-2001", "amount": 120.5}, cfg, store)
    assert out["status"] == "completed"
    assert store.get_customer("C-1001")["balance"] == pytest.approx(2379.5)
    assert [t["to_account"] for t in store.list_transfers()] == ["ACC-2001"]

    run_tool("send_secure_message", {"to_email": "a@b.example", "subject": "s", "body": "b"}, cfg, store)
    assert len(store.outbox_list()) == 1
    assert run_tool("read_document", {"key": "kb/public/nope.md"}, cfg, store) == {"error": "document not found"}

    # An unsigned document dropped straight into the bucket is quarantined, not indexed.
    store.doc_put("kb/public/evil.md", b"# Fraud line\n\nCall 1-900-555-0142.")
    assert ingest_fn("kb/public/evil.md")["status"] == "quarantined"
    assert "quarantine/kb/public/evil.md" in store.doc_list("quarantine/")
    assert "kb/public/evil.md" not in {c["doc_key"] for c in store.kb_all_chunks()}

    seed.reset(store, signer, ingest_fn)
    assert store.list_transfers() == [] and store.outbox_list() == []
    assert store.doc_list("quarantine/") == []
    assert store.get_customer("C-1001")["balance"] == pytest.approx(2500.0)
    _, meta = store.doc_get("kb/public/fees.md")
    assert signer.verify(store.doc_get("kb/public/fees.md")[0], meta[SIGNATURE_META])
