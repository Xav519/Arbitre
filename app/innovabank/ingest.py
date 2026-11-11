"""Knowledge base ingestion.

Poisoning is cheapest to stop before content is indexed. Two checks run here:
a signature check that proves the document came from the publishing pipeline,
and a content scan for text that addresses the assistant. A document failing
an enforced check is moved to quarantine and never reaches the index.
"""
from __future__ import annotations

from . import guards, rag
from .store import SIGNATURE_META


def ingest_document(key: str, cfg, store, embedder, signer, trace) -> dict:
    try:
        body, meta = store.doc_get(key)
    except KeyError:
        store.kb_delete_doc(key)
        return {"key": key, "status": "missing"}

    reasons = []
    if not signer.verify(body, meta.get(SIGNATURE_META, "")):
        enforced = cfg.on("ingest_integrity")
        trace.event("rag_document_rejected", "ingest_integrity", enforced,
                    f"{key}: missing or invalid publisher signature")
        if enforced:
            reasons.append("signature")

    text = body.decode("utf-8", errors="replace")
    verdict = guards.scan(text, document=True)
    if verdict.flagged:
        enforced = cfg.on("ingest_scan")
        trace.event("rag_document_rejected", "ingest_scan", enforced,
                    f"{key}: injection patterns {sorted(set(verdict.hits))}")
        if enforced:
            reasons.append("content")

    if reasons:
        store.doc_quarantine(key)
        store.kb_delete_doc(key)
        return {"key": key, "status": "quarantined", "reasons": reasons}

    chunks = [
        {"chunk_id": f"{key}#{i}", "doc_key": key, "text": piece, "embedding": embedder.embed(piece)}
        for i, piece in enumerate(rag.chunk(text))
    ]
    store.kb_replace_doc(key, chunks)
    return {"key": key, "status": "indexed", "chunks": len(chunks)}
