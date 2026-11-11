"""Retrieval.

The index is deliberately small and transparent: paragraphs are embedded and
stored in DynamoDB, and retrieval is a cosine scan in the tool function. At
this corpus size that is cheaper than any managed vector store, and it keeps
the ingestion path (where the poisoning controls live) fully visible.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

DIMENSIONS = 256
_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset("a an and are as at be by for from how i in is it my of on or the to what when with you your do does can".split())


def chunk(text: str, max_chars: int = 700) -> list[str]:
    """Group paragraphs into chunks of roughly max_chars."""
    chunks, current = [], ""
    for para in (p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()):
        if current and len(current) + len(para) + 2 > max_chars:
            chunks.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        chunks.append(current)
    return chunks


class LocalEmbedder:
    """Hashed bag of words. Good enough to retrieve by topic without AWS."""

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * DIMENSIONS
        for tok in _TOKEN.findall(text.lower()):
            if tok in _STOP:
                continue
            vec[int(hashlib.md5(tok.encode()).hexdigest(), 16) % DIMENSIONS] += 1.0
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [round(x / norm, 6) for x in vec]


class BedrockEmbedder:
    """Amazon Titan Text Embeddings V2, normalised, 256 dimensions."""

    def __init__(self, client, model_id: str):
        self.client = client
        self.model_id = model_id

    def embed(self, text: str) -> list[float]:
        body = json.dumps({"inputText": text[:8000], "dimensions": DIMENSIONS, "normalize": True})
        resp = self.client.invoke_model(modelId=self.model_id, body=body)
        return json.loads(resp["body"].read())["embedding"]


def retrieve(query: str, store, embedder, k: int = 3) -> list[dict]:
    q = embedder.embed(query)
    scored = []
    for c in store.kb_all_chunks():
        score = sum(a * b for a, b in zip(q, c["embedding"]))
        scored.append((score, c))
    scored.sort(key=lambda s: s[0], reverse=True)
    return [{"source": c["doc_key"], "text": c["text"], "score": round(s, 4)}
            for s, c in scored[:k] if s > 0.05]
