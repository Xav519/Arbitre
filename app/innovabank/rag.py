# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# When a customer asks a general question ("how do I reset my card PIN?"),
# Inno looks up the answer in the bank's knowledge base: a set of help
# documents. This file is the "look it up" part. People call this RAG,
# short for Retrieval Augmented Generation: find the right text first, then
# let the model write its answer from it.
#
# It works in three steps:
#
#   1. chunk():    cut each document into small pieces, a few paragraphs
#                  each, so we can hand the model just the relevant part.
#
#   2. embed():    give each piece of text a "fingerprint" made of numbers,
#                  so the computer can tell what it is about. A computer
#                  cannot compare meanings, but it can compare numbers.
#
#                  Picture a row of boxes, one per topic word, each holding
#                  a count of how often that word shows up:
#
#                      "Reset your card PIN"   -> card: 1, PIN: 1, loan: 0
#                      "Forgot my PIN code"    -> card: 0, PIN: 1, loan: 0
#                      "Loan interest rates"   -> card: 0, PIN: 0, loan: 1
#
#                  The first two rows look alike (both have PIN), so they
#                  are about the same thing. The third looks different.
#                  That row of numbers is what the code calls a "vector"
#                  or an "embedding"; the real ones just have 256 boxes.
#
#                  There are two ways to build the fingerprint:
#                    - LocalEmbedder: a simple word counting trick that runs
#                      on your laptop, used by the tests and offline runs.
#                    - BedrockEmbedder: Amazon's real embedding model, used
#                      when the lab is deployed to AWS.
#
#   3. retrieve(): build the same kind of fingerprint for the customer's
#                  question, compare it with the fingerprint of every stored
#                  piece, and return the pieces that look most alike.
#
# Why this matters for security: whatever comes out of retrieve() lands in
# front of the model. If an attacker sneaks a poisoned document into the
# knowledge base, this is the road it travels. The defences live elsewhere
# (ingest.py checks documents before they are stored, policy.py locks
# risky tools once retrieved text has been read), and this file is kept
# small on purpose so that road is easy to follow.
#
# =============================================================================

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

# Every vector has 256 numbers. Both embedders must use the same size, or
# a question embedded one way could not be compared with stored pieces.
# 256 is the smallest size Titan V2 offers: plenty for a tiny corpus, and
# it keeps the DynamoDB items small.
DIMENSIONS = 256

# A "word" is any run of lowercase letters or digits. Punctuation is ignored.
_TOKEN = re.compile(r"[a-z0-9]+")

# Very common words that appear in almost every question ("how", "the",
# "my"...). They say nothing about the topic, so counting them would make
# unrelated texts look similar. The local embedder skips them.
_STOP = frozenset("a an and are as at be by for from how i in is it my of on or the to what when with you your do does can".split())


def chunk(text: str, max_chars: int = 700) -> list[str]:
    """Group paragraphs into chunks of roughly max_chars."""
    # Why chunk at all: a whole document is too long and too mixed to match
    # one question well, and handing the model less text is cheaper and
    # keeps its answer focused.
    #
    # Why by paragraph: a paragraph is usually one idea, so we never cut a
    # sentence in half. Paragraphs are glued together until the next one
    # would push the piece past max_chars, then a new piece starts. A single
    # paragraph longer than max_chars stays whole rather than being split.
    chunks, current = [], ""
    # Paragraphs are separated by a blank line. Empty ones are dropped.
    for para in (p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()):
        # The "+ 2" accounts for the blank line we add between paragraphs.
        if current and len(current) + len(para) + 2 > max_chars:
            chunks.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    # Do not forget the last piece still being built.
    if current:
        chunks.append(current)
    return chunks


class LocalEmbedder:
    """Hashed bag of words. Good enough to retrieve by topic without AWS."""

    # This lets the tests and the offline harness run with no AWS account
    # and no cost, and always give the same result. It does not understand
    # meaning ("card" and "debit card" only match on the shared word), but
    # for a handful of help documents, matching on words is enough.

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * DIMENSIONS
        for tok in _TOKEN.findall(text.lower()):
            if tok in _STOP:
                continue
            # Each word is sent to one of the 256 slots by hashing it, and
            # that slot is counted up. The same word always lands in the
            # same slot, so texts sharing words share slots. MD5 is used
            # only as a stable shuffler here, not for security. Python's
            # built-in hash() would not work: it changes on every run.
            vec[int(hashlib.md5(tok.encode()).hexdigest(), 16) % DIMENSIONS] += 1.0
        # Scale the vector to length 1, like Titan does with normalize=True.
        # Then a long document does not win just for having more words, and
        # retrieve() can compare with a plain dot product. The "or 1.0"
        # avoids dividing by zero when the text has no useful words.
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        # Rounding keeps the stored numbers short and the output stable.
        return [round(x / norm, 6) for x in vec]


class BedrockEmbedder:
    """Amazon Titan Text Embeddings V2, normalised, 256 dimensions."""

    # The real embedder used on AWS. Same embed() method as LocalEmbedder,
    # so the rest of the code does not care which one it was given.

    def __init__(self, client, model_id: str):
        # client is a boto3 "bedrock-runtime" client. The model id comes
        # from configuration (pinned in supplychain/model-lock.yaml) rather
        # than being written here, so the model in use is always reviewed.
        self.client = client
        self.model_id = model_id

    def embed(self, text: str) -> list[float]:
        # Only the first 8000 characters are sent, to stay safely under the
        # model's input limit; a chunk is far shorter than that anyway.
        # normalize=True gives length-1 vectors, matching LocalEmbedder.
        body = json.dumps({"inputText": text[:8000], "dimensions": DIMENSIONS, "normalize": True})
        resp = self.client.invoke_model(modelId=self.model_id, body=body)
        return json.loads(resp["body"].read())["embedding"]


def retrieve(query: str, store, embedder, k: int = 3) -> list[dict]:
    # Find the k stored pieces closest in topic to the customer's question.
    # This is what the search_knowledge_base tool returns to the model.
    q = embedder.embed(query)
    scored = []
    # We compare the question against every stored piece, one by one. That
    # sounds slow, but the knowledge base is tiny, so it is fast and avoids
    # paying for a separate vector database.
    for c in store.kb_all_chunks():
        # Because both vectors have length 1, multiplying them slot by slot
        # and adding up gives the cosine similarity: 1 means same topic,
        # 0 means nothing in common.
        score = sum(a * b for a, b in zip(q, c["embedding"], strict=False))
        scored.append((score, c))
    # Best matches first.
    scored.sort(key=lambda s: s[0], reverse=True)
    # Keep the top k, but drop anything scoring 0.05 or less: such a weak
    # match is noise, and feeding the model unrelated text only invites a
    # wrong answer. "source" says which document each piece came from, so
    # the answer can be traced back.
    return [{"source": c["doc_key"], "text": c["text"], "score": round(s, 4)}
            for s, c in scored[:k] if s > 0.05]
