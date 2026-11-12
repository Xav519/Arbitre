"""Input, retrieval and output guards.

Two layers work together. The deterministic layer in this file is cheap, fully
testable and makes no network call. The managed layer is Amazon Bedrock
Guardrails, called through ApplyGuardrail so the same policy covers user input,
retrieved documents and the final answer.

None of this is treated as sufficient on its own. Heuristics and classifiers
can be evaded, which is why the tool policy and the taint lock do not depend on
detection at all.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

LEAK_CANARY = "IB-LEAK-CANARY-K4D9"

_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")  # escaped: no invisible characters in source
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

_FLAGS = re.IGNORECASE

# Patterns that have no business appearing in a customer banking question.
DIRECT_PATTERNS = [
    ("override_instructions", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,60}"
        r"\b(instructions?|rules|guidelines|prompt|polic(y|ies)|restrictions|safeguards)\b", _FLAGS)),
    ("role_reassignment", re.compile(
        r"\byou are (now|no longer)\b|\bact as (an? )?(unrestricted|jailbroken|developer|dan)\b"
        r"|\bdeveloper mode\b|\bdo anything now\b|\bwithout (any )?(restrictions|filters)\b", _FLAGS)),
    ("prompt_extraction", re.compile(
        r"\b(reveal|print|show|repeat|output|display|leak|dump)\b[^.\n]{0,60}"
        r"\b(system prompt|system message|initial instructions|hidden instructions"
        r"|your instructions|your prompt|text above)\b", _FLAGS)),
    ("fake_system_markup", re.compile(
        r"(?m)^\s*(#{2,}\s*)?(system|assistant|developer)\s*:"
        r"|<\s*/?\s*(system|instructions?)\s*>|\[\s*/?\s*(system|inst)\s*\]", _FLAGS)),
    ("new_instructions", re.compile(
        r"\b(new|updated|additional|revised) (instructions?|directives?|system prompt)\b\s*:", _FLAGS)),
]

# Extra patterns for content that is supposed to be reference material. A policy
# document has no reason to address the assistant or name its tools.
DOCUMENT_PATTERNS = [
    ("addresses_assistant", re.compile(
        r"\b(ai|assistant|model|chatbot|llm)\b[^.\n]{0,40}"
        r"\b(must|should|shall|is required to|needs to|has to)\b", _FLAGS)),
    ("tool_directive", re.compile(
        r"\b(transfer_funds|send_secure_message|get_account_summary|read_document"
        r"|search_knowledge_base)\b", _FLAGS)),
    ("concealment", re.compile(
        r"\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|alert|notify)\b"
        r"[^.\n]{0,20}\b(user|customer|client)\b", _FLAGS)),
]

ALLOWED_LINK_HOSTS = {"innovabank.example", "www.innovabank.example"}
ALLOWED_PHONES = {"18005550199"}
ALLOWED_EMAIL_DOMAINS = {"innovabank.example"}

_SIN = re.compile(r"\b\d{3}[- ]\d{3}[- ]\d{3}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SECRET = re.compile(r"\b(?:ibk_(?:live|test)_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)[^)]*\)")
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)[^\s)>\]]*", _FLAGS)
_HTML = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)")

REFUSAL = "I can't help with that request."
OUTPUT_BLOCKED = "I can't share that information."
WITHHELD = "[document withheld by security policy]"


@dataclass
class Verdict:
    hits: list = field(default_factory=list)
    obfuscated: bool = False

    @property
    def flagged(self) -> bool:
        return bool(self.hits)


def normalise(text: str) -> tuple[str, bool]:
    """Fold look-alike characters and strip invisible ones.

    Returns the cleaned text and whether anything suspicious was removed.
    """
    folded = unicodedata.normalize("NFKC", text)
    stripped = _CONTROL.sub("", _ZERO_WIDTH.sub("", folded))
    hidden = len(folded) - len(stripped)
    return stripped, hidden >= 3


def _decoded_blobs(text: str) -> list[str]:
    out = []
    for blob in _B64.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() and " " in decoded:
            out.append(decoded)
    return out


def scan(text: str, document: bool = False) -> Verdict:
    """Run the injection heuristics over user input or untrusted content."""
    clean, hidden = normalise(text)
    patterns = DIRECT_PATTERNS + (DOCUMENT_PATTERNS if document else [])
    verdict = Verdict()
    for name, rx in patterns:
        if rx.search(clean):
            verdict.hits.append(name)
    for decoded in _decoded_blobs(clean):
        inner = [n for n, rx in patterns if rx.search(decoded)]
        if inner:
            verdict.hits.extend(f"base64:{n}" for n in inner)
            verdict.obfuscated = True
    if hidden and verdict.hits:
        verdict.obfuscated = True
    return verdict


def spotlight(text: str, nonce: str) -> str:
    """Wrap untrusted content in delimiters the content itself cannot forge."""
    safe = text.replace("<<", "< <").replace(">>", "> >")
    return f"<<UNTRUSTED_DOCUMENT id={nonce}>>\n{safe}\n<<END_UNTRUSTED_DOCUMENT id={nonce}>>"


@dataclass
class OutputFinding:
    ib_event: str
    detail: str
    block: bool = False  # True: withhold the whole answer. False: redact in place.


def check_output(text: str, own_email: str = "") -> tuple[str, list[OutputFinding]]:
    """Return the answer as it would be released, and what was found in it.

    The caller decides whether the findings are enforced. When they are not,
    the original text is released and the findings are only logged.
    """
    findings: list[OutputFinding] = []
    if LEAK_CANARY in text or "IB-CANARY-SYSPROMPT" in text:
        findings.append(OutputFinding("system_prompt_leak", "prompt canary in output", block=True))
        return OUTPUT_BLOCKED, findings
    if _SECRET.search(text):
        findings.append(OutputFinding("sensitive_data_in_output", "credential pattern in output", block=True))
        return OUTPUT_BLOCKED, findings

    out = text
    if _SIN.search(out):
        out = _SIN.sub("[redacted id]", out)
        findings.append(OutputFinding("sensitive_data_in_output", "national id pattern redacted"))

    def _email(m: re.Match) -> str:
        if m.group(0).lower() == own_email.lower() or m.group(1).lower() in ALLOWED_EMAIL_DOMAINS:
            return m.group(0)
        findings.append(OutputFinding("sensitive_data_in_output", "third party email redacted"))
        return "[redacted email]"

    out = _EMAIL.sub(_email, out)

    def _image(m: re.Match) -> str:
        findings.append(OutputFinding("unsafe_output_rendering", f"markdown image removed: {m.group(1)[:80]}"))
        return "[image removed]"

    out = _MD_IMAGE.sub(_image, out)

    def _url(m: re.Match) -> str:
        if m.group(1).lower() in ALLOWED_LINK_HOSTS:
            return m.group(0)
        findings.append(OutputFinding("unsafe_output_rendering", f"link to {m.group(1)[:60]} removed"))
        return "[link removed]"

    out = _URL.sub(_url, out)
    if _HTML.search(out):
        out = _HTML.sub("", out)
        findings.append(OutputFinding("unsafe_output_rendering", "html markup stripped"))

    def _phone(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if digits in ALLOWED_PHONES or ("1" + digits) in ALLOWED_PHONES:
            return m.group(0)
        findings.append(OutputFinding("poisoned_content_in_output", "unverified phone number removed"))
        return "[unverified contact removed]"

    out = _PHONE.sub(_phone, out)
    return out, findings


class NullGuardrail:
    """Stands in for Bedrock Guardrails when running without AWS."""

    available = False

    def apply(self, text: str, source: str) -> tuple[bool, str]:
        return False, text


class BedrockGuardrail:
    """Thin wrapper over the ApplyGuardrail API."""

    available = True

    def __init__(self, client, guardrail_id: str, version: str):
        self.client = client
        self.guardrail_id = guardrail_id
        self.version = version

    def apply(self, text: str, source: str) -> tuple[bool, str]:
        """Evaluate text as INPUT or OUTPUT. Returns (intervened, text to use)."""
        if not text.strip():
            return False, text
        resp = self.client.apply_guardrail(
            guardrailIdentifier=self.guardrail_id,
            guardrailVersion=self.version,
            source=source,
            content=[{"text": {"text": text}}],
        )
        if resp.get("action") != "GUARDRAIL_INTERVENED":
            return False, text
        outputs = resp.get("outputs") or []
        replacement = outputs[0].get("text", REFUSAL) if outputs else REFUSAL
        return True, replacement
