"""Secret redaction for everything the engine renders."""
from __future__ import annotations

import re

MASK = "[REDACTED]"
PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@"),  # credentials in URLs (group 1)
]
ASSIGNMENT = re.compile(
    r"(?i)((?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)"
    r"[\w-]*\s*[:=]\s*)(['\"])([^'\"\s]{6,})\2")


def redact(text: str | None) -> str | None:
    if not text:
        return text
    for p in PATTERNS:
        if p.groups == 1 and "://" in p.pattern:
            text = p.sub(lambda m: m.group(0).replace(m.group(1), MASK), text)
        else:
            text = p.sub(MASK, text)
    text = ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(2)}", text)
    return text


def redact_obj(obj):
    """Recursively redact every string in a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
