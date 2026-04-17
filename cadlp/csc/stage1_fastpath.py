"""
Stage 1: Fast-Path Detection via Regex and Shannon Entropy Analysis.

Applies a curated library of regular expressions for known structured
sensitive patterns, augmented by entropy analysis for high-entropy secrets
that do not match a known format.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SensitiveSpan:
    """Represents a detected sensitive span within a prompt."""
    start: int
    end: int
    entity_type: str
    confidence: float
    value: str = ""
    stage: int = 1

    def __post_init__(self):
        self.confidence = max(0.0, min(1.0, self.confidence))

    def __repr__(self) -> str:
        snippet = self.value[:20] + "..." if len(self.value) > 20 else self.value
        return f"SensitiveSpan({self.entity_type}, conf={self.confidence:.2f}, val='{snippet}')"


# ── Pattern library ──────────────────────────────────────────────────────────

PATTERN_LIBRARY = [
    # Cloud provider API keys
    ("AWS_ACCESS_KEY",       r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",                 0.80),
    ("AWS_SECRET_KEY",       r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", 0.75),
    ("OPENAI_API_KEY",       r"sk-[A-Za-z0-9]{20,60}",                                  0.98),
    ("ANTHROPIC_API_KEY",    r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{80,120}",             0.99),
    ("GOOGLE_API_KEY",       r"AIza[0-9A-Za-z\-_]{35}",                                 0.97),
    ("GITHUB_TOKEN",         r"gh[pousr]_[A-Za-z0-9]{36,255}",                          0.99),
    ("SLACK_TOKEN",          r"xox[baprs]-[0-9A-Za-z\-]{10,}",                          0.99),
    ("STRIPE_KEY",           r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}",              0.99),
    # JWT
    ("JWT_TOKEN",            r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", 0.95),
    # SSH / private keys
    ("PRIVATE_KEY_BLOCK",    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",      1.00),
    # Database connection strings
    ("DB_CONNECTION_STRING", r"(?:postgresql|mysql|mongodb|redis|sqlite)://[^\s\"']+",  0.95),
    # OAuth / Bearer tokens
    ("BEARER_TOKEN",         r"[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*",                    0.90),
    # Email addresses (TLD must be letters only; prevents trailing-dot capture)
    ("EMAIL_ADDRESS",        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?", 0.85),
    # US Social Security Numbers
    ("SSN",                  r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b", 0.92),
    # Credit card numbers (Luhn-approximated via pattern)
    ("CREDIT_CARD",          r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", 0.95),
    # Phone numbers
    ("PHONE_NUMBER",         r"\+?1?\s*[\(\-]?\d{3}[\)\-\s]?\s*\d{3}[\-\s]?\d{4}",    0.70),
    # IPv4 private ranges
    ("INTERNAL_IP",          r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", 0.80),
    # Internal hostnames (heuristic: contains corp/internal/prod/dev/staging)
    ("INTERNAL_HOSTNAME",    r"\b[a-zA-Z0-9\-]+\.(?:corp|internal|intranet|local|prod|dev|staging)\b", 0.82),
    # Password patterns in code
    ("HARDCODED_PASSWORD",   r'(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?[^\s"\']{8,}["\']?', 0.88),
    # Generic secrets in env/config style
    ("ENV_SECRET",           r'[A-Z_]{4,}_(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD)\s*=\s*[^\s]{8,}', 0.90),
]

_COMPILED = [(label, re.compile(pattern, re.IGNORECASE), conf)
             for label, pattern, conf in PATTERN_LIBRARY]


# ── Entropy helpers ───────────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _classify_high_entropy(token: str) -> str:
    """Heuristically categorise a high-entropy token."""
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        return "HEX_SECRET"
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", token):
        return "BASE64_SECRET"
    if re.fullmatch(r"[A-Za-z0-9\-_]+=*", token):
        return "URL_SAFE_SECRET"
    return "HIGH_ENTROPY_SECRET"


def _tokenize_for_entropy(text: str) -> List[tuple]:
    """Split text into non-whitespace tokens and return (token, start, end)."""
    return [(m.group(), m.start(), m.end()) for m in re.finditer(r"\S+", text)]


# ── Main detection function ───────────────────────────────────────────────────

def detect(
    prompt: str,
    entropy_threshold: float = 4.5,
    min_entropy_token_len: int = 16,
) -> List[SensitiveSpan]:
    """
    Run Stage 1 fast-path detection on a prompt string.

    Args:
        prompt: The raw prompt text to inspect.
        entropy_threshold: Shannon entropy (bits/char) above which a token is
            considered a potential secret.
        min_entropy_token_len: Minimum token length for entropy analysis.

    Returns:
        A list of SensitiveSpan objects, deduplicated and sorted by start
        position.
    """
    spans: List[SensitiveSpan] = []

    # Pass 1: regex patterns
    for label, pattern, conf in _COMPILED:
        for match in pattern.finditer(prompt):
            spans.append(SensitiveSpan(
                start=match.start(),
                end=match.end(),
                entity_type=label,
                confidence=conf,
                value=match.group(),
            ))

    # Pass 2: entropy analysis on individual tokens
    for token, start, end in _tokenize_for_entropy(prompt):
        if len(token) < min_entropy_token_len:
            continue
        h = shannon_entropy(token)
        if h > entropy_threshold:
            entity_type = _classify_high_entropy(token)
            # Normalise confidence: entropy 4.5 -> 0.56, 8.0 -> 1.0
            conf = min(1.0, (h - entropy_threshold) / (8.0 - entropy_threshold) + 0.55)
            spans.append(SensitiveSpan(
                start=start,
                end=end,
                entity_type=entity_type,
                confidence=round(conf, 3),
                value=token,
            ))

    return _deduplicate(spans)


def _deduplicate(spans: List[SensitiveSpan]) -> List[SensitiveSpan]:
    """Remove overlapping spans, keeping the one with higher confidence."""
    if not spans:
        return spans
    spans.sort(key=lambda s: (s.start, -s.confidence))
    result = [spans[0]]
    for span in spans[1:]:
        prev = result[-1]
        if span.start < prev.end:      # overlapping: keep higher-confidence
            if span.confidence > prev.confidence:
                result[-1] = span
        else:
            result.append(span)
    return result
