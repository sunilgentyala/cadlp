"""
Stage 2: Named Entity Recognition with Operational/Exemplary Disambiguation.

Runs a NER pass over tokens not resolved by Stage 1, then applies context
features to determine whether each entity is operationally sensitive or
appears in a fictitious/exemplary discourse role.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import List, Tuple, Optional
from cadlp.csc.stage1_fastpath import SensitiveSpan


class ContextLabel(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    EXEMPLARY   = "EXEMPLARY"
    UNCERTAIN   = "UNCERTAIN"


# ── Heuristic lexica ─────────────────────────────────────────────────────────

# Markers that strongly suggest exemplary / hypothetical discourse
_EXEMPLARY_MARKERS = re.compile(
    r"\b(e\.g\.|for example|suppose|hypothetically|let['']s say|"
    r"imagine|pretend|in this scenario|as an example|sample|"
    r"dummy|placeholder|test user|fake|fictional|mock)\b",
    re.IGNORECASE,
)

# Action verbs that co-occur with real operational entities
_ACTION_VERBS = re.compile(
    r"\b(insert|update|delete|query|fetch|retrieve|submit|send|upload|"
    r"process|store|save|export|email|notify|alert|create|register|"
    r"authenticate|login|access)\b",
    re.IGNORECASE,
)

# NER-style patterns (simplified; production uses a fine-tuned BERT model)
_NER_PATTERNS = [
    # Person names: Title + Capitalized Word(s)
    ("PERSON",         re.compile(r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?")),
    # Also: two capitalised words not at sentence start
    ("PERSON",         re.compile(r"(?<!\.)\s([A-Z][a-z]{2,}\s+[A-Z][a-z]{2,})(?=[\s,\.])")),
    # Organisation heuristic: ends in Inc/Corp/LLC/Ltd/Co/Group
    ("ORGANIZATION",   re.compile(r"\b[A-Z][A-Za-z0-9\s&\-]+(?:Inc\.|Corp\.|LLC|Ltd\.|Co\.|Group|Technologies|Solutions|Systems)\b")),
    # Project codenames: ALL_CAPS identifiers (e.g. PROJ_X, OPS_BLUE_1)
    ("PROJECT_CODE",   re.compile(r"\b[A-Z]{2,}[_\-][A-Z0-9]+(?:[_\-][A-Z0-9]+)*\b")),
    # Employee IDs
    ("EMPLOYEE_ID",    re.compile(r"\bEMP[-_]?\d{4,8}\b", re.IGNORECASE)),
    # Internal ticket numbers
    ("TICKET_ID",      re.compile(r"\b[A-Z]{2,6}-\d{3,6}\b")),
]


def _context_window(prompt: str, start: int, end: int, window: int = 200) -> str:
    w_start = max(0, start - window)
    w_end   = min(len(prompt), end + window)
    return prompt[w_start:w_end]


def _compute_context_features(window: str, entity_text: str) -> dict:
    exemplary_score = len(_EXEMPLARY_MARKERS.findall(window))
    action_score    = len(_ACTION_VERBS.findall(window))
    # Higher repetition of the entity suggests real usage
    repeat_count    = window.lower().count(entity_text.lower())
    # Adjacent PII signals (digits adjacent to the entity suggest real ID)
    adj_digits      = len(re.findall(r"\d{4,}", window))
    return {
        "exemplary_score": exemplary_score,
        "action_score":    action_score,
        "repeat_count":    repeat_count,
        "adj_digits":      adj_digits,
    }


def _disambiguate(features: dict) -> Tuple[ContextLabel, float]:
    """
    Rule-based proxy for the fine-tuned BERT disambiguator.

    In production this is replaced by a BERT-base classifier trained on
    8,500 annotated enterprise prompt examples (kappa = 0.87).
    """
    e = features["exemplary_score"]
    a = features["action_score"]
    r = features["repeat_count"]
    d = features["adj_digits"]

    op_score  = a * 0.4 + r * 0.3 + d * 0.2
    ex_score  = e * 0.8

    if ex_score >= 1.6 and op_score < 0.5:
        return ContextLabel.EXEMPLARY, min(0.95, 0.60 + ex_score * 0.1)
    if op_score >= 0.8 and ex_score < 0.5:
        return ContextLabel.OPERATIONAL, min(0.95, 0.60 + op_score * 0.15)
    return ContextLabel.UNCERTAIN, 0.50


def detect(
    prompt: str,
    existing_spans: Optional[List[SensitiveSpan]] = None,
) -> List[SensitiveSpan]:
    """
    Run Stage 2 NER detection over the prompt, skipping positions already
    covered by Stage 1 spans.

    Args:
        prompt: Raw prompt text.
        existing_spans: Spans already detected by Stage 1 (to avoid
            double-counting overlapping regions).

    Returns:
        Additional SensitiveSpan objects detected by NER.
    """
    covered: List[Tuple[int, int]] = [(s.start, s.end) for s in (existing_spans or [])]

    def _is_covered(start: int, end: int) -> bool:
        return any(cs <= start and end <= ce for cs, ce in covered)

    new_spans: List[SensitiveSpan] = []

    for entity_type, pattern in _NER_PATTERNS:
        for match in pattern.finditer(prompt):
            s, e = match.start(), match.end()
            if _is_covered(s, e):
                continue
            entity_text = match.group().strip()
            if len(entity_text) < 3:
                continue
            window = _context_window(prompt, s, e)
            features = _compute_context_features(window, entity_text)
            label, conf = _disambiguate(features)

            # Only emit spans labelled OPERATIONAL or UNCERTAIN
            if label == ContextLabel.EXEMPLARY:
                continue

            new_spans.append(SensitiveSpan(
                start=s,
                end=e,
                entity_type=f"{entity_type}_{label.value}",
                confidence=conf,
                value=entity_text,
                stage=2,
            ))

    return new_spans
