"""
Utility-Preserving Redaction (UPR) Engine.

Replaces sensitive spans detected by the CSC with semantically typed
synthetic placeholders. Maintains per-session entity-to-placeholder
mappings for conversational consistency.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cadlp.csc.pipeline import SensitivityMap
from cadlp.csc.stage1_fastpath import SensitiveSpan
from cadlp.csc.stage3_ast import CodeBlock


# ── Placeholder templates by entity type ─────────────────────────────────────

_PLACEHOLDER_TEMPLATES: Dict[str, str] = {
    # Credentials
    "OPENAI_API_KEY":        "[API_KEY_{n}]",
    "ANTHROPIC_API_KEY":     "[API_KEY_{n}]",
    "GOOGLE_API_KEY":        "[API_KEY_{n}]",
    "GITHUB_TOKEN":          "[API_KEY_{n}]",
    "SLACK_TOKEN":           "[API_KEY_{n}]",
    "STRIPE_KEY":            "[API_KEY_{n}]",
    "AWS_ACCESS_KEY":        "[AWS_ACCESS_KEY_{n}]",
    "AWS_SECRET_KEY":        "[AWS_SECRET_{n}]",
    "JWT_TOKEN":             "[JWT_TOKEN_{n}]",
    "BEARER_TOKEN":          "[BEARER_TOKEN_{n}]",
    "PRIVATE_KEY_BLOCK":     "[PRIVATE_KEY_{n}]",
    "HARDCODED_PASSWORD":    "[PASSWORD_{n}]",
    "ENV_SECRET":            "[SECRET_{n}]",
    "HIGH_ENTROPY_SECRET":   "[SECRET_{n}]",
    "HEX_SECRET":            "[HEX_SECRET_{n}]",
    "BASE64_SECRET":         "[SECRET_B64_{n}]",
    "URL_SAFE_SECRET":       "[SECRET_{n}]",
    "DB_CONNECTION_STRING":  "[DB_CONNECTION_{n}]",
    # PII
    "EMAIL_ADDRESS":         "[EMAIL_{n}]",
    "PHONE_NUMBER":          "[PHONE_{n}]",
    "SSN":                   "[SSN_{n}]",
    "CREDIT_CARD":           "[CC_{n}]",
    # Infrastructure
    "INTERNAL_IP":           "[INTERNAL_IP_{n}]",
    "INTERNAL_HOSTNAME":     "[INTERNAL_HOST_{n}]",
    # NER entities
    "PERSON_OPERATIONAL":    "[PERSON_{n}]",
    "PERSON_UNCERTAIN":      "[PERSON_{n}]",
    "ORGANIZATION_OPERATIONAL": "[ORG_{n}]",
    "ORGANIZATION_UNCERTAIN":   "[ORG_{n}]",
    "PROJECT_CODE_OPERATIONAL": "[PROJECT_{n}]",
    "PROJECT_CODE_UNCERTAIN":   "[PROJECT_{n}]",
    "EMPLOYEE_ID_OPERATIONAL":  "[EMPLOYEE_ID_{n}]",
    "TICKET_ID_OPERATIONAL":    "[TICKET_{n}]",
    # Code IP placeholder (injected at block level)
    "PROPRIETARY_CODE":      "[PROPRIETARY_CODE_BLOCK_{n}]",
    # Default
    "_DEFAULT":              "[REDACTED_{type}_{n}]",
}


def _make_placeholder(entity_type: str, index: int) -> str:
    template = _PLACEHOLDER_TEMPLATES.get(
        entity_type,
        _PLACEHOLDER_TEMPLATES["_DEFAULT"].replace("{type}", entity_type.upper()),
    )
    return template.replace("{n}", str(index)).replace("{type}", entity_type)


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


# ── Session map ───────────────────────────────────────────────────────────────

class SessionRedactionMap:
    """
    Maintains entity-to-placeholder mappings across turns in a session.

    Guarantees that the same original value always maps to the same
    placeholder within a session, preserving cross-turn referential
    coherence.
    """

    def __init__(self):
        self._map: Dict[str, str] = {}
        self._counters: Dict[str, int] = defaultdict(int)

    def get_or_create(self, value: str, entity_type: str) -> str:
        if value in self._map:
            return self._map[value]
        self._counters[entity_type] += 1
        placeholder = _make_placeholder(entity_type, self._counters[entity_type])
        self._map[value] = placeholder
        return placeholder

    def __len__(self) -> int:
        return len(self._map)

    def inverse(self) -> Dict[str, str]:
        """Return placeholder -> original mapping for response rehydration."""
        return {v: k for k, v in self._map.items()}

    def reset(self) -> None:
        self._map.clear()
        self._counters.clear()


# ── Redaction result ──────────────────────────────────────────────────────────

@dataclass
class RedactionResult:
    original_prompt:  str
    redacted_prompt:  str
    num_redactions:   int
    entity_types:     List[str]
    session_map_size: int
    semantic_drift:   Optional[float] = None

    @property
    def was_redacted(self) -> bool:
        return self.num_redactions > 0

    def summary(self) -> str:
        if not self.was_redacted:
            return "No redactions applied."
        return (
            f"{self.num_redactions} redaction(s) applied: "
            f"{', '.join(self.entity_types[:5])}"
        )


# ── Main redaction engine ─────────────────────────────────────────────────────

class UtilityPreservingRedactor:
    """
    Applies typed synthetic placeholder substitution to prompts based on
    the CSC SensitivityMap.
    """

    def __init__(self, session_map: Optional[SessionRedactionMap] = None):
        self.session_map = session_map or SessionRedactionMap()

    def redact(
        self,
        sensitivity_map: SensitivityMap,
        redact_code_blocks: bool = True,
    ) -> RedactionResult:
        """
        Apply redaction to a prompt given its SensitivityMap.

        Args:
            sensitivity_map: Output of ContextualSensitivityClassifier.classify().
            redact_code_blocks: Whether to replace flagged code blocks.

        Returns:
            A RedactionResult with the sanitized prompt.
        """
        prompt = sensitivity_map.prompt
        redacted = list(prompt)  # work on a character list for safe in-place edits

        # Collect all replacements: (start, end, replacement_text)
        replacements: List[Tuple[int, int, str]] = []

        # From spans (Stage 1 + 2)
        for span in sensitivity_map.spans:
            placeholder = self.session_map.get_or_create(span.value, span.entity_type)
            replacements.append((span.start, span.end, placeholder))

        # From code blocks (Stage 3)
        if redact_code_blocks:
            for block in sensitivity_map.code_blocks:
                self.session_map._counters["PROPRIETARY_CODE"] += 1
                n = self.session_map._counters["PROPRIETARY_CODE"]
                placeholder = f"[PROPRIETARY_CODE_BLOCK_{n}]"
                replacements.append((block.start, block.end, placeholder))

        # Apply replacements in reverse order (highest start first) to
        # preserve offset integrity
        replacements.sort(key=lambda r: r[0], reverse=True)
        prompt_chars = list(prompt)
        for start, end, replacement in replacements:
            prompt_chars[start:end] = list(replacement)

        redacted_prompt = "".join(prompt_chars)

        entity_types = list({r[2].split("_")[0].lstrip("[") for r in replacements})

        return RedactionResult(
            original_prompt=prompt,
            redacted_prompt=redacted_prompt,
            num_redactions=len(replacements),
            entity_types=sensitivity_map.entity_types,
            session_map_size=len(self.session_map),
        )

    def new_session(self) -> None:
        """Reset the session map for a new conversation."""
        self.session_map.reset()
