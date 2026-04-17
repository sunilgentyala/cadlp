"""
CADLP Policy Engine.

Evaluates tenant-defined policies against a SensitivityMap and produces
a PolicyDecision (ALLOW, REDACT, BLOCK, QUARANTINE, AUDIT).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from cadlp.csc.pipeline import SensitivityMap


class Action(str, Enum):
    ALLOW      = "ALLOW"       # Pass through unchanged
    REDACT     = "REDACT"      # Apply UPR and forward
    BLOCK      = "BLOCK"       # Reject with error
    QUARANTINE = "QUARANTINE"  # Hold for human review
    AUDIT      = "AUDIT"       # Pass through and log (no redaction)


@dataclass
class PolicyRule:
    """A single policy rule evaluated against a SensitivityMap."""
    name: str
    entity_types: Set[str]           # Which entity types this rule matches
    min_confidence: float = 0.70     # Minimum detection confidence to trigger
    action: Action = Action.REDACT
    priority: int = 100              # Lower number = higher priority


@dataclass
class PolicyDecision:
    action: Action
    triggered_rule: Optional[str]
    reasons: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"Action: {self.action.value} | "
            f"Rule: {self.triggered_rule or 'default'} | "
            f"Reasons: {'; '.join(self.reasons) if self.reasons else 'none'}"
        )


# ── Default enterprise policy rules ──────────────────────────────────────────

DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule(
        name="block_credentials",
        entity_types={
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
            "GITHUB_TOKEN", "SLACK_TOKEN", "STRIPE_KEY", "JWT_TOKEN",
            "BEARER_TOKEN", "PRIVATE_KEY_BLOCK", "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY", "HARDCODED_PASSWORD", "ENV_SECRET",
        },
        min_confidence=0.85,
        action=Action.BLOCK,
        priority=10,
    ),
    PolicyRule(
        name="redact_pii",
        entity_types={
            "EMAIL_ADDRESS", "PHONE_NUMBER", "SSN", "CREDIT_CARD",
            "PERSON_OPERATIONAL", "PERSON_UNCERTAIN",
        },
        min_confidence=0.70,
        action=Action.REDACT,
        priority=20,
    ),
    PolicyRule(
        name="redact_infrastructure",
        entity_types={"INTERNAL_IP", "INTERNAL_HOSTNAME", "DB_CONNECTION_STRING"},
        min_confidence=0.75,
        action=Action.REDACT,
        priority=30,
    ),
    PolicyRule(
        name="redact_secrets",
        entity_types={
            "HIGH_ENTROPY_SECRET", "HEX_SECRET", "BASE64_SECRET",
            "URL_SAFE_SECRET",
        },
        min_confidence=0.80,
        action=Action.REDACT,
        priority=40,
    ),
    PolicyRule(
        name="quarantine_code_ip",
        entity_types={"PROPRIETARY_CODE"},
        min_confidence=0.70,
        action=Action.QUARANTINE,
        priority=50,
    ),
    PolicyRule(
        name="redact_org_entities",
        entity_types={
            "ORGANIZATION_OPERATIONAL", "PROJECT_CODE_OPERATIONAL",
            "EMPLOYEE_ID_OPERATIONAL", "TICKET_ID_OPERATIONAL",
        },
        min_confidence=0.75,
        action=Action.REDACT,
        priority=60,
    ),
]


class PolicyEngine:
    """
    Evaluates policy rules against a CSC SensitivityMap and returns
    a PolicyDecision.
    """

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = sorted(
            rules or DEFAULT_RULES, key=lambda r: r.priority
        )

    def evaluate(self, sensitivity_map: SensitivityMap) -> PolicyDecision:
        """
        Evaluate all rules against the sensitivity map.

        Rules are evaluated in priority order (lowest number first). The
        first matching rule determines the action.
        """
        if not sensitivity_map.is_sensitive:
            return PolicyDecision(
                action=Action.ALLOW,
                triggered_rule=None,
                reasons=["No sensitive content detected"],
            )

        detected_types: Set[str] = set(sensitivity_map.entity_types)
        if sensitivity_map.code_blocks:
            detected_types.add("PROPRIETARY_CODE")
        if (sensitivity_map.semantic_match
                and sensitivity_map.semantic_match.is_sensitive):
            detected_types.add(sensitivity_map.semantic_match.matched_class or "SEMANTIC")

        for rule in self.rules:
            matched_types = detected_types & rule.entity_types
            if not matched_types:
                continue
            # Check if at least one span has confidence >= rule threshold
            qualifying_spans = [
                s for s in sensitivity_map.spans
                if s.entity_type in matched_types
                and s.confidence >= rule.min_confidence
            ]
            qualifying_blocks = [
                b for b in sensitivity_map.code_blocks
                if "PROPRIETARY_CODE" in rule.entity_types
                and b.ip_score >= rule.min_confidence
            ]
            if qualifying_spans or qualifying_blocks:
                reasons = [
                    f"{s.entity_type} (conf={s.confidence:.2f})"
                    for s in qualifying_spans[:3]
                ]
                return PolicyDecision(
                    action=rule.action,
                    triggered_rule=rule.name,
                    reasons=reasons,
                )

        # Semantic match fallback
        if (sensitivity_map.semantic_match
                and sensitivity_map.semantic_match.is_sensitive):
            return PolicyDecision(
                action=Action.REDACT,
                triggered_rule="semantic_match",
                reasons=[f"Semantic similarity: {sensitivity_map.semantic_match.confidence:.2f}"],
            )

        # Sensitive content detected but no rule threshold met
        return PolicyDecision(
            action=Action.AUDIT,
            triggered_rule="low_confidence_audit",
            reasons=["Sensitive signals below threshold; auditing"],
        )
