"""
CADLP: Context-Aware Data Loss Prevention Proxy for LLMs.

A transparent enterprise proxy that inspects outbound prompts destined for
external LLM APIs, detects sensitive content, and applies utility-preserving
redaction before forwarding.
"""

__version__ = "1.0.0"
__author__ = "CADLP Research Team"
__license__ = "Apache-2.0"

from cadlp.csc.pipeline import ContextualSensitivityClassifier
from cadlp.upr.redaction import UtilityPreservingRedactor
from cadlp.policy.engine import PolicyEngine

__all__ = [
    "ContextualSensitivityClassifier",
    "UtilityPreservingRedactor",
    "PolicyEngine",
]
