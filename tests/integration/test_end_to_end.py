"""
Integration tests: full CADLP pipeline (CSC + UPR + Policy) on realistic prompts.

These tests exercise the complete system end-to-end using prompts that
represent real-world enterprise leakage scenarios.
"""

import pytest
from cadlp.csc.pipeline import ContextualSensitivityClassifier
from cadlp.upr.redaction import UtilityPreservingRedactor
from cadlp.policy.engine import Action, PolicyEngine


@pytest.fixture(scope="module")
def pipeline():
    return (
        ContextualSensitivityClassifier(),
        UtilityPreservingRedactor(),
        PolicyEngine(),
    )


def run(pipeline, prompt):
    csc, upr, policy = pipeline
    smap     = csc.classify(prompt)
    decision = policy.evaluate(smap)
    result   = upr.redact(smap) if decision.action == Action.REDACT else None
    return smap, decision, result


# ── Scenario 1: Inadvertent credential paste (V1) ─────────────────────────────

class TestCredentialLeakage:
    PROMPT = (
        "I'm getting a 401 error with the OpenAI library. "
        "Here's my setup:\n\n"
        "client = OpenAI(api_key='sk-testABCDEF1234567890abcdef')\n"
        "Please help me debug."
    )

    def test_detected(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert smap.is_sensitive

    def test_blocked_or_redacted(self, pipeline):
        _, decision, _ = run(pipeline, self.PROMPT)
        assert decision.action in (Action.BLOCK, Action.REDACT)

    def test_key_value_not_in_output(self, pipeline):
        smap, decision, result = run(pipeline, self.PROMPT)
        if decision.action == Action.REDACT and result:
            assert "sk-testABCDEF" not in result.redacted_prompt


# ── Scenario 2: PII in operational context (V1) ───────────────────────────────

class TestPIILeakage:
    PROMPT = (
        "Please send a password reset link to jane.doe@acmecorp.com. "
        "Her employee ID is EMP-00452 and her SSN on file is 345-67-8901."
    )

    def test_multiple_pii_detected(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert len(smap.spans) >= 2

    def test_action_is_redact_or_block(self, pipeline):
        _, decision, _ = run(pipeline, self.PROMPT)
        assert decision.action in (Action.REDACT, Action.BLOCK)

    def test_pii_values_removed_from_output(self, pipeline):
        smap, decision, result = run(pipeline, self.PROMPT)
        if decision.action == Action.REDACT and result:
            assert "jane.doe@acmecorp.com" not in result.redacted_prompt
            assert "345-67-8901" not in result.redacted_prompt


# ── Scenario 3: Proprietary code block (V1) ───────────────────────────────────

class TestCodeIPLeakage:
    PROMPT = (
        "Can you review this payment processor for performance?\n\n"
        "```python\n"
        "from internal.billing import TierOnePlatinumRouter\n"
        "from corp.auth import ServiceToken\n\n"
        "def process(txn):\n"
        "    rt = TierOnePlatinumRouter(host='pay.internal')\n"
        "    rt.authenticate(ServiceToken.load())\n"
        "    return rt.dispatch(txn)\n"
        "```"
    )

    def test_code_block_flagged(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert smap.code_blocks or smap.spans

    def test_internal_hostname_detected(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        host_spans = [s for s in smap.spans if "INTERNAL" in s.entity_type]
        assert host_spans or smap.code_blocks

    def test_not_allowed(self, pipeline):
        _, decision, _ = run(pipeline, self.PROMPT)
        assert decision.action != Action.ALLOW


# ── Scenario 4: Mixed credentials + PII ──────────────────────────────────────

class TestMixedLeakage:
    PROMPT = (
        "DB_PASSWORD=ProdSecret123 user=admin@corp.internal "
        "host=db-primary.corp connect to 10.0.1.55"
    )

    def test_multiple_types_detected(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert len(smap.entity_types) >= 2

    def test_sensitive_flagged(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert smap.is_sensitive


# ── Scenario 5: Clean prompt (no false positive) ──────────────────────────────

class TestCleanPrompt:
    PROMPT = (
        "Can you explain the difference between synchronous and asynchronous "
        "programming in Python? I want to understand when to use asyncio."
    )

    def test_not_sensitive(self, pipeline):
        smap, _, _ = run(pipeline, self.PROMPT)
        assert not smap.is_sensitive

    def test_allowed(self, pipeline):
        _, decision, _ = run(pipeline, self.PROMPT)
        assert decision.action == Action.ALLOW

    def test_no_redaction(self, pipeline):
        smap, _, result = run(pipeline, self.PROMPT)
        assert result is None


# ── Scenario 6: Multi-turn session consistency ────────────────────────────────

class TestSessionConsistency:
    def test_same_entity_same_placeholder(self):
        csc = ContextualSensitivityClassifier()
        upr = UtilityPreservingRedactor()

        p1 = "Please update the account for alice@company.com."
        p2 = "What is the last login date for alice@company.com?"

        smap1 = csc.classify(p1)
        smap2 = csc.classify(p2)

        r1 = upr.redact(smap1)
        r2 = upr.redact(smap2)

        # Extract placeholders for the email
        def extract_placeholder(text):
            import re
            matches = re.findall(r"\[EMAIL_\d+\]", text)
            return matches[0] if matches else None

        ph1 = extract_placeholder(r1.redacted_prompt)
        ph2 = extract_placeholder(r2.redacted_prompt)

        if ph1 and ph2:
            assert ph1 == ph2, "Same entity must map to same placeholder within a session"
