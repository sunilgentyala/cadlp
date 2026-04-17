"""Unit tests for the full CSC pipeline and UPR redaction engine."""

from cadlp.csc.pipeline import ContextualSensitivityClassifier
from cadlp.upr.redaction import UtilityPreservingRedactor
from cadlp.policy.engine import PolicyEngine, Action


# ── CSC Pipeline ─────────────────────────────────────────────────────────────

class TestCSCPipeline:
    def setup_method(self):
        self.csc = ContextualSensitivityClassifier()

    def test_clean_prompt_not_sensitive(self):
        smap = self.csc.classify("Explain the SOLID principles in software design.")
        assert not smap.is_sensitive
        assert smap.spans == []

    def test_api_key_detected(self):
        smap = self.csc.classify(
            "I'm using sk-abc123XYZdefGHI1234567890 as my OpenAI key."
        )
        assert smap.is_sensitive
        types = smap.entity_types
        assert "OPENAI_API_KEY" in types

    def test_pii_detected(self):
        smap = self.csc.classify(
            "Please reset the password for jane.smith@acme.com."
        )
        assert smap.is_sensitive
        assert "EMAIL_ADDRESS" in smap.entity_types

    def test_ssn_detected(self):
        smap = self.csc.classify("Patient SSN is 234-56-7890.")
        assert smap.is_sensitive

    def test_code_ip_detected(self):
        smap = self.csc.classify(
            "```python\nfrom internal.billing import PremiumRouter\n"
            "router = PremiumRouter(host='pay.internal')\n```"
        )
        # Flagged as sensitive either via code_blocks (IP score) or spans
        # (internal hostname detected by Stage 1)
        assert smap.is_sensitive

    def test_sensitivity_map_summary(self):
        smap = self.csc.classify("Email: test@corp.com")
        summary = smap.summary()
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_highest_confidence_bounded(self):
        smap = self.csc.classify("Some prompt with email user@test.com")
        assert 0.0 <= smap.highest_confidence <= 1.0

    def test_entity_types_unique(self):
        smap = self.csc.classify(
            "email1@test.com and email2@test.com are both invalid"
        )
        assert len(smap.entity_types) == len(set(smap.entity_types))


# ── UPR Redaction Engine ──────────────────────────────────────────────────────

class TestUPRRedaction:
    def setup_method(self):
        self.csc = ContextualSensitivityClassifier()
        self.upr = UtilityPreservingRedactor()

    def test_api_key_redacted(self):
        prompt = "My key is sk-abc123XYZdefGHI1234567890 for OpenAI."
        smap = self.csc.classify(prompt)
        result = self.upr.redact(smap)
        assert result.was_redacted
        assert "sk-abc123" not in result.redacted_prompt
        assert "[API_KEY_" in result.redacted_prompt

    def test_email_redacted(self):
        prompt = "Email john.doe@company.com about the meeting."
        smap = self.csc.classify(prompt)
        result = self.upr.redact(smap)
        assert result.was_redacted
        assert "john.doe@company.com" not in result.redacted_prompt

    def test_clean_prompt_unchanged(self):
        prompt = "What is the time complexity of merge sort?"
        smap = self.csc.classify(prompt)
        result = self.upr.redact(smap)
        assert not result.was_redacted
        assert result.redacted_prompt == prompt

    def test_redaction_count_matches(self):
        prompt = "Keys: sk-key1234567890abcdef and email@test.com"
        smap = self.csc.classify(prompt)
        result = self.upr.redact(smap)
        assert result.num_redactions == len(smap.spans)

    def test_session_consistency(self):
        prompt1 = "Contact alice@example.com for approval."
        prompt2 = "Please follow up with alice@example.com again."
        smap1 = self.csc.classify(prompt1)
        smap2 = self.csc.classify(prompt2)
        r1 = self.upr.redact(smap1)
        r2 = self.upr.redact(smap2)
        # The same email should produce the same placeholder
        ph1 = [ph for ph in r1.redacted_prompt.split() if ph.startswith("[EMAIL_")]
        ph2 = [ph for ph in r2.redacted_prompt.split() if ph.startswith("[EMAIL_")]
        if ph1 and ph2:
            assert ph1[0] == ph2[0]

    def test_new_session_resets_map(self):
        self.upr.new_session()
        assert len(self.upr.session_map) == 0

    def test_result_summary_not_empty(self):
        smap = self.csc.classify("token: sk-xyz1234567890abcdef1234567890")
        result = self.upr.redact(smap)
        assert isinstance(result.summary(), str)


# ── Policy Engine ─────────────────────────────────────────────────────────────

class TestPolicyEngine:
    def setup_method(self):
        self.csc    = ContextualSensitivityClassifier()
        self.policy = PolicyEngine()

    def test_clean_prompt_allowed(self):
        smap     = self.csc.classify("How does TCP/IP work?")
        decision = self.policy.evaluate(smap)
        assert decision.action == Action.ALLOW

    def test_api_key_blocked(self):
        smap     = self.csc.classify(
            "Here is my key: sk-ant-api03-" + "B" * 90
        )
        decision = self.policy.evaluate(smap)
        assert decision.action == Action.BLOCK

    def test_email_redacted(self):
        smap     = self.csc.classify("Send to user@internal.com please.")
        decision = self.policy.evaluate(smap)
        assert decision.action in (Action.REDACT, Action.BLOCK, Action.AUDIT)

    def test_decision_has_rule_name(self):
        smap     = self.csc.classify("sk-key1234567890abcdef1234567890abcd")
        decision = self.policy.evaluate(smap)
        if decision.action != Action.ALLOW:
            assert decision.triggered_rule is not None

    def test_decision_str_renderable(self):
        smap     = self.csc.classify("Normal question about Python.")
        decision = self.policy.evaluate(smap)
        assert isinstance(str(decision), str)
