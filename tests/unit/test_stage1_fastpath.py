"""Unit tests for Stage 1: Fast-Path regex and entropy detection."""

import pytest
from cadlp.csc.stage1_fastpath import detect, shannon_entropy, SensitiveSpan


# ── Entropy helpers ───────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_uniform_string_max_entropy(self):
        # 256 distinct bytes -> entropy = 8.0
        text = "".join(chr(i) for i in range(256))
        assert shannon_entropy(text) > 7.5

    def test_single_char_zero_entropy(self):
        assert shannon_entropy("aaaaaa") == 0.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_random_api_key_high_entropy(self):
        key = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4"
        assert shannon_entropy(key) > 3.5


# ── Regex detection ───────────────────────────────────────────────────────────

class TestRegexDetection:
    def test_openai_api_key(self):
        prompt = "My key is sk-abc123XYZdefGHIjklMNO1234567890ab"
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "OPENAI_API_KEY" in types

    def test_anthropic_api_key(self):
        prompt = "Use sk-ant-api03-" + "A" * 90 + " for auth"
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "ANTHROPIC_API_KEY" in types

    def test_github_token(self):
        prompt = "export GH_TOKEN=ghp_" + "a" * 36
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "GITHUB_TOKEN" in types

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123XYZdef"
        prompt = f"Authorization header: Bearer {jwt}"
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "JWT_TOKEN" in types or "BEARER_TOKEN" in types

    def test_private_key_block(self):
        prompt = "Here is my key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "PRIVATE_KEY_BLOCK" in types

    def test_database_connection_string(self):
        prompt = "DB: postgresql://admin:pass123@db.internal:5432/prod_db"
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert "DB_CONNECTION_STRING" in types

    def test_email_address(self):
        spans = detect("Contact john.doe@example.com for support.")
        types = [s.entity_type for s in spans]
        assert "EMAIL_ADDRESS" in types

    def test_ssn_detected(self):
        spans = detect("Customer SSN: 123-45-6789")
        types = [s.entity_type for s in spans]
        assert "SSN" in types

    def test_internal_hostname(self):
        spans = detect("Connect to db-primary.corp on port 5432.")
        types = [s.entity_type for s in spans]
        assert "INTERNAL_HOSTNAME" in types

    def test_internal_ip(self):
        spans = detect("Server is at 192.168.1.100")
        types = [s.entity_type for s in spans]
        assert "INTERNAL_IP" in types

    def test_hardcoded_password(self):
        spans = detect('password = "Sup3rS3cret!"')
        types = [s.entity_type for s in spans]
        assert "HARDCODED_PASSWORD" in types

    def test_env_secret(self):
        spans = detect("DB_PASSWORD=MySecretPass123")
        types = [s.entity_type for s in spans]
        # DB_PASSWORD=... may match either ENV_SECRET or HARDCODED_PASSWORD
        assert "ENV_SECRET" in types or "HARDCODED_PASSWORD" in types

    def test_clean_prompt_no_spans(self):
        prompt = "What is the difference between a list and a tuple in Python?"
        spans = detect(prompt)
        assert spans == []

    def test_deduplication_no_overlap_duplicates(self):
        prompt = "My email is test@test.com and again test@test.com"
        spans = detect(prompt)
        email_spans = [s for s in spans if s.entity_type == "EMAIL_ADDRESS"]
        # Both occurrences should be detected (they do not overlap)
        assert len(email_spans) == 2

    def test_span_confidence_range(self):
        spans = detect("Key: sk-abc123XYZ1234567890abcdefghij")
        for span in spans:
            assert 0.0 <= span.confidence <= 1.0


# ── Entropy detection ─────────────────────────────────────────────────────────

class TestEntropyDetection:
    def test_high_entropy_token_detected(self):
        # 32-char random-looking hex string
        secret = "A3f9B2e1D8c7F4a5B6e3C9d0E1f2A4b5"
        prompt = f"token={secret}"
        spans = detect(prompt, entropy_threshold=3.0)
        assert any(s.entity_type in ("HEX_SECRET", "HIGH_ENTROPY_SECRET",
                                      "BASE64_SECRET", "URL_SAFE_SECRET")
                   for s in spans)

    def test_short_token_below_min_length_ignored(self):
        prompt = "id=abc12"   # only 6 chars, below min_entropy_token_len=16
        spans = detect(prompt, entropy_threshold=3.0, min_entropy_token_len=16)
        entropy_spans = [s for s in spans if "SECRET" in s.entity_type]
        assert len(entropy_spans) == 0

    def test_low_entropy_word_not_flagged(self):
        prompt = "the quick brown fox"
        spans = detect(prompt, entropy_threshold=4.5)
        assert spans == []
