"""Unit tests for Stage 3: Code IP fingerprinting."""

from cadlp.csc.stage3_ast import detect, extract_code_blocks, _compute_ip_score


INTERNAL_CODE = '''```python
from internal.payments import TierOnePlatinumRouter
from corp.auth import ServiceAccountToken

def process_premium_txn(txn_id: str):
    router = TierOnePlatinumRouter(
        host="payments.internal",
        token=ServiceAccountToken.get(),
    )
    return router.dispatch(txn_id)
```'''

PUBLIC_CODE = '''```python
import os
import json
from pathlib import Path

def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
```'''

MIXED_PROMPT = (
    "Here is a generic helper:\n"
    "```python\nimport os\nprint(os.getcwd())\n```\n"
    "And our internal module:\n"
    + INTERNAL_CODE
)


class TestCodeBlockExtraction:
    def test_fenced_block_extracted(self):
        blocks = extract_code_blocks(INTERNAL_CODE)
        assert len(blocks) == 1
        assert "TierOnePlatinumRouter" in blocks[0].content

    def test_language_detected(self):
        blocks = extract_code_blocks(INTERNAL_CODE)
        assert blocks[0].language == "python"

    def test_multiple_blocks(self):
        blocks = extract_code_blocks(MIXED_PROMPT)
        assert len(blocks) == 2

    def test_no_blocks_returns_empty(self):
        blocks = extract_code_blocks("This is plain text with no code.")
        assert blocks == []


class TestIPScoring:
    def test_internal_code_high_ip_score(self):
        score, signals = _compute_ip_score(
            "from internal.payments import Router\n"
            "from corp.auth import Token",
            "python",
        )
        assert score >= 0.55
        assert any("internal" in s for s in signals)

    def test_public_code_low_ip_score(self):
        code = "import os\nimport json\nprint(os.getcwd())"
        score, signals = _compute_ip_score(code, "python")
        assert score < 0.55

    def test_internal_hostname_in_code_boosts_score(self):
        code = 'host = "api.internal"\nport = 8080'
        score, signals = _compute_ip_score(code, "")
        assert score >= 0.85
        assert "internal_hostname_in_code" in signals

    def test_ip_score_in_range(self):
        score, _ = _compute_ip_score("x = 1 + 2", "python")
        assert 0.0 <= score <= 1.0


class TestStage3Detection:
    def test_internal_code_flagged(self):
        blocks = detect(INTERNAL_CODE, ip_threshold=0.55)
        assert len(blocks) >= 1

    def test_public_code_not_flagged(self):
        blocks = detect(PUBLIC_CODE, ip_threshold=0.55)
        assert len(blocks) == 0

    def test_clean_text_no_blocks(self):
        blocks = detect("Can you explain recursion in Python?")
        assert blocks == []

    def test_threshold_sensitivity(self):
        # Lowering the threshold flags more blocks
        blocks_strict  = detect(INTERNAL_CODE, ip_threshold=0.90)
        blocks_lenient = detect(INTERNAL_CODE, ip_threshold=0.10)
        assert len(blocks_lenient) >= len(blocks_strict)
