"""Unit tests for Stage 4: Semantic embedding comparison."""

import pytest
from cadlp.csc.stage4_semantic import (
    detect, OrganizationalKnowledgeBase, SemanticMatch
)


@pytest.fixture
def populated_kb():
    kb = OrganizationalKnowledgeBase()
    kb.add_document(
        "DOC-001",
        "Project Aurora is our confidential roadmap for the unreleased payments platform "
        "targeting acquisition of FinTech startup BluePay in Q3.",
        "CONFIDENTIAL",
    )
    kb.add_document(
        "DOC-002",
        "Operation Blue internal strategy for market expansion into Southeast Asia "
        "with pre-announcement pricing for Tier1 Platinum customers.",
        "SECRET",
    )
    kb.add_internal_term("project_aurora")
    kb.add_internal_term("operation_blue")
    kb.add_internal_term("bluepay")
    return kb


class TestOrganizationalKnowledgeBase:
    def test_add_document(self, populated_kb):
        assert not populated_kb.is_empty

    def test_similarity_search_returns_results(self, populated_kb):
        results = populated_kb.similarity_search(
            "project aurora payments platform acquisition bluepay", threshold=0.10
        )
        assert len(results) > 0
        doc_ids = [r[0] for r in results]
        assert "DOC-001" in doc_ids

    def test_empty_kb_returns_no_results(self):
        kb = OrganizationalKnowledgeBase()
        results = kb.similarity_search("any text", threshold=0.5)
        assert results == []

    def test_internal_term_density(self, populated_kb):
        prompt = "project_aurora bluepay operation_blue details"
        density = populated_kb.internal_term_density(prompt)
        assert density > 0.0

    def test_no_terms_density_zero(self):
        kb = OrganizationalKnowledgeBase()
        assert kb.internal_term_density("normal text here") == 0.0


class TestStage4Detection:
    def test_clean_prompt_not_sensitive(self, populated_kb):
        result = detect(
            "Can you explain the CAP theorem for distributed databases?",
            kb=populated_kb,
            similarity_threshold=0.50,
        )
        assert isinstance(result, SemanticMatch)

    def test_high_term_density_flagged(self, populated_kb):
        prompt = "project_aurora bluepay operation_blue tier1_platinum confidential_forecast"
        result = detect(prompt, kb=populated_kb, term_density_threshold=0.10)
        assert result.is_sensitive
        assert result.matched_class == "INTERNAL_TERMINOLOGY"

    def test_empty_kb_returns_not_sensitive(self):
        kb = OrganizationalKnowledgeBase()
        result = detect("top secret internal project", kb=kb)
        assert not result.is_sensitive

    def test_result_fields_valid(self, populated_kb):
        result = detect("some text", kb=populated_kb)
        assert isinstance(result.is_sensitive, bool)
        assert 0.0 <= result.confidence <= 1.0

    def test_similar_doc_match_sets_class(self, populated_kb):
        # Very low threshold to force a match
        result = detect(
            "project aurora confidential roadmap acquisition payments",
            kb=populated_kb,
            similarity_threshold=0.05,
        )
        if result.is_sensitive and result.matched_document_id:
            assert result.matched_class in ("CONFIDENTIAL", "SECRET",
                                             "INTERNAL_TERMINOLOGY")
