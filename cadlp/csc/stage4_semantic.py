"""
Stage 4: Organizational Semantic Embedding Comparison.

Detects prompts that describe confidential organizational content in natural
language without containing any structured PII or code. Compares prompt
embeddings against an indexed organizational knowledge base.

In production this uses an E5-large-instruct sentence encoder with a FAISS
ANN index. This module ships a lightweight TF-IDF cosine similarity fallback
for environments without GPU or the sentence-transformers package, plus a
stub interface that accepts pre-computed embeddings for testing.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class SemanticMatch:
    """Result of a semantic similarity check."""
    is_sensitive: bool
    matched_class: Optional[str]
    confidence: float
    matched_document_id: Optional[str] = None
    internal_term_density: float = 0.0


# ── Internal terminology registry (org-specific; populated during onboarding) ─

_DEFAULT_INTERNAL_TERMS = [
    # These are placeholders; real deployment uses org-specific terms
    "project_x", "operation_blue", "tier1_platinum", "codename_aurora",
    "internal_roadmap", "unreleased_feature", "acquisition_target",
    "pre_announcement", "board_minutes", "confidential_forecast",
]


class OrganizationalKnowledgeBase:
    """
    Lightweight TF-IDF knowledge base for semantic sensitivity detection.

    In production this is replaced by a FAISS index of E5-large-instruct
    embeddings of the organization's classified document corpus.
    """

    def __init__(self):
        self._documents: Dict[str, Dict] = {}   # doc_id -> {text, class, tfidf}
        self._internal_terms: List[str] = list(_DEFAULT_INTERNAL_TERMS)
        self._idf: Dict[str, float] = {}
        self._vocab_size = 0

    def add_document(self, doc_id: str, text: str, classification: str) -> None:
        """Index a classified document."""
        tokens = self._tokenize(text)
        tf = self._compute_tf(tokens)
        self._documents[doc_id] = {
            "text": text,
            "class": classification,
            "tf": tf,
            "tokens": tokens,
        }
        self._rebuild_idf()

    def add_internal_term(self, term: str) -> None:
        self._internal_terms.append(term.lower())

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9_]{3,}", text.lower())

    def _compute_tf(self, tokens: List[str]) -> Dict[str, float]:
        freq: Dict[str, int] = {}
        for t in tokens:
            freq[t] = freq.get(t, 0) + 1
        n = max(len(tokens), 1)
        return {t: c / n for t, c in freq.items()}

    def _rebuild_idf(self) -> None:
        N = max(len(self._documents), 1)
        df: Dict[str, int] = {}
        for doc in self._documents.values():
            for term in set(doc["tokens"]):
                df[term] = df.get(term, 0) + 1
        self._idf = {t: math.log((N + 1) / (d + 1)) + 1.0 for t, d in df.items()}
        self._vocab_size = len(self._idf)

    def _tfidf_vector(self, tokens: List[str]) -> Dict[str, float]:
        tf = self._compute_tf(tokens)
        return {t: tf[t] * self._idf.get(t, 0.5) for t in tf}

    def _cosine(self, va: Dict[str, float], vb: Dict[str, float]) -> float:
        keys = set(va) & set(vb)
        if not keys:
            return 0.0
        dot  = sum(va[k] * vb[k] for k in keys)
        na   = math.sqrt(sum(v ** 2 for v in va.values()))
        nb   = math.sqrt(sum(v ** 2 for v in vb.values()))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    def similarity_search(
        self, query: str, k: int = 5, threshold: float = 0.82
    ) -> List[Tuple[str, float, str]]:
        """
        Return top-k documents above threshold as (doc_id, score, class).
        """
        if not self._documents:
            return []
        q_tokens = self._tokenize(query)
        q_vec    = self._tfidf_vector(q_tokens)
        results  = []
        for doc_id, doc in self._documents.items():
            d_vec = self._tfidf_vector(doc["tokens"])
            sim   = self._cosine(q_vec, d_vec)
            if sim >= threshold:
                results.append((doc_id, sim, doc["class"]))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:k]

    def internal_term_density(self, prompt: str) -> float:
        """Fraction of prompt tokens that are internal terminology."""
        tokens = self._tokenize(prompt)
        if not tokens:
            return 0.0
        hits = sum(1 for t in tokens if t in self._internal_terms)
        return hits / len(tokens)

    @property
    def is_empty(self) -> bool:
        return len(self._documents) == 0


# ── Module-level default KB (populated by CLI / onboarding) ──────────────────

_DEFAULT_KB = OrganizationalKnowledgeBase()
_SENSITIVE_CLASSES = {"CONFIDENTIAL", "SECRET", "RESTRICTED", "ATTORNEY_CLIENT"}


def get_default_kb() -> OrganizationalKnowledgeBase:
    return _DEFAULT_KB


def detect(
    prompt: str,
    kb: Optional[OrganizationalKnowledgeBase] = None,
    similarity_threshold: float = 0.82,
    term_density_threshold: float = 0.15,
) -> SemanticMatch:
    """
    Run Stage 4 semantic sensitivity detection.

    Args:
        prompt: Raw prompt text.
        kb: Organizational knowledge base to search. Uses the module-level
            default if None.
        similarity_threshold: Minimum cosine similarity to flag a match.
        term_density_threshold: Minimum internal-term fraction to flag.

    Returns:
        A SemanticMatch result.
    """
    kb = kb or _DEFAULT_KB

    # Check document similarity
    if not kb.is_empty:
        candidates = kb.similarity_search(prompt, threshold=similarity_threshold)
        for doc_id, score, doc_class in candidates:
            if doc_class in _SENSITIVE_CLASSES:
                return SemanticMatch(
                    is_sensitive=True,
                    matched_class=doc_class,
                    confidence=round(score, 3),
                    matched_document_id=doc_id,
                )

    # Check internal terminology density
    density = kb.internal_term_density(prompt)
    if density >= term_density_threshold:
        return SemanticMatch(
            is_sensitive=True,
            matched_class="INTERNAL_TERMINOLOGY",
            confidence=min(0.95, density * 3.0),
            internal_term_density=density,
        )

    return SemanticMatch(
        is_sensitive=False,
        matched_class=None,
        confidence=0.0,
        internal_term_density=density,
    )
