"""
CADLP Contextual Sensitivity Classifier (CSC) Pipeline.

Orchestrates the four detection stages and aggregates results into a
unified sensitivity map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from cadlp.csc.stage1_fastpath import SensitiveSpan, detect as stage1_detect
from cadlp.csc.stage2_ner       import detect as stage2_detect
from cadlp.csc.stage3_ast       import CodeBlock, detect as stage3_detect
from cadlp.csc.stage4_semantic  import (
    SemanticMatch, OrganizationalKnowledgeBase,
    detect as stage4_detect,
)


@dataclass
class SensitivityMap:
    """Aggregated output of the CSC pipeline for a single prompt."""
    prompt: str
    spans: List[SensitiveSpan] = field(default_factory=list)
    code_blocks: List[CodeBlock] = field(default_factory=list)
    semantic_match: Optional[SemanticMatch] = None

    @property
    def is_sensitive(self) -> bool:
        return bool(self.spans) or bool(self.code_blocks) or (
            self.semantic_match is not None and self.semantic_match.is_sensitive
        )

    @property
    def highest_confidence(self) -> float:
        scores = [s.confidence for s in self.spans]
        scores += [b.ip_score for b in self.code_blocks]
        if self.semantic_match and self.semantic_match.is_sensitive:
            scores.append(self.semantic_match.confidence)
        return max(scores, default=0.0)

    @property
    def entity_types(self) -> List[str]:
        types = [s.entity_type for s in self.spans]
        if self.code_blocks:
            types.append("PROPRIETARY_CODE")
        if self.semantic_match and self.semantic_match.is_sensitive:
            types.append(self.semantic_match.matched_class or "SEMANTIC_MATCH")
        return list(dict.fromkeys(types))   # deduplicated, order-preserving

    def summary(self) -> str:
        if not self.is_sensitive:
            return "CLEAN"
        parts = []
        if self.spans:
            parts.append(f"{len(self.spans)} span(s): {', '.join(self.entity_types[:4])}")
        if self.code_blocks:
            parts.append(f"{len(self.code_blocks)} code block(s) flagged as IP")
        if self.semantic_match and self.semantic_match.is_sensitive:
            parts.append(f"semantic match: {self.semantic_match.matched_class}")
        return " | ".join(parts)


class ContextualSensitivityClassifier:
    """
    Main CSC pipeline. Runs all four stages and returns a SensitivityMap.
    """

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        code_ip_threshold: float = 0.55,
        semantic_threshold: float = 0.82,
        kb: Optional[OrganizationalKnowledgeBase] = None,
    ):
        self.entropy_threshold  = entropy_threshold
        self.code_ip_threshold  = code_ip_threshold
        self.semantic_threshold = semantic_threshold
        self.kb = kb

    def classify(self, prompt: str) -> SensitivityMap:
        """
        Run the full CSC pipeline on a single prompt.

        Returns:
            A SensitivityMap containing all detected spans, code blocks,
            and semantic matches.
        """
        result = SensitivityMap(prompt=prompt)

        # Stage 1: fast-path regex + entropy
        s1_spans = stage1_detect(prompt, entropy_threshold=self.entropy_threshold)
        result.spans.extend(s1_spans)

        # Stage 2: NER + disambiguation (runs over full prompt)
        s2_spans = stage2_detect(prompt, existing_spans=s1_spans)
        result.spans.extend(s2_spans)

        # Stage 3: code IP fingerprinting
        flagged_blocks = stage3_detect(prompt, ip_threshold=self.code_ip_threshold)
        result.code_blocks.extend(flagged_blocks)

        # Stage 4: semantic embedding comparison
        semantic = stage4_detect(
            prompt,
            kb=self.kb,
            similarity_threshold=self.semantic_threshold,
        )
        if semantic.is_sensitive:
            result.semantic_match = semantic

        return result
