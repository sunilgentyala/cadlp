"""
Stage 3: Code Intellectual-Property Fingerprinting via AST Analysis.

Detects code blocks in prompts and estimates the probability that the code
originates from an internal proprietary codebase rather than public
open-source repositories.
"""

from __future__ import annotations

import ast
import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Code block detection ──────────────────────────────────────────────────────

_CODE_FENCE    = re.compile(r"```(?P<lang>[a-zA-Z]*)\n(?P<code>.*?)```", re.DOTALL)
_INLINE_CODE   = re.compile(r"`(?P<code>[^`\n]{20,})`")

# Internal import heuristics (patterns that suggest org-internal packages)
_INTERNAL_IMPORT_HINTS = re.compile(
    r"(?:import|from)\s+(?:com\.[a-z]+\.[a-z]+|org\.internal\.|"
    r"[a-z]+\.corp\.|[a-z]+\.internal\.|[a-z]+_internal\.|"
    r"internal\.[a-z]+)",
    re.IGNORECASE,
)

# Internal hostname hints inside code
_INTERNAL_HOST_IN_CODE = re.compile(
    r"['\"][a-zA-Z0-9\-]+\.(?:corp|internal|intranet|local|prod|staging)['\"]",
    re.IGNORECASE,
)

# Public package names (non-exhaustive; extended via corpus index in production)
_PUBLIC_PACKAGES: Set[str] = {
    "os", "sys", "re", "json", "math", "time", "datetime", "pathlib",
    "collections", "itertools", "functools", "typing", "dataclasses",
    "numpy", "pandas", "requests", "flask", "django", "fastapi",
    "sqlalchemy", "boto3", "pytest", "unittest", "logging", "argparse",
    "click", "pydantic", "httpx", "aiohttp", "asyncio", "threading",
    "subprocess", "hashlib", "base64", "uuid", "yaml", "toml",
    "scipy", "sklearn", "torch", "tensorflow", "transformers",
    "react", "vue", "angular", "express", "lodash", "axios",
}


@dataclass
class CodeBlock:
    """A code block extracted from a prompt."""
    content: str
    start: int
    end: int
    language: str = "unknown"
    ip_score: float = 0.0
    signals: List[str] = field(default_factory=list)


# ── AST feature extraction (Python only; other languages use token heuristics) ──

def _python_ast_features(code: str) -> Dict:
    features = {
        "node_count":          0,
        "function_count":      0,
        "class_count":         0,
        "import_names":        [],
        "identifier_entropy":  0.0,
        "cyclomatic_estimate": 1,
    }
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return features

    identifiers = []
    branch_nodes = (ast.If, ast.For, ast.While, ast.ExceptHandler,
                    ast.With, ast.Assert, ast.BoolOp)

    for node in ast.walk(tree):
        features["node_count"] += 1
        if isinstance(node, ast.FunctionDef):
            features["function_count"] += 1
            identifiers.append(node.name)
        elif isinstance(node, ast.ClassDef):
            features["class_count"] += 1
            identifiers.append(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                features["import_names"].extend(a.name for a in node.names)
            else:
                features["import_names"].append(node.module or "")
        elif isinstance(node, ast.Name):
            identifiers.append(node.id)
        elif isinstance(node, branch_nodes):
            features["cyclomatic_estimate"] += 1

    if identifiers:
        freq: Dict[str, int] = {}
        for ident in identifiers:
            freq[ident] = freq.get(ident, 0) + 1
        n = len(identifiers)
        features["identifier_entropy"] = -sum(
            (c / n) * math.log2(c / n) for c in freq.values()
        )

    return features


# ── Generic token-based features (language-agnostic fallback) ─────────────────

def _token_features(code: str) -> Dict:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code)
    public_hits  = sum(1 for t in tokens if t.lower() in _PUBLIC_PACKAGES)
    total_tokens = max(len(tokens), 1)
    return {
        "public_ratio":    public_hits / total_tokens,
        "line_count":      code.count("\n") + 1,
        "avg_line_length": len(code) / max(code.count("\n") + 1, 1),
    }


# ── IP score calculation ──────────────────────────────────────────────────────

def _compute_ip_score(code: str, language: str) -> Tuple[float, List[str]]:
    """
    Estimate probability [0, 1] that code is internal IP.

    Returns:
        (ip_score, [list of signals that influenced the score])
    """
    signals: List[str] = []
    score = 0.0

    # Hard-positive signals (near-certain internal origin)
    if _INTERNAL_IMPORT_HINTS.search(code):
        score = max(score, 0.90)
        signals.append("internal_import_pattern")

    if _INTERNAL_HOST_IN_CODE.search(code):
        score = max(score, 0.85)
        signals.append("internal_hostname_in_code")

    # Track whether any hard-positive signal was found (these cannot be overridden
    # by heuristic downgrade signals)
    hard_positive = score > 0.0

    # Language-specific AST features (Python only; not for unknown "")
    if language in ("python", "py"):
        feats = _python_ast_features(code)
        imports = [i.split(".")[0].lower() for i in feats["import_names"]]
        internal_imports = [i for i in imports if i not in _PUBLIC_PACKAGES and len(i) > 2]
        if internal_imports:
            boost = min(0.4, len(internal_imports) * 0.12)
            score = max(score, 0.45 + boost)
            signals.append(f"unknown_imports:{','.join(internal_imports[:3])}")
            hard_positive = True

        # Low identifier entropy suggests generic code; only reduce score when
        # no hard-positive signals exist
        if not hard_positive and feats["identifier_entropy"] < 1.5 and feats["function_count"] < 2:
            score = min(score, 0.30)
            signals.append("low_identifier_entropy")
        elif feats["identifier_entropy"] > 3.5 and feats["function_count"] >= 2:
            score = max(score, 0.55)
            signals.append("high_identifier_entropy")

    # Token-level features (language-agnostic); never override hard-positive signals
    tok = _token_features(code)
    if not hard_positive and tok["public_ratio"] > 0.7:
        score = min(score, 0.20)
        signals.append("high_public_package_ratio")
    elif tok["public_ratio"] < 0.2 and tok["line_count"] > 10:
        score = max(score, 0.50)
        signals.append("low_public_package_ratio")

    # Complexity signal: long, complex code is more likely proprietary
    if tok["line_count"] > 50:
        score = max(score, 0.40)
        signals.append("large_code_block")

    # Default: uncertain
    if not signals:
        score = 0.35
        signals.append("no_strong_signal")

    return round(min(1.0, score), 3), signals


# ── Public API ────────────────────────────────────────────────────────────────

def extract_code_blocks(prompt: str) -> List[CodeBlock]:
    """Extract all code blocks from the prompt."""
    blocks: List[CodeBlock] = []

    for match in _CODE_FENCE.finditer(prompt):
        lang = (match.group("lang") or "unknown").lower()
        code = match.group("code")
        blocks.append(CodeBlock(
            content=code,
            start=match.start(),
            end=match.end(),
            language=lang,
        ))

    if not blocks:
        for match in _INLINE_CODE.finditer(prompt):
            blocks.append(CodeBlock(
                content=match.group("code"),
                start=match.start(),
                end=match.end(),
                language="unknown",
            ))

    return blocks


def detect(prompt: str, ip_threshold: float = 0.55) -> List[CodeBlock]:
    """
    Run Stage 3 code IP fingerprinting on the prompt.

    Args:
        prompt: Raw prompt text.
        ip_threshold: Minimum ip_score to flag a block as potential IP.

    Returns:
        List of CodeBlock objects with ip_score > ip_threshold.
    """
    blocks = extract_code_blocks(prompt)
    flagged: List[CodeBlock] = []

    for block in blocks:
        score, signals = _compute_ip_score(block.content, block.language)
        block.ip_score = score
        block.signals  = signals
        if score >= ip_threshold:
            flagged.append(block)

    return flagged
