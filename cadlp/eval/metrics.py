"""
CADLP Evaluation Metrics.

Implements the four primary metrics from the paper:
  - LPR  (Leakage Prevention Rate)
  - FPR  (False Positive Rate)
  - TDS  (Task Degradation Score) -- requires LLM access; stubbed here
  - RTI  (Redaction Transparency Index) -- requires LLM judge; stubbed here
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

try:
    import click
    _CLICK = True
except ImportError:
    _CLICK = False

from cadlp.csc.pipeline import ContextualSensitivityClassifier


@dataclass
class EvalMetrics:
    tp: int = 0   # True positives  (sensitive span correctly detected)
    fp: int = 0   # False positives (benign span incorrectly flagged)
    fn: int = 0   # False negatives (sensitive span missed)
    tn: int = 0   # True negatives  (benign span correctly passed)

    @property
    def lpr(self) -> float:
        """Leakage Prevention Rate = TP / (TP + FN)."""
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def fpr(self) -> float:
        """False Positive Rate = FP / (FP + TN)."""
        return self.fp / max(self.fp + self.tn, 1)

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.lpr
        return 2 * p * r / max(p + r, 1e-9)

    def report(self) -> str:
        return (
            f"LPR (Recall):  {self.lpr:.4f}\n"
            f"FPR:           {self.fpr:.4f}\n"
            f"Precision:     {self.precision:.4f}\n"
            f"F1:            {self.f1:.4f}\n"
            f"TP={self.tp}  FP={self.fp}  FN={self.fn}  TN={self.tn}"
        )


def evaluate_sample(
    sample: Dict,
    csc: ContextualSensitivityClassifier,
    threshold: float = 0.50,
) -> Tuple[int, int, int, int]:
    """
    Evaluate a single dataset sample.

    Expected sample format:
    {
        "prompt":  "...",
        "labels":  [
            {"start": 10, "end": 25, "sensitive": true},
            ...
        ]
    }

    Returns: (tp, fp, fn, tn)
    """
    prompt = sample["prompt"]
    labels = sample.get("labels", [])

    smap    = csc.classify(prompt)
    detected = [(s.start, s.end) for s in smap.spans if s.confidence >= threshold]

    tp = fp = fn = tn = 0

    for lbl in labels:
        lbl_s, lbl_e, is_sensitive = lbl["start"], lbl["end"], lbl["sensitive"]
        was_detected = any(
            ds <= lbl_s and lbl_e <= de
            for ds, de in detected
        )
        if is_sensitive and was_detected:
            tp += 1
        elif is_sensitive and not was_detected:
            fn += 1
        elif not is_sensitive and was_detected:
            fp += 1
        else:
            tn += 1

    return tp, fp, fn, tn


def run_evaluation(dataset_path: Path, threshold: float = 0.50) -> EvalMetrics:
    """Load a SEPAD-10K format JSON file and compute aggregate metrics."""
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    samples = data if isinstance(data, list) else data.get("samples", [])

    csc = ContextualSensitivityClassifier()
    metrics = EvalMetrics()

    for sample in samples:
        tp, fp, fn, tn = evaluate_sample(sample, csc, threshold)
        metrics.tp += tp
        metrics.fp += fp
        metrics.fn += fn
        metrics.tn += tn

    if _CLICK:
        click.echo(f"\nEvaluation Results ({len(samples)} samples, threshold={threshold})")
        click.echo("-" * 50)
        click.echo(metrics.report())
    else:
        print(metrics.report())

    return metrics
