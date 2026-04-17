# CADLP: Context-Aware Data Loss Prevention Proxy for LLMs

[![CI](https://github.com/sunilgentyala/cadlp/actions/workflows/ci.yml/badge.svg)](https://github.com/sunilgentyala/cadlp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

CADLP is a research-grade, enterprise-ready proxy layer that intercepts prompts sent to large language model (LLM) APIs and detects, classifies, and redacts sensitive data before it leaves the organization. It addresses the **Shadow AI** problem: employees using unapproved consumer AI tools that inadvertently expose credentials, PII, proprietary code, or internal operational context.

The system is described in full in the accompanying IEEE-style paper: *"Contextual Sensitivity Classification and Utility-Preserving Redaction for Enterprise LLM Deployments."*

---

## Architecture Overview

```
Prompt Input
     │
     ▼
┌────────────────────────────────────────────────┐
│     Contextual Sensitivity Classifier (CSC)    │
│                                                │
│  Stage 1: Regex + Entropy  (fast-path)         │
│  Stage 2: NER + Disambiguation                 │
│  Stage 3: AST Code IP Fingerprinting           │
│  Stage 4: Semantic / KB Similarity             │
└──────────────────────┬─────────────────────────┘
                       │ SensitivityMap
                       ▼
             ┌─────────────────┐
             │  Policy Engine  │  ALLOW / REDACT / BLOCK / QUARANTINE
             └────────┬────────┘
                      │
          ┌───────────┴────────────┐
          │                        │
          ▼                        ▼
 ┌─────────────────┐     ┌──────────────────┐
 │ UPR Redaction   │     │  Audit Logger    │
 │ (typed placeh.) │     │  (zero-retention)│
 └─────────────────┘     └──────────────────┘
          │
          ▼
   Sanitised Prompt → LLM API
```

---

## Key Features

- **Four-stage detection pipeline** combining fast regex/entropy, heuristic NER, AST-based code IP fingerprinting, and TF-IDF semantic similarity.
- **Operational vs. exemplary disambiguation** in NER: entities appearing in hypothetical examples are suppressed; entities in action-verb contexts are escalated.
- **Utility-Preserving Redaction (UPR)**: typed, indexed placeholders (`[EMAIL_1]`, `[API_KEY_1]`, `[PERSON_A]`) replace sensitive spans while preserving prompt structure and downstream LLM utility.
- **Session-level redaction map**: the same real-world entity always maps to the same placeholder within a multi-turn session, maintaining referential consistency.
- **Zero-retention audit logging**: only metadata (entity types, action taken, timestamp) is logged; raw prompt content is never persisted.
- **Policy engine** with six default rules, each configurable independently.

---

## Installation

```bash
# Basic install (no optional ML dependencies)
pip install cadlp

# Full install with semantic similarity support
pip install "cadlp[full]"

# Development install
git clone https://github.com/sugentyala/cadlp
cd cadlp
pip install -e ".[dev]"
```

---

## Quick Start

### Python API

```python
from cadlp import ContextualSensitivityClassifier, UtilityPreservingRedactor
from cadlp.policy.engine import PolicyEngine, Action

csc    = ContextualSensitivityClassifier()
upr    = UtilityPreservingRedactor()
policy = PolicyEngine()

prompt = "Please reset the password for alice@company.com. Her SSN is 234-56-7890."

smap     = csc.classify(prompt)
decision = policy.evaluate(smap)

if decision.action == Action.REDACT:
    result = upr.redact(smap)
    print(result.redacted_prompt)
    # "Please reset the password for [EMAIL_1]. Her SSN is [SSN_1]."
elif decision.action == Action.BLOCK:
    print(f"Prompt blocked: {decision.triggered_rule}")
```

### CLI

```bash
# Scan a prompt from stdin
echo "My API key is sk-abc123XYZ..." | cadlp scan

# Run the built-in demo
cadlp demo

# Run evaluation on the SEPAD-10K sample
cadlp eval --dataset data/sepad10k/sample.json
```

### Docker

```bash
docker compose up cadlp
```

---

## Detection Capabilities

| Entity Type            | Stage | Method              | Confidence |
|------------------------|-------|---------------------|------------|
| API Keys (OpenAI, etc.)| 1     | Regex               | 0.95-0.99  |
| Private Keys           | 1     | Regex               | 1.00       |
| JWT Tokens             | 1     | Regex               | 0.95       |
| Email Addresses        | 1     | Regex               | 0.85       |
| SSN / Credit Cards     | 1     | Regex               | 0.92-0.95  |
| Internal Hostnames     | 1     | Regex               | 0.82       |
| High-entropy Secrets   | 1     | Shannon Entropy     | variable   |
| Person Names           | 2     | NER + Disambiguation| 0.60-0.95  |
| Org / Project Codes    | 2     | NER + Disambiguation| 0.60-0.95  |
| Ticket / Employee IDs  | 2     | NER + Disambiguation| 0.60-0.95  |
| Proprietary Code       | 3     | AST + Import Analysis| variable  |
| Internal Terminology   | 4     | TF-IDF Similarity   | variable   |

---

## Running Tests

```bash
# Full suite (90 tests)
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v --cov=cadlp --cov-report=term-missing

# Integration tests only
pytest tests/integration/ -v
```

---

## Dataset: SEPAD-10K

The `data/sepad10k/sample.json` file contains 10 annotated representative prompts from the SEPAD-10K synthetic enterprise prompt benchmark. Each entry includes:

- `id`: unique sample identifier
- `prompt`: raw prompt text
- `label`: `SENSITIVE` or `CLEAN`
- `category`: sensitivity category (CREDENTIAL, PII, CODE_IP, MIXED, EXEMPLARY_CONTEXT, etc.)
- `expected_action`: expected policy decision
- `annotations`: entity types, detection stage, confidence bounds

---

## Project Structure

```
cadlp/
├── cadlp/
│   ├── csc/
│   │   ├── stage1_fastpath.py   # Regex + entropy detection
│   │   ├── stage2_ner.py        # NER with disambiguation
│   │   ├── stage3_ast.py        # Code IP fingerprinting
│   │   ├── stage4_semantic.py   # Semantic / KB similarity
│   │   └── pipeline.py          # CSC orchestrator
│   ├── upr/
│   │   └── redaction.py         # Utility-preserving redactor
│   ├── policy/
│   │   └── engine.py            # Policy rule engine
│   ├── audit/
│   │   └── logger.py            # Zero-retention audit logger
│   ├── eval/
│   │   └── metrics.py           # LPR / FPR / F1 metrics
│   └── cli.py                   # Click CLI entrypoint
├── tests/
│   ├── unit/                    # 75 unit tests
│   └── integration/             # 15 integration tests
├── data/
│   └── sepad10k/
│       └── sample.json          # SEPAD-10K sample (10 prompts)
├── .github/workflows/ci.yml
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

## Citation

If you use CADLP in your research, please cite:

```
@article{cadlp2025,
  title   = {Contextual Sensitivity Classification and Utility-Preserving Redaction
             for Enterprise LLM Deployments},
  author  = {CADLP Research Team},
  year    = {2025},
  url     = {https://github.com/sunilgentyala/cadlp}
}
```
