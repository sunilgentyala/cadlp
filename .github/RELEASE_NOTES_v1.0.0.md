# CADLP v1.0.0 — Initial Release

We are pleased to release **CADLP v1.0.0**, a research-grade, enterprise-ready Context-Aware Data Loss Prevention proxy for Large Language Model deployments.

---

## What is CADLP?

CADLP intercepts prompts before they reach external LLM APIs (OpenAI, Anthropic, etc.) and detects, classifies, and redacts sensitive data — including credentials, PII, proprietary source code, and internal operational context — using a four-stage detection pipeline.

---

## Highlights

### Four-Stage Detection Pipeline

| Stage | Method | Detects |
|-------|--------|---------|
| 1 | Regex + Shannon Entropy | API keys, secrets, SSN, credit cards, emails, internal IPs/hostnames |
| 2 | NER + Disambiguation | Person names, org names, project codes, employee/ticket IDs |
| 3 | AST Code Fingerprinting | Proprietary Python code with internal import paths |
| 4 | TF-IDF Semantic Similarity | Prompts semantically similar to internal documentation |

### Utility-Preserving Redaction

Sensitive spans are replaced with typed, indexed placeholders (`[EMAIL_1]`, `[API_KEY_1]`, `[PERSON_A]`) that preserve the semantic structure of the prompt. A session-level redaction map ensures the same entity always maps to the same placeholder across multi-turn conversations.

### Policy Engine

Six configurable rules (BLOCK credentials, REDACT PII, REDACT infrastructure, REDACT secrets, QUARANTINE code IP, REDACT org entities) with five action types: ALLOW, REDACT, BLOCK, QUARANTINE, AUDIT.

### Zero-Retention Audit Logging

Only metadata is logged — entity types, action taken, confidence, timestamp. Raw prompt content is never persisted.

---

## Quick Start

```bash
pip install cadlp
echo "My key is sk-abc123XYZdef..." | cadlp scan
cadlp demo
```

---

## Test Results

```
90 passed in 0.11s
├── 75 unit tests (all stages, pipeline, UPR, policy)
└── 15 integration tests (6 real-world enterprise scenarios)
```

---

## What's Next (v1.1.0)

- Fine-tuned BERT-base classifier for Stage 2 NER disambiguation
- E5-large embedding support for Stage 4 semantic similarity
- Full SEPAD-10K dataset (10,000 annotated enterprise prompts)
- PyPI package publication

---

**Full changelog:** [CHANGELOG.md](CHANGELOG.md)
**Documentation:** [README.md](README.md)
**License:** Apache 2.0
