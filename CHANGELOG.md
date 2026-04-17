# Changelog

All notable changes to CADLP are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-04-16

### Added

**Core Pipeline**
- Four-stage Contextual Sensitivity Classifier (CSC):
  - Stage 1: 22-pattern regex library covering API keys (OpenAI, Anthropic, GitHub, Slack, Stripe), JWT tokens, private key blocks, database connection strings, email addresses, SSNs, credit card numbers, internal hostnames, internal IP ranges, hardcoded passwords, and environment secrets. Secondary Shannon entropy pass flags high-entropy tokens (threshold: 4.5 bits/char, min length: 16 chars).
  - Stage 2: Heuristic NER for PERSON, ORGANIZATION, PROJECT_CODE, EMPLOYEE_ID, and TICKET_ID entities. Context-window disambiguator classifies each entity as OPERATIONAL, EXEMPLARY, or UNCERTAIN. Only OPERATIONAL and UNCERTAIN spans are emitted.
  - Stage 3: AST-based code IP fingerprinting for Python code blocks. Computes function count, class count, identifier entropy, cyclomatic complexity estimate, and import names. Internal import heuristics and internal hostname detection provide hard-positive signals that cannot be overridden by soft heuristics. Non-Python code uses token-level features.
  - Stage 4: TF-IDF cosine similarity against an Organizational Knowledge Base (KB). Internal-term density check as a secondary signal.

**Utility-Preserving Redactor (UPR)**
- Typed, indexed placeholders: `[EMAIL_1]`, `[API_KEY_1]`, `[SSN_1]`, `[PERSON_A]`, `[INTERNAL_HOST_1]`, `[PROPRIETARY_CODE_BLOCK_1]`, etc.
- Session-level `SessionRedactionMap` ensures the same real-world entity maps to the same placeholder across multiple turns in a conversation.
- `new_session()` method resets the session map for new conversations.

**Policy Engine**
- Six configurable rules evaluated in priority order: `block_credentials`, `redact_pii`, `redact_infrastructure`, `redact_secrets`, `quarantine_code_ip`, `redact_org_entities`.
- Five actions: ALLOW, REDACT, BLOCK, QUARANTINE, AUDIT.
- Each `PolicyDecision` records the triggered rule name and action.

**Audit Logger**
- Zero-retention design: entity types, action, confidence scores, and timestamps are logged; raw prompt content is never persisted.
- Structured log entries exportable in CEF (Common Event Format) and JSON.

**CLI**
- `cadlp scan` — scan a prompt from stdin or a file.
- `cadlp demo` — run the built-in demonstration against five example prompts.
- `cadlp eval` — evaluate against a JSON dataset and print LPR, FPR, precision, recall, and F1.

**Evaluation Framework**
- `EvalMetrics` dataclass with Leakage Prevention Rate (LPR), False Positive Rate (FPR), precision, recall, and F1 properties.
- SEPAD-10K sample dataset: 10 annotated enterprise prompts covering credentials, PII, code IP, mixed leakage, exemplary context, and clean prompts.

**Infrastructure**
- `pyproject.toml` with `setuptools.build_meta` build backend. Optional dependency groups: `dev` (pytest, pytest-cov) and `full` (sentence-transformers, faiss-cpu, httpx).
- Dockerfile and `docker-compose.yml` for containerised deployment.
- GitHub Actions CI: tests on Python 3.9, 3.10, and 3.11 + ruff lint check.
- Apache 2.0 license.

**Tests**
- 90 tests total: 75 unit tests across all four stages and the pipeline/UPR/policy, plus 15 integration tests covering six real-world enterprise leakage scenarios.

### Fixed

- Email regex updated to prevent trailing-period capture that broke session-level redaction map consistency across multi-turn prompts.
- Project codename regex updated to allow single-character second segment (e.g., `PROJ_X`).
- Stage 3 AST analysis no longer runs on non-Python fenced code blocks (previously, an empty language tag triggered Python AST parsing which caused false downgrades).
- `hard_positive` guard in Stage 3 IP scoring prevents low-identifier-entropy heuristic from overriding definitive internal-import or internal-hostname signals.
- All unused imports and variables removed (ruff E/F/W clean).

---

## [Unreleased]

- Fine-tuned BERT-base disambiguator for Stage 2 NER (replaces heuristic rule-based proxy).
- E5-large embedding support for Stage 4 semantic similarity (replaces TF-IDF).
- Full SEPAD-10K dataset release (10,000 annotated enterprise prompts).
- BERTScore-based Task Degradation Score (TDS) metric in the evaluation framework.
- PyPI package publication.
