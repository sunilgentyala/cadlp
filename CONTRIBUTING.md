# Contributing to CADLP

Thank you for your interest in contributing to CADLP. This document explains how to get started, what kinds of contributions are welcome, and how the review process works.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Ways to Contribute](#ways-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold these standards.

---

## Getting Started

```bash
# 1. Fork the repo and clone your fork
git clone https://github.com/<your-username>/cadlp.git
cd cadlp

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install in development mode with all dev dependencies
pip install -e ".[dev]"

# 4. Run the test suite to confirm everything works
pytest tests/ -v
```

---

## Ways to Contribute

| Type | Examples |
|------|----------|
| Bug fix | Fix a false positive in the regex library, fix a broken test |
| New detection pattern | Add a pattern for a new secret format (e.g. Azure SAS tokens) |
| NER improvement | Improve operational/exemplary disambiguation accuracy |
| Performance | Reduce latency of the CSC pipeline |
| Documentation | Improve README, add docstrings, fix typos |
| Dataset | Add annotated samples to SEPAD-10K |
| Evaluation | Improve LPR/FPR metrics, add new evaluation scenarios |

---

## Development Workflow

1. Create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes. Keep commits focused and atomic.

3. Run linting and tests before pushing:
   ```bash
   ruff check cadlp/ tests/ --select=E,F,W --ignore=E501
   pytest tests/ -v --tb=short
   ```

4. Push your branch and open a Pull Request against `main`.

---

## Coding Standards

- **Python 3.9+** compatible syntax only.
- **Type hints** on all public functions and methods.
- **Docstrings** on all public classes and functions (Google style).
- **Ruff** is the linter. Run `ruff check` before committing. The CI will block on any `E`, `F`, or `W` errors.
- Line length limit is 100 characters (E501 is ignored by the linter, but keep lines readable).
- Do not add dependencies to `pyproject.toml` without discussion in an issue first.

---

## Testing Requirements

- All new detection patterns must include at least one positive and one negative unit test in `tests/unit/`.
- All new pipeline features must include an integration test in `tests/integration/`.
- The overall test suite must remain at 90+ tests with 0 failures before a PR will be merged.
- Do not reduce code coverage below the current baseline.

```bash
# Run with coverage report
pytest tests/ --cov=cadlp --cov-report=term-missing
```

---

## Submitting a Pull Request

1. Fill in the PR template completely.
2. Link the PR to any related issue (e.g. `Closes #42`).
3. Ensure all CI checks pass (tests on Python 3.9, 3.10, 3.11 + ruff lint).
4. Request a review from a maintainer.
5. Address review comments in new commits (do not force-push after review starts).

---

## Reporting Bugs

Open a [Bug Report issue](../../issues/new?template=bug_report.md) and include:

- CADLP version (`pip show cadlp`)
- Python version
- Minimal reproducible example
- Expected vs. actual behaviour
- Full traceback if applicable

---

## Feature Requests

Open a [Feature Request issue](../../issues/new?template=feature_request.md) describing:

- The problem you are trying to solve
- The proposed solution
- Any alternatives you considered
- Whether you are willing to implement it yourself

---

## Questions

For general questions, open a [Discussion](../../discussions) rather than an issue.
