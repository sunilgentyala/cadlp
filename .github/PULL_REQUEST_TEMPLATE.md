## Summary

<!-- What does this PR do? Link to the relevant issue if applicable (e.g. Closes #42) -->

## Type of Change

- [ ] Bug fix (detection error, false positive/negative, pipeline failure)
- [ ] New detection pattern (Stage 1 regex or entropy rule)
- [ ] NER improvement (Stage 2)
- [ ] Code IP fingerprinting improvement (Stage 3)
- [ ] Semantic similarity improvement (Stage 4)
- [ ] Policy engine change
- [ ] UPR / redaction improvement
- [ ] Documentation
- [ ] Infrastructure / CI
- [ ] Other

## Changes Made

<!-- List the specific files changed and what was changed in each -->

## Test Coverage

- [ ] Added unit tests for new detection logic
- [ ] Added integration test for end-to-end scenario (if applicable)
- [ ] All 90 existing tests still pass (`pytest tests/ -v`)
- [ ] Ruff check passes (`ruff check cadlp/ tests/ --select=E,F,W --ignore=E501`)

## False Positive / False Negative Analysis

<!-- For detection changes: show example inputs that should be caught and inputs that should NOT be flagged -->

**Correctly detected (true positives):**
```
<example>
```

**Correctly ignored (true negatives):**
```
<example>
```

## Checklist

- [ ] Code follows the project style (type hints, docstrings, ruff clean)
- [ ] Self-reviewed the diff
- [ ] No hardcoded secrets or real PII in test fixtures
- [ ] CHANGELOG.md updated under `[Unreleased]`
