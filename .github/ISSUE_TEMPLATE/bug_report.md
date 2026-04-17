---
name: Bug Report
about: Report a detection error, false positive, false negative, or pipeline failure
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear description of what the bug is.

## Reproduction

```python
from cadlp import ContextualSensitivityClassifier
csc = ContextualSensitivityClassifier()
smap = csc.classify("paste your prompt here")
print(smap.spans)
```

**Prompt used** (redact any real secrets before posting):

```
<prompt here>
```

**Expected behaviour:**
<!-- e.g. "Should detect OPENAI_API_KEY with confidence > 0.95" -->

**Actual behaviour:**
<!-- e.g. "No spans returned" or "Returns EMAIL_ADDRESS for a non-email string" -->

## Environment

- CADLP version: <!-- `pip show cadlp` -->
- Python version: <!-- `python --version` -->
- OS: <!-- e.g. Ubuntu 22.04, macOS 14, Windows 11 -->
- Install variant: <!-- `pip install cadlp` or `pip install "cadlp[full]"` -->

## Additional Context

<!-- Stack traces, screenshots, or anything else relevant -->
