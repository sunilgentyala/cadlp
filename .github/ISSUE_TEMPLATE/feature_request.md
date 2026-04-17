---
name: Feature Request
about: Suggest a new detection pattern, pipeline improvement, or capability
title: "[FEAT] "
labels: enhancement
assignees: ''
---

## Problem Statement

What problem are you trying to solve? What sensitive data is currently leaking that CADLP does not catch?

## Proposed Solution

Describe the feature or detection pattern you would like added. Include example inputs that should be caught and example inputs that should not be flagged (to keep false positives low).

**Should detect:**
```
<example input that should be flagged>
```

**Should NOT detect (avoid false positives):**
```
<example input that should pass through>
```

## Which Stage Would This Affect?

- [ ] Stage 1 (regex / entropy) — new pattern for a known secret format
- [ ] Stage 2 (NER / disambiguation) — new entity type or improved context rules
- [ ] Stage 3 (AST / code IP) — new code fingerprinting signal
- [ ] Stage 4 (semantic / KB) — improved similarity or term density
- [ ] Policy Engine — new rule or action type
- [ ] UPR — new placeholder type or redaction strategy
- [ ] CLI / evaluation — tooling improvement
- [ ] Other

## Alternatives Considered

What other approaches did you consider? Why is your proposed solution better?

## Are You Willing to Implement This?

- [ ] Yes, I can submit a PR
- [ ] No, but I can provide more details if needed
