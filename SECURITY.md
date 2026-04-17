# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in CADLP — including bypasses of detection logic, false-negative patterns that could allow sensitive data to leak, or vulnerabilities in the audit logging system — please report it responsibly.

### How to Report

Send a description of the vulnerability to: **security@cadlp.io**

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected version(s)
- Any suggested mitigations you are aware of

### What to Expect

- **Acknowledgement** within 48 hours of receipt
- **Initial assessment** within 5 business days
- **Fix or mitigation** for confirmed vulnerabilities within 30 days
- **Credit** in the release notes for responsible disclosures (unless you prefer to remain anonymous)

### Scope

The following are in scope for security reports:

- Detection bypasses: crafted inputs that cause CADLP to miss sensitive entities it should detect
- False-negative patterns in the regex library or entropy analyser
- Prompt injection attacks against the CSC pipeline itself
- Information leakage from the audit logger (i.e., raw prompt content being persisted)
- Dependency vulnerabilities with a direct exploit path

The following are out of scope:

- Denial-of-service attacks based on pathological regex input (we are aware of ReDoS risks and mitigate them on a best-effort basis)
- Vulnerabilities in optional dependencies (`sentence-transformers`, `faiss-cpu`) that are not exploitable through the CADLP API surface

## Security Design Notes

CADLP is designed with the following security properties:

- **Zero retention**: the audit logger records only metadata (entity types, action, confidence). Raw prompt content is never written to disk.
- **No external network calls**: the core pipeline makes no outbound HTTP requests. Outbound calls only occur in the optional `full` install if you use the semantic similarity stage with a remote model endpoint.
- **Stateless detection**: each `classify()` call is independent. Session state is held in memory only and is not persisted.
