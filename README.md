# @syedahmedx3/aiguard

A zero-dependency, type-safe, fail-safe closed security guardrail for AI agents and LLM applications. Protect local application execution paths from directory traversal attacks, accidental sensitive resource leakage, or unauthorized system access.

## Features

- 🛡️ **Fail-Safe Closed Invariants**: Any error, edge case, or misconfiguration results in strict access denial.
- 📂 **Path Containment Enforcement**: Prevents directory traversal (`../`), null-byte manipulation, and URL-style paths.
- 🔄 **Symlink Attack Mitigation**: Validates file descriptors atomically post-open to neutralize race conditions (TOCTOU).
- 📜 **Policy Engine**: Pattern matches against an `.aipolicy` file using robust glob mechanics via `minimatch`.
- 📊 **Structured Auditing**: Built-in, high-performance memory and appending file-based audit logging sinks.
- 🔒 **Secret Redaction (Phase 3)**: Opt-in structural text masking for high-risk tokens (`OPENAI_API_KEY`, private keys, etc.).
- 🤝 **Interactive Consent (Phase 4)**: Asynchronous hook architecture ("Ask Mode") for real-time human-in-the-loop validation.

---

## Installation

```bash
npm install @syedahmedx3/aiguard
```
