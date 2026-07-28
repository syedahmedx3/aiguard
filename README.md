# 🛡️ @syedahmedx3/aiguard

A zero-dependency, type-safe, fail-safe closed security guardrail for AI agents and LLM applications. This package protects local application execution paths from directory traversal attacks, accidental sensitive resource leakage, or unauthorized system access by enforcing strict runtime security bounds.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://badge.fury.io/js/%40syedahmedx3%2Faiguard.svg)](https://www.npmjs.com/package/@syedahmedx3/aiguard)

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#1e293b',
    'primaryTextColor': '#f8fafc',
    'primaryBorderColor': '#334155',
    'lineColor': '#64748b',
    'fontSize': '14px'
  }
}}%%
flowchart LR
    %% Main Nodes
    Agent["AI Agent / LLM"]
    
    subgraph Engine ["aiguard Core Security Perimeter"]
        direction TB
        Guardrail{"Guardrail Engine"}
        Features["• Path Containment<br>• Symlink Validation (TOCTOU)<br>• Glob Policy Matching<br>• Secret Token Masking"]
        Guardrail --- Features
    end

    %% Outcomes
    Denied["Access Denied<br>(Fail-Safe Closed)"]
    Success["Path Authorized"]
    Audit["Audit Log Appended"]

    %% Flow Mechanics
    Agent -->|"Resource Request"| Guardrail
    
    Guardrail -->|"Violation / Error"| Denied
    Guardrail -->|"Policy Match"| Success
    Guardrail -->|"Emit Telemetry"| Audit

    %% Individual Node Styling over theme
    style Engine fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#f8fafc
    style Guardrail fill:#1e293b,stroke:#475569,color:#f8fafc
    style Features fill:#111827,stroke:#1f2937,color:#9ca3af,text-align:left
    style Denied fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fca5a5
    style Success fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#a7f3d0
    style Audit fill:#1e293b,stroke:#475569,color:#cbd5e1
```

## Features

*  **Fail-Safe Closed Invariants:** Engineered so that any unexpected error, edge case, or misconfiguration results in strict access denial by default.
*  **Path Containment Enforcement:** Hardens file boundaries by actively preventing directory traversal (`../`), null-byte manipulation, and malicious URL-style paths.
*  **Symlink Attack Mitigation:** Validates file descriptors atomically post-open to neutralize Time-of-Check to Time-of-Use (**TOCTOU**) race conditions.
*  **Policy Engine:** Evaluates pattern matching against a dedicated `.aipolicy` file using robust, high-performance glob mechanics via `minimatch`.
*  **Structured Auditing:** Features built-in, low-overhead memory buffers and appending file-based audit logging sinks.
*  **Secret Redaction (Phase 3):** Opt-in structural text masking designed to filter high-risk tokens (e.g., `OPENAI_API_KEY`, private keys) from agent outputs.
*  **Interactive Consent (Phase 4):** Provides an asynchronous hook architecture ("Ask Mode") to support real-time, human-in-the-loop authorization flows.

---

## Tech Stack & Prerequisites

* **Runtime Support:** Node.js `>= 18.0.0` (LTS recommended)
* **Language:** TypeScript `^5.0.0` / JavaScript (ES6+)
* **Dependencies:** Zero external production dependencies (except bundled internal utilities)

---

## Getting Started

### Installation

Install the package via your preferred package manager:

```bash
npm install @syedahmedx3/aiguard
