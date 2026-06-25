# AIGuard Architecture

Current Flow

AI Agent
↓
AIGuard
↓
Filesystem

Future MCP Flow

AI Agent
↓
MCP Server
↓
AIGuard Policy Engine
↓
Filesystem

Trust Boundaries

- AI Agent is untrusted
- File system is sensitive
- Policy engine is authoritative

Extension Points

- PolicyEngine
- AuditSink
- Redactor
- MCP Adapter
