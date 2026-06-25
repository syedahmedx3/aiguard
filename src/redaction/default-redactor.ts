// src/redaction/default-redactor.ts
import type { Redactor } from "./redactor.js";

export function redactSecrets(content: string): string {
  let result = content;

  // 1. Full Cryptographic Private Key Blocks
  result = result.replace(
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
    "[REDACTED PRIVATE KEY]",
  );

  // 2. High-risk environment variable and config target matches
  const targetKeys = [
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
  ];

  for (const key of targetKeys) {
    const regex = new RegExp(
      `(\\b${key}\\s*[=:]\\s*['" ]?)([^'"\\s\\n;]+)(['" ]?)`,
      "gi",
    );
    result = result.replace(regex, "$1[REDACTED]$3");
  }

  // 3. Standalone known platform token structures (high confidence fallback)
  result = result.replace(/\bsk-[a-zA-Z0-9-_]{24,}\b/g, "[REDACTED]");
  result = result.replace(/\bghp_[a-zA-Z0-9]{36}\b/g, "[REDACTED]");

  return result;
}

// Added class implementation to resolve test execution requirements
export class DefaultRedactor implements Redactor {
  redact(content: string): string {
    return redactSecrets(content);
  }
}
