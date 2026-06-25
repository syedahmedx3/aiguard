// src\redaction\redactor.ts
export interface Redactor {
  redact(content: string): string;
}
