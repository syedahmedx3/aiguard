export type AuditDecision = "allowed" | "blocked";

export type AuditDestination = "memory" | "file";

export interface AuditLogEntry {
  timestamp: string;
  path: string;
  resolvedPath: string;
  decision: AuditDecision;
  rule?: string;
}

export interface AuditOptions {
  enabled?: boolean;
  destination?: AuditDestination;
  filePath?: string;
}

export interface RedactionOptions {
  enabled?: boolean;
}

export type InteractiveConsentHook = (context: {
  path: string;
  resolvedPath: string;
}) => Promise<boolean> | boolean;

export interface CreateGuardOptions {
  policyPath?: string;
  audit?: AuditOptions;
  redaction?: RedactionOptions;
  onAsk?: InteractiveConsentHook;
}
