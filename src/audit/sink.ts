import type { AuditLogEntry } from "../types.js";

export interface AuditSink {
  write(entry: AuditLogEntry): void;

  getEntries(): AuditLogEntry[];
}
