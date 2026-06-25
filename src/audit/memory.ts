import type { AuditLogEntry } from "../types.js";
import type { AuditSink } from "./sink.js";

export class MemoryAuditSink implements AuditSink {
  readonly #entries: AuditLogEntry[] = [];

  write(entry: AuditLogEntry): void {
    this.#entries.push({
      ...entry,
    });
  }

  getEntries(): AuditLogEntry[] {
    return this.#entries.map((e) => ({
      ...e,
    }));
  }
}
