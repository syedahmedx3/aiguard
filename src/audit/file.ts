import fs from "node:fs";

import type { AuditLogEntry } from "../types.js";
import type { AuditSink } from "./sink.js";

export class FileAuditSink implements AuditSink {
  readonly #filePath: string;

  constructor(filePath: string) {
    this.#filePath = filePath;
  }

  write(entry: AuditLogEntry): void {
    fs.appendFileSync(this.#filePath, `${JSON.stringify(entry)}\n`, "utf8");
  }

  getEntries(): AuditLogEntry[] {
    return [];
  }
}
