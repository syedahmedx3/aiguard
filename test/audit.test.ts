import { describe, expect, it } from "vitest";
import { MemoryAuditSink } from "../src/audit/memory.js";

describe("MemoryAuditSink", () => {
  it("stores entries", () => {
    const sink = new MemoryAuditSink();

    sink.write({
      timestamp: "2025-01-01",
      path: "test.txt",
      resolvedPath: "/tmp/test.txt",
      decision: "allowed",
    });

    expect(sink.getEntries()).toHaveLength(1);
  });
});
