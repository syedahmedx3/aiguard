import { describe, expect, it } from "vitest";
import { DefaultRedactor } from "../src/redaction/default-redactor.js";

describe("DefaultRedactor", () => {
  const redactor = new DefaultRedactor();

  it("redacts OpenAI keys", () => {
    const input = "OPENAI_API_KEY=sk-123456789";

    const output = redactor.redact(input);

    expect(output).toContain("[REDACTED]");
  });

  it("redacts database urls", () => {
    const input = "DATABASE_URL=postgres://secret";

    const output = redactor.redact(input);

    expect(output).toContain("[REDACTED]");
  });
});
