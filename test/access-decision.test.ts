import { describe, expect, it } from "vitest";
import type { AccessDecision } from "../src/policy/access-decision.js";

describe("AccessDecision", () => {
  it("supports allowed decisions", () => {
    const decision: AccessDecision = {
      status: "allowed",
      resolvedPath: "/tmp/test.txt",
    };

    expect(decision.status).toBe("allowed");
  });

  it("supports blocked decisions", () => {
    const decision: AccessDecision = {
      status: "blocked",
      resolvedPath: "/tmp/.env",
      reason: "policy_match",
      rule: ".env",
    };

    expect(decision.status).toBe("blocked");
  });
});
