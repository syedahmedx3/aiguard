import { describe, expect, it } from "vitest";
import type { MCPRequest, MCPResponse } from "../src/mcp/types.js";

describe("MCP types", () => {
  it("compiles correctly", () => {
    const request: MCPRequest = {
      path: ".env",
    };

    const response: MCPResponse = {
      decision: {
        status: "blocked",
        resolvedPath: ".env",
        reason: "policy_match",
      },
    };

    expect(request.path).toBe(".env");
    expect(response.decision.status).toBe("blocked");
  });
});
