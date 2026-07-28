import { describe, expect, it } from "vitest";
import { createMCPAdapter } from "../src/index.js";
import type { MCPRequest, MCPResponse } from "../src/mcp/types.js";
import type { PolicyEngine } from "../src/policy/engine.js";

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

  it("adapts policy engine decisions into MCP responses", async () => {
    const engine: PolicyEngine = {
      evaluate: (requestedPath) => ({
        status: "allowed",
        resolvedPath: `/workspace/${requestedPath}`,
      }),
    };

    const adapter = createMCPAdapter(engine);

    await expect(
      adapter.handleAccessRequest({ path: "README.md" }),
    ).resolves.toEqual({
      decision: {
        status: "allowed",
        resolvedPath: "/workspace/README.md",
      },
    });
  });

  it("fails closed for invalid MCP access requests", async () => {
    const engine: PolicyEngine = {
      evaluate: () => {
        throw new Error("should not be called");
      },
    };

    const adapter = createMCPAdapter(engine);

    await expect(adapter.handleAccessRequest({ path: "" })).resolves.toEqual({
      decision: {
        status: "blocked",
        resolvedPath: "",
        reason: "invalid_request",
      },
    });
  });

  it("fails closed when the policy engine throws", async () => {
    const engine: PolicyEngine = {
      evaluate: (requestedPath) => {
        expect(requestedPath).toBe(".env");
        throw new Error("engine unavailable");
      },
    };

    const adapter = createMCPAdapter(engine);

    await expect(adapter.handleAccessRequest({ path: ".env" })).resolves.toEqual(
      {
        decision: {
          status: "blocked",
          resolvedPath: ".env",
          reason: "policy_engine_error",
        },
      },
    );
  });
});
