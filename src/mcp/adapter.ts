import type { PolicyEngine } from "../policy/engine.js";
import type { MCPRequest, MCPResponse } from "./types.js";

export interface MCPAdapter {
  handleAccessRequest(request: MCPRequest): Promise<MCPResponse>;
}

export function createMCPAdapter(engine: PolicyEngine): MCPAdapter {
  return {
    async handleAccessRequest(request: MCPRequest): Promise<MCPResponse> {
      if (typeof request.path !== "string" || request.path.trim() === "") {
        return {
          decision: {
            status: "blocked",
            resolvedPath: "",
            reason: "invalid_request",
          },
        };
      }

      try {
        return {
          decision: engine.evaluate(request.path),
        };
      } catch {
        return {
          decision: {
            status: "blocked",
            resolvedPath: request.path,
            reason: "policy_engine_error",
          },
        };
      }
    },
  };
}
