import type { AccessDecision } from "../policy/access-decision.js";

export interface MCPRequest {
  path: string;
}

export interface MCPResponse {
  decision: AccessDecision;
}
