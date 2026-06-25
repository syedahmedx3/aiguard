import type { AccessDecision } from "./access-decision.js";

export interface PolicyEngine {
  evaluate(path: string): AccessDecision;
}
