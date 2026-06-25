export type AccessDecision =
  | {
      status: "allowed";
      resolvedPath: string;
    }
  | {
      status: "blocked";
      resolvedPath: string;
      reason: string;
      rule?: string;
    };
