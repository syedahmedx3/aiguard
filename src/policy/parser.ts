export interface ParsedPolicyRule {
  raw: string;
  pattern: string;
  negated: boolean;
}

export function normalizePolicyPath(filePath: string): string {
  return filePath.normalize("NFC").replaceAll("\\", "/");
}

export function parsePolicyFile(content: string): ParsedPolicyRule[] {
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => {
      const negated = line.startsWith("!");
      const rawPattern = negated ? line.slice(1).trim() : line;
      const normalized = normalizePolicyPath(rawPattern).replace(/^\/+/, "");
      const pattern = normalized.endsWith("/")
        ? `${normalized.replace(/\/+$/, "")}/**`
        : normalized;

      return {
        raw: line,
        pattern,
        negated,
      };
    })
    .filter((rule) => rule.pattern !== "");
}
