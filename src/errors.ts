// src\errors.ts
export class AccessDeniedError extends Error {
  constructor(path: string) {
    super(`Access denied to path: ${path}`);
    this.name = "AccessDeniedError";
  }
}
