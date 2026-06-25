// src\index.ts
import fs from "node:fs";
import path from "node:path";
import { minimatch } from "minimatch";
import { AccessDeniedError } from "./errors.js";

export type AuditDecision = "allowed" | "blocked";
export type AuditDestination = "memory" | "file";

export interface AuditLogEntry {
  timestamp: string;
  path: string;
  resolvedPath: string;
  decision: AuditDecision;
  rule?: string;
}

export interface AuditOptions {
  enabled?: boolean;
  destination?: AuditDestination;
  filePath?: string;
}

export interface RedactionOptions {
  enabled?: boolean;
}

export interface CreateGuardOptions {
  policyPath?: string;
  audit?: AuditOptions;
  redaction?: RedactionOptions; // Added for Phase 3
}

interface PolicyRule {
  raw: string;
  normalized: string;
}

interface AccessCheckResult {
  allowed: boolean;
  resolvedPath: string;
  rule?: string;
}

interface AuditSink {
  write(entry: AuditLogEntry): void;
  getEntries(): AuditLogEntry[];
}

// ---------------------------------------------------------------------------
// Internal helpers (stateless — operate on an explicit patterns array)
// ---------------------------------------------------------------------------

function loadPatterns(policyPath: string): PolicyRule[] {
  try {
    const content = fs.readFileSync(policyPath, "utf-8");
    return content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => ({
        raw: line,
        normalized: normalizePolicyPath(line),
      }));
  } catch {
    return [];
  }
}

class MemoryAuditSink implements AuditSink {
  readonly #entries: AuditLogEntry[] = [];

  write(entry: AuditLogEntry): void {
    this.#entries.push({ ...entry });
  }

  getEntries(): AuditLogEntry[] {
    return this.#entries.map((entry) => ({ ...entry }));
  }
}

class FileAuditSink implements AuditSink {
  readonly #filePath: string;

  constructor(filePath: string) {
    this.#filePath = filePath;
  }

  write(entry: AuditLogEntry): void {
    fs.appendFileSync(this.#filePath, `${JSON.stringify(entry)}\n`, "utf-8");
  }

  getEntries(): AuditLogEntry[] {
    return [];
  }
}

class DisabledAuditSink implements AuditSink {
  write(): void {
    return;
  }

  getEntries(): AuditLogEntry[] {
    return [];
  }
}

function createAuditSink(
  options: AuditOptions | undefined,
  rootDir: string,
): AuditSink {
  if (!options?.enabled) {
    return new DisabledAuditSink();
  }

  const destination = options.destination ?? "memory";
  if (destination === "memory") {
    return new MemoryAuditSink();
  }

  if (!options.filePath) {
    throw new TypeError("aiguard: audit.filePath is required for file logging");
  }

  return new FileAuditSink(path.resolve(rootDir, options.filePath));
}

function recordAudit(
  sink: AuditSink,
  filePath: string,
  resolvedPath: string,
  decision: AuditDecision,
  rule?: string,
): void {
  const entry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    path: filePath,
    resolvedPath,
    decision,
    ...(rule ? { rule } : {}),
  };

  try {
    sink.write(entry);
  } catch {
    return;
  }
}

function normalizePolicyPath(filePath: string): string {
  return filePath.normalize("NFC").replaceAll("\\", "/");
}

function normalizeForContainment(filePath: string): string {
  const normalized = path.resolve(filePath).normalize("NFC");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isInsideOrEqual(childPath: string, parentPath: string): boolean {
  const relative = path.relative(parentPath, childPath);
  return (
    relative === "" ||
    (relative !== "" &&
      !relative.startsWith("..") &&
      !path.isAbsolute(relative))
  );
}

function hasUnsafePathSyntax(filePath: string): boolean {
  if (filePath.includes("\0")) return true;

  const slashNormalized = filePath.replaceAll("\\", "/");
  if (
    slashNormalized.startsWith("//?/") ||
    slashNormalized.startsWith("//./")
  ) {
    return true;
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(filePath);
  const isWindowsAbsolutePath = /^[a-zA-Z]:[\\/]/.test(filePath);
  return hasScheme && !isWindowsAbsolutePath;
}

function assertInsideRoot(
  candidatePath: string,
  rootDir: string,
  requestedPath: string,
): void {
  const normalizedCandidate = normalizeForContainment(candidatePath);
  const normalizedRoot = normalizeForContainment(rootDir);
  if (!isInsideOrEqual(normalizedCandidate, normalizedRoot)) {
    throw new AccessDeniedError(requestedPath);
  }
}

function assertRealPathInsideRoot(
  candidatePath: string,
  rootDir: string,
  requestedPath: string,
): void {
  const realCandidate = fs.realpathSync.native(candidatePath);
  const realRoot = fs.realpathSync.native(rootDir);
  assertInsideRoot(realCandidate, realRoot, requestedPath);
}

function openReadOnlyNoFollow(filePath: string, requestedPath: string): number {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  try {
    return fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ELOOP"
    ) {
      throw new AccessDeniedError(requestedPath);
    }
    throw error;
  }
}

function assertOpenedFileStillMatchesPath(
  fd: number,
  filePath: string,
  requestedPath: string,
): void {
  const openedStat = fs.fstatSync(fd);
  const currentStat = fs.statSync(filePath);
  if (
    openedStat.dev !== currentStat.dev ||
    openedStat.ino !== currentStat.ino
  ) {
    throw new AccessDeniedError(requestedPath);
  }
}

function getAccessCheckResult(
  filePath: string,
  patterns: PolicyRule[],
  rootDir: string,
): AccessCheckResult {
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(resolvedRoot, filePath);

  if (hasUnsafePathSyntax(filePath)) {
    return { allowed: false, resolvedPath: resolved };
  }

  try {
    assertInsideRoot(resolved, resolvedRoot, filePath);
  } catch {
    return { allowed: false, resolvedPath: resolved };
  }

  const relative = normalizePolicyPath(path.relative(resolvedRoot, resolved));
  const matchingRule = patterns.find((pattern) =>
    minimatch(relative, pattern.normalized, { dot: true, nocase: true }),
  );
  if (matchingRule) {
    return {
      allowed: false,
      resolvedPath: resolved,
      rule: matchingRule.raw,
    };
  }

  return { allowed: true, resolvedPath: resolved };
}

function checkCanRead(
  filePath: string,
  patterns: PolicyRule[],
  rootDir: string,
): boolean {
  return getAccessCheckResult(filePath, patterns, rootDir).allowed;
}

/**
 * Scans text content for high-risk sensitive signatures and redacts them.
 */
export function redactSecrets(content: string): string {
  let result = content;

  // 1. Full Cryptographic Private Key Blocks
  result = result.replace(
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
    "[REDACTED PRIVATE KEY]",
  );

  // 2. High-risk environment variable and config target matches
  const targetKeys = [
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
  ];

  for (const key of targetKeys) {
    const regex = new RegExp(
      `(\\b${key}\\s*[=:]\\s*['" ]?)([^'"\\s\\n;]+)(['" ]?)`,
      "gi",
    );
    result = result.replace(regex, "$1[REDACTED]$3");
  }

  // 3. Standalone known platform token structures (high confidence fallback)
  result = result.replace(/\bsk-[a-zA-Z0-9-_]{24,}\b/g, "[REDACTED]");
  result = result.replace(/\bghp_[a-zA-Z0-9]{36}\b/g, "[REDACTED]");

  return result;
}

function readFile(
  filePath: string,
  patterns: PolicyRule[],
  encoding: BufferEncoding = "utf-8",
  rootDir = process.cwd(),
  auditSink: AuditSink = new DisabledAuditSink(),
  redaction?: RedactionOptions,
): string {
  const accessCheck = getAccessCheckResult(filePath, patterns, rootDir);
  if (!accessCheck.allowed) {
    recordAudit(
      auditSink,
      filePath,
      accessCheck.resolvedPath,
      "blocked",
      accessCheck.rule,
    );
    throw new AccessDeniedError(filePath);
  }
  const resolvedRoot = path.resolve(rootDir);
  const resolved = accessCheck.resolvedPath;
  let fd: number | undefined;

  try {
    const stat = fs.lstatSync(resolved);

    if (stat.isSymbolicLink()) {
      throw new AccessDeniedError(filePath);
    }

    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);

    fd = openReadOnlyNoFollow(resolved, filePath);

    assertOpenedFileStillMatchesPath(fd, resolved, filePath);

    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);

    const rawContent = fs.readFileSync(fd, { encoding }) as string;

    // Apply token filtering dynamically if enabled explicitly
    const finalContent = redaction?.enabled
      ? redactSecrets(rawContent)
      : rawContent;

    recordAudit(auditSink, filePath, resolved, "allowed");

    return finalContent;
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

// ---------------------------------------------------------------------------
// Stateless factory API (preferred — no shared mutable state)
// ---------------------------------------------------------------------------

export function createGuard(options?: CreateGuardOptions | string) {
  const policyPath =
    typeof options === "string"
      ? options
      : (options?.policyPath ?? ".aipolicy");
  const auditOptions = typeof options === "object" ? options?.audit : undefined;
  const redactionOptions =
    typeof options === "object" ? options?.redaction : undefined;

  const patterns = loadPatterns(policyPath);
  const rootDir = process.cwd();
  const auditSink = createAuditSink(auditOptions, rootDir);

  if (patterns.length === 0) {
    process.emitWarning(
      "aiguard: no policy patterns loaded — all paths are accessible",
      "AiguardWarning",
    );
  }

  return {
    canRead: (p: string) => checkCanRead(p, patterns, rootDir),
    secureReadFile: (p: string, enc?: BufferEncoding) =>
      readFile(p, patterns, enc, rootDir, auditSink, redactionOptions),
    getAuditEntries: () => auditSink.getEntries(),
  };
}

// ---------------------------------------------------------------------------
// Legacy stateful API (kept for backwards compat — avoid in servers)
// ---------------------------------------------------------------------------

let policyPatterns: PolicyRule[] = [];

export function loadPolicy(policyPath = ".aipolicy"): void {
  policyPatterns = loadPatterns(policyPath);
}

export function canRead(filePath: string, rootDir = process.cwd()): boolean {
  return checkCanRead(filePath, policyPatterns, rootDir);
}

export function secureReadFile(
  filePath: string,
  encoding: BufferEncoding = "utf-8",
): string {
  return readFile(filePath, policyPatterns, encoding);
}
