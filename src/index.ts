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

export interface CreateGuardOptions {
  policyPath?: string;
  audit?: AuditOptions;
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

function readFile(
  filePath: string,
  patterns: PolicyRule[],
  encoding: BufferEncoding = "utf-8",
  rootDir = process.cwd(),
  auditSink: AuditSink = new DisabledAuditSink(),
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
  // Block symlinks — they bypass the path check
  try {
    const stat = fs.lstatSync(resolved);

    if (stat.isSymbolicLink()) {
      throw new AccessDeniedError(filePath);
    }

    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);

    fd = openReadOnlyNoFollow(resolved, filePath);

    assertOpenedFileStillMatchesPath(fd, resolved, filePath);

    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);

    const content = fs.readFileSync(fd, {
      encoding,
    }) as string;

    recordAudit(auditSink, filePath, resolved, "allowed");

    return content;
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
  }
}

// ---------------------------------------------------------------------------
// Stateless factory API (preferred — no shared mutable state)
// ---------------------------------------------------------------------------

export function createGuard(policyPath = ".aipolicy") {
  const patterns = loadPatterns(policyPath);
  if (patterns.length === 0) {
    process.emitWarning(
      "aiguard: no policy patterns loaded — all paths are accessible",
      "AiguardWarning",
    );
  }
  const rootDir = process.cwd();
  return {
    canRead: (p: string) => checkCanRead(p, patterns, rootDir),
    secureReadFile: (p: string, enc?: BufferEncoding) =>
      readFile(p, patterns, enc, rootDir),
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
