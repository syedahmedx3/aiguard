// src/index.ts
import fs from "node:fs";
import path from "node:path";
import { minimatch } from "minimatch";
import { AccessDeniedError } from "./errors.js";
import { redactSecrets } from "./redaction/default-redactor.js";
import {
  normalizePolicyPath,
  parsePolicyFile,
} from "./policy/parser.js";
import type { ParsedPolicyRule as PolicyRule } from "./policy/parser.js";

export { createMCPAdapter } from "./mcp/adapter.js";
export type { MCPAdapter } from "./mcp/adapter.js";
export type { MCPRequest, MCPResponse } from "./mcp/types.js";
export type { AccessDecision } from "./policy/access-decision.js";
export type { PolicyEngine } from "./policy/engine.js";
export { parsePolicyFile } from "./policy/parser.js";
export type { ParsedPolicyRule } from "./policy/parser.js";
export {
  getDefaultPolicyContent,
  isCoveredByPolicy,
  scanWorkspace,
} from "./scanner/index.js";
export type { ScanResult, ScanSeverity } from "./scanner/index.js";

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

export type InteractiveConsentHook = (context: {
  path: string;
  resolvedPath: string;
}) => Promise<boolean> | boolean;

export interface CreateGuardOptions {
  policyPath?: string;
  audit?: AuditOptions;
  redaction?: RedactionOptions;
  onAsk?: InteractiveConsentHook;
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
    return parsePolicyFile(content);
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

function normalizeForContainment(filePath: string): string {
  const normalized = path.resolve(filePath).normalize("NFC");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

// Fixed validation edge case check
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

  const pathVariants = getUnsafeSyntaxVariants(filePath);

  return pathVariants.some((pathVariant) => {
    const slashNormalized = pathVariant.replaceAll("\\", "/");
    if (
      slashNormalized.startsWith("//?/") ||
      slashNormalized.startsWith("//./")
    ) {
      return true;
    }

    if (
      slashNormalized === ".." ||
      slashNormalized.startsWith("../")
    ) {
      return true;
    }

    const hasScheme = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(pathVariant);
    const isWindowsAbsolutePath = /^[a-zA-Z]:[\\/]/.test(pathVariant);
    return hasScheme && !isWindowsAbsolutePath;
  });
}

function getUnsafeSyntaxVariants(filePath: string): string[] {
  const variants = [filePath, filePath.normalize("NFKC")];
  let decoded = filePath;

  for (let index = 0; index < 2; index += 1) {
    try {
      const nextDecoded = decodeURIComponent(decoded);
      if (nextDecoded === decoded) break;
      decoded = nextDecoded;
      variants.push(decoded, decoded.normalize("NFKC"));
    } catch {
      break;
    }
  }

  return [...new Set(variants)];
}

function hasUnsafeCompatibilityPathSyntax(filePath: string): boolean {
  const compatibilityNormalized = filePath.normalize("NFKC");
  if (compatibilityNormalized === filePath) return false;

  const originalSlashNormalized = filePath.replaceAll("\\", "/");
  const compatibilitySlashNormalized = compatibilityNormalized.replaceAll(
    "\\",
    "/",
  );

  if (
    compatibilitySlashNormalized.includes("/") &&
    !originalSlashNormalized.includes("/")
  ) {
    return true;
  }

  return (
    compatibilitySlashNormalized === ".." ||
    compatibilitySlashNormalized.startsWith("../")
  );
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

// Added filesystem verification layers
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

function matchesPolicyRule(relativePath: string, rule: PolicyRule): boolean {
  const options = { dot: true, nocase: true };
  if (rule.pattern.includes("/")) {
    return minimatch(relativePath, rule.pattern, options);
  }

  return minimatch(path.basename(relativePath), rule.pattern, options);
}

function findLastMatchingRule(
  relativePath: string,
  patterns: PolicyRule[],
): PolicyRule | undefined {
  let matchingRule: PolicyRule | undefined;

  for (const pattern of patterns) {
    if (matchesPolicyRule(relativePath, pattern)) {
      matchingRule = pattern;
    }
  }

  return matchingRule;
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
  if (hasUnsafeCompatibilityPathSyntax(relative)) {
    return { allowed: false, resolvedPath: resolved };
  }

  const matchingRule = findLastMatchingRule(relative, patterns);
  if (matchingRule && !matchingRule.negated) {
    return {
      allowed: false,
      resolvedPath: resolved,
      rule: matchingRule.raw,
    };
  }

  return { allowed: true, resolvedPath: resolved };
}

async function evaluateAccessAsync(
  filePath: string,
  patterns: PolicyRule[],
  rootDir: string,
  onAsk?: InteractiveConsentHook,
): Promise<{ allowed: boolean; resolvedPath: string; rule?: string }> {
  const result = getAccessCheckResult(filePath, patterns, rootDir);

  if (!result.allowed) {
    return result;
  }

  if (onAsk) {
    try {
      const userConsent = await onAsk({
        path: filePath,
        resolvedPath: result.resolvedPath,
      });

      if (!userConsent) {
        return {
          allowed: false,
          resolvedPath: result.resolvedPath,
          rule: "interactive_consent_denied",
        };
      }
    } catch {
      return {
        allowed: false,
        resolvedPath: result.resolvedPath,
        rule: "interactive_consent_error",
      };
    }
  }

  return { allowed: true, resolvedPath: result.resolvedPath };
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
// Stateless factory API
// ---------------------------------------------------------------------------

export function createGuard(options?: CreateGuardOptions | string) {
  const policyPath =
    typeof options === "string"
      ? options
      : (options?.policyPath ?? ".aipolicy");
  const auditOptions = typeof options === "object" ? options?.audit : undefined;
  const redactionOptions =
    typeof options === "object" ? options?.redaction : undefined;
  const onAskHook = typeof options === "object" ? options?.onAsk : undefined;

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

    checkAccess: async (p: string): Promise<boolean> => {
      const evaluation = await evaluateAccessAsync(
        p,
        patterns,
        rootDir,
        onAskHook,
      );
      return evaluation.allowed;
    },

    secureReadFileAsync: async (
      p: string,
      enc?: BufferEncoding,
    ): Promise<string> =>
      readFileAsync(
        p,
        patterns,
        enc,
        rootDir,
        auditSink,
        redactionOptions,
        onAskHook,
      ),

    secureReadFile: (p: string, enc?: BufferEncoding) =>
      readFile(p, patterns, enc, rootDir, auditSink, redactionOptions),

    getAuditEntries: () => auditSink.getEntries(),
  };
}

// ---------------------------------------------------------------------------
// Legacy stateful API (Backward Compatibility)
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

async function readFileAsync(
  filePath: string,
  patterns: PolicyRule[],
  encoding: BufferEncoding = "utf-8",
  rootDir = process.cwd(),
  auditSink: AuditSink,
  redaction?: RedactionOptions,
  onAsk?: InteractiveConsentHook,
): Promise<string> {
  const accessCheck = await evaluateAccessAsync(
    filePath,
    patterns,
    rootDir,
    onAsk,
  );

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
    if (stat.isSymbolicLink()) throw new AccessDeniedError(filePath);

    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);
    fd = openReadOnlyNoFollow(resolved, filePath);
    assertOpenedFileStillMatchesPath(fd, resolved, filePath);
    assertRealPathInsideRoot(resolved, resolvedRoot, filePath);

    const rawContent = fs.readFileSync(fd, { encoding }) as string;
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
