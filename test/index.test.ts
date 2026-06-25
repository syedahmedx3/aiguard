import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadPolicy,
  secureReadFile,
  canRead,
  createGuard,
} from "../src/index.js";
import { AccessDeniedError } from "../src/errors.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const originalCwd = process.cwd();

let tmpDir = "";
let outsideDir = "";

function writePolicy(patterns = [".env", "*.pem", "secrets/**"]): void {
  fs.writeFileSync(".aipolicy", patterns.join("\n"));
  loadPolicy(".aipolicy");
}

function isSymlinkUnsupported(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    ["EACCES", "EINVAL", "EPERM"].includes(String(error.code))
  );
}

function tryCreateFileSymlink(target: string, linkPath: string): boolean {
  try {
    fs.symlinkSync(target, linkPath, "file");
    return true;
  } catch (error) {
    if (isSymlinkUnsupported(error)) return false;
    throw error;
  }
}

function tryCreateDirectorySymlink(target: string, linkPath: string): boolean {
  try {
    fs.symlinkSync(
      target,
      linkPath,
      process.platform === "win32" ? "junction" : "dir",
    );
    return true;
  } catch (error) {
    if (isSymlinkUnsupported(error)) return false;
    throw error;
  }
}

describe("aiguard", () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiguard-"));
    outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiguard-outside-"));
    process.chdir(tmpDir);

    writePolicy();
    fs.writeFileSync("test.txt", "file content");
    fs.writeFileSync(".env", "secret");
    fs.mkdirSync("secrets", { recursive: true });
    fs.writeFileSync(path.join("secrets", "key.txt"), "secret");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(outsideDir, { recursive: true, force: true });
  });

  it("blocks access to .env", () => {
    expect(() => secureReadFile(".env")).toThrow(AccessDeniedError);
  });

  it("allows access to valid files", () => {
    expect(secureReadFile("test.txt")).toBe("file content");
  });

  it("uses the factory root for secureReadFile after cwd changes", () => {
    const guard = createGuard();
    fs.writeFileSync(path.join(outsideDir, "test.txt"), "outside content");
    process.chdir(outsideDir);

    expect(guard.secureReadFile("test.txt")).toBe("file content");
  });

  it("detects patterns correctly with canRead", () => {
    expect(canRead(path.join("secrets", "key.txt"))).toBe(false);
    expect(canRead("hello.txt")).toBe(true);
  });

  it("blocks path traversal attempts", () => {
    expect(canRead("../etc/passwd")).toBe(false);
    expect(canRead(".env/../../etc/shadow")).toBe(false);
  });

  it("blocks dotfiles (dot:true)", () => {
    expect(canRead(".env")).toBe(false);
  });

  it("returns true for all paths when policy file is absent", () => {
    loadPolicy(".missing");
    expect(canRead("anything.txt")).toBe(true);
  });

  it("blocks symlinks", () => {
    const linkCreated = tryCreateFileSymlink(
      path.join(tmpDir, "test.txt"),
      path.join(tmpDir, "safe-looking-link.txt"),
    );
    if (!linkCreated) return;

    expect(() => secureReadFile("safe-looking-link.txt")).toThrow(
      AccessDeniedError,
    );
  });

  it("normalizes Windows separators in policy rules and paths", () => {
    writePolicy(["secrets\\**"]);

    expect(canRead(path.join("secrets", "key.txt"))).toBe(false);
  });

  it("blocks case variants of denied paths", () => {
    expect(canRead(".ENV")).toBe(false);
  });

  it("blocks Unicode normalization variants of denied paths", () => {
    writePolicy(["unicod\u00e9/**"]);

    expect(canRead("unicode\u0301/key.txt")).toBe(false);
  });

  it("blocks URL-style paths before filesystem access", () => {
    expect(canRead("file:///etc/passwd")).toBe(false);
    expect(canRead("https://example.com/secret")).toBe(false);
    expect(() => secureReadFile("file:///etc/passwd")).toThrow(
      AccessDeniedError,
    );
  });

  it("blocks ambiguous Windows drive-relative paths", () => {
    expect(canRead("C:secrets/key.txt")).toBe(false);
  });

  it("blocks null byte paths before filesystem access", () => {
    expect(canRead("safe\0.txt")).toBe(false);
    expect(() => secureReadFile("safe\0.txt")).toThrow(AccessDeniedError);
  });

  it("blocks absolute paths outside the root even when they share a prefix", () => {
    const siblingPath = path.join(
      path.dirname(tmpDir),
      `${path.basename(tmpDir)}-evil`,
      "file.txt",
    );

    expect(canRead(siblingPath, tmpDir)).toBe(false);
  });

  it("blocks symlinked directories that escape the root", () => {
    fs.writeFileSync(path.join(outsideDir, "secret.txt"), "escaped");
    const linkCreated = tryCreateDirectorySymlink(
      outsideDir,
      path.join(tmpDir, "linked"),
    );
    if (!linkCreated) return;

    expect(() => secureReadFile(path.join("linked", "secret.txt"))).toThrow(
      AccessDeniedError,
    );
  });

  it("treats a final symlink swap during open as access denied", () => {
    vi.spyOn(fs, "openSync").mockImplementationOnce(() => {
      const error = new Error(
        "too many symbolic links",
      ) as NodeJS.ErrnoException;
      error.code = "ELOOP";
      throw error;
    });

    expect(() => secureReadFile("test.txt")).toThrow(AccessDeniedError);
  });

  // ===========================================================================
  // Phase 3: Secret Redaction Suite
  // ===========================================================================
  describe("Phase 3: Secret Redaction Engine", () => {
    it("preserves raw text strings by default when option is omitted", () => {
      const guard = createGuard();
      const rawEnv = "OPENAI_API_KEY=sk-abcdef123456789012345678";
      fs.writeFileSync("test-default.txt", rawEnv, "utf-8");

      try {
        expect(guard.secureReadFile("test-default.txt")).toBe(rawEnv);
      } finally {
        fs.unlinkSync("test-default.txt");
      }
    });

    it("redacts target sensitive variables accurately when explicit opt-in is configured", () => {
      const guard = createGuard({
        redaction: { enabled: true },
      });

      const secretsContent = [
        "OPENAI_API_KEY=sk-keycontenthere123456789",
        "AWS_SECRET_ACCESS_KEY='secret-aws-key-token'",
        'DATABASE_URL="postgresql://postgres:secretpass@127.0.0.1:5432/production"',
        "GITHUB_TOKEN: ghp_mytokenhashstringhere36charslong",
      ].join("\n");

      fs.writeFileSync("test-redacted.txt", secretsContent, "utf-8");

      try {
        const processed = guard.secureReadFile("test-redacted.txt");
        expect(processed).toContain("OPENAI_API_KEY=[REDACTED]");
        expect(processed).toContain("AWS_SECRET_ACCESS_KEY='[REDACTED]'");
        expect(processed).toContain('DATABASE_URL="[REDACTED]"');
        expect(processed).toContain("GITHUB_TOKEN: [REDACTED]");
      } finally {
        fs.unlinkSync("test-redacted.txt");
      }
    });

    it("scrubs multi-line asymmetric cryptographic private key block formats completely", () => {
      const guard = createGuard({
        redaction: { enabled: true },
      });

      const privateKey = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEogIBAAKCAQEAnzY4sS...",
        "D3fG7h1b90asXz...",
        "-----END RSA PRIVATE KEY-----",
      ].join("\n");

      fs.writeFileSync("test-key.txt", privateKey, "utf-8");

      try {
        expect(guard.secureReadFile("test-key.txt")).toBe(
          "[REDACTED PRIVATE KEY]",
        );
      } finally {
        fs.unlinkSync("test-key.txt");
      }
    });
  });
});
