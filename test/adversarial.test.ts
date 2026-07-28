import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { canRead, createGuard, loadPolicy } from "../src/index.js";
import { DefaultRedactor } from "../src/redaction/default-redactor.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const originalCwd = process.cwd();
let tmpDir = "";

function writePolicy(patterns: string[]): void {
  fs.writeFileSync(".aipolicy", patterns.join("\n"));
  loadPolicy(".aipolicy");
}

describe("adversarial AI bypass suite", () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiguard-adversarial-"));
    process.chdir(tmpDir);
    writePolicy([".env", "secrets/**", "!secrets/public.txt"]);
    fs.writeFileSync(".env", "OPENAI_API_KEY=sk-test");
    fs.mkdirSync("safe", { recursive: true });
    fs.mkdirSync("secrets", { recursive: true });
    fs.writeFileSync(path.join("secrets", "public.txt"), "public");
    fs.writeFileSync(path.join("secrets", "private.txt"), "private");
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("blocks path traversal and obfuscation payloads", () => {
    expect(canRead("%252e%252e%252fetc%252fpasswd")).toBe(false);
    expect(canRead(".env\0.png")).toBe(false);
    expect(canRead("..\\../.env")).toBe(false);
    expect(canRead("/safe/dir/../../.env")).toBe(false);
    expect(canRead("....//....//.env")).toBe(false);
  });

  it("blocks Unicode compatibility spoofing and honors NFC path matching", () => {
    expect(canRead("\uff0e\uff0e\uff0f.env")).toBe(false);
    expect(canRead("\uff0f.env")).toBe(false);

    writePolicy(["unicod\u00e9/**"]);

    expect(canRead("unicode\u0301/key.txt")).toBe(false);
  });

  it("blocks policy bypass attempts after path normalization", () => {
    expect(canRead("/safe/dir/../.env")).toBe(false);

    const guard = createGuard();

    expect(guard.canRead("secrets/../secrets/public.txt")).toBe(true);
    expect(guard.secureReadFile("secrets/../secrets/public.txt")).toBe(
      "public",
    );
    expect(guard.canRead("secrets/../secrets/private.txt")).toBe(false);
  });

  it("redacts multi-layer embedded credentials in a single stream", () => {
    const redactor = new DefaultRedactor();
    const input = [
      "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
      "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
      "OAUTH_TOKEN=ya29.a0AfH6SMCabcdefghijklmnopqrstuvwxyz",
      "-----BEGIN RSA PRIVATE KEY-----",
      "super secret private key body",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");

    const output = redactor.redact(input);

    expect(output).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890");
    expect(output).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(output).not.toContain("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    expect(output).not.toContain("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ");
    expect(output).not.toContain("ya29.a0AfH6SMCabcdefghijklmnopqrstuvwxyz");
    expect(output).not.toContain("super secret private key body");
    expect(output).toContain("[REDACTED PRIVATE KEY]");
  });
});
