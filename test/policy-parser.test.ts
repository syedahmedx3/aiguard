import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createGuard, parsePolicyFile } from "../src/index.js";
import { AccessDeniedError } from "../src/errors.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const originalCwd = process.cwd();
let tmpDir = "";

describe("policy parser", () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiguard-policy-"));
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("parses comments, blank lines, negation, and normalized paths", () => {
    expect(
      parsePolicyFile(`
        # blocked secrets
        *.env

        secrets\\**
        !secrets/public.txt
      `),
    ).toEqual([
      { raw: "*.env", pattern: "*.env", negated: false },
      { raw: "secrets\\**", pattern: "secrets/**", negated: false },
      {
        raw: "!secrets/public.txt",
        pattern: "secrets/public.txt",
        negated: true,
      },
    ]);
  });

  it("normalizes directory-specific patterns to recursive globs", () => {
    expect(parsePolicyFile("secrets/\n**/logs/*.log")).toEqual([
      { raw: "secrets/", pattern: "secrets/**", negated: false },
      { raw: "**/logs/*.log", pattern: "**/logs/*.log", negated: false },
    ]);
  });

  it("returns no rules for empty policy files", () => {
    expect(parsePolicyFile("\n  \n# comment only\n")).toEqual([]);
  });

  it("blocks basic globs and directory wildcards through createGuard", () => {
    fs.writeFileSync(
      ".aipolicy",
      ["*.env", "secrets/**", "**/logs/*.log"].join("\n"),
    );
    const guard = createGuard();

    expect(guard.canRead("app.env")).toBe(false);
    expect(guard.canRead(path.join("nested", "app.env"))).toBe(false);
    expect(guard.canRead(path.join("secrets", "key.txt"))).toBe(false);
    expect(guard.canRead(path.join("service", "logs", "debug.log"))).toBe(
      false,
    );
    expect(guard.canRead("README.md")).toBe(true);
  });

  it("lets later negation rules unblock specific paths", () => {
    fs.mkdirSync("secrets", { recursive: true });
    fs.writeFileSync(path.join("secrets", "private.txt"), "private");
    fs.writeFileSync(path.join("secrets", "public.txt"), "public");
    fs.writeFileSync(
      ".aipolicy",
      ["secrets/**", "!secrets/public.txt"].join("\n"),
    );

    const guard = createGuard();

    expect(guard.canRead(path.join("secrets", "private.txt"))).toBe(false);
    expect(guard.canRead(path.join("secrets", "public.txt"))).toBe(true);
    expect(() => guard.secureReadFile(path.join("secrets", "private.txt")))
      .toThrow(AccessDeniedError);
    expect(guard.secureReadFile(path.join("secrets", "public.txt"))).toBe(
      "public",
    );
  });
});
