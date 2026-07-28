import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  getDefaultPolicyContent,
  scanWorkspace,
  type ScanResult,
} from "../src/index.js";
import {
  appendUnhandledPolicyRules,
  initPolicyFile,
} from "../src/cli/index.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let tmpDir = "";

function writeFile(filePath: string): void {
  const absolutePath = path.join(tmpDir, filePath);
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  fs.writeFileSync(absolutePath, "test");
}

function byPath(results: ScanResult[], filePath: string): ScanResult {
  const result = results.find((entry) => entry.filePath === filePath);
  expect(result).toBeDefined();
  return result as ScanResult;
}

describe("sensitive-file scanner", () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiguard-scan-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("detects critical sensitive file signatures", () => {
    writeFile(".env");
    writeFile(".env.local");
    writeFile("certs/server.pem");
    writeFile("keys/private.key");
    writeFile(".ssh/id_rsa");
    writeFile(".ssh/id_ed25519");
    writeFile("certs/client.pfx");
    writeFile("certs/client.p12");

    const results = scanWorkspace({ rootDir: tmpDir });

    expect(byPath(results, ".env").severity).toBe("critical");
    expect(byPath(results, ".env.local").severity).toBe("critical");
    expect(byPath(results, "certs/server.pem").severity).toBe("critical");
    expect(byPath(results, "keys/private.key").severity).toBe("critical");
    expect(byPath(results, ".ssh/id_rsa").severity).toBe("critical");
    expect(byPath(results, ".ssh/id_ed25519").severity).toBe("critical");
    expect(byPath(results, "certs/client.pfx").severity).toBe("critical");
    expect(byPath(results, "certs/client.p12").severity).toBe("critical");
  });

  it("detects high and medium sensitive file signatures", () => {
    writeFile("credentials.json");
    writeFile("service-account-prod.json");
    writeFile(".aws/credentials");
    writeFile(".ssh/config");
    writeFile("backup.sql");
    writeFile("exports/prod.dump");
    writeFile("config/database.json");

    const results = scanWorkspace({ rootDir: tmpDir });

    expect(byPath(results, "credentials.json").severity).toBe("high");
    expect(byPath(results, "service-account-prod.json").severity).toBe("high");
    expect(byPath(results, ".aws/credentials").severity).toBe("high");
    expect(byPath(results, ".ssh/config").severity).toBe("high");
    expect(byPath(results, "backup.sql").severity).toBe("medium");
    expect(byPath(results, "exports/prod.dump").severity).toBe("medium");
    expect(byPath(results, "config/database.json").severity).toBe("medium");
  });

  it("marks sensitive files already covered by .aipolicy", () => {
    writeFile(".env");
    writeFile("secrets/private.key");
    writeFile("secrets/public.key");
    fs.writeFileSync(
      path.join(tmpDir, ".aipolicy"),
      ["*.env", "secrets/**", "!secrets/public.key"].join("\n"),
    );

    const results = scanWorkspace({ rootDir: tmpDir });

    expect(byPath(results, ".env").alreadyCoveredByPolicy).toBe(true);
    expect(byPath(results, "secrets/private.key").alreadyCoveredByPolicy).toBe(
      true,
    );
    expect(byPath(results, "secrets/public.key").alreadyCoveredByPolicy).toBe(
      false,
    );
  });

  it("generates default .aipolicy content with init", () => {
    expect(initPolicyFile(tmpDir)).toBe(true);

    const policy = fs.readFileSync(path.join(tmpDir, ".aipolicy"), "utf-8");
    expect(policy).toBe(getDefaultPolicyContent());
    expect(initPolicyFile(tmpDir)).toBe(false);
  });

  it("appends unhandled scan results to .aipolicy", () => {
    writeFile(".env");
    writeFile("credentials.json");
    fs.writeFileSync(path.join(tmpDir, ".aipolicy"), "*.env\n");
    const results = scanWorkspace({ rootDir: tmpDir });

    expect(appendUnhandledPolicyRules(results, tmpDir)).toBe(1);

    const policy = fs.readFileSync(path.join(tmpDir, ".aipolicy"), "utf-8");
    expect(policy).toContain("credentials.json");
    expect(policy).not.toContain("\n.env\n");
  });
});
