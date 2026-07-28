#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  getDefaultPolicyContent,
  scanWorkspace,
  type ScanResult,
} from "../scanner/index.js";

export interface RunCliOptions {
  argv?: string[];
  cwd?: string;
  stdout?: Pick<NodeJS.WriteStream, "write">;
  stderr?: Pick<NodeJS.WriteStream, "write">;
}

export function initPolicyFile(rootDir = process.cwd()): boolean {
  const policyPath = path.join(rootDir, ".aipolicy");
  if (fs.existsSync(policyPath)) {
    return false;
  }

  fs.writeFileSync(policyPath, getDefaultPolicyContent(), "utf-8");
  return true;
}

export function appendUnhandledPolicyRules(
  results: ScanResult[],
  rootDir = process.cwd(),
): number {
  const unhandledFiles = results
    .filter((result) => !result.alreadyCoveredByPolicy)
    .map((result) => result.filePath);

  if (unhandledFiles.length === 0) {
    return 0;
  }

  const policyPath = path.join(rootDir, ".aipolicy");
  const prefix = fs.existsSync(policyPath) ? "\n" : getDefaultPolicyContent();
  const generatedRules = [
    "# Added by `aiguard scan --generate-policy`.",
    ...unhandledFiles,
    "",
  ].join("\n");

  fs.appendFileSync(policyPath, `${prefix}${generatedRules}`, "utf-8");
  return unhandledFiles.length;
}

export function formatScanReport(results: ScanResult[]): string {
  if (results.length === 0) {
    return "AIGuard scan: no sensitive files detected.\n";
  }

  const lines = ["AIGuard sensitive-file scan report"];
  for (const severity of ["critical", "high", "medium"] as const) {
    const severityResults = results.filter(
      (result) => result.severity === severity,
    );
    if (severityResults.length === 0) continue;

    lines.push("", severity.toUpperCase());
    for (const result of severityResults) {
      const policyState = result.alreadyCoveredByPolicy
        ? "covered"
        : "unhandled";
      lines.push(`- ${result.filePath} (${policyState}) - ${result.reason}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export async function runCli(options: RunCliOptions = {}): Promise<number> {
  const argv = options.argv ?? process.argv.slice(2);
  const cwd = options.cwd ?? process.cwd();
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const [command, ...flags] = argv;

  if (command === "init") {
    const created = initPolicyFile(cwd);
    stdout.write(
      created
        ? "Created .aipolicy with default sensitive-file rules.\n"
        : ".aipolicy already exists; no changes made.\n",
    );
    return 0;
  }

  if (command === "scan") {
    const results = scanWorkspace({ rootDir: cwd });
    stdout.write(formatScanReport(results));

    if (flags.includes("--generate-policy")) {
      const added = appendUnhandledPolicyRules(results, cwd);
      stdout.write(`Added ${added} unhandled path(s) to .aipolicy.\n`);
    }

    return 0;
  }

  stderr.write("Usage: aiguard <init|scan> [--generate-policy]\n");
  return 1;
}

const executedFilePath = process.argv[1]
  ? path.resolve(process.argv[1])
  : "";
const currentFilePath = fileURLToPath(import.meta.url);

if (executedFilePath === currentFilePath) {
  runCli().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
