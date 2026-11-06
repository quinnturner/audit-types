import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary = mkdtempSync(join(tmpdir(), "audit-types-consumer-"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const tsc = resolve(root, "node_modules/.bin", process.platform === "win32" ? "tsc.cmd" : "tsc");

try {
  const packed = JSON.parse(
    execFileSync(
      npm,
      [
        "pack",
        "--ignore-scripts",
        "--json",
        "--pack-destination",
        temporary,
        "--cache",
        join(temporary, "cache"),
      ],
      { cwd: root, encoding: "utf8" },
    ),
  )[0];
  const paths = packed.files.map((file) => file.path);
  assert(paths.includes("index.d.ts"));
  assert(paths.includes("README.md"));
  assert(paths.includes("SOURCES.md"));
  assert(
    paths.every((path) =>
      ["index.d.ts", "README.md", "SOURCES.md", "package.json", "LICENSE"].includes(path),
    ),
    `Unexpected published files: ${paths.join(", ")}`,
  );

  const installed = join(temporary, "node_modules/audit-types");
  mkdirSync(installed, { recursive: true });
  execFileSync("tar", [
    "-xzf",
    join(temporary, packed.filename),
    "-C",
    installed,
    "--strip-components=1",
  ]);

  const consumer = `
import type {
  NPMAuditReportV1, NPMAuditReportV2, YarnAudit, Yarn2And3AuditReport,
  YarnNpmAuditReport, PNPMAuditReport, BunAuditReport, NPMAuditBulkReport,
  NPMAuditSignaturesReport, PNPMAuditSignaturesReport,
} from "audit-types";
export const cleanBun: BunAuditReport.AuditResponse = {};
export const bulk: NPMAuditBulkReport.AuditResponse = cleanBun;
export const npmSignatures: NPMAuditSignaturesReport.Audit = {invalid: [], missing: []};
export const pnpmSignatures: PNPMAuditSignaturesReport.Audit = {invalid: [], missing: [], audited: 0, verified: 0};
export function advisoryUrls(line: YarnNpmAuditReport.AuditResponse): string[] {
  return "children" in line && line.children.URL ? [line.children.URL] : [];
}
export type ExistingNamespaces = NPMAuditReportV1.AuditResponse | NPMAuditReportV2.AuditResponse
  | YarnAudit.AuditResponse | Yarn2And3AuditReport.AuditResponse | PNPMAuditReport.AuditResponse;
`;
  for (const extension of ["mts", "cts"]) {
    const path = join(temporary, `consumer.${extension}`);
    writeFileSync(path, consumer);
    execFileSync(
      tsc,
      [
        "--strict",
        "--noEmit",
        "--target",
        "ES2020",
        "--module",
        "NodeNext",
        "--moduleResolution",
        "NodeNext",
        path,
      ],
      { cwd: temporary, stdio: "inherit" },
    );
  }
  console.log("Packed package verified for ESM and CommonJS consumers.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
