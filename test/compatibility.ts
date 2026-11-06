import type {
  NPMAuditReportV1,
  NPMAuditReportV2,
  PNPMAuditReport,
  Yarn2And3AuditReport,
  YarnAudit,
  YarnNpmAuditReport,
  BunAuditReport,
  NPMAuditBulkReport,
  NPMAuditSignaturesReport,
  PNPMAuditSignaturesReport,
} from "../index";
import type * as Pnpm11 from "./upstream/pnpm11";
import type * as Yarn3 from "./upstream/yarn3";
import { legacyReport } from "./upstream-fixtures";

// Verify structural compatibility with the package managers' own declarations.
declare const pnpm11: Pnpm11.AuditReport;
const currentPnpm: PNPMAuditReport.CurrentAudit = pnpm11;
const commonPnpm: PNPMAuditReport.Audit = currentPnpm;
declare const yarn3: Yarn3.AuditResponse;
const berry3: Yarn2And3AuditReport.Audit = yarn3;
const npm6 = { ...legacyReport, runId: "test-run" } satisfies NPMAuditReportV1.Audit;
const legacyPnpm: PNPMAuditReport.Audit = legacyReport;

const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
const pnpm12 = {
  advisories: {
    "1244013": {
      id: 1244013,
      title: "Glob cancellation bypass",
      module_name: "glob",
      findings: [
        { version: "14.0.1", paths: [".>glob"], dev: true, optional: false, bundled: false },
      ],
      severity: "moderate",
      vulnerable_versions: ">=9.0.0 <=14.0.1",
      patched_versions: null,
      patched_versions_unpublished: true,
      cwe: "CWE-400",
      github_advisory_id: "GHSA-3g3m-2fjr-6pw4",
      url: "https://github.com/advisories/GHSA-3g3m-2fjr-6pw4",
    },
  },
  metadata: {
    vulnerabilities: counts,
    dependencies: 1,
    devDependencies: 1,
    optionalDependencies: 0,
    totalDependencies: 1,
  },
} satisfies PNPMAuditReport.CurrentAudit;

// npm 7's serializer predates CWE/CVSS metadata.
const npm7Via = {
  source: 123,
  name: "foo",
  dependency: "foo",
  title: "Issue",
  url: "https://github.com/advisories/GHSA-a-b-c",
  severity: "high",
  range: "*",
} satisfies NPMAuditReportV2.Via;
const currentAdvisory = {
  name: "foo",
  severity: "high",
  isDirect: true,
  via: [npm7Via, "bar"],
  effects: [],
  range: "*",
  nodes: ["node_modules/foo"],
  fixAvailable: { name: "foo", version: "2.0.0", isSemVerMajor: true },
  fixBlockedByReleaseAge: true,
} satisfies NPMAuditReportV2.Advisory;
const npmV2 = {
  auditReportVersion: 2,
  vulnerabilities: { foo: currentAdvisory },
  metadata: {
    vulnerabilities: { ...counts, total: 1 },
    dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
  },
} satisfies NPMAuditReportV2.Audit;
const plainNpmError: NPMAuditReportV2.ErrorResponse = {
  error: { summary: "No installed dependencies", detail: "" },
};
const pnpmError: PNPMAuditReport.ErrorResponse = {
  error: { code: "ERR_PNPM_AUDIT_NO_LOCKFILE", message: "No lockfile" },
};

const deprecated = {
  value: "foo",
  children: {
    ID: "foo (deprecation)",
    Issue: "Deprecated",
    Severity: "moderate",
    "Vulnerable Versions": "1.0.0",
    "Tree Versions": ["1.0.0"],
    Dependents: ["root@workspace:."],
  },
} satisfies YarnNpmAuditReport.AuditResponse;
const errorLine = {
  type: "error",
  name: 1,
  displayName: "YN0001",
  indent: "",
  data: "Failure",
} satisfies YarnNpmAuditReport.AuditResponse;
const classicLines: YarnAudit.AuditResponse[] = [
  { type: "warning", data: "A registry warning" },
  { type: "error", data: "Request failed" },
  { type: "info", data: "Custom information" },
  { type: "activityTick", data: { id: 0, name: "" } },
  { type: "finished", data: 0.1 },
  { type: "progressTick", data: { id: 0, current: 1 } },
];

// Empty JSON objects are legitimate clean reports; Yarn 4 may instead emit zero lines.
const cleanBun: BunAuditReport.AuditResponse = {};
const cleanBulk: NPMAuditBulkReport.AuditResponse = {};
const noYarnLines: YarnNpmAuditReport.AuditResponse[] = [];

// Signature outputs deliberately use separate namespaces and verified field types.
const signatures = {
  invalid: [
    {
      name: "foo",
      version: "1.0.0",
      location: "node_modules/foo",
      registry: "https://registry.npmjs.org/",
      code: "EATTESTATIONVERIFY",
      message: "Could not verify",
      type: "dependencies",
      predicateType: "https://slsa.dev/provenance/v1",
    },
  ],
  missing: [
    {
      name: "bar",
      version: "1.0.0",
      location: "node_modules/bar",
      registry: "https://registry.npmjs.org/",
    },
  ],
  verified: [
    {
      name: "baz",
      version: "1.0.0",
      location: "node_modules/baz",
      registry: "https://registry.npmjs.org/",
      attestations: { url: "https://registry.npmjs.org/-/npm/v1/attestations/baz@1.0.0" },
      attestationBundles: [
        {
          predicateType: "https://slsa.dev/provenance/v1",
          bundle: {
            mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
            dsseEnvelope: {
              payload: "base64",
              payloadType: "application/vnd.in-toto+json",
              signatures: [{ sig: "base64" }],
            },
          },
        },
      ],
    },
  ],
} satisfies NPMAuditSignaturesReport.Audit;
const pnpmSignatures = {
  audited: 2,
  verified: 1,
  invalid: [
    {
      name: "foo",
      version: "1.0.0",
      registry: "https://registry.npmjs.org/",
      reason: "Invalid signature",
    },
  ],
  missing: [],
} satisfies PNPMAuditSignaturesReport.Audit;

// Do not accidentally broaden either JSON format into the other.
// @ts-expect-error pnpm emits a count, while npm emits attestation records.
const badNpmSignatures: NPMAuditSignaturesReport.Audit = pnpmSignatures;
// @ts-expect-error npm does not emit pnpm's counts.
const badPnpmSignatures: PNPMAuditSignaturesReport.Audit = signatures;
// @ts-expect-error bulk responses contain advisory arrays, not processed vulnerabilities.
const badBun: BunAuditReport.AuditResponse = npmV2;
// @ts-expect-error summary counts must be nested inside data.vulnerabilities.
const badSummary: YarnAudit.AuditSummary = { type: "auditSummary", data: counts };
// @ts-expect-error npm's auditReportVersion is the literal 2.
const badNpmVersion: NPMAuditReportV2.Audit = { ...npmV2, auditReportVersion: 1 };
// @ts-expect-error severity values remain constrained.
const badSeverity: NPMAuditReportV2.Advisory = { ...currentAdvisory, severity: "urgent" };
// @ts-expect-error modern pnpm's cwe is a string.
const badPnpmCwe: PNPMAuditReport.CurrentAdvisory = { ...pnpm12.advisories["1244013"], cwe: [] };

void [
  commonPnpm,
  berry3,
  npm6,
  legacyPnpm,
  pnpm12,
  npmV2,
  plainNpmError,
  pnpmError,
  deprecated,
  errorLine,
  classicLines,
  cleanBun,
  cleanBulk,
  noYarnLines,
  badNpmSignatures,
  badPnpmSignatures,
  badBun,
  badSummary,
  badNpmVersion,
  badSeverity,
  badPnpmCwe,
];

// Older registries can return npm advisory URLs rather than GitHub URLs.
const historicalNpmVia = {
  ...npm7Via,
  url: "https://www.npmjs.com/advisories/123",
} satisfies NPMAuditReportV2.Via;
void historicalNpmVia;
