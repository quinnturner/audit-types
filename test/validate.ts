import type { NPMAuditReportV2, PNPMAuditReport, YarnAudit } from "../index";

// npm audit --json (v7+, auditReportVersion 2)
const npmV2: NPMAuditReportV2.AuditResponse = {
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: "lodash",
      severity: "high",
      isDirect: true,
      via: [
        {
          source: 1106913,
          name: "lodash",
          dependency: "lodash",
          title: "Command Injection in lodash",
          url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
          severity: "high",
          cwe: ["CWE-77", "CWE-94"],
          cvss: {
            score: 7.2,
            vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
          },
          range: "<4.17.21",
        },
      ],
      effects: [],
      range: "<=4.17.23",
      nodes: ["node_modules/lodash"],
      fixAvailable: true,
    },
  },
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 1,
      critical: 0,
      total: 1,
    },
    dependencies: {
      prod: 2,
      dev: 0,
      optional: 0,
      peer: 0,
      peerOptional: 0,
      total: 1,
    },
  },
};

// pnpm audit --json (v1-style, numeric advisory keys)
const pnpmV1: PNPMAuditReport.AuditResponse = {
  actions: [],
  advisories: {
    "1106913": {
      findings: [{ version: "4.17.15", paths: [".>lodash"] }],
      found_by: null,
      deleted: null,
      references: "",
      created: "2021-05-06T16:05:51.000Z",
      id: 1106913,
      npm_advisory_id: null,
      overview: "",
      reported_by: null,
      title: "Command Injection in lodash",
      metadata: null,
      cves: ["CVE-2021-23337"],
      access: "public",
      severity: "high",
      module_name: "lodash",
      vulnerable_versions: "<4.17.21",
      github_advisory_id: "GHSA-35jh-r3h4-6jhm",
      recommendation: "Upgrade to version 4.17.21 or later",
      patched_versions: ">=4.17.21",
      updated: "2025-08-12T21:44:25.000Z",
      cvss: { score: 7.2, vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" },
      cwe: ["CWE-77", "CWE-94"],
      url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    },
  },
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 1,
      critical: 0,
    },
    dependencies: 2,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies: 2,
  },
};

const pnpmError: PNPMAuditReport.AuditResponse = {
  error: {
    code: "ERR_PNPM_AUDIT_NO_LOCKFILE",
    message:
      "No pnpm-lock.yaml found: Cannot audit a project without a lockfile",
  },
};

// yarn audit --json (classic, NDJSON lines)
const yarnClassicLine: YarnAudit.AuditResponse = {
  type: "auditAdvisory",
  data: {
    resolution: {
      id: 1106913,
      path: "lodash",
      dev: false,
      optional: false,
      bundled: false,
    },
    advisory: {
      findings: [{ version: "4.17.15", paths: ["lodash"] }],
      metadata: null,
      vulnerable_versions: "<4.17.21",
      module_name: "lodash",
      severity: "high",
      github_advisory_id: "GHSA-35jh-r3h4-6jhm",
      cves: ["CVE-2021-23337"],
      access: "public",
      patched_versions: ">=4.17.21",
      cvss: { score: 7.2, vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" },
      updated: "2025-08-12T21:44:25.000Z",
      recommendation: "Upgrade to version 4.17.21 or later",
      cwe: ["CWE-77", "CWE-94"],
      found_by: null,
      deleted: null,
      id: 1106913,
      references: "",
      created: "2021-05-06T16:05:51.000Z",
      reported_by: null,
      title: "Command Injection in lodash",
      npm_advisory_id: null,
      overview: "",
      url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    },
  },
};

void npmV2;
void pnpmV1;
void pnpmError;
void yarnClassicLine;

// npm can report both a direct advisory and a vulnerable dependency in `via`.
const globAdvisory = {
  source: 1244013,
  name: "glob",
  dependency: "glob",
  title: "Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal",
  url: "https://github.com/advisories/GHSA-3g3m-2fjr-6pw4",
  severity: "moderate",
  cwe: ["CWE-400"],
  cvss: { score: 0, vectorString: null },
  range: ">=9.0.0 <=14.0.1",
} satisfies NPMAuditReportV2.Via;

const mixedVia: NPMAuditReportV2.Advisory["via"] = [globAdvisory, "minimatch"];
const reversedVia: NPMAuditReportV2.Advisory["via"] = ["minimatch", globAdvisory];
const advisoryOnlyVia: NPMAuditReportV2.Advisory["via"] = [globAdvisory];
const dependencyOnlyVia: NPMAuditReportV2.Advisory["via"] = ["minimatch"];
const emptyVia: NPMAuditReportV2.Advisory["via"] = [];

// The wider types must still reject malformed data.
// @ts-expect-error via entries must be advisory objects or package names.
const invalidVia: NPMAuditReportV2.Advisory["via"] = [42];
// @ts-expect-error a CVSS vector must be a string or null.
const invalidCvss: NPMAuditReportV2.ViaCvss = { score: 0, vectorString: 42 };

void mixedVia;
void reversedVia;
void advisoryOnlyVia;
void dependencyOnlyVia;
void emptyVia;
void invalidVia;
void invalidCvss;
