import type { Yarn2And3AuditReport, YarnAudit, BunAuditReport, NPMAuditBulkReport } from "../index";

// Unmodified registry fixture from https://github.com/yarnpkg/yarn/blob/c2dda503f3759b5be5f0e24ecd9cf5c97a540147/__tests__/fixtures/audit/single-vulnerable-dep-installed/audit-api-response.json
export const legacyReport = {
  actions: [
    {
      action: "install",
      module: "minimatch",
      target: "3.0.4",
      isMajor: false,
      resolves: [
        {
          id: 118,
          path: "minimatch",
          dev: false,
          optional: false,
          bundled: false,
        },
      ],
    },
  ],
  advisories: {
    "118": {
      findings: [
        {
          version: "3.0.0",
          paths: ["minimatch"],
          dev: false,
          optional: false,
          bundled: false,
        },
      ],
      id: 118,
      created: "2016-05-25T16:37:20.000Z",
      updated: "2018-03-01T21:58:01.072Z",
      deleted: null,
      title: "Regular Expression Denial of Service",
      found_by: {
        name: "Nick Starke",
      },
      reported_by: {
        name: "Nick Starke",
      },
      module_name: "minimatch",
      cves: ["CVE-2016-10540"],
      vulnerable_versions: "<=3.0.1",
      patched_versions: ">=3.0.2",
      overview:
        "Affected versions of `minimatch` are vulnerable to regular expression denial of service attacks when user input is passed into the `pattern` argument of `minimatch(path, pattern)`.\n\n\n## Proof of Concept\n```\nvar minimatch = require(\u201cminimatch\u201d);\n\n// utility function for generating long strings\nvar genstr = function (len, chr) {\n  var result = \u201c\u201d;\n  for (i=0; i<=len; i++) {\n    result = result + chr;\n  }\n  return result;\n}\n\nvar exploit = \u201c[!\u201d + genstr(1000000, \u201c\\\\\u201d) + \u201cA\u201d;\n\n// minimatch exploit.\nconsole.log(\u201cstarting minimatch\u201d);\nminimatch(\u201cfoo\u201d, exploit);\nconsole.log(\u201cfinishing minimatch\u201d);\n```",
      recommendation: "Update to version 3.0.2 or later.",
      references: "",
      access: "public",
      severity: "high",
      cwe: "CWE-400",
      metadata: {
        module_type: "Multi.Library",
        exploitability: 4,
        affected_components:
          "Internal::Code::Function::minimatch({type:'args', key:0, vector:{type:'string'}})",
      },
      url: "https://nodesecurity.io/advisories/118",
    },
  },
  muted: [],
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 1,
      critical: 0,
    },
    dependencies: 5,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies: 5,
  },
} satisfies Yarn2And3AuditReport.Audit;

export const classicSummary = {
  type: "auditSummary",
  data: legacyReport.metadata,
} satisfies YarnAudit.AuditSummary;
export const classicAdvisory = {
  type: "auditAdvisory",
  data: {
    resolution: legacyReport.actions[0].resolves[0],
    advisory: legacyReport.advisories["118"],
  },
} satisfies YarnAudit.AuditAdvisory;

// Unmodified ms response selected from https://github.com/oven-sh/bun/blob/b1305ddc7ceebad383019d796d1367cc68f66ba0/test/cli/install/registry/fixtures/audit/audit-fixtures.json
export const bunReport = {
  ms: [
    {
      id: 1094419,
      url: "https://github.com/advisories/GHSA-w9mr-4mfr-499f",
      title: "Vercel ms Inefficient Regular Expression Complexity vulnerability",
      severity: "moderate",
      vulnerable_versions: "<2.0.0",
      cwe: ["CWE-1333"],
      cvss: {
        score: 5.3,
        vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
      },
    },
    {
      id: 1098340,
      url: "https://github.com/advisories/GHSA-3fx5-fwvr-xrjg",
      title: "Regular Expression Denial of Service in ms",
      severity: "high",
      vulnerable_versions: "<0.7.1",
      cwe: ["CWE-400", "CWE-1333"],
      cvss: {
        score: 7.5,
        vectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      },
    },
  ],
} satisfies BunAuditReport.AuditResponse;
export const bulkReport: NPMAuditBulkReport.AuditResponse = bunReport;
