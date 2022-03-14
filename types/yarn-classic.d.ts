import {
  CVE,
  CWE,
  FoundBy,
  GitHubAdvisoryId,
  ISO8601Date,
  Metadata,
  ReportedBy,
  Severity,
  SeverityMap,
} from "./shared";

export namespace YarnAudit {
  export type AuditResponseType =
    | "warning"
    | "activityStart"
    | "activityTick"
    | "activityEnd"
    | "auditAdvisory"
    | "auditSummary";

  export type AuditSummary = {
    type: "auditSummary";
    data: SeverityMap;
  };

  export type ActivityStart = {
    type: "activityStart";
    data: {
      id: number;
    };
  };

  export type ActivityTick = {
    type: "activityTick";
    data: {
      id: number;
      name: `${string}@${number}.${number}.${string}`;
    };
  };

  // Start audit advisory

  export type AuditAdvisoryResponse = {
    resolution: Resolution;
    advisory: Advisory;
  };

  export type Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> = {
    findings: Finding[];
    metadata: Metadata | null;
    vulnerable_versions: string;
    module_name: string;
    severity: Severity;
    github_advisory_id: ID;
    cves: CVE[];
    access: string;
    patched_versions: string;
    cvss: Cvss;
    updated: ISO8601Date;
    recommendation: string;
    cwe: CWE[];
    found_by: FoundBy | null;
    deleted: ISO8601Date | null;
    id: number;
    references: string;
    created: ISO8601Date;
    reported_by: ReportedBy | null;
    title: string;
    npm_advisory_id: null;
    overview: string;
    url: `https://github.com/advisories/${ID}`;
  };

  export type Cvss = {
    score: number;
    vectorString: string | null;
  };

  export type Finding = {
    version: string;
    paths: string[];
  };

  export type Resolution = {
    id: number;
    path: string;
    dev: boolean;
    bundled: boolean;
    optional: boolean;
  };

  export type AuditAdvisory = {
    type: "auditAdvisory";
    data: AuditAdvisoryResponse;
  };

  export type ActivityEnd = {
    type: "activityEnd";
    data: {
      id: number;
    };
  };

  export type NoLicenseFieldWarning<P extends string = string> = {
    type: "warning";
    data: `${P}: No license field`;
  };

  export type WarningResponse = NoLicenseFieldWarning;

  export type NoLockfileFound = {
    type: "info";
    data: "No lockfile found.";
  };

  export type BugInfo = {
    type: "info";
    data: `If you think this is a bug, please open a bug report with the information provided in ${string}`;
  };

  export type MoreInfo = {
    type: "info";
    data: "Visit \u001b[1mhttps://yarnpkg.com/en/docs/cli/audit\u001b[22m for documentation about this command.";
  };

  export type InfoResponse = NoLockfileFound | MoreInfo | BugInfo | MoreInfo;

  // No internet connection
  export type ENOTFOUNDError = {
    type: "error";
    data: 'An unexpected error occurred: "https://registry.yarnpkg.com/-/npm/v1/security/audits: getaddrinfo ENOTFOUND registry.yarnpkg.com".';
  };

  export type ErrorResponse = ENOTFOUNDError;

  type AuditResponse =
    | InfoResponse
    | WarningResponse
    | ErrorResponse
    | AuditSummary
    | ActivityEnd
    | ActivityTick;
}
