export type Severity = "info" | "low" | "moderate" | "high" | "critical";

export interface SeverityMap extends Record<Severity, number> {}

export type GitHubAdvisoryId = `GHSA-${string}-${string}-${string}`;

export type CVE = `CVE-${number}-${number}`;

export type CWE = `CWE-${number}`;

// This is a simple approximation.
export type ISO8601Date =
  `${number}-${number}-${number}T${number}:${number}:${number}.${number}Z`;

// This isn't exactly correct, as `1.0.` works.
export type Semver = `${number}.${number}.${number | string}`;

export interface FoundBy {
  link: string;
  name: string;
  email: string;
}

export interface ReportedBy {
  link: string;
  name: string;
  email: string;
}

export interface Metadata {
  module_type: string;
  exploitability: number;
  affected_components: string;
}

declare namespace YarnAudit {
  type AuditResponseType =
    | "warning"
    | "activityStart"
    | "activityTick"
    | "activityEnd"
    | "auditAdvisory"
    | "auditSummary";

  interface AuditSummary {
    type: "auditSummary";
    data: SeverityMap;
  }

  interface ActivityStart {
    type: "activityStart";
    data: {
      id: number;
    };
  }

  interface ActivityTick {
    type: "activityTick";
    data: {
      id: number;
      name: `${string}@${number}.${number}.${string}`;
    };
  }

  // Start audit advisory

  interface AuditAdvisoryResponse {
    resolution: Resolution;
    advisory: Advisory;
  }

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
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
  }

  interface Cvss {
    score: number;
    vectorString: string | null;
  }

  interface Finding {
    version: string;
    paths: string[];
  }

  interface Resolution {
    id: number;
    path: string;
    dev: boolean;
    bundled: boolean;
    optional: boolean;
  }

  interface AuditAdvisory {
    type: "auditAdvisory";
    data: AuditAdvisoryResponse;
  }

  interface ActivityEnd {
    type: "activityEnd";
    data: {
      id: number;
    };
  }

  interface NoLicenseFieldWarning<P extends string = string> {
    type: "warning";
    data: `${P}: No license field`;
  }

  type WarningResponse = NoLicenseFieldWarning;

  interface NoLockfileFound {
    type: "info";
    data: "No lockfile found.";
  }

  interface BugInfo {
    type: "info";
    data: `If you think this is a bug, please open a bug report with the information provided in ${string}`;
  }

  interface MoreInfo {
    type: "info";
    data: "Visit \u001b[1mhttps://yarnpkg.com/en/docs/cli/audit\u001b[22m for documentation about this command.";
  }

  type InfoResponse = NoLockfileFound | MoreInfo | BugInfo | MoreInfo;

  // No internet connection
  interface ENOTFOUNDError {
    type: "error";
    data: `An unexpected error occurred: "${string}: getaddrinfo ENOTFOUND ${string}".`;
  }

  type ErrorResponse = ENOTFOUNDError;

  type AuditResponse =
    | InfoResponse
    | WarningResponse
    | ErrorResponse
    | AuditSummary
    | ActivityEnd
    | ActivityTick;
}

declare namespace NPMAuditReportV1 {
  interface AuditResponse {
    actions: Action[];
    advisories: AdvisoryMap;
    muted: any[];
    metadata: AuditMetadata;
    runId: string;
  }

  interface AuditMetadata {
    vulnerabilities: SeverityMap;
    dependencies: number;
    devDependencies: number;
    optionalDependencies: number;
    totalDependencies: number;
  }

  interface AdvisoryMap extends Record<GitHubAdvisoryId, Advisory> {}

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
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
  }

  interface Cvss {
    score: number;
    vectorString: string | null;
  }

  interface Finding {
    version: string;
    paths: string[];
  }

  interface Action {
    isMajor: boolean;
    action: string;
    resolves: Resolve[];
    module: string;
    target: string;
  }

  interface Resolve {
    id: number;
    path: string;
    dev: boolean;
    optional: boolean;
    bundled: boolean;
  }
}

declare namespace NPMAuditReportV2 {
  interface AuditResponse {
    auditReportVersion: 2;
    vulnerabilities: Vulnerabilities;
    metadata: Metadata;
  }

  interface Metadata {
    vulnerabilities: VulnerabilityMetadata;
    dependencies: Dependencies;
  }

  interface VulnerabilityMetadata extends Record<Severity, number> {}

  interface Dependencies {
    prod: number;
    dev: number;
    optional: number;
    peer: number;
    peerOptional: number;
    total: number;
  }

  interface Vulnerabilities extends Record<string, Advisory> {}

  interface Advisory {
    name: string;
    severity: Severity;
    isDirect: boolean;
    via: Via[];
    effects: string[];
    range: string;
    nodes: string[];
    fixAvailable: FixAvailable;
  }

  interface FixAvailable {
    name: string;
    version: string;
    isSemVerMajor: boolean;
  }

  interface Via<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    source: number;
    name: string;
    dependency: string;
    title: string;
    url: `https://github.com/advisories/${ID}`;
    severity: Severity;
    range: string;
  }

  // Error handling

  interface ENOLOCKError {
    error: {
      code: "ENOLOCK";
      summary: "This command requires an existing lockfile.";
      detail: "Try creating one first with: npm i --package-lock-only\nOriginal error: loadVirtual requires existing shrinkwrap file";
    };
  }
}
