export type Severity = "info" | "low" | "moderate" | "high" | "critical";

export interface SeverityMap extends Readonly<Record<Severity, number>> {}

export type GitHubAdvisoryId = `GHSA-${string}-${string}-${string}`;

export type CVE = `CVE-${number}-${number}`;

export type CWE = `CWE-${number}`;

// This is a simple approximation.
export type ISO8601Date =
  `${number}-${number}-${number}T${number}:${number}:${number}.${number}Z`;

// This isn't exactly correct, as `1.0.` works.
export type Semver = `${number}.${number}.${number | string}`;

export interface FoundBy {
  readonly link: string;
  readonly name: string;
  readonly email: string;
}

export interface ReportedBy {
  readonly link: string;
  readonly name: string;
  readonly email: string;
}

export interface Metadata {
  readonly module_type: string;
  readonly exploitability: number;
  readonly affected_components: string;
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
    readonly type: "auditSummary";
    readonly data: SeverityMap;
  }

  interface ActivityStart {
    readonly type: "activityStart";
    readonly data: {
      readonly id: number;
    };
  }

  interface ActivityTick {
    readonly type: "activityTick";
    readonly data: {
      readonly id: number;
      readonly name: `${string}@${number}.${number}.${string}`;
    };
  }

  // Start audit advisory

  interface AuditAdvisoryResponse {
    readonly resolution: Resolution;
    readonly advisory: Advisory;
  }

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    readonly findings: Finding[];
    readonly metadata: Metadata | null;
    readonly vulnerable_versions: string;
    readonly module_name: string;
    readonly severity: Severity;
    readonly github_advisory_id: ID;
    readonly cves: CVE[];
    readonly access: string;
    readonly patched_versions: string;
    readonly cvss: Cvss;
    readonly updated: ISO8601Date;
    readonly recommendation: string;
    readonly cwe: CWE[];
    readonly found_by: FoundBy | null;
    readonly deleted: ISO8601Date | null;
    readonly id: number;
    readonly references: string;
    readonly created: ISO8601Date;
    readonly reported_by: ReportedBy | null;
    readonly title: string;
    readonly npm_advisory_id: null;
    readonly overview: string;
    readonly url: `https://github.com/advisories/${ID}`;
  }

  interface Cvss {
    readonly score: number;
    readonly vectorString: string | null;
  }

  interface Finding {
    readonly version: string;
    readonly paths: string[];
  }

  interface Resolution {
    readonly id: number;
    readonly path: string;
    readonly dev: boolean;
    readonly bundled: boolean;
    readonly optional: boolean;
  }

  interface AuditAdvisory {
    readonly type: "auditAdvisory";
    readonly data: AuditAdvisoryResponse;
  }

  interface ActivityEnd {
    readonly type: "activityEnd";
    readonly data: {
      readonly id: number;
    };
  }

  interface NoLicenseFieldWarning<P extends string = string> {
    readonly type: "warning";
    readonly data: `${P}: No license field`;
  }

  type WarningResponse = NoLicenseFieldWarning;

  interface NoLockfileFound {
    readonly type: "info";
    readonly data: "No lockfile found.";
  }

  interface BugInfo {
    readonly type: "info";
    readonly data: `If you think this is a bug, please open a bug report with the information provided in ${string}`;
  }

  interface MoreInfo {
    readonly type: "info";
    readonly data: "Visit \u001b[1mhttps://yarnpkg.com/en/docs/cli/audit\u001b[22m for documentation about this command.";
  }

  type InfoResponse = NoLockfileFound | MoreInfo | BugInfo | MoreInfo;

  // No internet connection
  interface ENOTFOUNDError {
    readonly type: "error";
    readonly data: `An unexpected error occurred: "${string}: getaddrinfo ENOTFOUND ${string}".`;
  }

  type ErrorResponse = ENOTFOUNDError;

  type AuditResponse =
    | AuditAdvisory
    | InfoResponse
    | WarningResponse
    | ErrorResponse
    | AuditSummary
    | ActivityEnd
    | ActivityTick;
}

declare namespace NPMAuditReportV1 {
  interface Audit {
    readonly actions: Action[];
    readonly advisories: AdvisoryMap;
    readonly muted: any[];
    readonly metadata: AuditMetadata;
    readonly runId: string;
  }

  interface AuditMetadata {
    readonly vulnerabilities: SeverityMap;
    readonly dependencies: number;
    readonly devDependencies: number;
    readonly optionalDependencies: number;
    readonly totalDependencies: number;
  }

  interface AdvisoryMap extends Readonly<Record<GitHubAdvisoryId, Advisory>> {}

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    readonly findings: Finding[];
    readonly metadata: Metadata | null;
    readonly vulnerable_versions: string;
    readonly module_name: string;
    readonly severity: Severity;
    readonly github_advisory_id: ID;
    readonly cves: CVE[];
    readonly access: string;
    readonly patched_versions: string;
    readonly cvss: Cvss;
    readonly updated: ISO8601Date;
    readonly recommendation: string;
    readonly cwe: CWE[];
    readonly found_by: FoundBy | null;
    readonly deleted: ISO8601Date | null;
    readonly id: number;
    readonly references: string;
    readonly created: ISO8601Date;
    readonly reported_by: ReportedBy | null;
    readonly title: string;
    readonly npm_advisory_id: null;
    readonly overview: string;
    readonly url: `https://github.com/advisories/${ID}`;
  }

  interface Cvss {
    readonly score: number;
    readonly vectorString: string | null;
  }

  interface Finding {
    readonly version: string;
    readonly paths: string[];
  }

  interface Action {
    readonly isMajor?: boolean;
    readonly action: string;
    readonly resolves: Resolve[];
    readonly module: string;
    readonly target?: string;
  }

  interface Resolve {
    readonly id: number;
    readonly path: string;
    readonly dev: boolean;
    readonly optional: boolean;
    readonly bundled: boolean;
  }

  interface GenericError {
    readonly code: string;
    readonly summary: string;
    readonly detail: string;
  }

  interface ErrorResponse {
    readonly error: GenericError;
  }

  type AuditResponse = Audit | ErrorResponse;
}

/**
 * Yarn Berry's audit seems to be identical in structure to NPM's v6 audit format.
 */
declare namespace YarnBerryAuditReport {
  interface Audit {
    readonly actions: Action[];
    readonly advisories: AdvisoryMap;
    readonly muted: any[];
    readonly metadata: AuditMetadata;
    readonly runId: string;
  }

  interface AuditMetadata {
    readonly vulnerabilities: SeverityMap;
    readonly dependencies: number;
    readonly devDependencies: number;
    readonly optionalDependencies: number;
    readonly totalDependencies: number;
  }

  interface AdvisoryMap extends Readonly<Record<GitHubAdvisoryId, Advisory>> {}

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    readonly findings: Finding[];
    readonly metadata: Metadata | null;
    readonly vulnerable_versions: string;
    readonly module_name: string;
    readonly severity: Severity;
    readonly github_advisory_id: ID;
    readonly cves: CVE[];
    readonly access: string;
    readonly patched_versions: string;
    readonly cvss: Cvss;
    readonly updated: ISO8601Date;
    readonly recommendation: string;
    readonly cwe: CWE[];
    readonly found_by: FoundBy | null;
    readonly deleted: ISO8601Date | null;
    readonly id: number;
    readonly references: string;
    readonly created: ISO8601Date;
    readonly reported_by: ReportedBy | null;
    readonly title: string;
    readonly npm_advisory_id: null;
    readonly overview: string;
    readonly url: `https://github.com/advisories/${ID}`;
  }

  interface Cvss {
    readonly score: number;
    readonly vectorString: string | null;
  }

  interface Finding {
    readonly version: string;
    readonly paths: string[];
  }

  interface Action {
    readonly isMajor?: boolean;
    readonly action: string;
    readonly resolves: Resolve[];
    readonly module: string;
    readonly target?: string;
  }

  interface Resolve {
    readonly id: number;
    readonly path: string;
    readonly dev: boolean;
    readonly optional: boolean;
    readonly bundled: boolean;
  }

  interface GenericError {
    readonly code: string;
    readonly summary: string;
    readonly detail: string;
  }

  interface ErrorResponse {
    readonly error: GenericError;
  }

  type AuditResponse = Audit | ErrorResponse;
}

declare namespace NPMAuditReportV2 {
  interface Audit {
    readonly auditReportVersion: 2;
    readonly vulnerabilities: Vulnerabilities;
    readonly metadata: Metadata;
  }

  interface Metadata {
    readonly vulnerabilities: VulnerabilityMetadata;
    readonly dependencies: Dependencies;
  }

  interface VulnerabilityMetadata extends Record<Severity, number> {}

  interface Dependencies {
    readonly prod: number;
    readonly dev: number;
    readonly optional: number;
    readonly peer: number;
    readonly peerOptional: number;
    readonly total: number;
  }

  interface Vulnerabilities extends Readonly<Record<string, Advisory>> {}

  interface Advisory {
    readonly name: string;
    readonly severity: Severity;
    readonly isDirect: boolean;
    readonly via: Via[] | string[];
    readonly effects: string[];
    readonly range: string;
    readonly nodes: string[];
    readonly fixAvailable: FixAvailable | false;
  }

  interface FixAvailable {
    readonly name: string;
    readonly version: string;
    readonly isSemVerMajor: boolean;
  }

  interface Via<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    readonly source: number;
    readonly name: string;
    readonly dependency: string;
    readonly title: string;
    readonly url: `https://github.com/advisories/${ID}`;
    readonly severity: Severity;
    readonly range: string;
  }

  // Error handling

  interface ECONNREFUSEDMessageResponse {
    readonly message: `request to ${string} failed, reason: connect ECONNREFUSED ${string}`
  }

  interface GenericMessageResponse {
    readonly message: string;
  }

  type MessageResponse = ECONNREFUSEDMessageResponse | GenericMessageResponse;

  interface ENOLOCKError {
    readonly code: "ENOLOCK";
    readonly summary: "This command requires an existing lockfile.";
    readonly detail: "Try creating one first with: npm i --package-lock-only\nOriginal error: loadVirtual requires existing shrinkwrap file";
  }

  interface GenericError {
    readonly code: string;
    readonly summary: string;
    readonly detail: string;
  }

  interface ErrorResponse {
    readonly error: ENOLOCKError | GenericError;
  }

  type AuditResponse = Audit | ErrorResponse | MessageResponse;
}

declare namespace PNPMAuditReport {
  interface Audit {
    readonly actions: Action[];
    readonly advisories: AdvisoryMap;
    readonly muted: any[];
    readonly metadata: AuditMetadata;
  }

  interface AuditMetadata {
    readonly vulnerabilities: SeverityMap;
    readonly dependencies: number;
    readonly devDependencies: number;
    readonly optionalDependencies: number;
    readonly totalDependencies: number;
  }

  interface AdvisoryMap extends Readonly<Record<GitHubAdvisoryId, Advisory>> {}

  interface Advisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
    readonly findings: Finding[];
    readonly metadata: Metadata | null;
    readonly vulnerable_versions: string;
    readonly module_name: string;
    readonly severity: Severity;
    readonly github_advisory_id: ID;
    readonly cves: CVE[];
    readonly access: string;
    readonly patched_versions: string;
    readonly cvss: Cvss;
    readonly updated: ISO8601Date;
    readonly recommendation: string;
    readonly cwe: CWE[];
    readonly found_by: FoundBy | null;
    readonly deleted: ISO8601Date | null;
    readonly id: number;
    readonly references: string;
    readonly created: ISO8601Date;
    readonly reported_by: ReportedBy | null;
    readonly title: string;
    readonly npm_advisory_id: null;
    readonly overview: string;
    readonly url: `https://github.com/advisories/${ID}`;
  }

  interface Cvss {
    readonly score: number;
    readonly vectorString: string | null;
  }

  interface Finding {
    readonly version: string;
    readonly paths: string[];
  }

  interface Action {
    readonly action: string;
    readonly resolves: Resolve[];
    readonly module: string;
  }

  interface Resolve {
    readonly id: number;
    readonly path: string;
    readonly dev: boolean;
    readonly optional: boolean;
    readonly bundled: boolean;
  }

  interface GenericError {
    readonly code: string;
    readonly summary: string;
    readonly detail: string;
  }

  interface ErrorResponse {
    readonly error: GenericError;
  }

  type AuditResponse = Audit | ErrorResponse;
}
