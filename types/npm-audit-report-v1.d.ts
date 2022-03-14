import {
  CVE,
  CWE,
  FoundBy,
  GitHubAdvisoryId,
  Metadata,
  ReportedBy,
  Severity,
  ISO8601Date,
  SeverityMap,
} from "./shared";

export namespace NPMAuditReportV1 {
  export type AuditResponse = {
    actions: Action[];
    advisories: AdvisoryMap;
    muted: any[];
    metadata: AuditMetadata;
    runId: string;
  };

  export type AuditMetadata = {
    vulnerabilities: SeverityMap;
    dependencies: number;
    devDependencies: number;
    optionalDependencies: number;
    totalDependencies: number;
  };

  export type AdvisoryMap = Record<GitHubAdvisoryId, Advisory>;

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

  export type Action = {
    isMajor: boolean;
    action: string;
    resolves: Resolve[];
    module: string;
    target: string;
  };

  export type Resolve = {
    id: number;
    path: string;
    dev: boolean;
    optional: boolean;
    bundled: boolean;
  };
}
