import { GitHubAdvisoryId, Severity } from "./shared";

export namespace NPMAuditReportV2 {
  export type AuditResponse = {
    auditReportVersion: 2;
    vulnerabilities: Vulnerabilities;
    metadata: Metadata;
  };

  export type Metadata = {
    vulnerabilities: VulnerabilityMetadata;
    dependencies: Dependencies;
  };

  export type VulnerabilityMetadata = Record<Severity, number>;

  export type Dependencies = {
    prod: number;
    dev: number;
    optional: number;
    peer: number;
    peerOptional: number;
    total: number;
  };

  export type Vulnerabilities = Record<string, Advisory>;

  export type Advisory = {
    name: string;
    severity: Severity;
    isDirect: boolean;
    via: Via[];
    effects: string[];
    range: string;
    nodes: string[];
    fixAvailable: FixAvailable;
  };

  export type FixAvailable = {
    name: string;
    version: string;
    isSemVerMajor: boolean;
  };

  export type Via<ID extends GitHubAdvisoryId = GitHubAdvisoryId> = {
    source: number;
    name: string;
    dependency: string;
    title: string;
    url: `https://github.com/advisories/${ID}`;
    severity: Severity;
    range: string;
  };

  // Error handling

  export type ENOLOCKError = {
    error: {
      code: "ENOLOCK";
      summary: "This command requires an existing lockfile.";
      detail: "Try creating one first with: npm i --package-lock-only\nOriginal error: loadVirtual requires existing shrinkwrap file";
    };
  };
}
