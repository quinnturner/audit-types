/** JSON wire formats; these declarations do not validate untrusted input. */
export type Severity = "info" | "low" | "moderate" | "high" | "critical";
export interface SeverityMap extends Readonly<Record<Severity, number>> {}
export type GitHubAdvisoryId = `GHSA-${string}-${string}-${string}`;
export type NpmAdvisoryId = `${number}`;
export type AdvisoryMapKey = NpmAdvisoryId | GitHubAdvisoryId;
export type CVE = `CVE-${number}-${number}`;
export type CWE = `CWE-${number}`;
/** Approximation retained for consumers that use this helper explicitly. */
export type ISO8601Date = `${number}-${number}-${number}T${number}:${number}:${number}.${number}Z`;
export type Semver = `${number}.${number}.${number | string}`;

export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
export interface JsonObject {
  readonly [key: string]: JsonValue;
}
export interface Cvss {
  readonly score: number;
  readonly vectorString: string | null;
}
export interface FoundBy {
  readonly name: string;
  readonly link?: string;
  readonly email?: string;
}
export interface ReportedBy extends FoundBy {}
export interface Metadata {
  readonly module_type: string;
  readonly exploitability: number;
  readonly affected_components: string;
}
export interface LegacyAuditMetadata {
  readonly vulnerabilities: SeverityMap;
  readonly dependencies: number;
  readonly devDependencies: number;
  readonly optionalDependencies: number;
  readonly totalDependencies: number;
}
export interface AuditFinding {
  readonly version: string;
  readonly paths: string[];
  readonly dev?: boolean;
  readonly optional?: boolean;
  readonly bundled?: boolean;
}
export interface AuditResolution {
  readonly id: number;
  readonly path: string;
  readonly dev: boolean;
  readonly optional: boolean;
  readonly bundled: boolean;
}
export interface AuditAction {
  readonly action: string;
  readonly module: string;
  readonly resolves: AuditResolution[];
  readonly target?: string;
  readonly isMajor?: boolean;
}
export interface AuditError {
  readonly code?: string;
  readonly summary: string;
  readonly detail: string;
}
/** Quick-audit advisories predate the registry's GitHub advisory migration. */
export interface LegacyAuditAdvisory<ID extends GitHubAdvisoryId = GitHubAdvisoryId> {
  readonly findings: AuditFinding[];
  readonly id: number;
  readonly title: string;
  readonly module_name: string;
  readonly severity: Severity;
  readonly vulnerable_versions: string;
  readonly patched_versions: string;
  readonly url: string;
  readonly github_advisory_id?: ID;
  readonly npm_advisory_id?: number | null;
  readonly cvss?: Cvss;
  readonly cwe: string | string[];
  readonly cves: string[];
  readonly metadata: Metadata | null;
  readonly access: string;
  readonly created: string;
  readonly updated: string;
  readonly deleted?: boolean | string | null;
  readonly found_by: FoundBy | null;
  readonly reported_by: ReportedBy | null;
  readonly references: string;
  readonly overview: string;
  readonly recommendation: string;
}

/** One JSON line from Yarn Classic's reporter (stdout and stderr). */
export namespace YarnAudit {
  interface Message<T extends string> {
    readonly type: T;
    readonly data: string;
  }
  interface AuditMetadata extends LegacyAuditMetadata {}
  interface Advisory<
    ID extends GitHubAdvisoryId = GitHubAdvisoryId,
  > extends LegacyAuditAdvisory<ID> {}
  interface Cvss extends SharedCvss {}
  interface Finding extends AuditFinding {}
  interface Resolution extends AuditResolution {}
  interface AuditAdvisoryResponse {
    readonly resolution: Resolution;
    readonly advisory: Advisory;
  }
  interface AuditAdvisory {
    readonly type: "auditAdvisory";
    readonly data: AuditAdvisoryResponse;
  }
  interface AuditSummary {
    readonly type: "auditSummary";
    readonly data: AuditMetadata;
  }
  interface ActivityStart {
    readonly type: "activityStart";
    readonly data: { readonly id: number };
  }
  interface ActivityEnd {
    readonly type: "activityEnd";
    readonly data: { readonly id: number };
  }
  interface ActivityTick {
    readonly type: "activityTick";
    readonly data: { readonly id: number; readonly name: string };
  }
  interface ProgressStart {
    readonly type: "progressStart";
    readonly data: { readonly id: number; readonly total: number };
  }
  interface ProgressTick {
    readonly type: "progressTick";
    readonly data: { readonly id: number; readonly current: number };
  }
  interface ProgressFinish {
    readonly type: "progressFinish";
    readonly data: { readonly id: number };
  }
  interface ActivitySetStart {
    readonly type: "activitySetStart";
    readonly data: { readonly id: number; readonly total: number; readonly workers: number };
  }
  interface ActivitySetTick {
    readonly type: "activitySetTick";
    readonly data: {
      readonly id: number;
      readonly header: string;
      readonly current: number;
      readonly worker: number;
      readonly message: string;
    };
  }
  interface ActivitySetEnd {
    readonly type: "activitySetEnd";
    readonly data: { readonly id: number };
  }
  interface Finished {
    readonly type: "finished";
    readonly data: number;
  }
  interface NoLicenseFieldWarning<P extends string = string> extends Message<"warning"> {
    readonly data: `${P}: No license field`;
  }
  interface NoLockfileFound extends Message<"info"> {
    readonly data: "No lockfile found.";
  }
  interface BugInfo extends Message<"info"> {
    readonly data: `If you think this is a bug, please open a bug report with the information provided in ${string}`;
  }
  interface MoreInfo extends Message<"info"> {
    readonly data: "Visit \u001b[1mhttps://yarnpkg.com/en/docs/cli/audit\u001b[22m for documentation about this command.";
  }
  interface ENOTFOUNDError extends Message<"error"> {
    readonly data: `An unexpected error occurred: "${string}: getaddrinfo ENOTFOUND ${string}".`;
  }
  type WarningResponse = Message<"warning">;
  type InfoResponse = Message<"info">;
  type ErrorResponse = Message<"error">;
  type AuditResponse =
    | AuditAdvisory
    | AuditSummary
    | InfoResponse
    | WarningResponse
    | ErrorResponse
    | Message<"verbose" | "log" | "success" | "command">
    | ActivityStart
    | ActivityEnd
    | ActivityTick
    | ActivitySetStart
    | ActivitySetTick
    | ActivitySetEnd
    | ProgressStart
    | ProgressTick
    | ProgressFinish
    | Finished;
  type AuditResponseType = AuditResponse["type"];
}

// Private alias avoids shadowing the shared interface inside namespaces.
type SharedCvss = Cvss;

export namespace NPMAuditReportV1 {
  interface Audit {
    readonly actions: Action[];
    readonly advisories: AdvisoryMap;
    readonly muted: unknown[];
    readonly metadata: AuditMetadata;
    readonly runId: string;
  }
  interface AuditMetadata extends LegacyAuditMetadata {}
  interface AdvisoryMap extends Readonly<Record<string, Advisory>> {}
  interface Advisory<
    ID extends GitHubAdvisoryId = GitHubAdvisoryId,
  > extends LegacyAuditAdvisory<ID> {}
  interface Cvss extends SharedCvss {}
  interface Finding extends AuditFinding {}
  interface Action extends AuditAction {}
  interface Resolve extends AuditResolution {}
  interface GenericError extends AuditError {}
  interface ErrorResponse {
    readonly error: GenericError;
  }
  type AuditResponse = Audit | ErrorResponse;
}

/** Yarn 2/3 forwards the quick-audit registry response. */
export namespace Yarn2And3AuditReport {
  interface Audit extends Omit<NPMAuditReportV1.Audit, "runId"> {
    readonly runId?: string;
  }
  interface AuditMetadata extends LegacyAuditMetadata {}
  interface AdvisoryMap extends Readonly<Record<string, Advisory>> {}
  interface Advisory<
    ID extends GitHubAdvisoryId = GitHubAdvisoryId,
  > extends LegacyAuditAdvisory<ID> {}
  interface Cvss extends SharedCvss {}
  interface Finding extends AuditFinding {}
  interface Action extends AuditAction {}
  interface Resolve extends AuditResolution {}
  interface GenericError extends AuditError {}
  interface ErrorResponse {
    readonly error: GenericError;
  }
  type AuditResponse = Audit | ErrorResponse;
}

/** Yarn 4+ emits one tree entry per line, or reporter diagnostics. A clean audit may emit no lines. */
export namespace YarnNpmAuditReport {
  interface AuditAdvisory<A extends string = string> {
    readonly value: A;
    readonly children: {
      readonly ID?: number | string;
      readonly Issue: string;
      readonly URL?: string;
      readonly Severity: Severity;
      readonly "Vulnerable Versions": string;
      readonly "Tree Versions": string[];
      readonly Dependents: `${string}@${string}`[];
    };
  }
  interface Message {
    readonly type: "info" | "warning" | "error";
    readonly name: number | null;
    readonly displayName: string;
    readonly indent: string;
    readonly data: string;
  }
  type AuditResponse<A extends string = string> = AuditAdvisory<A> | Message;
}

export namespace NPMAuditReportV2 {
  interface Audit {
    readonly auditReportVersion: 2;
    readonly vulnerabilities: Vulnerabilities;
    readonly metadata: Metadata;
  }
  interface Metadata {
    readonly vulnerabilities: VulnerabilityMetadata;
    readonly dependencies: Dependencies;
  }
  interface VulnerabilityMetadata extends SeverityMap {
    readonly total: number;
  }
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
    readonly via: (Via | string)[];
    readonly effects: string[];
    readonly range: string;
    readonly nodes: string[];
    readonly fixAvailable: boolean | FixAvailable;
    readonly fixBlockedByReleaseAge?: boolean;
  }
  interface FixAvailable {
    readonly name: string;
    readonly version: string;
    readonly isSemVerMajor: boolean;
  }
  interface ViaCvss extends SharedCvss {}
  interface Via {
    readonly source: number;
    readonly name: string;
    readonly dependency: string;
    readonly title: string;
    readonly url: string;
    readonly severity: Severity;
    readonly range: string;
    readonly cwe?: string[];
    readonly cvss?: ViaCvss;
  }
  interface ECONNREFUSEDMessageResponse {
    readonly message: `request to ${string} failed, reason: connect ECONNREFUSED ${string}`;
  }
  interface GenericMessageResponse {
    readonly message: string;
  }
  type MessageResponse = ECONNREFUSEDMessageResponse | GenericMessageResponse;
  interface ENOLOCKError extends AuditError {
    readonly code: "ENOLOCK";
    readonly summary: "This command requires an existing lockfile.";
    readonly detail: "Try creating one first with: npm i --package-lock-only\nOriginal error: loadVirtual requires existing shrinkwrap file";
  }
  interface GenericError extends AuditError {}
  interface ErrorResponse {
    readonly error: ENOLOCKError | GenericError;
  }
  type AuditResponse = Audit | ErrorResponse | MessageResponse;
}

export namespace PNPMAuditReport {
  interface Audit {
    readonly actions?: Action[];
    readonly advisories: AdvisoryMap;
    readonly muted?: unknown[];
    readonly metadata: AuditMetadata;
  }
  interface AuditMetadata extends LegacyAuditMetadata {}
  interface AdvisoryMap extends Readonly<Record<string, Advisory>> {}
  /** Common view of legacy quick-audit and modern bulk-derived pnpm advisories. */
  interface Advisory<ID extends string = string> extends Omit<
    Partial<LegacyAuditAdvisory>,
    "github_advisory_id" | "patched_versions"
  > {
    readonly findings: Finding[];
    readonly id: number;
    readonly title: string;
    readonly module_name: string;
    readonly severity: Severity;
    readonly vulnerable_versions: string;
    readonly url: string;
    readonly github_advisory_id?: ID;
    readonly patched_versions?: string | null;
    readonly patched_versions_unpublished?: boolean;
    readonly cwe: string | string[];
  }
  interface LegacyAdvisory<
    ID extends GitHubAdvisoryId = GitHubAdvisoryId,
  > extends LegacyAuditAdvisory<ID> {}
  /** pnpm 11/12 synthesize these fields from bulk advisories and the lockfile. */
  interface CurrentAdvisory extends Advisory {
    readonly findings: CurrentFinding[];
    readonly github_advisory_id: string;
    readonly cwe: string;
  }
  interface CurrentAudit extends Audit {
    readonly advisories: Readonly<Record<string, CurrentAdvisory>>;
  }
  interface Cvss extends SharedCvss {}
  interface Finding extends AuditFinding {}
  interface CurrentFinding extends Finding {
    readonly dev: boolean;
    readonly optional: boolean;
    readonly bundled: boolean;
  }
  interface Action extends AuditAction {}
  interface Resolve extends AuditResolution {}
  interface GenericError extends AuditError {}
  interface PnpmError {
    readonly code: string;
    readonly message: string;
  }
  interface ErrorResponse {
    readonly error: GenericError | PnpmError;
  }
  type AuditResponse = Audit | ErrorResponse;
}

/** Registry /-/npm/v1/security/advisories/bulk response, before dependency-tree processing. */
export namespace NPMAuditBulkReport {
  interface Advisory {
    readonly id: number;
    readonly name?: string;
    readonly url: string;
    readonly title: string;
    readonly severity: Severity;
    readonly vulnerable_versions: string;
    readonly cwe?: string | string[];
    readonly cvss?: Cvss;
  }
  type AuditResponse = Readonly<Record<string, Advisory[]>>;
}

/** bun audit --json prints the unfiltered bulk response; errors may produce no JSON. */
export namespace BunAuditReport {
  interface Advisory extends NPMAuditBulkReport.Advisory {}
  type Audit = Readonly<Record<string, Advisory[]>>;
  type AuditResponse = Audit;
}

/** npm audit signatures --json (distinct from vulnerability reports). */
export namespace NPMAuditSignaturesReport {
  interface Package {
    readonly name: string;
    readonly version: string;
    readonly location: string;
    readonly registry: string;
  }
  interface MissingSignature extends Package {
    readonly integrity?: string;
    readonly resolved?: string;
  }
  interface InvalidSignature extends MissingSignature {
    readonly code: "EINTEGRITYSIGNATURE" | "EATTESTATIONVERIFY";
    readonly message: string;
    readonly type: "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies";
    readonly keyid?: string;
    readonly signature?: string;
    readonly predicateType?: string;
  }
  /** Registry metadata is extensible; bundle contents follow the external Sigstore schema. */
  interface Attestations extends JsonObject {
    readonly url: string;
  }
  interface AttestationBundle {
    readonly predicateType: string;
    readonly bundle: JsonObject;
  }
  interface VerifiedPackage extends Package {
    readonly attestations: Attestations;
    readonly attestationBundles?: AttestationBundle[];
  }
  interface Audit {
    readonly invalid: InvalidSignature[];
    readonly missing: MissingSignature[];
    /** Present with --include-attestations; counts are not emitted by npm. */
    readonly verified?: VerifiedPackage[];
  }
  type AuditResponse = Audit | NPMAuditReportV2.ErrorResponse;
}

/** pnpm audit signatures --json emits counts rather than npm's attestation bundles. */
export namespace PNPMAuditSignaturesReport {
  interface SignatureIssue {
    readonly name: string;
    readonly registry: string;
    readonly version: string;
    readonly integrity?: string;
    readonly reason?: string;
    readonly resolved?: string;
  }
  interface Audit {
    readonly audited: number;
    readonly invalid: SignatureIssue[];
    readonly missing: SignatureIssue[];
    readonly verified: number;
  }
  type AuditResponse = Audit | PNPMAuditReport.ErrorResponse;
}
