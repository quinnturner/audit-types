export type Severity = "info" | "low" | "moderate" | "high" | "critical";

export type SeverityMap = Record<Severity, number>;

export type GitHubAdvisoryId = `GHSA-${string}-${string}-${string}`;

export type CVE = `CVE-${number}-${number}`

export type CWE = `CWE-${number}`;

// This is a simple approximation.
export type ISO8601Date = `${number}-${number}-${number}T${number}:${number}:${number}.${number}Z`;

// This isn't exactly correct, as `1.0.` works.
export type Semver = `${number}.${number}.${number | string}`;

export type FoundBy = {
  link: string;
  name: string;
  email: string;
};

export type ReportedBy = {
  link: string;
  name: string;
  email: string;
};

export type Metadata = {
  module_type: string;
  exploitability: number;
  affected_components: string;
};
