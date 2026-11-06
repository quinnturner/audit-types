# audit-types

Dependency-free TypeScript declarations for package-manager audit JSON. This package describes wire formats; it does not parse or validate JSON at runtime.

| Command                         | Namespace                   | Output                                                                        |
| ------------------------------- | --------------------------- | ----------------------------------------------------------------------------- |
| npm 6 `audit --json`            | `NPMAuditReportV1`          | One quick-audit report                                                        |
| npm 7+ `audit --json`           | `NPMAuditReportV2`          | One processed report, `auditReportVersion: 2`                                 |
| Yarn Classic `audit --json`     | `YarnAudit`                 | Reporter NDJSON on stdout/stderr                                              |
| Yarn 2/3 `npm audit --json`     | `Yarn2And3AuditReport`      | One quick-audit report                                                        |
| Yarn 4+ `npm audit --json`      | `YarnNpmAuditReport`        | Advisory-tree NDJSON or reporter diagnostics; a clean audit may emit no lines |
| pnpm `audit --json`             | `PNPMAuditReport`           | Legacy quick-audit or modern bulk-derived report                              |
| Bun `audit --json`              | `BunAuditReport`            | Raw registry bulk-advisory response                                           |
| npm `audit signatures --json`   | `NPMAuditSignaturesReport`  | Signature issues and optional attestation records                             |
| pnpm `audit signatures --json`  | `PNPMAuditSignaturesReport` | Signature issues and verification counts                                      |
| Registry bulk-advisory endpoint | `NPMAuditBulkReport`        | Package names mapped to advisory arrays                                       |

## Usage

```ts
import type { NPMAuditReportV2 } from "audit-types";

const report = JSON.parse(stdout) as NPMAuditReportV2.AuditResponse;
if ("vulnerabilities" in report) {
  for (const advisory of Object.values(report.vulnerabilities)) {
    for (const via of advisory.via) {
      if (typeof via === "string") {
        console.log("Vulnerable dependency:", via);
      } else {
        console.log(via.title, via.cvss?.vectorString);
      }
    }
  }
}
```

`via` may mix advisory objects and package names. CWE/CVSS metadata is absent in older npm reports; a CVSS vector can also be `null`. `fixAvailable` can be `true`, `false`, or an upgrade object.

Parse Yarn NDJSON one nonempty line at a time:

```ts
import type { YarnNpmAuditReport } from "audit-types";

const lines: YarnNpmAuditReport.AuditResponse[] = stdout
  .split(/\r?\n/)
  .filter((line) => line.trim().length > 0)
  .map((line) => JSON.parse(line));

for (const line of lines) {
  if ("children" in line) {
    console.log(line.value, line.children.ID, line.children.URL);
  } else {
    console.log(line.type, line.data);
  }
}
```

Yarn 4 advisory IDs can be strings, including deprecation IDs, and URLs can be absent. `YarnNpmAuditReport.AuditAdvisory` describes just an advisory line. `AuditResponse` also includes diagnostic messages. Yarn Classic's `auditSummary.data` is the full metadata object, with counts under `data.vulnerabilities`.

`PNPMAuditReport.Advisory` exposes the common fields of old and new pnpm output. `CurrentAdvisory`/`CurrentAudit` describe pnpm 11/12, and `LegacyAdvisory` describes older quick-audit data. Modern pnpm does not provide the old CVE, CVSS, author, or timestamp fields. Its `cwe` is a string; `patched_versions` may be absent (pnpm 11) or `null` (pnpm 12), and `patched_versions_unpublished` can indicate that no fix has been published.

Bun prints the raw bulk response, including when reporting thresholds or ignored advisories affect its exit code. It does not emit npm's dependency-tree report. Successful clean bulk responses are `{}`. Errors may produce no JSON, so inspect the process result separately.

Signature audits have distinct schemas: npm's optional `verified` field is an array of attestation records enabled by `--include-attestations`; pnpm's required `verified` field is a number. Sigstore bundle bodies are represented as extensible JSON objects. Signature reports are not vulnerability reports.

Deno's audit implementation inspected for 2.9.8 emits formatted output rather than a CLI JSON report, so no Deno JSON namespace is provided. `audit fix` installation output is also outside these report types.

## Compatibility notes for 0.7

- Existing namespaces and named helper types remain available. Repeated legacy fields share definitions.
- Legacy CWE values can be strings or arrays. Historical advisory URLs and dates are strings; author email/link fields and post-migration GitHub/CVSS fields may be absent.
- Arbitrary package versions, registry messages, and map keys are represented as strings. `CVE`, `CWE`, `GitHubAdvisoryId`, `ISO8601Date`, and `Semver` remain available as opt-in helpers.
- `YarnNpmAuditReport.AuditResponse` is now a union. Narrow with `"children" in line` before accessing advisory fields.
- Some fields became optional or nullable to match real reports. Consumers must account for missing data.

## Verification and sources

Run `pnpm install --frozen-lockfile` and `pnpm test`. Tests compile real upstream fixtures, verify compatibility with upstream pnpm/Yarn declarations, and check that malformed reports are rejected. CI runs without contacting audit registries.

The reviewed implementations and versions are recorded in [SOURCES.md](SOURCES.md). Tests are development-only and are excluded from the published package.
