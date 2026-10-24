# Report and finding schema (schema_version 1.0)

`report.json` top level: `schema_version`, `meta`, `scope`, `summary`, `inventory`, `tools`, `checks`,
`coverage_limitations`, `findings`, `triage_log`, `remediation`, `evidence_integrity`.

## Check statuses
| Status | Meaning |
|---|---|
| `COMPLETED` | Tool ran to completion and its output parsed. |
| `PARTIAL` | Ran, but part of the input was not assessed (e.g. unpinned requirements) or output was truncated. |
| `FAILED` | Non-zero exit or unparseable/unexpected output. Results, if any, are not trusted as complete. |
| `BLOCKED` | The tool could not reach its data source (network denied). |
| `TIMED_OUT` | Exceeded the per-tool timeout and was killed. |
| `UNAVAILABLE` | Tool not installed / not on `SECAUDIT_TOOL_PATH`. |
| `SKIPPED_NOT_APPLICABLE` | Nothing for the tool to analyze (e.g. no Python files). |
| `SKIPPED_NOT_PERMITTED` | Needs a permission the scope does not grant. |
| `SKIPPED_BY_OPERATOR` | Excluded with `--only`. |
| `NOT_IMPLEMENTED` | Required by the spec, not built yet. Listed so coverage is never overstated. |
| `PENDING` | Agent review not yet applied. |

## Finding fields
| Field | Notes |
|---|---|
| `id` | Stable. `SA-` code/config (rule family + path + normalized line text), `SEC-` secrets, `DEP-` dependencies (ecosystem + package + version + primary advisory). Line numbers are not part of the hash. |
| `kind` | `code`, `config`, `secret`, `dependency`, `contextual` |
| `severity` | `critical`, `high`, `medium`, `low`, `info`; `severity_source` says where it came from (`tool`, `default (...)`, `triage`, `agent review`). |
| `confidence` | `high`, `medium`, `low`. Raised one step when independent tools agree on the same line. |
| `validation` | `confirmed`, `probable`, `unverified`, `informational`, `false_positive` |
| `cwe`, `cvss` | CWE list; CVSS only when the source provides it. |
| `locations` | `path` relative to target, `start_line`, `end_line`, `snippet` (redacted; never stored for secrets). |
| `evidence` | One entry per tool/rule plus agent notes; `raw_file` points into `evidence/`. |
| `package` | Dependency findings: ecosystem, name, version, advisory_ids (incl. aliases), fixed_versions, direct. |
| `root_cause`, `impact`, `reproduction`, `remediation`, `verification` | Filled by tools where possible, otherwise by triage. |
| `remediation_status` | Phase 3/4: `FIXED_VERIFIED`, `PARTIALLY_MITIGATED`, `FIX_APPLIED_UNVERIFIED`, `UNRESOLVED`, `BLOCKED`, `FALSE_POSITIVE`. Only `FALSE_POSITIVE` is set in this release. |
| `tracking` | `new` / `recurring` when `--baseline` is used. |
| `tool_confidence` | Confidence as the tool(s) reported it, kept unchanged. |
| `confidence_score`, `confidence_factors` | Phase 2 model: tool base (high .8 / medium .55 / low .3), +.15 per extra independent tool (max +.3), −.2 in test code; triage confirmed = 1.0, false positive = 0, probable ≥ .75, informational ≤ .5. `confidence` is re-derived from the score (≥.75 high, ≥.45 medium). |
| `risk_score`, `priority`, `risk_factors` | Severity weight (10/7/4/2/0.5) × exposure (route file 1.3, entry point 1.15, build/deploy config 1.1, direct dep 1.1, transitive 0.9, test code 0.3) × validation (confirmed 1.2, probable 1.0, unverified 0.8, informational 0.3, false positive 0) × confidence × 10, capped at 100. P0 ≥ 60, P1 ≥ 35, P2 ≥ 15, else P3. |
| `code_context` | Up to ±2 lines around the first location, redacted. Never populated for secrets. |
| `in_test_code` | Path looks like test code (`tests/`, `test_*.py`, `*.test.ts`, …). |

`summary.release_blockers` lists critical/high findings that are `confirmed` or `probable`.

## Run directory
```
<run>/inventory.json     discovery output
<run>/state.json         engine state (redacted)
<run>/report.json        machine-readable report
<run>/report.md          human report
<run>/evidence/          raw tool output, byte-for-byte, mode 0600
<run>/evidence/manifest.json  sha256, argv, exit code, tool version per raw file
```
