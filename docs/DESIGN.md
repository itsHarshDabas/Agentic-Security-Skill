# Design: Agentic Security Skill (Phase 0)

Status legend used throughout this repo: **Designed**, **Implemented**, **Tested**, **Verified**, **Planned**, **Blocked**.

## 1. Platform decision

| Question | Decision | Evidence |
|---|---|---|
| Agent platform | Claude Code | Target environment for this project; docs at code.claude.com/docs/en/skills (fetched 2026-10-24) |
| Skill format | Agent Skills `SKILL.md` (YAML frontmatter + Markdown), packaged as a Claude Code plugin | Skills docs + plugins reference (`.claude-plugin/plugin.json`, default `skills/` scan) |
| Frontmatter | Only the six portable fields (`name`, `description`, `license`, `compatibility`, `metadata`, `allowed-tools`) | Docs: other fields fail validation on claude.ai upload / Skills API |
| Execution model | The model follows `SKILL.md`; all deterministic work runs through one CLI, `scripts/secaudit`, located via `${CLAUDE_SKILL_DIR}` | Docs: `${CLAUDE_SKILL_DIR}` resolves for personal, project and plugin installs |
| Engine language | Python 3.10+, standard library only | Python is present wherever Semgrep/Bandit are; no install step for the engine itself |

The engine lives inside the skill directory (`skills/security-audit/lib/secaudit`) so a copied skill folder keeps working without the rest of the repo. Nothing in the engine depends on Claude: it is a normal CLI that any agent or a human can run.

## 2. Architecture

```
SKILL.md (agent instructions: workflow, triage, honesty rules)
   │  invokes
   ▼
scripts/secaudit  ──►  secaudit.cli
                         ├─ scope.py        scope manifest, permission gate (enforced in code)
                         ├─ paths.py        path validation, symlink/escape checks
                         ├─ safe_exec.py    argv-only subprocess, timeout, output cap, env scrub, rlimits
                         ├─ discovery.py    read-only inventory (languages, frameworks, manifests, routes, risky files)
                         ├─ planner.py      tool selection + test plan with skip reasons
                         ├─ adapters/       semgrep, bandit, gitleaks, osv-scanner, pip-audit, npm-audit
                         ├─ normalize.py    common finding schema, stable IDs, cross-tool merge
                         ├─ evidence.py     run dir, raw outputs, sha256 manifest
                         ├─ redact.py       secret redaction for reports
                         ├─ triage.py       merges agent triage/contextual findings (validated JSON)
                         └─ report.py       report.json + report.md
```

Pipeline (sequential by design; no parallel agents):
`scope → discover → plan → run adapters → normalize/merge → (agent triage) → report`

Each stage writes JSON into the run directory, so any stage can be re-run or inspected.

| Module | Input | Output | Failure states |
|---|---|---|---|
| scope | `scope.json` or defaults | `Scope` object | invalid manifest → abort before any tool runs |
| discovery | target root | `inventory.json` | unreadable files are listed, not fatal |
| planner | inventory, scope, tool availability | `plan.json` (every check with status + reason) | none; unknowns become `SKIPPED_*` |
| adapter | target, scope, run dir | raw output file + `CheckResult` | `UNAVAILABLE`, `SKIPPED_NOT_PERMITTED`, `TIMED_OUT`, `FAILED`, `PARTIAL` |
| normalize | adapter results | `findings.json` | malformed tool output → check marked `FAILED`, others continue |
| triage | `findings.json`, `triage.json` | updated findings | schema error → triage rejected, report still produced |
| report | everything above | `report.json`, `report.md` | none |

## 3. Threat model of the auditor itself

Assets: the operator's machine, credentials in the environment, the target's source, integrity of the report.

| Threat | Control (where enforced) |
|---|---|
| Prompt injection in repo files, tool output, package metadata | SKILL.md treats all of it as data; scope can only be widened by the operator's manifest, never by repo content (`scope.py`). Report renders findings as data. |
| Malicious repo scripts | Engine never runs project scripts, build commands, or package installs. `npm audit --package-lock-only` runs in a temp copy holding only `package.json`/lockfile; `pip-audit` uses `--no-deps --disable-pip` (no resolver, no setup.py). |
| Shell injection | `safe_exec.run()` accepts argv lists only, `shell=False`, rejects NUL bytes. |
| Path traversal / symlink escape | `paths.py` resolves every path and refuses anything outside the scope roots; discovery does not follow symlinks. |
| Tool config in target suppressing results | Bandit `--ignore-nosec`, Semgrep `--disable-nosem`, Gitleaks `--ignore-gitleaks-allow`; target-supplied tool configs (`.gitleaks.toml`, `.semgrepignore`, `.bandit`) are listed in the report as a suppression risk. |
| Unauthorized network | Network-using adapters declare it; the gate refuses them unless `permissions.network` is true. Semgrep runs with `--metrics=off` and local rules only. |
| Secret leakage | Gitleaks `--redact`; `redact.py` masks secret-shaped strings in every rendered report; child env is scrubbed to an allowlist (no tokens passed to tools). |
| Resource exhaustion | Per-tool timeout, stdout/stderr byte caps, `RLIMIT_CPU`/`RLIMIT_FSIZE`, file-count and file-size caps in discovery. |
| Forged/corrupted results | Raw outputs stored unmodified with sha256 in `evidence/manifest.json`; parse errors mark the check `FAILED` instead of producing empty "clean" results. |
| Writing into the target | Read-only default. Report dir must be outside the target unless `permissions.write_reports_to_target` is true. Phase 1 never edits target files. |
| Incorrect scope expansion | Only paths under `scope.roots` are scanned; `exclude` globs applied before tools run (passed as tool excludes). |

## 4. Initial stack and tools

| Category | Tool | Version installed here | Network | Status |
|---|---|---|---|---|
| SAST (multi-lang) | Semgrep CE + bundled rule pack | 1.182.1 | no (local rules, metrics off) | Implemented |
| SAST (Python) | Bandit | 1.9.4 | no | Implemented |
| Secrets | Gitleaks | 8.30.1 (built via proxy.golang.org) | no | Implemented |
| SCA (all ecosystems) | OSV-Scanner | 2.7.0 | yes (api.osv.dev, deps.dev) | Implemented; **Blocked** in this sandbox (egress denied) |
| SCA (Python) | pip-audit | 2.10.1 | yes (pypi.org) | Implemented |
| SCA (Node) | npm audit | npm 10.9.4 | yes (registry.npmjs.org) | Implemented |
| IaC / pipelines | Checkov | 3.3.30 | no (`--skip-download`, no API key) | Implemented |
| Secrets (history) | Gitleaks `git` mode | 8.30.1 | no | Implemented |
| Container images | Trivy | not installed | — | Not implemented (needs a container runtime) |
| DAST (passive) | built-in `dast.py` (stdlib http.client) | — | local target only | Implemented |
| DAST baseline | OWASP ZAP `zap-baseline.py` | not installed (no Docker here) | local target | Implemented; tested with a fake binary only |

The Semgrep public registry (semgrep.dev) is not reachable from this sandbox, and the community `semgrep-rules` repo has a license that restricts redistribution, so the skill ships its own small rule pack and accepts extra `--semgrep-config` paths the operator supplies.

## 5. Finding model

See `skills/security-audit/references/finding-schema.md`. Key points:
- Stable ID = hash of (rule family, file path, normalized source line) for code; (ecosystem, package, version, advisory) for dependencies. Line numbers are excluded so edits above a finding don't change its ID.
- `validation` ∈ `confirmed | probable | unverified | informational | false_positive`. Scanner output starts as `unverified`; only triage with a written rationale can change it.
- `remediation_status` (Phase 3/4): `FIXED_VERIFIED | PARTIALLY_MITIGATED | FIX_APPLIED_UNVERIFIED | UNRESOLVED | BLOCKED | FALSE_POSITIVE`.

## 6. Phased plan

| Phase | Scope | Acceptance (measurable) | Status |
|---|---|---|---|
| 0 | Platform, architecture, threat model | This document | Implemented |
| 1 | Discovery, SAST, SCA, secrets, normalization, MD/JSON reports, scope gate | AC 1,2,3,4,6,7,13,14,15 on the fixture; benchmark recall reported | Implemented + tested (see README) |
| 2 | Dedup tuning, confidence, evidence snippets, risk prioritization, triage workflow, benchmark metrics | AC 5,6; precision/recall/FP rate tracked per run | Implemented + tested |
| 3 | Remediation: worktree isolation, regression tests, diff review, approval gates | AC 8,9,12 | Implemented + tested |
| 4 | Verification: re-scan, diff findings, regression detection | AC 10,11 | Implemented + tested |
| 5 | Passive DAST against approved local targets, rate limits, optional ZAP baseline | Scope enforcement tests on URLs | Implemented + tested |
| 6 | IaC (checkov), git-history secrets, run trends | per adapter tests | Implemented + tested; container images and fuzzing not implemented |

## 7. Risks and missing capabilities

1. **Egress policy.** OSV-Scanner cannot reach its API here, so Python/Node SCA rely on pip-audit/npm audit. The report marks OSV-Scanner `FAILED`/`BLOCKED`, never "no vulnerabilities".
2. **Rule coverage.** A small bundled Semgrep pack has far lower recall than the commercial/registry packs. Operators should add `--semgrep-config` packs they are licensed to use.
3. **Contextual bugs (IDOR, business logic)** are not found by scanners. Phase 1 relies on the agent's targeted review recorded through `triage.json`; this is the least deterministic part and is labeled as such in reports.
4. **pip-audit with unpinned requirements** cannot audit ranges without resolving (which would run package code); unpinned entries are reported as skipped.
5. **Tool supply chain.** Tools are installed by the operator; the engine records the version it ran but does not verify binary signatures (Planned).
6. **No sandbox around scanners.** rlimits and env scrubbing are applied, but scanners run as the operator's user. Containerized execution is Planned.

## 8. Phase 3 design notes (remediation)

- Isolation: `git worktree add` on a new `secaudit/fix-<run>` branch from HEAD, plus a detached `base` worktree for red/green checks; both live in the run directory outside the repository. The operator's working tree, index and HEAD are not touched; a snapshot of their uncommitted changes (status + content hashes) is compared after every step.
- Git hardening (`safe_git.py`): `-c` overrides for fsmonitor, hooks, pager, editors, ssh, credential helper, protocol.allow=never, external diff; no system/global config; repositories whose local config sets filter/textconv/merge drivers, include paths or similar are refused.
- Checkpoints are tree objects (`git add -A && git write-tree` in the fix worktree), so per-finding diffs are exact and no commits are created until `fix commit`.
- Gate (`patchgate.py`) runs on every recorded diff; violations roll the worktree back to the last accepted tree.
- Red/green: base worktree is reset to the pre-fix tree, the fix's test files are overlaid, the command must fail; the same command must pass in the fix worktree.
- Residual risk: running project tests executes repository code with the operator's privileges (rlimits, scrubbed env, no network proxy, but no container). That is why it needs a separate `execute_project_code` permission.

## 9. Phase 4 design notes (verification)

- `verify` re-runs the scanners that completed in the original scan against the fix worktree (same scope, same excludes, permissions copied from the verified manifest) with the original report as baseline.
- A finding counts as still present if its stable ID reappears, or if the same file has a hit from the same tool rule in the same CWE family (conservative: a reformatted but unfixed line is not "gone").
- Status assignment is a pure function of recorded evidence (`_status`), unit-tested separately; new findings in files a fix touched downgrade FIXED_VERIFIED to FIX_APPLIED_UNVERIFIED and are reported as regressions.
- Optional suite command runs on the fixed tree; its result is reported separately from per-finding status.

## 10. Phase 5 design notes (dynamic checks)

- Deliberately passive. The skill does not ship injection, authentication-bypass or fuzzing payloads; those need a separately authorized engagement and purpose-built tools.
- Authorization (`dast.authorize`): `dynamic_testing` permission; exact (scheme, host, port) match against `targets.urls`; no credentials in URLs; the host is resolved once and must be loopback/private unless `external_services` is granted; link-local, multicast, reserved and unspecified addresses are always refused. Requests are sent to the pinned IP with the original `Host` header (no DNS rebinding). `http.client` ignores proxy environment variables.
- Traffic: GET only, plus one GET with `Origin: https://secaudit-origin-check.invalid` for CORS. Paths are the given URL and parameterless GET routes from discovery; `standard` intensity adds 11 well-known paths. Redirects are never followed. Budget (default 50, max 500 requests), minimum interval (default 0.2 s, min 0.05 s), 10 s timeout, 512 KB body cap.
- Evidence: the request log (method, path, status, headers, timing; bodies are not stored) is saved to the run's evidence with sha256. Findings are `kind: dynamic`, `validation: confirmed` because they are direct observations of the response.
- The scan records a `dast` check as `PENDING`; `secaudit dast` replaces it with `dast-http` (and `dast-zap`) results and the report's limitations change accordingly.
- Residual risk: even GET requests can have side effects in badly designed applications; that is why only discovered parameterless GET routes are requested, and why the target must be a local/staging instance the operator names.

## 11. Phase 6 design notes

- **Checkov.** Checkov loads `.checkov.yaml` from the scanned directory even when `--config-file` is passed (verified with 3.3.30), and that file can skip checks or point `external-checks-dir` at Python in the repository, which checkov would import. So checkov never sees the target: the adapter copies only regular, IaC-shaped files (`*.tf`, `*.y(a)ml`, `*.json`, `Dockerfile*`, …, max 2 MB each, no symlinks, scope excludes applied, `.checkov*` dropped) into a temp mirror and scans that. `--quiet` is not used because it hides skipped checks; inline `checkov:skip` suppressions are reported as findings with the suppression noted. Findings are `kind: iac` (resource-level; not merged with line-level findings). Severities come from an engine-side map (`severity_source: secaudit-map`).
- **Gitleaks config.** Without `--config`, gitleaks loads `.gitleaks.toml` from the scan root; a target could allowlist its own secrets (verified: an allowlist of `.*` hid a real match). Both gitleaks checks now pass a temp config containing only `[extend] useDefault = true`. This also hardens the Phase 1 working-tree scan.
- **History secrets.** `gitleaks git` runs `git log -p` itself. The adapter refuses repositories whose local config sets code-executing keys (`safe_git.require_safe`, status `BLOCKED`), and passes `safe_git.OVERRIDES` to every git child through `GIT_CONFIG_COUNT/KEY/VALUE`, plus `--no-textconv --no-ext-diff` in the log options and `GIT_CONFIG_NOSYSTEM`/`GIT_CONFIG_GLOBAL=/dev/null`. Findings carry the commit and file, never the secret.
- **History/trends.** `secaudit history` reads existing `report.json` files only; it reports per-run counts, new and no-longer-reported IDs, checks that did not complete, and findings open since an earlier run. It warns that "no longer reported" is not a fix.
- **Not implemented:** container-image scanning (needs a runtime), fuzzing (would execute project code under generated inputs; would need its own permission and sandbox), Go/Java SAST beyond Semgrep's bundled rules.
