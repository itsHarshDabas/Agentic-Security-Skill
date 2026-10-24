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
| Container/IaC | Trivy | not installed | — | Planned (Phase 6); Docker/Compose/Actions covered by Semgrep rules for now |
| DAST | OWASP ZAP | not installed | — | Planned (Phase 5) |

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
| 4 | Verification: re-scan, diff findings, regression detection | AC 10,11 | Planned |
| 5 | DAST/API testing against approved local targets (ZAP), rate limits | Scope enforcement tests on URLs | Planned |
| 6 | More ecosystems, Trivy, fuzzing, history | per adapter | Planned |

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
