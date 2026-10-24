# Agentic Security Skill

An agent skill that audits a repository you are authorized to assess: it runs real
security tools through a scope-enforcing engine, normalizes their output into one
finding format, guides the agent through triage and contextual review, and writes
Markdown + JSON reports that say exactly what ran, what failed and what was skipped.

Packaged for **Claude Code** as a plugin containing one Agent Skill
(`skills/security-audit/SKILL.md`). The engine is plain Python (stdlib only) and
works from any shell or agent.

> Automated tools cannot find every vulnerability. This skill reports the checks it
> performed and their results. It never declares a project secure.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Platform validation, architecture, threat model ([docs/DESIGN.md](docs/DESIGN.md)) | Implemented |
| 1 | Discovery, SAST, SCA, secrets, normalization, MD/JSON reports, scope gate | Implemented, tested |
| 2 | Cross-tool dedup, evidence context, confidence model, risk prioritization, triage workflow, seeded benchmark | Implemented, tested |
| 3 | Isolated remediation, regression tests, approval gates | Designed (manual procedure in `references/remediation.md`), not implemented |
| 4 | Automated verification, regression detection | Partly: `--baseline` tracks new/recurring/no-longer-reported findings; no fix verification yet |
| 5 | DAST/API testing (ZAP) on approved targets | Planned |
| 6 | More ecosystems, Trivy, fuzzing, history scanning | Planned |

## Install

```bash
# As a Claude Code plugin (from this repo)
/plugin marketplace add itsHarshDabas/Agentic-Security-Skill
/plugin install agentic-security-skill@agentic-security-skill

# Or copy just the skill
cp -r skills/security-audit ~/.claude/skills/
```

Scanners are installed separately; any that are missing are reported as `UNAVAILABLE`:

```bash
pip install semgrep==1.182.1 bandit==1.9.4 pip-audit==2.10.1
go install github.com/zricethezav/gitleaks/v8@v8.30.1
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0
# npm audit uses your existing npm
```

If they live outside `PATH`, set `SECAUDIT_TOOL_PATH=/dir/one:/dir/two`.

## Use

In Claude Code: *"audit ./my-app for security issues"* or `/security-audit`.

Directly:

```bash
S=skills/security-audit/scripts/secaudit
$S doctor                                   # which tools are available
$S scan ./my-app                            # read-only, offline
$S scan ./my-app --scope ~/scopes/my-app.json   # e.g. with network for dependency checks
$S triage <run-dir> <run-dir>/triage.json   # apply validated triage + contextual findings
$S scan ./my-app --baseline <old-run>/report.json   # track new / recurring findings
```

A scope manifest (stored **outside** the target) is the only way to grant permissions:

```json
{"version": 1, "exclude": ["vendor"], "permissions": {"network": true}}
```

See [`references/scope-manifest.md`](skills/security-audit/references/scope-manifest.md).

## What runs

| Check | Tool | Needs network | Notes |
|---|---|---|---|
| SAST (Python, JS/TS, Dockerfile, Compose, GitHub Actions) | Semgrep CE + bundled rules | no | `--metrics=off`, `--disable-nosem`, local rules only |
| SAST (Python) | Bandit | no | `--ignore-nosec` |
| Secrets (working tree) | Gitleaks | no | `--redact`, `--ignore-gitleaks-allow` |
| Dependencies (all ecosystems) | OSV-Scanner | yes | |
| Dependencies (pinned requirements) | pip-audit | yes | `--no-deps --disable-pip`: never installs or resolves packages |
| Dependencies (npm lockfile) | npm audit | yes | runs on a temp copy of `package.json` + lockfile only, empty npmrc |
| Contextual review (authz, IDOR, logic) | the agent | no | recorded via `triage`, validated by the engine |

## Safety controls (enforced in code, covered by tests)

- Default read-only and offline; permissions only from an operator manifest that may not live inside the target.
- No project code is executed; no package installs; no git commands against the target.
- Subprocesses: argv lists only, timeouts, output caps, CPU/file-size rlimits, scrubbed environment (no tokens passed to tools), network proxies pointed nowhere when network is off.
- Paths validated against scope; symlinks never followed out of the target; tool results pointing outside the target are dropped.
- Target-supplied suppressions (`# nosec`, `nosemgrep`, `gitleaks:allow`) ignored; tool configs found in the target are flagged in the report.
- Raw output stored byte-for-byte with sha256; tampering shows up as a warning in the report.
- Malformed, truncated or unexpected tool output becomes `FAILED`/`PARTIAL`, never an empty "clean" result.
- Secrets redacted from every report; Gitleaks findings never store the matched line.
- Agent triage requires rationale; "confirmed" requires reproduction or evidence; locations must exist in the target.
- The wrapper runs Python in isolated mode so files in the audited project cannot shadow engine modules.

## Benchmark

`fixtures/vulnapp` is a small intentionally vulnerable Flask + Express app with Docker,
Compose and CI config: 19 seeded code vulnerabilities (16 scanner-detectable, 3 that
need contextual review), 9 config issues, 7 known-vulnerable packages, 2 generated
secrets, and 5 decoys (safe code that scanners commonly flag).

Latest run (2026-10-24, this sandbox, network allowed for PyPI/npm, OSV.dev blocked):

| Metric | Value |
|---|---|
| Scanner-detectable seed recall | 16/16 |
| Config seed recall | 9/9 |
| Vulnerable package recall | 7/7 (pip-audit + npm audit) |
| Injected secrets found | 2/2 |
| Code/config findings | 33: 28 on seeded lines, 3 on decoys, 2 unlabeled |
| Precision on labeled lines | 0.90 |
| Decoys flagged by scanners | 3/4 (fixed-argv subprocess, md5 ETag, random jitter) |
| Findings confirmed without triage | 0 |
| Contextual seed recall | not measured for a live agent (see below) |
| Mean risk score, seeded vs decoy lines | 51.1 vs 30.5 |
| Scan duration | ~26 s |

**How to read this.** The bundled Semgrep rules were written alongside this fixture, so
the recall numbers mostly show that the pipeline works end to end. They say little about
recall on unseen code, which will be much lower with this small rule pack. The decoy
results are the point: scanners flag safe code, and the skill keeps those as
`unverified` until triage marks them. Contextual findings are produced by the agent; the
tests exercise the triage plumbing with a fixed triage file, which is not a measurement of
agent accuracy. Reproduce with `python tests/benchmark.py [--network] [--output file.json]`; methodology in
[docs/BENCHMARK.md](docs/BENCHMARK.md).

## Tests

```bash
python -m venv .venv && .venv/bin/pip install semgrep==1.182.1 bandit==1.9.4 pip-audit==2.10.1 pytest
SECAUDIT_TOOL_PATH=$PWD/.venv/bin:$HOME/go/bin .venv/bin/python -m pytest -q          # offline
SECAUDIT_TEST_NETWORK=1 SECAUDIT_TOOL_PATH=... .venv/bin/python -m pytest -q          # + dependency scanners
```

54 tests: scope/permission gate, path and symlink handling, subprocess hardening, env
scrubbing, redaction, honest statuses for missing/failed/blocked/timed-out tools, evidence
tamper detection, triage validation, stable IDs across edits, new-issue detection, no
writes to the target, no secrets in outputs, and the seeded benchmark. Integration tests
skip when a scanner is not installed.

## Known limitations

- OSV-Scanner needs api.osv.dev and api.deps.dev; when they are unreachable it is reported `BLOCKED`.
- Git history is not scanned for secrets yet.
- pip-audit only audits pinned `requirements*.txt` lines; unpinned lines make the check `PARTIAL`. `pyproject.toml`/`poetry.lock` rely on OSV-Scanner.
- No container image, IaC (Terraform/K8s) or DAST coverage yet.
- Scanners run as your user with rlimits, not in a container.

## Layout

```
.claude-plugin/            plugin + marketplace manifests
skills/security-audit/
  SKILL.md                 agent instructions
  scripts/secaudit         entry point
  references/              scope, triage, review checklist, schema, remediation
  lib/secaudit/            engine (scope, safe_exec, discovery, adapters, findings, triage, report)
  lib/secaudit/rules/semgrep/  bundled rules
fixtures/vulnapp/          seeded benchmark app + expected.json
tests/                     pytest suite + benchmark harness
docs/DESIGN.md             Phase 0 design and threat model
```

License: MIT.
