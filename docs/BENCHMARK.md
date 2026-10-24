# Benchmark methodology

`tests/benchmark.py` measures the skill against `fixtures/vulnapp`.

## Procedure
1. Copy the fixture to a fresh temp directory.
2. Record the line of every `SEED:<id>` and `DECOY:<id>` marker, then strip the markers so a reviewer (human or agent) cannot read the answers.
3. Inject two freshly generated fake secrets (an RSA-style private key block and a high-entropy API token). Nothing secret is committed.
4. Run `scan` with a scope manifest outside the target (`network` on with `--network`).
5. Score `report.json` against `fixtures/vulnapp/expected.json`.

## Metrics
| Metric | Definition |
|---|---|
| `scanner_seed_recall` | Scanner-detectable code seeds with at least one code finding within ±1 line / total such seeds |
| `config_seed_recall` | Config seeds (Docker, Compose, Actions) with a finding on the matching line / total |
| `contextual_seed_recall` | Contextual seeds (IDOR, mass assignment, missing role check) covered by an agent `contextual` finding. 0 for a scanner-only run by design |
| `precision_labeled` | Code/config findings on seeded lines / findings on seeded or decoy lines. Findings on unlabeled lines are reported separately as `unlabeled` and excluded |
| `decoy_false_positive_rate` | Decoys (excluding the lodash one, which is SCA territory) flagged by any scanner / total |
| `dependency_package_recall` | Expected vulnerable packages with at least one dependency finding |
| `secrets_found` | Secret findings vs. injected secrets |
| `confirmed_without_triage` | Findings marked confirmed with no rationale. Must be empty |
| `mean_risk_seeded` / `mean_risk_decoys` | Mean Phase 2 risk score of findings on seeded vs decoy lines. Seeds should rank higher |
| `scan_duration_s` | Wall time of `scan` |
| Remediation / verification metrics | Produced by the Phase 3/4 remediation benchmark tests (`tests/test_remediation*.py`) |

## Limitations
- One small fixture written by the same author as the bundled Semgrep rules. Recall here is an upper bound and a regression guard, not an estimate of real-world recall.
- Line-proximity matching (±1) can credit a finding on an adjacent line that describes a different issue.
- Dependency results depend on advisory databases on the day of the run.
- Contextual recall depends on the agent doing the review; the automated tests only exercise the triage plumbing with a fixed triage file.
