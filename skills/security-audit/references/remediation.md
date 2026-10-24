# Remediation (Phase 3) and verification (Phase 4)

Only when the operator asks for fixes **and** the scope manifest grants
`modify_source` (and `execute_project_code` to run tests, `commit` to commit).

## What the engine enforces
- Fixes are made in a separate git worktree on branch `secaudit/fix-<run>` created from HEAD. The operator's working tree, index and current branch are never touched; the session records a snapshot of their uncommitted changes and `fix diff` reports whether it is still byte-identical.
- Git runs with code-executing config neutralized (`core.fsmonitor`, hooks, pager, editors, ssh, credential helpers, network protocols). A repository whose own config sets filter drivers, diff textconv, `include.path` and similar is refused.
- Every change is gated (`patchgate.py`) before it is accepted:
  - refused: paths outside the scope roots or in `.git/`, binary changes, file deletions, scanner suppressions (`nosec`, `nosemgrep`, `gitleaks:allow`, `eslint-disable`, …), scanner config edits, removed or skipped tests;
  - approval required (`--approve` after the operator agrees): more than 60 changed lines, more than 3 source files, dependency manifests, security-sensitive files (auth, session, crypto…);
  - a regression test (a file under the test tree) is required, or an explicit `--no-test-reason`, which caps the result at `FIX_APPLIED_UNVERIFIED`.
  Rejected changes are rolled back in the worktree automatically.
- Red/green regression check (`fix test`): the test command runs (argv, no shell, network off, timeout) on the tree before the fix plus the new test files (must fail), then on the fixed tree (must pass). Output is stored as evidence.
- `fix commit` needs the `commit` permission and commits only on the session branch. Nothing is ever pushed.

## Procedure
1. **Scan and triage** first; fix only `confirmed` or `probable` findings.
2. `secaudit fix start <run>`: prints the fix worktree path.
3. `secaudit fix plan <run> --finding <ID> ...`: write the plan (flaw, root cause, intended change, affected components, regression test, security verification, compatibility risk, approval needed). Show it to the operator; get approval where flagged.
4. Make the fix **in the fix worktree only**: either edit files there and run `secaudit fix record <run> --finding <ID>`, or write a unified diff and run `secaudit fix apply <run> --finding <ID> --patch fix.diff`. Smallest idiomatic change; add a regression test that fails on the vulnerable code.
5. `secaudit fix test <run> --finding <ID> -- python -m pytest -q tests/test_x.py`: red/green check. Then run the broader suite the same way.
6. `secaudit verify <run>` (Phase 4): re-scan the fixed worktree, compare with the original findings, assign final statuses, detect new findings (regressions), write `verification.json` and update the report.
7. `secaudit fix diff <run>`: review every changed file with the operator.
8. Only with `commit` permission and the operator's go-ahead: `secaudit fix commit <run> -m "..."`. Then `secaudit fix cleanup <run>` removes the worktrees and keeps the branch.

## Final statuses
| Status | Assigned when |
|---|---|
| `FIXED_VERIFIED` | Red/green regression test passed and the original detector (if any) no longer reports it, with no new findings in the changed files |
| `PARTIALLY_MITIGATED` | Detector still reports it at lower severity, or red/green passed but the detector still reports it |
| `FIX_APPLIED_UNVERIFIED` | Fix recorded but no red/green evidence (no test, test not run, or test did not fail before the fix) |
| `UNRESOLVED` | Detector still reports it, or the regression test still fails after the fix |
| `BLOCKED` | The fix was rejected by a gate or awaits approval |
| `FALSE_POSITIVE` | Triage marked it false positive |

A passing scanner or test is evidence, not proof: the report says exactly which evidence each status rests on.
