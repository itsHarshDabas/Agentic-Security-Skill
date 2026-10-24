# Remediation and verification (manual procedure; automation is Phase 3/4)

Status: **Designed**, not implemented as engine commands. Follow this only when the
operator explicitly asks for fixes, and treat each step as requiring their consent.

1. **Baseline.** Have a completed scan (`report.json`) and run the project's existing tests if the operator approves running them. Record results.
2. **Working tree.** `git status`. If there are unrelated uncommitted changes, do not reset, stash or overwrite them. Prefer a new branch or `git worktree add` for the fix.
3. **Plan per finding** (write it down before editing): flaw, root cause, intended change, affected files, regression test, security test, compatibility risk, whether approval is needed. Risky or ambiguous fixes: show the diff and wait.
4. **Test first.** Add a regression test that fails on the vulnerable code (e.g. a request with `' OR 1=1 --` must not authenticate).
5. **Minimal patch.** Idiomatic, smallest change; no suppressions (`# nosec`, `nosemgrep`), no deleted tests, no scanner-config changes to get a clean result. Dependency upgrades: smallest patched version, check changelogs for breaking changes.
6. **Verify.** Run the new test (passes), the related tests, then the broader suite and lint/type checks if present. Re-scan with `--baseline <pre-fix report.json>` and confirm the finding is no longer reported and nothing new appeared.
7. **Review the diff** file by file.
8. **Status.** `FIXED_VERIFIED` only when the regression test and re-scan both support it; otherwise `FIX_APPLIED_UNVERIFIED` or `PARTIALLY_MITIGATED`, stating what remains unverified.
9. Do not commit, push or deploy without explicit authorization.
