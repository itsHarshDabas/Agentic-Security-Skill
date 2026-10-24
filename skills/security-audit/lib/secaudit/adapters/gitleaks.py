from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .. import safe_git
from ..discovery import SKIP_DIRS, _excluded
from ..errors import ScopeError, SecauditError
from ..findings import Evidence, Finding, Location, secret_id
from .base import BLOCKED, COMPLETED, FAILED, SKIPPED_NOT_APPLICABLE, Adapter

# Without --config, gitleaks loads `.gitleaks.toml` from the scanned directory, so a target could
# allowlist its own secrets. Always pass an explicit config that extends the built-in rules.
DEFAULT_CONFIG = "[extend]\nuseDefault = true\n"


def _config(tmp: str) -> str:
    p = Path(tmp) / "gitleaks-default.toml"
    p.write_text(DEFAULT_CONFIG)
    return str(p)


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    binary = "gitleaks"
    category = "secrets"
    objective = "Detect hardcoded credentials and secrets in the working tree (secrets redacted at source)"

    def version(self):
        if not self.path:
            return None
        er = self.execute([self.path, "version"], cwd=Path(tempfile.gettempdir()), network=False, timeout=30)
        v = er.stdout.decode(errors="replace").strip()
        return v if v and "build process" not in v else "unknown (built from source without version stamp)"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gitleaks.json"
            empty_ignore = Path(tmp) / "ignore"
            empty_ignore.mkdir()
            findings_raw = []
            raw_blobs = []
            for root in self.ctx.scope.roots:
                argv = [self.path, "dir", str(root), "--report-format", "json", "--report-path", str(out),
                        "--redact", "--no-banner", "--exit-code", "0", "--ignore-gitleaks-allow",
                        "--gitleaks-ignore-path", str(empty_ignore), "--max-target-megabytes", "5",
                        "--log-level", "error", "--config", _config(tmp)]
                er = self.execute(argv, cwd=Path(tmp), network=False)
                raw = out.read_bytes() if out.exists() else b""
                raw_blobs.append(raw)
                if not self.finish(res, er, f"gitleaks-{len(raw_blobs)}.json", raw=raw):
                    return res
                try:
                    findings_raw += json.loads(raw or b"[]")
                except json.JSONDecodeError:
                    res.status, res.reason = FAILED, "unparseable JSON output"
                    return res
        if (target / ".git").exists():
            res.notes.append("working tree only; git history is covered by the gitleaks-history check")
        for r in findings_raw:
            rel = self.rel(r["File"])
            if rel is None:
                continue
            # gitleaks has no exclude flag for `dir`; apply scope excludes and skip dirs here.
            if _excluded(rel, self.ctx.scope.exclude) or set(rel.split("/")[:-1]) & SKIP_DIRS:
                continue
            line = r.get("StartLine")
            text = self.read_line(rel, line)
            res.findings.append(Finding(
                id=secret_id(r["RuleID"], rel, text),
                kind="secret",
                title=f"Possible hardcoded secret: {r.get('Description') or r['RuleID']}",
                description=("Gitleaks matched a secret pattern. It may be a real credential, a test value or a "
                             "false positive; confirm before rotating."),
                severity="high",
                confidence="medium",
                category="hardcoded-secret",
                cwe=["CWE-798"],
                locations=[Location(rel, line, r.get("EndLine"), None)],  # never store the line itself
                evidence=[Evidence("gitleaks", r["RuleID"], f"entropy={r.get('Entropy')}", self.last_raw)],
                tools=["gitleaks"],
                remediation="Remove the secret from source, load it from a secret manager or environment, and rotate it if it was ever valid.",
            ))
        res.findings_count = len(res.findings)
        res.status = COMPLETED
        return res


class GitleaksHistoryAdapter(GitleaksAdapter):
    name = "gitleaks-history"
    objective = "Detect secrets committed anywhere in git history, including ones since deleted (redacted at source)"

    def applicable(self):
        if (self.ctx.scope.target / ".git").exists():
            return True, ""
        return False, "target is not the root of a git repository"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        try:
            safe_git.require_safe(target)
        except (ScopeError, SecauditError) as e:
            res.status, res.reason = BLOCKED, f"not scanned: {e}"
            return res
        # gitleaks runs `git log -p` itself; apply the same code-execution overrides as safe_git via env.
        git_env = dict(safe_git.GIT_ENV, GIT_CONFIG_COUNT=str(len(safe_git.OVERRIDES)))
        for i, o in enumerate(safe_git.OVERRIDES):
            k, v = o.split("=", 1)
            git_env[f"GIT_CONFIG_KEY_{i}"], git_env[f"GIT_CONFIG_VALUE_{i}"] = k, v
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gitleaks-history.json"
            empty_ignore = Path(tmp) / "ignore"
            empty_ignore.mkdir()
            argv = [self.path, "git", str(target), "--report-format", "json", "--report-path", str(out),
                    "--redact", "--no-banner", "--exit-code", "0", "--ignore-gitleaks-allow",
                    "--gitleaks-ignore-path", str(empty_ignore), "--max-target-megabytes", "5",
                    "--log-level", "error", "--config", _config(tmp),
                    "--log-opts=--all --full-history --no-textconv --no-ext-diff"]
            er = self.execute(argv, cwd=Path(tmp), network=False, extra_env=git_env)
            raw = out.read_bytes() if out.exists() else b""
            if not self.finish(res, er, "gitleaks-history.json", raw=raw):
                return res
            try:
                data = json.loads(raw or b"[]")
            except json.JSONDecodeError:
                res.status, res.reason = FAILED, "unparseable JSON output"
                return res
        commits = set()
        for r in data:
            rel = r.get("File", "")
            if not rel or rel.startswith("/") or ".." in rel.split("/"):
                continue
            if _excluded(rel, self.ctx.scope.exclude) or set(rel.split("/")[:-1]) & SKIP_DIRS:
                continue
            commit = r.get("Commit", "")[:12]
            commits.add(commit)
            present = (target / rel).is_file()
            res.findings.append(Finding(
                id=secret_id(r["RuleID"], f"{rel}@{commit}", str(r.get("StartLine"))),
                kind="secret",
                title=f"Secret in git history: {r.get('Description') or r['RuleID']}"[:160],
                description=(f"Gitleaks matched a secret pattern in commit {commit} ({r.get('Date', '')[:10]}), "
                             f"file {rel}. " + ("The file still exists in the working tree. " if present else
                             "The file is no longer in the working tree, but the secret remains in history. ")
                             + "Anyone with a clone can read it; treat it as exposed if it was ever valid."),
                severity="high",
                confidence="medium",
                category="hardcoded-secret",
                cwe=["CWE-798"],
                # Not a working-tree location; line numbers refer to the commit's version of the file.
                locations=[Location(rel, None, None, None)],
                evidence=[Evidence("gitleaks-history", r["RuleID"],
                                   f"commit={commit} line={r.get('StartLine')} entropy={r.get('Entropy')}", self.last_raw)],
                tools=["gitleaks-history"],
                remediation="Rotate the credential. Removing it from history (git filter-repo) only helps "
                            "before others have cloned; rotation is what matters.",
            ))
        res.findings_count = len(res.findings)
        res.status = COMPLETED
        res.reason = f"{len(commits)} commit(s) with matches"
        return res
