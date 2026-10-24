from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..discovery import SKIP_DIRS, _excluded
from ..findings import Evidence, Finding, Location, secret_id
from .base import COMPLETED, FAILED, SKIPPED_NOT_APPLICABLE, Adapter


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
                        "--log-level", "error"]
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
            res.notes.append("git history was NOT scanned (Phase 1 scans the working tree only)")
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
