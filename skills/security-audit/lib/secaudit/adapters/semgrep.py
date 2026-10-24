from __future__ import annotations

import json
from pathlib import Path

from ..discovery import SKIP_DIRS
from ..findings import Evidence, Finding, Location, code_id, cwe_norm
from .base import COMPLETED, FAILED, SKIPPED_NOT_APPLICABLE, Adapter

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
LANGS = {"python", "javascript", "typescript", "yaml"}


class SemgrepAdapter(Adapter):
    name = "semgrep"
    binary = "semgrep"
    category = "sast"
    objective = "Pattern and taint-based static analysis of application code, Dockerfiles, Compose and CI config"
    requires = ()  # local rules only; metrics and version checks disabled
    tool_env = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}

    def applicable(self):
        inv = self.ctx.inventory
        if LANGS & set(inv["languages"]) or inv["docker"] or inv["ci"]:
            return True, ""
        return False, "no languages or config types covered by the bundled rules"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        configs = [str(RULES_DIR)] + list(self.ctx.semgrep_configs)
        argv = [self.path, "scan", "--json", "--metrics=off", "--disable-version-check", "--disable-nosem",
                "--oss-only", "--no-git-ignore", "--timeout", "30", "--max-target-bytes", "2000000"]
        for c in configs:
            argv += ["--config", c]
        for x in sorted(SKIP_DIRS) + list(self.ctx.scope.exclude):
            argv += ["--exclude", x]
        argv += [r.relative_to(target).as_posix() or "." for r in self.ctx.scope.roots]
        er = self.execute(argv, cwd=target, network=False)
        # semgrep exits 0 with or without findings; 2+ = error, but JSON may still carry partial results
        ok = self.finish(res, er, "semgrep.json", ok_codes=(0, 1))
        try:
            data = json.loads(er.stdout or b"{}")
        except json.JSONDecodeError:
            res.status, res.reason = FAILED, "unparseable JSON output"
            return res
        if not ok and not data.get("results"):
            return res
        errors = data.get("errors", [])
        if errors:
            res.notes.append(f"{len(errors)} semgrep error(s) (rule or parse failures); see raw output")
        seen: dict[str, int] = {}
        for r in data.get("results", []):
            rel = self.rel(r["path"])
            if rel is None:
                continue
            line = r["start"]["line"]
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            cwes = cwe_norm(meta.get("cwe") if isinstance(meta.get("cwe"), list) else [meta.get("cwe")])
            text = self.read_line(rel, line)
            fam = cwes[0] if cwes else r["check_id"].split(".")[-1]
            key = f"{fam}|{rel}|{text}"
            occ = seen.get(key, 0)
            seen[key] = occ + 1
            res.findings.append(Finding(
                id=code_id(fam, rel, text, occ),
                kind="config" if meta.get("category") == "config" else "code",
                title=meta.get("title") or r["check_id"].split(".")[-1].replace("-", " "),
                description=extra.get("message", ""),
                severity=meta.get("impact", SEV.get(extra.get("severity", "WARNING"), "medium")).lower(),
                confidence=(meta.get("confidence") or "medium").lower(),
                category=meta.get("vuln_class") or meta.get("category") or "security",
                cwe=cwes,
                locations=[Location(rel, line, r["end"]["line"], text.strip())],
                evidence=[Evidence("semgrep", r["check_id"], extra.get("message", "")[:500], self.last_raw)],
                tools=["semgrep"],
                remediation=meta.get("fix"),
                references=list(meta.get("references", []) or []),
            ))
        res.findings_count = len(res.findings)
        if res.status == "PLANNED":
            res.status = COMPLETED
        if not data.get("paths", {}).get("scanned"):
            res.notes.append("semgrep reported no scanned paths")
        return res
