from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from .base import COMPLETED, FAILED, PARTIAL, SKIPPED_NOT_APPLICABLE, Adapter
from .deps_common import dep_finding

PINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_-]+)\s*(;.*)?$")


def split_requirements(text: str) -> tuple[list[str], list[str]]:
    """Return (pinned lines, skipped lines). Includes/options/URLs are skipped, never followed."""
    pinned, skipped = [], []
    for line in text.splitlines():
        s = line.split(" #", 1)[0].strip()
        if not s or s.startswith("#"):
            continue
        m = PINNED.match(s)
        if m:
            pinned.append(f"{m.group(1)}=={m.group(3)}")
        else:
            skipped.append(s[:120])
    return pinned, skipped


class PipAuditAdapter(Adapter):
    name = "pip-audit"
    binary = "pip-audit"
    category = "sca"
    objective = "Known-vulnerability lookup for pinned Python requirements (PyPI advisory data)"
    requires = ("network",)

    def _files(self):
        return [m["path"] for m in self.ctx.inventory["manifests"]
                if m["path"].rsplit("/", 1)[-1].startswith("requirements") and m["path"].endswith(".txt")]

    def applicable(self):
        if self._files():
            return True, ""
        return False, "no requirements*.txt files (pyproject/poetry are covered by osv-scanner only)"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        total_skipped = []
        with tempfile.TemporaryDirectory() as tmp:
            for i, rel in enumerate(self._files()):
                src = (target / rel).resolve(strict=True)
                src.relative_to(target)
                pinned, skipped = split_requirements(src.read_text(errors="replace"))
                total_skipped += [f"{rel}: {s}" for s in skipped]
                if not pinned:
                    continue
                req = Path(tmp) / f"req{i}.txt"
                req.write_text("\n".join(pinned) + "\n")
                out = Path(tmp) / f"out{i}.json"
                argv = [self.path, "-r", str(req), "--no-deps", "--disable-pip", "-f", "json", "-o", str(out),
                        "--progress-spinner", "off", "-s", "pypi", "--cache-dir", str(Path(tmp) / "cache")]
                er = self.execute(argv, cwd=Path(tmp), network=True)
                raw = out.read_bytes() if out.exists() else b""
                if not self.finish(res, er, f"pip-audit-{i}.json", raw=raw, ok_codes=(0, 1)):
                    return res
                try:
                    data = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    res.status, res.reason = FAILED, "unparseable JSON output"
                    return res
                for dep in data.get("dependencies", []):
                    if dep.get("skip_reason"):
                        total_skipped.append(f"{rel}: {dep['name']} ({dep['skip_reason']})")
                    for v in dep.get("vulns", []):
                        res.findings.append(dep_finding(
                            "pip-audit", "pypi", dep["name"], dep["version"], [v["id"]] + v.get("aliases", []),
                            v.get("description", ""), rel, self.last_raw,
                            None, v.get("fix_versions", [])))
        res.findings_count = len(res.findings)
        if total_skipped:
            res.status = PARTIAL
            res.reason = f"{len(total_skipped)} requirement line(s) not audited (unpinned, includes or options)"
            res.notes += total_skipped[:50]
        else:
            res.status = COMPLETED
        return res
