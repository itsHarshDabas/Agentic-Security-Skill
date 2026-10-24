from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from ..discovery import iter_files
from ..findings import Evidence, Finding, Location, code_id
from .base import COMPLETED, FAILED, Adapter

FRAMEWORKS = ["terraform", "cloudformation", "kubernetes", "helm", "kustomize", "dockerfile", "github_actions",
              "gitlab_ci", "serverless", "arm", "bicep"]
# Open-source checkov does not ship severities (they come from the commercial platform), so the
# engine assigns them: a short list of high-impact checks, keyword-based "low" for hygiene checks,
# "medium" otherwise. Recorded as severity_source "secaudit-map".
HIGH = {"CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260", "CKV_AWS_277", "CKV_AWS_20", "CKV_AWS_57", "CKV_AWS_40",
        "CKV_AWS_1", "CKV_AWS_62", "CKV_AWS_63", "CKV_AWS_17", "CKV_AWS_41", "CKV_AWS_46", "CKV_AWS_45",
        "CKV_AZURE_9", "CKV_AZURE_10", "CKV_GCP_2", "CKV_GCP_3", "CKV_K8S_16", "CKV_K8S_17", "CKV_K8S_18",
        "CKV_K8S_19", "CKV_K8S_27", "CKV_GHA_2", "CKV_GHA_3", "CKV_SECRET_2", "CKV_SECRET_6"}
LOW_WORDS = re.compile(r"(?i)description|notification|tag|label|logging|log |versioning|replication|healthcheck|"
                       r"lifecycle|monitoring|backup|readiness|liveness|image pull policy|cross-region|"
                       r"query logging|deletion protection|default namespace|cpu|memory")


IAC_NAME = re.compile(r"(?i).*\.(tf|tfvars|hcl|ya?ml|json|template|bicep|dockerfile)|dockerfile.*")
MAX_FILE = 2 * 1024 * 1024


def severity(check_id: str, name: str) -> str:
    if check_id in HIGH:
        return "high"
    return "low" if LOW_WORDS.search(name) else "medium"


class CheckovAdapter(Adapter):
    name = "checkov"
    binary = "checkov"
    category = "iac"
    objective = "IaC and pipeline misconfiguration (Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, CI)"
    tool_env = {"CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false", "LOG_LEVEL": "ERROR"}

    def applicable(self):
        inv = self.ctx.inventory
        if inv.get("docker") or inv.get("ci") or set(inv["languages"]) & {"terraform", "yaml", "json"}:
            return True, ""
        return False, "no IaC, container or CI configuration files"

    def run(self):
        res = self.result(tool_version=self.version())
        target = self.ctx.scope.target
        results: list[tuple[dict, bool]] = []
        with tempfile.TemporaryDirectory() as tmp:
            # Checkov reads `.checkov.yaml` from the scanned directory even when --config-file is given,
            # and such a file can skip checks or load external (executable) checks. So it runs on a mirror
            # holding only IaC-shaped regular files from the scope, never the target itself.
            mirror = Path(tmp) / "src"
            copied = 0
            for full, rel in iter_files(self.ctx.scope):
                if full is None or not IAC_NAME.fullmatch(full.name) or full.name.startswith(".checkov"):
                    continue
                if full.stat().st_size > MAX_FILE:
                    continue
                dst = mirror / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(full.read_bytes())
                copied += 1
            if not copied:
                res.status, res.reason = COMPLETED, "no IaC-shaped files in scope"
                return res
            # No --quiet: it drops skipped (inline-suppressed) checks. --skip-download: no policy/guideline download; no API key is passed, so nothing is uploaded.
            argv = [self.path, "-d", str(mirror), "-o", "json", "--compact", "--skip-download",
                    "--soft-fail", "--framework", *FRAMEWORKS]
            er = self.execute(argv, cwd=Path(tmp), network=False)
            if not self.finish(res, er, "checkov.json"):
                return res
            try:
                data = json.loads(er.stdout or b"[]")
            except json.JSONDecodeError:
                res.status, res.reason = FAILED, "unparseable JSON output"
                return res
            if isinstance(data, dict):
                data = [data] if "results" in data else []
            for block in data:
                if block.get("summary", {}).get("parsing_errors"):
                    res.notes.append(f"{block['check_type']}: {block['summary']['parsing_errors']} file(s) failed to parse")
                r = block.get("results", {})
                results += [(c, False) for c in r.get("failed_checks", [])]
                # Inline `checkov:skip` comments come from the target, which is untrusted: report them anyway.
                results += [(c, True) for c in r.get("skipped_checks", [])]
        seen = set()
        for c, suppressed in results:
            rel = c["file_path"].lstrip("/")
            if not (target / rel).is_file():
                continue
            start, end = (c.get("file_line_range") or [None, None])[:2]
            key = (c["check_id"], rel, start)
            if key in seen:
                continue
            seen.add(key)
            desc = f"Checkov {c['check_id']} failed for {c.get('resource', 'resource')}."
            if suppressed:
                desc += f" The target suppresses this check inline ({(c.get('check_result') or {}).get('suppress_comment', 'no reason')!s:.120}); suppressions in the target are not trusted."
            res.findings.append(Finding(
                id=code_id(f"checkov:{c['check_id']}", rel, c.get("resource", "")),
                # kind "iac": checks are per resource, so several distinct checks share one location and
                # must not be merged the way line-level code/config findings are.
                kind="iac", title=c["check_name"], description=desc,
                severity=severity(c["check_id"], c["check_name"]), severity_source="secaudit-map",
                confidence="medium", category="iac-misconfiguration",
                locations=[Location(rel, start, end, None)],
                evidence=[Evidence("checkov", c["check_id"], c.get("resource", ""), self.last_raw)],
                tools=["checkov"], references=[c["guideline"]] if c.get("guideline") else [],
                remediation="See the checkov guideline for this check."))
        if any(s for _, s in results):
            res.notes.append("target contains inline checkov:skip suppressions; reported as findings anyway")
        res.findings_count = len(res.findings)
        res.status = COMPLETED
        return res
