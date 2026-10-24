"""Adapter contract. Each adapter declares its purpose, applicability and the
permissions it needs; the orchestrator enforces those before calling run()."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import safe_exec
from ..evidence import RunStore
from ..findings import Finding
from ..scope import Scope

# Check statuses. A check that did not complete is never reported as clean.
COMPLETED = "COMPLETED"
SKIPPED_NOT_APPLICABLE = "SKIPPED_NOT_APPLICABLE"
SKIPPED_NOT_PERMITTED = "SKIPPED_NOT_PERMITTED"
SKIPPED_BY_OPERATOR = "SKIPPED_BY_OPERATOR"
UNAVAILABLE = "UNAVAILABLE"
FAILED = "FAILED"
TIMED_OUT = "TIMED_OUT"
PARTIAL = "PARTIAL"
BLOCKED = "BLOCKED"

NETWORK_DENIED = re.compile(r"(?i)forbidden|request blocked|tunnel connection failed|proxyerror|"
                            r"could not resolve host|name or service not known|network is unreachable|"
                            r"ENOTFOUND|EAI_AGAIN|ECONNREFUSED|connection refused")


@dataclass
class Context:
    scope: Scope
    inventory: dict
    store: RunStore
    tool_dirs: list[str]
    timeout: int = 600
    semgrep_configs: list[str] = field(default_factory=list)


@dataclass
class CheckResult:
    check_id: str
    tool: str
    objective: str
    category: str
    permissions_required: list[str]
    status: str = "PLANNED"
    reason: str | None = None
    tool_version: str | None = None
    argv: list[str] | None = None
    exit_code: int | None = None
    duration_s: float | None = None
    raw_outputs: list[str] = field(default_factory=list)
    findings_count: int = 0
    stderr_excerpt: str | None = None
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "findings"}
        return d


class Adapter:
    name = "base"
    binary = ""
    category = ""
    objective = ""
    requires: tuple[str, ...] = ()
    tool_env: dict[str, str] = {}  # always set for this tool (e.g. disable telemetry)

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.path = safe_exec.which(self.binary, ctx.tool_dirs) if self.binary else None

    def result(self, **kw) -> CheckResult:
        return CheckResult(check_id=self.name, tool=self.name, objective=self.objective,
                           category=self.category, permissions_required=list(self.requires), **kw)

    def applicable(self) -> tuple[bool, str]:
        return True, ""

    def version(self) -> str | None:
        if not self.path:
            return None
        try:
            r = safe_exec.run([self.path, "--version"], cwd=Path(os.path.expanduser("~")),
                              env=safe_exec.build_env(network=False, extra=self.tool_env), timeout=60)
        except OSError:
            return None
        text = (r.stdout or r.stderr).decode(errors="replace")
        m = re.search(r"\d+\.\d+(\.\d+)?", text)
        return m.group(0) if m else text.strip()[:60] or None

    def execute(self, argv: list[str], cwd: Path, network: bool, extra_env=None, timeout=None):
        env = safe_exec.build_env(network=network, extra={**self.tool_env, **(extra_env or {})})
        return safe_exec.run(argv, cwd=cwd, env=env, timeout=timeout or self.ctx.timeout)

    def run(self) -> CheckResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # helpers -------------------------------------------------------------
    def finish(self, res: CheckResult, er, raw_name: str, raw: bytes | None = None,
               ok_codes=(0,)) -> bool:
        """Record exec metadata + raw output. Returns False if the run did not complete."""
        res.argv, res.exit_code, res.duration_s = er.argv, er.returncode, er.duration_s
        data = er.stdout if raw is None else raw
        self.last_raw = self.ctx.store.save_raw(raw_name, data, {
            "tool": self.name, "version": res.tool_version, "argv": er.argv, "exit_code": er.returncode})
        res.raw_outputs.append(self.last_raw)
        if er.stderr:
            res.raw_outputs.append(self.ctx.store.save_raw(raw_name + ".stderr", er.stderr, {"tool": self.name}))
            res.stderr_excerpt = er.stderr.decode(errors="replace")[-800:]
        if er.timed_out:
            res.status, res.reason = TIMED_OUT, f"exceeded {self.ctx.timeout}s timeout"
            return False
        if er.stdout_truncated:
            res.status, res.reason = PARTIAL, "output exceeded size cap; results incomplete"
            return False
        if er.returncode not in ok_codes:
            text = er.stderr.decode(errors="replace") + er.stdout[-4000:].decode(errors="replace")
            if NETWORK_DENIED.search(text):
                res.status = BLOCKED
                res.reason = f"exit code {er.returncode}: network access to the tool's data source failed or was denied"
            else:
                res.status, res.reason = FAILED, f"exit code {er.returncode}"
            return False
        return True

    def read_line(self, rel: str, line: int | None) -> str:
        if not line:
            return ""
        p = (self.ctx.scope.target / rel)
        try:
            p = p.resolve(strict=True)
            p.relative_to(self.ctx.scope.target)
            with open(p, "rb") as f:
                for i, raw in enumerate(f, 1):
                    if i == line:
                        return raw.decode(errors="replace").rstrip("\n")[:400]
                    if i > line:
                        break
        except (OSError, ValueError):
            pass
        return ""

    def rel(self, path: str, base: Path | None = None) -> str | None:
        """Tool path -> target-relative path, or None if it points outside the target."""
        p = Path(path)
        if not p.is_absolute():
            p = (base or self.ctx.scope.target) / p
        try:
            return p.resolve(strict=False).relative_to(self.ctx.scope.target).as_posix()
        except ValueError:
            return None
