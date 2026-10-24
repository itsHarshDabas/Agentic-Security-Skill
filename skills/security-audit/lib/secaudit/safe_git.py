"""Git against an untrusted repository, with the config keys that execute code neutralized.

Git reads the repository's own .git/config. Keys such as core.fsmonitor,
filter drivers, diff textconv and include.path can make ordinary git commands
run attacker-chosen programs. We override the ones that can be overridden on
the command line and refuse to operate on a repository that sets the others.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import safe_exec
from .errors import ScopeError, SecauditError

OVERRIDES = [
    "core.fsmonitor=false", "core.hooksPath=/dev/null", "core.pager=cat", "core.editor=false",
    "sequence.editor=false", "core.sshCommand=false", "credential.helper=", "protocol.allow=never",
    "diff.external=", "core.askPass=false", "gc.auto=0", "commit.gpgSign=false", "tag.gpgSign=false",
    "core.untrackedCache=false",
]
RISKY_KEYS = re.compile(
    r"^(filter\..+\.(clean|smudge|process)|diff\..+\.(textconv|command)|merge\..+\.driver|"
    r"core\.(fsmonitor|sshcommand|gitproxy|alternaterefscommand|askpass)|include\.path|includeif\..+|"
    r"uploadpack\..+|receive\..+hook.*|remote\..+\.(uploadpack|receivepack)|gpg\..*program)=", re.I)
GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_AUTHOR_NAME": "secaudit", "GIT_AUTHOR_EMAIL": "secaudit@localhost",
           "GIT_COMMITTER_NAME": "secaudit", "GIT_COMMITTER_EMAIL": "secaudit@localhost"}


def git_bin() -> str:
    g = safe_exec.which("git")
    if not g:
        raise SecauditError("git is not installed")
    return g


def run(repo: Path, args: list[str], timeout: int = 120, check: bool = True, env_extra=None):
    argv = [git_bin()]
    for o in OVERRIDES:
        argv += ["-c", o]
    argv += ["-C", str(repo)] + args
    er = safe_exec.run(argv, cwd=repo, env=safe_exec.build_env(network=False, extra={**GIT_ENV, **(env_extra or {})}),
                       timeout=timeout)
    if check and er.returncode != 0:
        raise SecauditError(f"git {' '.join(args[:3])} failed: {er.stderr.decode(errors='replace')[-400:]}")
    return er


def out(repo: Path, args: list[str], **kw) -> str:
    return run(repo, args, **kw).stdout.decode(errors="replace")


def risky_config(repo: Path) -> list[str]:
    """Config entries in the repository (local + worktree) that could execute code."""
    text = out(repo, ["config", "--local", "--list"], check=False)
    return [line.split("=", 1)[0] for line in text.splitlines() if RISKY_KEYS.match(line)]


def toplevel(path: Path) -> Path:
    er = run(path, ["rev-parse", "--show-toplevel"], check=False)
    if er.returncode != 0:
        raise ScopeError(f"{path} is not inside a git repository; remediation needs git for isolation")
    return Path(er.stdout.decode().strip()).resolve()


def require_safe(repo: Path) -> None:
    bad = risky_config(repo)
    if bad:
        raise ScopeError("repository config sets keys that can execute programs during git operations: "
                         f"{sorted(set(bad))}. Review .git/config and remove them, or remediate manually.")
