"""The only place the engine starts subprocesses.

argv lists only, never a shell; bounded time, output and resources; scrubbed
environment so credentials in the operator's shell are not handed to tools.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import SecauditError

DEFAULT_TIMEOUT = 600
DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024  # bytes kept per stream
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
                 "https_proxy", "http_proxy", "no_proxy")
PROXY_VARS = {"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"}


@dataclass
class ExecResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    duration_s: float
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool


def which(name: str, extra_dirs: list[str] | None = None) -> str | None:
    path = os.environ.get("PATH", "")
    if extra_dirs:
        path = os.pathsep.join(extra_dirs + [path])
    return shutil.which(name, path=path)


def build_env(network: bool, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in ENV_ALLOWLIST if k in os.environ}
    if not network:
        # Point proxies at an unroutable address so an adapter that unexpectedly
        # tries the network fails fast instead of leaking.
        for k in PROXY_VARS:
            env[k] = "http://127.0.0.1:9"
        env["NO_PROXY"] = env["no_proxy"] = ""
    env.setdefault("LANG", "C.UTF-8")
    if extra:
        env.update(extra)
    return env


def _limits(cpu_seconds: int, max_file_bytes: int):
    def apply():  # runs in the child before exec
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_bytes, max_file_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, ValueError, OSError):
            pass
        os.setsid()
    return apply


def _read_capped(f, cap: int) -> tuple[bytes, bool]:
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    return f.read(cap), size > cap


def run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT, cpu_seconds: int | None = None,
        max_file_bytes: int = 512 * 1024 * 1024) -> ExecResult:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise SecauditError("argv must be a non-empty list of strings")
    if any("\x00" in a for a in argv):
        raise SecauditError("argv contains NUL byte")
    start = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            shell=False, close_fds=True,
            preexec_fn=_limits(cpu_seconds or timeout * 2, max_file_bytes) if os.name == "posix" else None,
        )
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                proc.kill()
            proc.wait()
            rc = None
        so, so_t = _read_capped(out, max_output)
        se, se_t = _read_capped(err, max_output)
    return ExecResult(argv, rc, so, se, round(time.monotonic() - start, 3), timed_out, so_t, se_t)
