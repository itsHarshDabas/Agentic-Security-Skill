"""Phase 5: passive dynamic checks against an explicitly authorized local/staging URL.

Safety model (enforced here, not in the prompt):
- requires the `dynamic_testing` permission and an exact origin match in scope.targets.urls;
- the host must resolve to loopback or a private address; anything else additionally
  needs `external_services`. The address is resolved once and every request goes to
  that pinned IP (no DNS rebinding);
- GET/HEAD only, no attack payloads, redirects are never followed;
- request budget, minimum interval between requests, per-request timeout and
  response-size cap.
`passive` intensity fetches only the base URL and GET routes found by discovery;
`standard` also requests a short fixed list of well-known debug/admin paths.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import safe_exec
from .errors import ScopeError, SecauditError
from .evidence import RunStore
from .findings import Evidence, Finding, Location, code_id
from .scope import Scope, load_scope

UA = "secaudit-passive/0.1 (+authorized assessment)"
MAX_BODY = 512 * 1024
WELL_KNOWN = ["/console", "/debug", "/admin", "/.env", "/server-status", "/actuator/env", "/phpinfo.php",
              "/.git/HEAD", "/swagger.json", "/openapi.json", "/graphql"]
SEC_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", "CWE-1021", "low"),
    "x-content-type-options": ("Missing X-Content-Type-Options: nosniff", "CWE-693", "low"),
    "referrer-policy": ("Missing Referrer-Policy", "CWE-200", "info"),
}
DEBUG_MARKERS = [("Werkzeug Debugger", "Werkzeug interactive debugger exposed", "critical"),
                 ("Traceback (most recent call last)", "Python stack trace in response", "medium"),
                 ("at Object.<anonymous>", "Node.js stack trace in response", "medium"),
                 ("DEBUG = True", "Debug configuration visible in response", "medium")]


@dataclass
class Budget:
    max_requests: int = 50
    min_interval: float = 0.2
    timeout: float = 10.0
    used: int = 0
    last: float = 0.0
    log: list = field(default_factory=list)

    def take(self):
        if self.used >= self.max_requests:
            raise SecauditError("request budget exhausted")
        wait = self.min_interval - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.used += 1
        self.last = time.monotonic()


def authorize(scope: Scope, url: str) -> tuple[str, str, int, str]:
    """Return (scheme, host, port, pinned_ip) or raise ScopeError."""
    scope.require("dynamic_testing", "dynamic testing")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ScopeError("URL must be http(s)://host[:port]/path without credentials")
    port = u.port or (443 if u.scheme == "https" else 80)
    origin = (u.scheme, u.hostname.lower(), port)
    allowed = set()
    for a in scope.urls:
        au = urlsplit(a)
        if au.hostname:
            allowed.add((au.scheme, au.hostname.lower(), au.port or (443 if au.scheme == "https" else 80)))
    if origin not in allowed:
        raise ScopeError(f"{u.scheme}://{u.hostname}:{port} is not listed in scope.targets.urls")
    try:
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ScopeError(f"cannot resolve {u.hostname}: {e}") from e
    ips = {ipaddress.ip_address(i[4][0]) for i in infos}
    local = all(ip.is_loopback or ip.is_private for ip in ips)
    if not local and not scope.allows("external_services"):
        raise ScopeError(f"{u.hostname} resolves to a non-private address {sorted(map(str, ips))}; "
                         "testing it needs the external_services permission")
    if any(ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local for ip in ips):
        raise ScopeError("target resolves to a multicast/unspecified/reserved/link-local address")
    return u.scheme, u.hostname, port, str(sorted(ips, key=str)[0])


def _request(scheme, host, port, ip, method, path, budget: Budget, headers=None) -> dict:
    budget.take()
    hdrs = {"Host": host if port in (80, 443) else f"{host}:{port}", "User-Agent": UA, "Accept": "*/*",
            **(headers or {})}
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(ip, port, timeout=budget.timeout, context=ctx)
        conn._tunnel_host = None
        # Verify the certificate against the hostname while connecting to the pinned IP.
        conn.sock = ctx.wrap_socket(socket.create_connection((ip, port), timeout=budget.timeout), server_hostname=host)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=budget.timeout)
    t0 = time.monotonic()
    try:
        conn.request(method, path, headers=hdrs)
        r = conn.getresponse()
        body = r.read(MAX_BODY + 1) if method != "HEAD" else b""
        res = {"method": method, "path": path, "status": r.status, "headers": {k.lower(): v for k, v in r.getheaders()},
               "set_cookie": r.headers.get_all("Set-Cookie") or [], "body": body[:MAX_BODY].decode(errors="replace"),
               "truncated": len(body) > MAX_BODY, "ms": round((time.monotonic() - t0) * 1000)}
    except (OSError, http.client.HTTPException) as e:
        res = {"method": method, "path": path, "error": f"{type(e).__name__}: {e}"}
    finally:
        conn.close()
    budget.log.append({k: v for k, v in res.items() if k != "body"})
    return res


def _finding(url_path, title, desc, sev, cwe, evidence, conf="high", fix=None) -> Finding:
    return Finding(id=code_id("dast:" + cwe, url_path, title), kind="dynamic", title=title, description=desc,
                   severity=sev, confidence=conf, category="runtime-configuration", cwe=[cwe],
                   locations=[Location(url_path)], evidence=[Evidence("secaudit-http", title, evidence[:500])],
                   tools=["secaudit-http"], remediation=fix,
                   validation="confirmed", validation_rationale="Observed directly in the HTTP response.")


def check_response(base: str, res: dict, scheme: str) -> list[Finding]:
    out = []
    if "error" in res:
        return out
    where = urljoin(base, res["path"])
    h = res["headers"]
    if res.get("_primary"):
        for name, (title, cwe, sev) in SEC_HEADERS.items():
            if name not in h:
                out.append(_finding(where, title, f"Response to GET {res['path']} has no {name} header.", sev, cwe,
                                    f"status {res['status']}", fix=f"Set the {name} header in the application or proxy."))
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            out.append(_finding(where, "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                                "low", "CWE-1021", f"status {res['status']}", fix="Set CSP frame-ancestors 'none' or X-Frame-Options DENY."))
        if scheme == "https" and "strict-transport-security" not in h:
            out.append(_finding(where, "Missing Strict-Transport-Security", "HTTPS response without HSTS.", "low",
                                "CWE-319", "", fix="Send Strict-Transport-Security with a long max-age."))
        for name in ("server", "x-powered-by"):
            if name in h and any(c.isdigit() for c in h[name]):
                out.append(_finding(where, f"Version disclosed in {name} header", f"{name}: {h[name]}", "info",
                                    "CWE-200", f"{name}: {h[name]}", fix="Remove version details from response headers."))
    for c in res["set_cookie"]:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [f for f, ok in (("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low),
                                   ("Secure", "secure" in low or scheme == "http")) if not ok]
        if missing:
            out.append(_finding(where, f"Cookie {name} missing {', '.join(missing)}",
                                f"Set-Cookie for {name} lacks {', '.join(missing)}.", "medium" if "HttpOnly" in missing else "low",
                                "CWE-1004" if "HttpOnly" in missing else "CWE-1275", f"cookie {name} attributes: "
                                + "; ".join(p.strip().split("=")[0] for p in c.split(";")[1:]),
                                fix="Set HttpOnly, Secure and SameSite on session cookies."))
    for marker, title, sev in DEBUG_MARKERS:
        if marker in res["body"]:
            out.append(_finding(where, title, f"Response to GET {res['path']} contains '{marker}'.", sev,
                                "CWE-489" if "Debug" in title else "CWE-209", f"status {res['status']}",
                                fix="Disable debug mode and generic error pages in deployed environments."))
    return out


def check_cors(base, scheme, host, port, ip, budget) -> list[Finding]:
    probe = "https://secaudit-origin-check.invalid"
    res = _request(scheme, host, port, ip, "GET", "/", budget, headers={"Origin": probe})
    if "error" in res:
        return []
    acao = res["headers"].get("access-control-allow-origin", "")
    cred = res["headers"].get("access-control-allow-credentials", "").lower() == "true"
    if acao == probe and cred:
        return [_finding(base, "CORS reflects arbitrary origins with credentials",
                         "An unrelated Origin is echoed in Access-Control-Allow-Origin with credentials allowed, so any "
                         "website can read authenticated responses.", "high", "CWE-942",
                         f"ACAO: {acao}; ACAC: true", fix="Allowlist trusted origins; never reflect Origin with credentials.")]
    if acao == "*" and cred:
        return [_finding(base, "CORS wildcard with credentials", "ACAO * combined with credentials.", "medium",
                         "CWE-942", "ACAO: *; ACAC: true", fix="Use an explicit origin allowlist.")]
    return []


def run_dast(scope: Scope, url: str, inventory: dict | None = None, max_requests: int = 50,
             min_interval: float = 0.2) -> tuple[list[Finding], dict]:
    scheme, host, port, ip = authorize(scope, url)
    budget = Budget(max_requests=max_requests, min_interval=min_interval)
    base = f"{scheme}://{host}:{port}"
    start_path = urlsplit(url).path or "/"
    paths = [start_path]
    for r in (inventory or {}).get("routes", []):
        p = r["path"]
        if r["method"] in ("GET", "ROUTE", "ALL") and p.startswith("/") and "<" not in p and ":" not in p \
                and "{" not in p and "*" not in p and p not in paths:
            paths.append(p)
    if scope.intensity == "standard":
        paths += [p for p in WELL_KNOWN if p not in paths]
    findings: list[Finding] = []
    first = True
    skipped = []
    for p in paths:
        if budget.used >= budget.max_requests - 1:
            skipped.append(p)
            continue
        res = _request(scheme, host, port, ip, "GET", p, budget)
        if first:
            res["_primary"] = True
            first = False
        findings += check_response(base, res, scheme)
        if p in WELL_KNOWN and res.get("status") == 200 and p in ("/console", "/.env", "/.git/HEAD", "/actuator/env",
                                                                    "/server-status", "/phpinfo.php"):
            findings.append(_finding(urljoin(base, p), f"Sensitive endpoint reachable: {p}",
                                     f"GET {p} returned 200.", "high", "CWE-200", f"status 200, {len(res.get('body',''))} bytes",
                                     conf="medium", fix="Remove or restrict this endpoint."))
    if budget.used < budget.max_requests:
        findings += check_cors(base, scheme, host, port, ip, budget)
    seen, uniq = set(), []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            uniq.append(f)
    meta = {"url": url, "pinned_ip": ip, "intensity": scope.intensity, "requests": budget.used,
            "max_requests": max_requests, "methods": sorted({e["method"] for e in budget.log}),
            "paths_skipped_budget": skipped, "log": budget.log}
    return uniq, meta


class ZapBaselineAdapter:
    """OWASP ZAP baseline (passive) scan, if ZAP's zap-baseline.py is installed. Not available in all environments."""
    name = "zap-baseline"
    binary = "zap-baseline.py"

    def __init__(self, tool_dirs):
        self.path = safe_exec.which(self.binary, tool_dirs)

    def run(self, scope: Scope, url: str, store: RunStore, timeout: int = 900) -> tuple[list[Finding], dict]:
        authorize(scope, url)
        if not self.path:
            return [], {"status": "UNAVAILABLE", "reason": "zap-baseline.py not found (install OWASP ZAP)"}
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "zap.json"
            er = safe_exec.run([self.path, "-t", url, "-J", str(out), "-I", "-m", "1"], cwd=Path(tmp),
                               env=safe_exec.build_env(network=True), timeout=timeout)
            raw = out.read_bytes() if out.exists() else b""
        ref = store.save_raw("zap-baseline.json", raw, {"tool": "zap-baseline", "argv": er.argv, "exit_code": er.returncode})
        if er.timed_out:
            return [], {"status": "TIMED_OUT", "raw": ref}
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return [], {"status": "FAILED", "reason": "unparseable ZAP output", "raw": ref}
        risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
        findings = []
        for site in data.get("site", []):
            for al in site.get("alerts", []):
                cwe = f"CWE-{al.get('cweid')}" if str(al.get("cweid", "")).isdigit() and al.get("cweid") != "-1" else "CWE-16"
                inst = (al.get("instances") or [{}])[0]
                findings.append(Finding(
                    id=code_id("zap:" + str(al.get("pluginid")), inst.get("uri", url), al.get("name", "")),
                    kind="dynamic", title=al.get("name", "ZAP alert"), description=al.get("desc", "")[:600],
                    severity=risk.get(str(al.get("riskcode")), "info"), confidence="medium", category="dast",
                    cwe=[cwe], locations=[Location(inst.get("uri", url))],
                    evidence=[Evidence("zap-baseline", str(al.get("pluginid")), al.get("name", ""), ref)],
                    tools=["zap-baseline"], remediation=al.get("solution", "")[:400] or None))
        return findings, {"status": "COMPLETED", "raw": ref, "alerts": len(findings)}


def _reload_scope(scope_dict: dict) -> Scope:
    """Re-read the operator manifest recorded at scan time and refuse if it changed."""
    from .paths import is_within
    src = scope_dict.get("source")
    if not scope_dict.get("source_sha256") or not src or not Path(src).exists():
        raise ScopeError("dynamic testing needs an operator scope manifest granting dynamic_testing")
    target = Path(scope_dict["target"])
    scope = load_scope(target, Path(src), allow_in_target=is_within(Path(src).resolve(), target))
    if scope.source_sha256 != scope_dict["source_sha256"]:
        raise ScopeError("scope manifest changed since the scan; start a new scan")
    return scope


def record(run_dir: Path, url: str, max_requests: int = 50, min_interval: float = 0.2, zap: bool = False,
           timeout: int = 900) -> dict:
    """Run passive checks (and optionally ZAP baseline) and add them to an existing run's report."""
    from .adapters.base import CheckResult
    from .pipeline import tool_dirs
    from .prioritize import enrich
    from .redact import redact_obj
    from .report import render
    run = Path(run_dir).resolve(strict=True)
    store = RunStore(run)
    state = json.loads((run / "state.json").read_text())
    scope = _reload_scope(state["scope"])
    if not 1 <= max_requests <= 500:
        raise SecauditError("--max-requests must be between 1 and 500")
    if min_interval < 0.05:
        raise SecauditError("--min-interval must be at least 0.05 s")
    inventory = json.loads((run / "inventory.json").read_text())
    t0 = time.monotonic()
    findings, meta = run_dast(scope, url, inventory, max_requests=max_requests, min_interval=min_interval)
    ref = store.save_raw(f"dast-http-{len([c for c in state['checks'] if c['check_id'].startswith('dast-http')])}.json",
                         json.dumps(meta, indent=2).encode(), {"tool": "secaudit-http", "url": url})
    errors = sum(1 for e in meta["log"] if "error" in e)
    status = "FAILED" if errors == meta["requests"] else "PARTIAL" if errors or meta["paths_skipped_budget"] else "COMPLETED"
    checks = [CheckResult(
        check_id="dast-http", tool="secaudit-http", category="dast", permissions_required=["dynamic_testing"],
        objective=f"Passive HTTP checks (headers, cookies, CORS, debug output) against {url}",
        status=status, duration_s=round(time.monotonic() - t0, 2), raw_outputs=[ref], findings_count=len(findings),
        reason=f"{meta['requests']} GET requests to pinned {meta['pinned_ip']}, {errors} errors, "
               f"{len(meta['paths_skipped_budget'])} paths skipped (budget)",
        notes=["passive only: no payloads, no state-changing methods, redirects not followed"])]
    if zap:
        zf, zmeta = ZapBaselineAdapter(tool_dirs()).run(scope, url, store, timeout=timeout)
        findings += zf
        checks.append(CheckResult(check_id="dast-zap", tool="zap-baseline", category="dast",
                                  permissions_required=["dynamic_testing"], objective=f"OWASP ZAP baseline (passive) scan of {url}",
                                  status=zmeta["status"], reason=zmeta.get("reason"), findings_count=len(zf),
                                  raw_outputs=[zmeta["raw"]] if zmeta.get("raw") else []))
    findings = enrich(findings, inventory, scope.target)
    known = {f["id"] for f in state["findings"]}
    state["findings"] += [f.to_dict() for f in findings if f.id not in known]
    state["checks"] = [c for c in state["checks"] if c["check_id"] != "dast"] + [c.to_dict() for c in checks]
    store.write_json("state.json", redact_obj(state))
    render(store)
    return {"checks": [{"check_id": c.check_id, "status": c.status, "reason": c.reason} for c in checks],
            "findings": [{"id": f.id, "severity": f.severity, "title": f.title} for f in findings],
            "requests": meta["requests"], "methods": meta["methods"], "report_md": str(run / "report.md")}
