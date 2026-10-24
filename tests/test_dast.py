"""Phase 5: passive, scope-locked dynamic checks against a local test server."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import make_fake_tool
from secaudit import dast
from secaudit.cli import main
from secaudit.errors import ScopeError
from secaudit.evidence import RunStore
from secaudit.pipeline import scan
from secaudit.scope import load_scope

TRACE = "Traceback (most recent call last):\n  File \"app.py\", line 3\nValueError: boom"


class Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _reply(self):
        Handler.seen.append((self.command, self.path, self.headers.get("Host"), self.headers.get("Origin")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://198.51.100.7/elsewhere")
            self.end_headers()
            return
        body = TRACE.encode() if self.path == "/err" else b"<html>ok</html>"
        self.send_response(500 if self.path == "/err" else 200)
        self.send_header("Server", "Werkzeug/2.0.1 Python/3.11")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _reply


@pytest.fixture
def server():
    Handler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _scope(tmp_path, urls, intensity="passive", **perms):
    target = tmp_path / "app"
    target.mkdir(exist_ok=True)
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    m = tmp_path / "scope.json"
    m.write_text(json.dumps({"version": 1, "permissions": perms, "targets": {"urls": urls}, "intensity": intensity}))
    return load_scope(target, m)


INV = {"routes": [{"method": "GET", "path": "/health", "file": "app.py"},
                  {"method": "GET", "path": "/err", "file": "app.py"},
                  {"method": "GET", "path": "/user/<int:id>", "file": "app.py"},
                  {"method": "POST", "path": "/delete", "file": "app.py"},
                  {"method": "GET", "path": "/redirect", "file": "app.py"}]}


def test_passive_checks_find_headers_cookies_cors_and_stack_traces(tmp_path, server):
    sc = _scope(tmp_path, [server], dynamic_testing=True)
    findings, meta = dast.run_dast(sc, server + "/", INV, min_interval=0.01)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "No clickjacking protection" in titles
    assert "Version disclosed in server header" in titles
    assert any(t.startswith("Cookie session missing HttpOnly") for t in titles)
    assert "CORS reflects arbitrary origins with credentials" in titles
    assert "Python stack trace in response" in titles
    assert all(f.kind == "dynamic" and f.tools == ["secaudit-http"] for f in findings)
    # GET only; parameterised and POST routes are not requested; redirects are not followed.
    assert {m for m, *_ in Handler.seen} == {"GET"} and meta["methods"] == ["GET"]
    paths = [p for _, p, *_ in Handler.seen]
    assert "/delete" not in paths and not any("<" in p for p in paths)
    assert paths.count("/redirect") == 1 and "/elsewhere" not in paths
    # The only non-default header sent is the benign CORS origin.
    assert {o for *_, o in Handler.seen} == {None, "https://secaudit-origin-check.invalid"}
    assert meta["requests"] == len(Handler.seen)
    assert "body" not in json.dumps(meta["log"])


def test_passive_intensity_does_not_probe_well_known_paths(tmp_path, server):
    dast.run_dast(_scope(tmp_path, [server], dynamic_testing=True), server, {}, min_interval=0.01)
    assert not any(p in dast.WELL_KNOWN for _, p, *_ in Handler.seen)
    Handler.seen = []
    dast.run_dast(_scope(tmp_path, [server], intensity="standard", dynamic_testing=True), server, {},
                  max_requests=100, min_interval=0.01)
    assert {p for _, p, *_ in Handler.seen} >= set(dast.WELL_KNOWN)


def test_request_budget_is_enforced(tmp_path, server):
    sc = _scope(tmp_path, [server], intensity="standard", dynamic_testing=True)
    _, meta = dast.run_dast(sc, server, INV, max_requests=3, min_interval=0.01)
    assert len(Handler.seen) == meta["requests"] <= 3
    assert meta["paths_skipped_budget"]
    b = dast.Budget(max_requests=1, min_interval=0)
    b.take()
    with pytest.raises(Exception, match="budget"):
        b.take()


def test_requires_dynamic_testing_permission(tmp_path, server):
    with pytest.raises(ScopeError, match="dynamic_testing"):
        dast.run_dast(_scope(tmp_path, [server]), server, {})
    assert Handler.seen == []


@pytest.mark.parametrize("url", ["http://127.0.0.1:1/", "http://localhost:{port}/", "https://127.0.0.1:{port}/",
                                 "http://user:pw@127.0.0.1:{port}/", "ftp://127.0.0.1:{port}/"])
def test_url_must_match_an_allowed_origin_exactly(tmp_path, server, url):
    port = server.rsplit(":", 1)[1]
    with pytest.raises(ScopeError):
        dast.run_dast(_scope(tmp_path, [server], dynamic_testing=True), url.format(port=port), {})
    assert Handler.seen == []


def _fake_dns(monkeypatch, ip):
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if host.endswith(".test") or host == "example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real(host, port, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_public_address_needs_external_services(tmp_path, monkeypatch):
    _fake_dns(monkeypatch, "93.184.216.34")
    with pytest.raises(ScopeError, match="external_services"):
        dast.authorize(_scope(tmp_path, ["https://example.com"], dynamic_testing=True), "https://example.com/")
    sc = _scope(tmp_path, ["https://example.com"], dynamic_testing=True, external_services=True)
    assert dast.authorize(sc, "https://example.com/")[3] == "93.184.216.34"


def test_link_local_metadata_address_always_refused(tmp_path, monkeypatch):
    _fake_dns(monkeypatch, "169.254.169.254")
    sc = _scope(tmp_path, ["http://meta.test"], dynamic_testing=True, external_services=True)
    with pytest.raises(ScopeError, match="link-local"):
        dast.authorize(sc, "http://meta.test/")


def test_requests_go_to_the_pinned_ip_with_original_host(tmp_path, server, monkeypatch):
    port = int(server.rsplit(":", 1)[1])
    _fake_dns(monkeypatch, "127.0.0.1")
    url = f"http://app.test:{port}"
    _, meta = dast.run_dast(_scope(tmp_path, [url], dynamic_testing=True), url, {}, min_interval=0.01)
    assert meta["pinned_ip"] == "127.0.0.1"
    assert {h for _, _, h, _ in Handler.seen} == {f"app.test:{port}"}


def test_zap_adapter_unavailable_and_parses_fake_output(tmp_path, server):
    sc = _scope(tmp_path, [server], dynamic_testing=True)
    (tmp_path / "run" / "evidence").mkdir(parents=True)
    store = RunStore(tmp_path / "run")
    ad = dast.ZapBaselineAdapter([str(tmp_path / "empty")])
    ad.path = None
    assert ad.run(sc, server, store)[1]["status"] == "UNAVAILABLE"
    report = {"site": [{"alerts": [{"pluginid": "10038", "name": "CSP Header Not Set", "riskcode": "2", "cweid": "693",
                                    "desc": "d", "solution": "s", "instances": [{"uri": server + "/"}]}]}]}
    make_fake_tool(tmp_path / "bin", "zap-baseline.py",
                   "import sys, json\nout = sys.argv[sys.argv.index('-J') + 1]\n"
                   f"open(out, 'w').write(json.dumps({report!r}))\n")
    findings, meta = dast.ZapBaselineAdapter([str(tmp_path / "bin")]).run(sc, server, store)
    assert meta["status"] == "COMPLETED"
    assert findings[0].severity == "medium" and findings[0].cwe == ["CWE-693"]
    with pytest.raises(ScopeError):
        dast.ZapBaselineAdapter([str(tmp_path / "bin")]).run(sc, "http://127.0.0.1:1/", store)


def test_cli_records_dast_into_run_and_report(tmp_path, server, capsys):
    sc = _scope(tmp_path, [server], dynamic_testing=True)
    store = scan(sc, tmp_path / "runs", only=set())
    r = json.loads((store.path / "report.json").read_text())
    assert {c["check_id"]: c["status"] for c in r["checks"]}["dast"] == "PENDING"
    assert main(["dast", str(store.path), "--url", server, "--min-interval", "0.05"]) == 0
    r = json.loads((store.path / "report.json").read_text())
    checks = {c["check_id"]: c for c in r["checks"]}
    assert "dast" not in checks and checks["dast-http"]["status"] in ("COMPLETED", "PARTIAL")
    assert any(f["kind"] == "dynamic" for f in r["findings"])
    assert any("passive (GET only" in s for s in r["coverage_limitations"])
    assert "dynamic" in (store.path / "report.md").read_text()
    assert main(["dast", str(store.path), "--url", server, "--max-requests", "0"]) == 3
    (tmp_path / "scope.json").write_text(json.dumps({"version": 1, "permissions": {"dynamic_testing": True},
                                                      "targets": {"urls": [server, "http://10.0.0.5"]}}))
    assert main(["dast", str(store.path), "--url", server]) == 2
    assert "changed since the scan" in capsys.readouterr().err


def test_cli_refuses_run_without_manifest(tmp_path, server, capsys):
    target = tmp_path / "app"
    target.mkdir()
    store = scan(load_scope(target, None), tmp_path / "runs", only=set())
    assert main(["dast", str(store.path), "--url", server]) == 2
    assert Handler.seen == []
