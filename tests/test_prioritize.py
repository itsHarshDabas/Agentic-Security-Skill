from pathlib import Path

from secaudit.findings import Evidence, Finding, Location
from secaudit.prioritize import enrich, is_test_path

INV = {"routes": [{"file": "app.py", "line": 1, "method": "GET", "path": "/"}], "entry_points": ["app.py"]}


def _f(path="lib.py", tools=("semgrep",), conf="medium", sev="high", kind="code", validation="unverified", line=2):
    return Finding(id=f"SA-{path}-{len(tools)}-{validation}", kind=kind, title="t", description="", severity=sev,
                   confidence=conf, category="c", cwe=["CWE-89"], locations=[Location(path, line, line)],
                   evidence=[Evidence(t, "r", "m") for t in tools], tools=list(tools), validation=validation)


def _target(tmp_path):
    for name in ("lib.py", "app.py", "tests/test_x.py"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('import x\npassword = "hunter2hunter2"\nq = 1\n')
    return tmp_path


def test_test_paths():
    assert is_test_path("tests/test_api.py") and is_test_path("src/foo.test.ts") and is_test_path("conftest.py")
    assert not is_test_path("src/testimony.py") and not is_test_path("app.py")


def test_agreement_raises_and_test_code_lowers(tmp_path):
    t = _target(tmp_path)
    one, two, test = enrich([_f(), _f(tools=("semgrep", "bandit")), _f("tests/test_x.py")], INV, t)
    assert two.confidence_score > one.confidence_score > test.confidence_score
    assert test.in_test_code and test.risk_score < one.risk_score
    assert any("independent tools" in x for x in two.confidence_factors)


def test_validation_drives_score(tmp_path):
    t = _target(tmp_path)
    c, fp, u = enrich([_f(validation="confirmed"), _f(validation="false_positive"), _f()], INV, t)
    assert c.confidence_score == 1.0 and fp.confidence_score == 0.0
    assert c.risk_score > u.risk_score and fp.risk_score == 0 and fp.priority == "P3"


def test_route_exposure_raises_risk(tmp_path):
    t = _target(tmp_path)
    lib, app = enrich([_f("lib.py"), _f("app.py")], INV, t)
    assert app.risk_score > lib.risk_score
    assert any("routes" in x for x in app.risk_factors)


def test_enrich_is_idempotent(tmp_path):
    t = _target(tmp_path)
    fs = enrich([_f("tests/test_x.py", conf="high")], INV, t)
    first = (fs[0].confidence_score, fs[0].risk_score, fs[0].confidence)
    enrich(fs, INV, t)
    assert (fs[0].confidence_score, fs[0].risk_score, fs[0].confidence) == first


def test_code_context_is_redacted_and_skipped_for_secrets(tmp_path):
    t = _target(tmp_path)
    code, secret = enrich([_f(), _f(kind="secret")], INV, t)
    assert [c["line"] for c in code.code_context] == [1, 2, 3]
    assert "hunter2hunter2" not in str(code.code_context)
    assert secret.code_context is None
