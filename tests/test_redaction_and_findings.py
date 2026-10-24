from secaudit.findings import Evidence, Finding, Location, code_id, merge
from secaudit.redact import redact


def test_redacts_common_secret_shapes():
    text = ("key=AKIAABCDEFGHIJKLMNOP token ghp_" + "a" * 36 +
            '\npassword = "hunter2hunter2"\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----'
            "\npostgres://user:s3cretpw@db/x")
    out = redact(text)
    for s in ("AKIAABCDEFGHIJKLMNOP", "ghp_aaaa", "hunter2hunter2", "MIIabc", "s3cretpw"):
        assert s not in out
    assert 'password = "[REDACTED]"' in out


def test_code_ids_ignore_line_shifts_and_whitespace():
    assert code_id("CWE-89", "app.py", "  cur.execute(q)") == code_id("CWE-89", "app.py", "cur.execute(q)   ")
    assert code_id("CWE-89", "app.py", "cur.execute(q)") != code_id("CWE-89", "other.py", "cur.execute(q)")


def _f(tool, cwe, line=10, sev="medium", conf="medium"):
    return Finding(id=code_id(cwe, "a.py", f"x{tool}"), kind="code", title=tool, description="", severity=sev,
                   confidence=conf, category="c", cwe=[cwe], locations=[Location("a.py", line)],
                   evidence=[Evidence(tool, "r", "m")], tools=[tool])


def test_cross_tool_merge_keeps_all_evidence_and_raises_confidence():
    merged = merge([_f("semgrep", "CWE-89", sev="high"), _f("bandit", "CWE-89", sev="medium")])
    assert len(merged) == 1
    f = merged[0]
    assert f.tools == ["semgrep", "bandit"] and len(f.evidence) == 2
    assert f.severity == "high" and f.confidence == "high"


def test_related_cwes_on_same_line_merge_but_different_lines_do_not():
    assert len(merge([_f("semgrep", "CWE-916"), _f("bandit", "CWE-327")])) == 1
    assert len(merge([_f("semgrep", "CWE-89", line=1), _f("bandit", "CWE-89", line=2)])) == 2
    assert len(merge([_f("semgrep", "CWE-89"), _f("bandit", "CWE-22")])) == 2
