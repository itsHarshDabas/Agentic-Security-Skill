# Triage guide

## Decision criteria

| Validation | Use when | Required |
|---|---|---|
| `confirmed` | You traced attacker-controlled input to the sink with no effective control, or reproduced it safely. | `rationale` + `reproduction` or `evidence` |
| `probable` | Code inspection supports exploitability but a precondition is unverified (e.g. route exposure, config). | `rationale` |
| `informational` | Real weakness or hygiene issue without a plausible attack path in this context. | `rationale` |
| `false_positive` | The flagged pattern is not a vulnerability here (constant input, non-security use, effective sanitization). | `rationale` naming the reason |
| `unverified` | Default. Leave findings you did not inspect as unverified rather than guessing. | — |

Rationale must be specific: name the variable, the control (or its absence) and the line. "Looks fine" is rejected in spirit even if it passes the length check.

Adjust severity only with a reason (exposure, privileges required, data sensitivity, existing mitigations). Do not raise severity on a hunch; lower confidence instead.

Dependency findings: check whether the vulnerable function or feature is used. If you cannot tell, keep `unverified` and say so; recommend the fixed version anyway.

Secrets: never paste the secret into triage text. Decide whether it is a real credential, a test fixture, or an example; recommend rotation only if it may be real.

## triage.json

```json
{
  "reviewer": "claude (security-audit skill)",
  "decisions": [
    {"id": "SA-1a2b3c4d5e6f", "validation": "false_positive",
     "rationale": "hashlib.md5 is used to compute an HTTP ETag in etag(); no security property depends on it."},
    {"id": "SA-0f9e8d7c6b5a", "validation": "confirmed", "severity": "critical",
     "rationale": "username from request.form is interpolated into the SELECT on line 35 with no parameterization.",
     "reproduction": "POST /login with username=' OR '1'='1' -- and any password logs in as the first user.",
     "root_cause": "SQL built with an f-string", "impact": "Authentication bypass and arbitrary data read."}
  ],
  "contextual_findings": [
    {"title": "Invoice IDOR", "severity": "high", "confidence": "high", "validation": "probable",
     "category": "broken-object-level-authorization", "cwe": ["CWE-639"],
     "description": "Any authenticated user can read any invoice by ID.",
     "rationale": "get_invoice() checks login but never compares invoices.owner_id with the session user.",
     "locations": [{"path": "app.py", "start_line": 48}],
     "remediation": "Add `AND owner_id = ?` with the session user id and return 404 when no row matches."}
  ]
}
```

Allowed keys are fixed; unknown keys are rejected. `locations[].path` must be an existing file inside the target.
