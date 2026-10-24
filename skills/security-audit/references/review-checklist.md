# Contextual review checklist

Use on the top `high_risk_files` and on every route handler. Scanners rarely catch these.

## Authorization (highest yield)
- Object-level: every handler that takes an ID (`/<id>`, `?id=`, body field) checks the record belongs to the caller or the caller has a role that allows it. Look for queries by ID without an owner/tenant predicate.
- Function-level: admin/export/delete/debug routes check a role, not just "logged in".
- Mass assignment: request JSON copied into models/SQL/updates (`**request.json`, `Object.assign(user, req.body)`, dynamic column lists) letting users set `role`, `is_admin`, `owner_id`, `balance`.
- Tenancy: multi-tenant queries always filter by tenant.

## Authentication and sessions
- Password storage uses argon2/bcrypt/scrypt; comparisons are constant time.
- Session/JWT: secret not hardcoded; algorithm pinned; `verify` not disabled; expiry enforced; logout invalidates server-side state where relevant.
- Password reset tokens: random, single-use, expiring, not leaked in URLs/logs; reset does not reveal account existence.
- Login/reset/OTP endpoints have rate limiting or lockout.

## Input handling
- Every flow from request to SQL, shell, filesystem, template, URL fetch, redirect, deserializer, or `eval` that scanners did not already flag.
- Upload: size limit, type check on content, stored outside web root, generated filenames.
- Download: path resolved and checked against a base directory.

## Business logic
- Negative/zero/huge quantities and prices; currency rounding; replayed or reordered steps (pay → ship); race conditions on balance or inventory updates (check-then-act without a transaction/lock).

## Data exposure
- Responses return whole ORM objects (password hashes, tokens, internal fields).
- Errors return stack traces or SQL in production configuration.
- Logs contain passwords, tokens, or personal data.

## Configuration
- Debug modes, permissive CORS with credentials, missing security headers set in code, default credentials, admin interfaces bound to 0.0.0.0.
- CI: `pull_request_target`, script injection from event fields, broad token permissions, unpinned third-party actions.

Record each issue as a contextual finding with the exact line. If you suspect something but cannot confirm the precondition, use `probable` and say what is unverified.
