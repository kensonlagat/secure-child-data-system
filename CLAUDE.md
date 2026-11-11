# Secure Child Data Management System

Capstone project (Strathmore University). Flask + PostgreSQL web app for Kenyan schools and
children's homes. The point of the project is the security architecture, not the CRUD: role
scoping, an append-only audit log, OTP-gated sensitive actions, encryption at rest, and
anomaly detection. Never trade these away for convenience.

## Working agreement
- The user is a student. Explain security-relevant decisions briefly and plainly.
- One task per branch. Branch from updated `main`, commit in small steps, open a PR with
  `gh pr create`. Merge with a merge commit (`gh pr merge <n> --merge`), never squash, so
  stacked PRs keep a clean diff.
- Merge rule. Claude Code may merge a PR itself only when one of these is true:
  (a) `gh pr diff <n> --name-only` shows no security-tier files AND the full test suite
  passes on the branch; or (b) the user has said "approved #N" in the current session
  (for security-tier PRs, that comes after the lead engineer's review). Never merge a
  security-tier PR on your own judgement. Merge one PR at a time, in stack order. After each
  merge: `git checkout main; git pull`, run the full suite, and stop and tell the user if
  anything fails. Report one line per merge: merged, tests passed or failed.
- Every task has a GitHub issue. Use "Refs #N" in commits and "Closes #N" in the PR body.
  Assign new issues to milestone 7 with
  `gh api -X PATCH repos/kensonlagat/secure-child-data-system/issues/<n> --field milestone=7`
  (`gh issue create --milestone <number>` fails).
- Never print, log or paste secrets in commands or output. Read them from `.env`. Never put
  passwords or keys in tracked files, and never pass a key on a command line.
- No formatting-only changes in files you are not otherwise changing.
- If you change anything beyond what was asked, say so explicitly in your summary.
- Report real command output for tests. Never claim something passed without running it.
- Security-tier files are reviewed by the user's separate "lead engineer" chat before merge.
  Before asking for that review, run an adversarial self-review of the diff against the hard
  rules (fail-open defaults, missing audit rows, sensitive data in logs or responses, OTP
  identity and single-use gaps, UI-only permission checks), put findings and fixes in the PR
  description, and give the exact `git diff` command for the security-tier files. End every
  task by listing the exact security-tier files you changed. UI, template, CSS, docs and
  test-only PRs need no lead engineer review.
- Security tier: `app/services/access_service.py`, `app/middleware/rbac.py`,
  `app/services/audit_service.py`, `app/services/otp_service.py`, `app/services/sms_service.py`,
  `app/services/record_validation.py`, `app/blueprints/auth/routes.py`, every migration, every
  model change, and anything touching the legal-status or deletion flows.

## Hard rules (do not break these, even if a shortcut would work)
1. The audit log is insert-only. All writes go through `log_action()` in
   `app/services/audit_service.py`. Never update or delete audit rows in app code. The one
   sanctioned exception is `flask clear-synthetic-audit-data`, which deletes `is_synthetic`
   rows only. Never log sensitive values (names, medical notes, OTP codes, passwords).
2. Fail closed. Role scoping lives in `app/services/access_service.py`
   (`get_accessible_records`, `can_access_record`, `get_visible_fields`, `get_writable_fields`).
   Routes never query `ChildRecord` directly. Write permissions are ALLOWLISTS, never
   denylists (a denylist once failed open when new columns were added).
3. `legal_status` is never writable through generic updates, for any role. It changes only
   through the two-person workflow: requester is not the approver, each OTP is bound to the
   user it was sent to, and the status must be in `VALID_LEGAL_STATUSES`.
4. Deletion is soft (`is_deleted`), admin-only and OTP-gated. `is_deleted` and `deleted_at`
   are not writable via PATCH. Deleted records are invisible to every role.
5. Sensitive columns (`full_name`, `guardian_contact`, `medical_notes`) use `EncryptedType`.
   Any new sensitive field must be encrypted too.
6. Passwords and OTP codes are hashed. OTP codes come from `secrets`. OTPs expire in 5
   minutes, lock after 5 attempts, are single use, and are identity-bound
   (`otp.user_id == current_user.id`). The `action_context` string must match exactly between
   generation and lookup.
7. No account enumeration. Public endpoints return identical responses with matching timing
   (forgot-password has a 2 s response floor, login does one hash on every failure path).
8. CSRF is enforced (Flask-WTF). Forms need `csrf_token`. `fetch()` gets the token from
   `static/js/csrf.js`. Do not exempt routes.
9. Use `require_role()` and `@login_required` for protected routes.
10. Anomaly detection is alert-only and never blocks. Models are trained on synthetic data only.
    Real data is scored but never trained on.
11. The web app currently connects as the `postgres` superuser. The least-privilege DB role
    (issue #72) and row-level security (issue #19) are NOT built yet. Do not describe the audit
    log as database-enforced until #72 is merged.

## Stack and commands (Windows, PowerShell)
Python 3.12.10, Flask 3.0.3 app factory + blueprints, SQLAlchemy/Flask-Migrate, Flask-Login,
Flask-WTF, PostgreSQL 17, Jinja2 templates with vanilla JS, scikit-learn, Africa's Talking SMS
via `curl_cffi` (plain `requests` fails TLS on this machine, so this is a documented
environment workaround). Local machine notes, including how to start PostgreSQL, are in
`CLAUDE.local.md`.
- Activate venv: `.\.venv\Scripts\Activate.ps1`
- Run app: `python run.py` (http://127.0.0.1:5000/login)
- Tests: `python -m pytest`
- Migrations: `$env:FLASK_APP='run.py'; flask db migrate -m "..."; flask db upgrade`. After
  generating a migration that touches encrypted columns, check it has `import sqlalchemy_utils`.
- CLI: `seed-roles`, `create-admin`, `test-sms --to <phone>`, `generate-synthetic-audit-data`,
  `clear-synthetic-audit-data`, `train-anomaly-models`, `score-anomalies`.
- Secrets live in `.env` (gitignored). SMS uses the Africa's Talking sandbox, so messages
  appear in its simulator, not on a phone.

## Structure
`app/__init__.py` (factory), `app/config.py`, `app/models/`, `app/blueprints/<module>/routes.py`
(auth, admin, school_mode, childrens_home_mode, audit, notifications, anomaly),
`app/services/`, `app/middleware/rbac.py`, `app/templates/`, `app/static/`, `tests/`.

## Roles and scoping
- administrator: all non-deleted records, both modes. Writes only `full_name`, `date_of_birth`,
  `guardian_contact`, `class_assigned`, `medical_notes`, `caseload_worker_id`.
- teacher: school records in their own class. Writes `guardian_contact` only.
- school_nurse (shown as "clinical officer"): school records, writes `medical_notes`.
- social_worker: own caseload in children's-home mode, writes `medical_notes`.
- legal_officer: all children's-home records, no direct writes (workflow only).
- parent_guardian: no access yet. Planned: principal (school) and home_manager
  (children's home), both read-only oversight of their own mode.

## Design decisions already made
- A portal dropdown (School / Children's Home) never decides access. After the password
  verifies, the server checks the role's `institution_mode` against the chosen portal.
- Parents sign in by phone number plus OTP and see only linked children, with a reduced field
  set (needs a guardian-link table).
- Record creation stays admin-only. A teacher cannot change `class_assigned`.

## Current state
Done: authentication, RBAC with field scoping, record create/update, OTP soft-delete,
two-person legal-status workflow, forgot password, CSRF, SMS service, dashboard UI, anomaly
pipeline. Merged 2026-11-11: login hardening with lockout, portal binding and hashed unknown
identifiers (#38); the "safeguarding ledger" UI foundation and landing page (#44);
administrators see one portal at a time and can switch, display only (#46); every
`require_role` refusal is audited, bounded to one row per actor, endpoint and minute, and
never blocks the 401/403 (#46). 79 tests on main.

Open: #37 SMS diagnostics touches `sms_service.py` (security tier), so it needs the
self-review and an "approved #37" before merging. Review follow-ups: #73 (audit-hash subkey,
refuse default `SECRET_KEY`), #74 (lowercase email in forgot/reset), #75 (bound record-level
`access_denied` auditing; record refusals are audited but not yet bounded).

Unconfirmed: the OTP deletion test on record 43, and the guardian SMS appearing in the
simulator.

## Roadmap (in order)
The build order lives in tracking issue #71 (agreed 2026-11-11). Check it off as PRs merge.
1. Foundations: user management (#30), new roles and safeguarding-lead flag (#47),
   least-privilege DB role (#72, right after #47), classes and enrolment (#48), fuller child
   profile (#49), search and pagination (#32).
2. Safeguarding and consent: safeguarding concerns (#62; admins see metadata only, every
   narrative read audited), consent (#63).
3. School daily work: attendance (#50), pickup list (#51), clinic log (#52), principal overview (#53).
4. Children's home: intake (#54), care plan and case notes (#55), court dates (#56), health and
   medication (#57), family visits (#58), placement and aftercare (#59), missing child alert
   (#60), home manager overview (#61).
5. Record life cycle: archiving (#64), OTP-protected export (#65), document storage (#66).
6. Parents and hardening: parent sign-in (#67), staff second sign-in step (#68), audit log
   viewer (#31), backups (#69), report cards (#70), row-level security (#19, last).
Ongoing: tests in every PR (#33), notifications (#20), report (#21). Left out on purpose: fees,
timetables, library, transport, payroll, biometrics.

## Known limitations (keep honest in the report)
- OTP attempt limit is per code, not per account. `/forgot-password` has no rate limit (#25).
- The SMS call is not sent off the request path (#26), so a slow provider can leak timing.
- Anomaly detection covers administrator, teacher and legal_officer only, trained on synthetic
  data. Failed logins for unknown emails have no `user_id`, so the model never sees them.
- Only the sandbox SMS host is exercised. Live credentials are untested.
