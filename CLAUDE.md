# Secure Child Data Management System

Capstone project (Strathmore University). Flask + PostgreSQL web app for Kenyan schools and
children's homes. The point of the project is the security architecture, not the CRUD: role
scoping, an append-only audit log, OTP-gated sensitive actions, encryption at rest, and
anomaly detection. Never trade these away for convenience.

## Working agreement
- The user is a student. Explain security-relevant decisions briefly and plainly.
- One task per branch. Branch from updated `main`, commit in small steps, open a PR with
  `gh pr create`. NEVER merge a PR. The user merges.
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
  End every task by listing the exact security-tier files you changed so the user can paste
  their diff there.
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
11. The web app currently connects as the `postgres` superuser. The least-privilege DB role and
    row-level security are NOT built yet (issue #19). Do not describe the audit log as
    database-enforced until they are.

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
pipeline. PR #38 (login hardening) is open and needs a follow-up commit (see below).
Unconfirmed: whether PR #37 (SMS diagnostics) is merged, the OTP deletion test on record 43,
and the guardian SMS appearing in the simulator.

Follow-up for PR #38 (`feature/login-hardening`): portal mismatch and inactive-account
handling happen after the password verifies, so they must NOT write `login_failed` rows or
count toward lockout. Staff mismatch message: "This account doesn't belong to the selected
portal. Choose the other portal and try again." Parent accounts on the staff form:
"Parent accounts use the parent sign-in." Raise `LOGIN_IP_MAX_FAILURES` to 100 (coarse flood
guard for shared networks). Add tests, and rerun the timing comparison with a real account
(`synthetic.teacher.02@example.com`), an unknown email and a locked account.

## Roadmap (in order)
1. Finish PR #38. 2. Landing/portal pages and the new roles. 3. Guardian links, parent OTP
login and a parent read-only view (strictest review). 4. One role module per PR (teacher
attendance and marks, clinical visits, principal overview, home welfare notes and court dates).
5. Admin user-management UI, audit log viewer (admin only, filters, pagination), record
search and pagination. 6. Automated tests (#33). 7. Least-privilege DB role and RLS (#19).
8. Notifications (#20). 9. Report (#21).

## Known limitations (keep honest in the report)
- OTP attempt limit is per code, not per account. `/forgot-password` has no rate limit (#25).
- The SMS call is not sent off the request path (#26), so a slow provider can leak timing.
- Anomaly detection covers administrator, teacher and legal_officer only, trained on synthetic
  data. Failed logins for unknown emails have no `user_id`, so the model never sees them.
- Only the sandbox SMS host is exercised. Live credentials are untested.
