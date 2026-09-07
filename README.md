# Secure Child Data Management System

Capstone project — Kenson Lagat (166450), Strathmore University.
Secure web-based child data management system for Kenyan schools and
children's homes, built with Flask + PostgreSQL.

## Project structure

```
app/
  __init__.py          # App factory — wires config, extensions, blueprints
  config.py            # Dev/Test/Prod config, all secrets via .env
  models/              # SQLAlchemy models = your ERD entities
  blueprints/           # One folder per module from the proposal
    auth/               # Sprint 1: registration, login, OTP
    admin/              # User/role management, mode config, audit access
    school_mode/         # Sprint 3
    childrens_home_mode/ # Sprint 4
    audit/               # Sprint 5: tamper-proof logging
    notifications/       # Sprint 6: SMS via Africa's Talking
    anomaly/             # Sprint 7: Isolation Forest anomaly detection
  services/             # Reusable logic: OTP, SMS, audit writing
  middleware/           # rbac.py — role enforcement, runs on every request
  templates/, static/    # Frontend
migrations/             # Flask-Migrate/Alembic migration files
tests/                  # pytest
run.py                  # Entry point
```

## Local setup

1. **Clone and enter the project**, then create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Set up PostgreSQL** — create a local database:
   ```bash
   createdb child_data_system
   ```

3. **Copy the environment template** and fill in real values:
   ```bash
   cp .env.example .env
   ```
   Generate a `FIELD_ENCRYPTION_KEY`:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Get free `AFRICASTALKING_API_KEY` sandbox credentials at
   https://account.africastalking.com (sign up, create an app, use sandbox mode).

4. **Initialize the database**:
   ```bash
   flask db init        # only once, ever
   flask db migrate -m "initial schema"
   flask db upgrade
   ```

5. **Run the app**:
   ```bash
   python run.py
   ```

## Git workflow

```bash
git init
git add .
git commit -m "Initial project scaffold"
```

Suggested branch pattern for the sprint structure: `sprint-1-auth`,
`sprint-2-rbac`, etc. — merge to `main` at the end of each sprint review,
matching your Scrum sprint reviews in the proposal.

## Working with GitHub Copilot on this project

Copilot is a **typing accelerator inside an architecture I've already
designed with you** — not the architect. That distinction matters a lot on
a project like this, where the whole point is deliberate security design
(RBAC boundaries, tamper-proof logs, encryption). A generic Copilot
suggestion optimized for "get it working" can quietly undermine that.

Rules of thumb:

1. **Never let Copilot invent a data model, route structure, or security
   check from scratch.** Bring me the task first ("I need to build X"), I'll
   give you the plan/interface/pseudocode, then let Copilot help you
   type out the implementation against that shape.

2. **Write a clear docstring or comment before the function**, then let
   Copilot complete it. Copilot's autocomplete quality is directly
   proportional to how specific your comment is. Compare:
   - Weak: `# check password`
   - Strong: `# verify submitted password against user.password_hash using
     werkzeug's check_password_hash; return False if user is None`

3. **Treat every Copilot suggestion touching security as a draft to review
   with me**, specifically:
   - Anything with `password`, `otp`, `token`, `encrypt`, `decrypt`
   - Anything touching `AuditLogEntry` (must stay insert-only — if Copilot
     suggests an `.update()` or `.delete()` on it, reject it)
   - Anything touching role checks (`require_role`, `current_user.role`)

4. **Use Copilot Chat (not just inline autocomplete) for**: writing test
   cases, explaining an error traceback, converting a snippet's style,
   generating boilerplate HTML templates. These are lower-risk and
   Copilot Chat is genuinely good at them.

5. **Paste tricky errors or design questions back to me** rather than
   accepting a Copilot fix you don't understand — on a security-focused
   capstone, your supervisor will ask you to explain *why* something works,
   not just show that it runs.

## Sprint plan (from proposal, Chapter 3)

| Sprint | Module | Duration |
|---|---|---|
| 1 | Authentication | 2 weeks |
| 2 | Role-Based Access Control | 2 weeks |
| 3 | School Mode | 2 weeks |
| 4 | Children's Home Mode | 2 weeks |
| 5 | Audit Logging | 2 weeks |
| 6 | Notifications + Dashboard | 2 weeks |
| 7 | Anomaly Detection | 2 weeks |
