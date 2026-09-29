# Testing Credentials

Base URL:
- http://127.0.0.1:5000/login

Primary test accounts:
- Administrator: `you@example.com` / `Admin#2026`
- Teacher: `teacher@example.com` / `Teacher#2026`
- Legal officer 1: `legal1@example.com` / `Legal#2026A`
- Legal officer 2: `legal2@example.com` / `Legal#2026B`

Synthetic administrator accounts:
- `synthetic.admin.02@example.com` / `Synthetic#2026`
- `synthetic.admin.03@example.com` / `Synthetic#2026`
- `synthetic.admin.04@example.com` / `Synthetic#2026`

Synthetic teacher accounts:
- `synthetic.teacher.02@example.com` / `Synthetic#2026` — assigned class `Grade 5B`
- `synthetic.teacher.03@example.com` / `Synthetic#2026` — assigned class `Grade 6A`
- `synthetic.teacher.04@example.com` / `Synthetic#2026` — assigned class `Grade 7C`

Synthetic legal officer accounts:
- `synthetic.legal.03@example.com` / `Synthetic#2026`
- `synthetic.legal.04@example.com` / `Synthetic#2026`
- `synthetic.legal.05@example.com` / `Synthetic#2026`

Useful routes after login:
- Admin dashboard: http://127.0.0.1:5000/admin/dashboard
- Anomaly alerts: http://127.0.0.1:5000/admin/anomaly-alerts
- School records: http://127.0.0.1:5000/school/records
- Children's home records: http://127.0.0.1:5000/home-mode/records
- Legal status requests: http://127.0.0.1:5000/home-mode/legal-status/requests