# CSAP Backend (FastAPI)

Centralized REST API for CSAP. Incidents, users, audit log and settings live in
a database (PostgreSQL in production, SQLite in development). Authentication
uses server-side sessions delivered via an httpOnly `csap_session` cookie.

## Requirements

- Python 3.11–3.13
- (Production) PostgreSQL. Development runs on SQLite with zero setup.

## Quick start (development)

```bash
cd backend

# 1. Create and activate a virtual environment
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) configure env — defaults are fine for dev
cp .env.example .env
# For plain-HTTP local dev set COOKIE_SECURE=false in .env so the browser keeps
# the session cookie over http://localhost.

# 4. Run the API (auto-creates tables on first start)
uvicorn app.main:app --reload --port 8000
```

The API is served under `/api`. Health check: `GET http://localhost:8000/api/health`.

Tables are created automatically on startup via
`Base.metadata.create_all` — no migrations needed for v1.

## First run

There are no users initially. `GET /api/auth/bootstrap` returns
`{"hasUsers": false}`. The first `POST /api/users` succeeds without auth and the
created user is forced to the `admin` role. After that, creating/deleting users
requires an admin session.

## Full backup

`GET /api/backup/export` (admin only) returns a single JSON envelope with every
user (password hashes included), incident, audit entry and the shared settings.
`POST /api/backup/import` (admin only) restores such an envelope, atomically
replacing all current data; the importing admin's session survives the restore
and their account is preserved even when absent from the backup. See the root
`README.md` § Full platform backup for the envelope shape and semantics.

## Configuration

All settings come from environment variables (see `.env.example`):

| Variable            | Default                 | Purpose                                            |
| ------------------- | ----------------------- | -------------------------------------------------- |
| `DATABASE_URL`      | `sqlite:///./csap.db`   | SQLAlchemy URL. Prod: `postgresql+psycopg://…`.    |
| `DB_PASSWORD` (+ `DB_USER`/`DB_HOST`/`DB_PORT`/`DB_NAME`) | — | Alternative to `DATABASE_URL`: PostgreSQL URL assembled by the app with escaping (password may contain any character). |
| `SECRET_KEY`        | `dev-insecure-change-me`| Signing/entropy secret. Set a strong value in prod.|
| `COOKIE_SECURE`     | `true`                  | Mark the session cookie Secure (HTTPS only).       |
| `SESSION_TTL_HOURS` | `12`                    | Session lifetime in hours.                         |

## Production

Run behind gunicorn with uvicorn workers, reverse-proxied by nginx:

```bash
gunicorn -k uvicorn.workers.UvicornWorker app.main:app --bind 127.0.0.1:8000
```

Set `DATABASE_URL` to your PostgreSQL instance and `COOKIE_SECURE=true` (served
over HTTPS). See the root `README.md` for the full RHEL deployment guide
(PostgreSQL setup, systemd unit, SELinux, nginx).
