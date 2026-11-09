# Nik — Forensic analysis platform

![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Python_3.11+-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker%20%2F%20Podman-Compose-2496ED?logo=docker&logoColor=white)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A full-stack web platform for analysing digital-forensics artifacts, laid out
like a SOC dashboard. Analysts organise their work into **incidents** (forensic
cases identified by a host and/or username), import artifacts from a machine,
flag suspicious events and build a timeline of the malicious activity — with
every action attributed to a named analyst and recorded in a global audit log.

**Key traits:**

- **Client-side artifact parsing** — SQLite artifacts (Chromium `History`,
  Firefox `places.sqlite`, Safari `History.db`, …) are parsed **in the
  analyst's browser** via WebAssembly (`sql.js`); Apple property lists (binary
  or XML), shell histories and DFIR CSV/JSON exports are parsed the same way. Raw forensic files are never uploaded anywhere: only the
  normalized entries reach the server.
- **Centralized storage** — incidents, users, settings and the audit log live
  in PostgreSQL behind a FastAPI REST API. Every analyst who signs in sees the
  same data, from any machine, and work is attributable across the team.
- **Lazy loading** — sign-in downloads only the light incident list; an
  incident's artifacts are fetched when it is opened (with a non-blocking
  loading state) and edits send only what changed, so many large incidents
  never slow the platform down.
- **Host-OS aware** — each incident is tied to a host OS (Windows / macOS /
  Linux) that drives the suggested artifact paths, the available shells and the
  incident icon.
- **Browser forensics** — one sub-tab per browser (Chrome, Firefox, Edge,
  Brave, Opera, Safari), each with **several profiles** (Default, Profile 1,
  Work…): browsing history, downloads, bookmarks (Safari's Reading List
  included) and omnibox shortcuts, with event classification
  (visit / search / redirect).
- **Command history** — one sub-tab per shell (Bash, Zsh, Fish, PowerShell):
  parses the native history files and detects shell/PowerShell tradecraft.
- **Endpoint artifacts** — program execution, persistence, file & folder
  access and removable devices, imported from DFIR tool CSV/JSON exports with
  OS-specific guidance on where to find each source.
- **Malware analysis** — suspicious files are stored on the Nik server (named
  by SHA-256, never executed) and analysed statically: hashes, file type,
  entropy per block, strings and indicators of compromise, PE/ELF/Mach-O
  structure with imphash, YARA matches (built-in and admin rules), all
  flaggable like any other event, with links to VirusTotal and MalwareBazaar
  and a download only inside a password-protected zip.
- **Super-timeline** — every timestamped event across all tabs merged into one
  chronological, filterable view, plus a collapsible `tail -f` side panel with
  the latest events on every tab.
- **SOC detection engine** — editable suspicious-keyword rules plus built-in
  command and endpoint rulesets, and a configurable business-hours window,
  highlight suspicious events automatically.
- **Case management** — per-event flags with comments, free-form notes, a
  vertical incident timeline, and self-contained JSON export/import for
  exchanging cases between analysts.
- **Full backup** — admins can export the entire platform (all incidents,
  users, settings and the audit log) to a single JSON file and restore it
  later, e.g. when moving the deployment to another machine.
- **Authentication & audit** — session-based login (bcrypt hashes, httpOnly
  cookie), `admin` / `analyst` roles, and a global audit trail of every
  meaningful action. Detection rules, business hours, accounts and the audit
  log all live in one sectioned **Settings** panel.

**Documentation site:** <https://n36l3c7.github.io/Nik/> — overview, installation,
configuration, API reference and release notes, served from [`/docs`](docs/) on
GitHub Pages (plain HTML, no build step).

### Stack

| Layer | Technology |
|---|---|
| Frontend | [React](https://react.dev) 19 · [Vite](https://vite.dev) 6 · [Tailwind CSS](https://tailwindcss.com) 4 · [lucide-react](https://lucide.dev) · [sql.js](https://sql.js.org) (SQLite → WASM) · [papaparse](https://www.papaparse.com) |
| Backend | [FastAPI](https://fastapi.tiangolo.com) (Python 3.11+) · SQLAlchemy 2 · gunicorn + uvicorn |
| Database | PostgreSQL (production) · SQLite (zero-setup development) |
| Delivery | nginx (static SPA + `/api` reverse proxy) · Docker/Podman Compose · systemd on RHEL |

---

## Table of contents

1. [Installation](#1-installation)
   - [Quick start with Docker / Podman](#11-quick-start-with-docker--podman)
   - [Local development setup](#12-local-development-setup)
   - [Configuration reference](#13-configuration-reference)
2. [Production deployment](#2-production-deployment)
   - [Docker / Podman in production](#21-docker--podman-in-production)
   - [Manual deployment on RHEL](#22-manual-deployment-on-rhel)
- [REST API and interactive docs](#rest-api-and-interactive-docs)
3. [Architecture](#3-architecture)
   - [High-level design](#31-high-level-design)
   - [Why parsing is client-side](#32-why-parsing-is-client-side)
   - [Folder structure](#33-folder-structure)
   - [State and the data model](#34-state-and-the-data-model)
   - [Authentication, sessions and the audit log](#35-authentication-sessions-and-the-audit-log)
4. [Extending the platform](#4-extending-the-platform)
   - [Add a new analysis tab](#41-add-a-new-analysis-tab)
   - [Extend the SOC detection rules](#42-extend-the-soc-detection-rules)
   - [Browsers, parsers and formats](#43-browsers-parsers-and-formats)
   - [UI kit reference](#44-ui-kit-reference)
5. [Incident export / import (JSON)](#5-incident-export--import-json)
6. [Full platform backup](#6-full-platform-backup)

---

## 1. Installation

### 1.1 Quick start with Docker / Podman

The fastest way to run the whole stack — nginx (static SPA + `/api` reverse
proxy), the FastAPI backend and PostgreSQL — is the bundled Compose file:

```bash
cp .env.example .env          # then edit DB_PASSWORD and SECRET_KEY
docker compose up -d --build  # build the images and start db + api + web
```

Open **https://localhost:8443** and create the first user — that account becomes
the **admin**. Database tables are created automatically on the API's first
start, so there is nothing to migrate.

> On first start the `web` container self-signs a TLS certificate, so the
> browser shows a one-time "connection not private" warning — accept it to
> proceed (or mount a real certificate, see §2.1). Plain HTTP stays available
> on **http://localhost:8080**.

```bash
docker compose logs -f api    # follow backend logs
docker compose ps             # container status
docker compose down           # stop (keeps the database volume)
docker compose down -v        # stop AND delete the database volume (wipes data)
```

Podman is a drop-in replacement (rootless is fine for ports 8080/8443):

```bash
cp .env.example .env
podman-compose up -d --build  # or: podman compose up -d --build
```

### 1.2 Local development setup

**Prerequisites:** Node.js 20+ (with npm) and Python 3.11–3.13. No database
server is needed: the backend defaults to a local SQLite file.

**Backend** (terminal 1):

```bash
cd backend

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# IMPORTANT for dev over plain HTTP: set COOKIE_SECURE=false in backend/.env,
# otherwise the browser drops the session cookie and login won't stick.

uvicorn app.main:app --reload --port 8000
```

Health check: `curl http://localhost:8000/api/health` → `{"status":"ok"}`.

**Frontend** (terminal 2, from the repository root):

```bash
npm install
npm run dev        # http://localhost:5173
```

The Vite dev server proxies every `/api` request to `http://127.0.0.1:8000`
(see `vite.config.js`), so the frontend and backend work together end-to-end
with no CORS configuration. On first load, create the first user (it becomes
the admin) and sign in.

Other npm scripts:

```bash
npm run build      # production build (static site in dist/)
npm run preview    # serve the production build locally
npm test           # frontend unit tests (Node's built-in test runner, no deps)
npm run lint       # ESLint (React + hooks rules), must report no problems
npm run format     # Prettier: rewrite JS/JSX, CSS, JSON, HTML and YAML in place
npm run format:check  # Prettier in check mode (what CI runs)
npm run test:e2e   # Playwright smoke test of the whole stack (build first)
```

The end-to-end test (`e2e/smoke.spec.js`, `playwright.config.js`) starts the
backend on a throw-away SQLite database and the production build behind
`vite preview` (which proxies `/api`, like the dev server), then drives the app
as an analyst would: first-run setup, sign-in, a new incident, demo data in
every tab, the timeline and the `tail -f` panel. It needs `npm run build`, the
backend dependencies on `PATH` (activate the venv) and a Chromium from
`npx playwright install chromium`.

Backend tests run with `pytest`, the linter with `ruff check .` and the
formatter with `ruff format .` (`--check` in CI), all from `backend/` after
`pip install -r requirements-dev.txt`; Ruff settings live in `backend/ruff.toml`.
Formatting is enforced, not reviewed: run the formatters before committing.
Markdown is excluded from Prettier (see `.prettierignore`). CI runs the linters,
the format checks, both unit suites, the build and then the end-to-end test; a
change is done only when all of them pass. The documentation site in `docs/`
is updated in the same change as the behaviour it describes.

**Upgrading an existing database:** run `alembic upgrade head` from `backend/`
after pulling a release that adds a migration (the Docker image does this on
start). A database created by the dev-mode `create_all` is adopted by the
baseline migration. Upgrading to **2.0.0** rewrites every incident once
(migration `0003_browser_profiles`: browser data moves into a "Default"
profile); on large databases the first start takes longer — take a backup
first.

Tailwind v4 is wired in through the Vite plugin (`@tailwindcss/vite`), so there
is no `tailwind.config.js` and no extra setup step.

### 1.3 Configuration reference

**Backend** (environment variables, optionally from `backend/.env` — see
`backend/.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./nik.db` | SQLAlchemy URL. Production: `postgresql+psycopg://nik:PASS@host/nik` (password must be URL-encoded). |
| `DB_PASSWORD` + `DB_USER`/`DB_HOST`/`DB_PORT`/`DB_NAME` | — | Alternative to `DATABASE_URL`: the app assembles the PostgreSQL URL itself with escaping, so the password may contain any character. |
| `SECRET_KEY` | `dev-insecure-change-me` | Signing/entropy secret. Set a long random value in production. |
| `COOKIE_SECURE` | `true` | `Secure` flag on the session cookie (HTTPS only). Set `false` only for plain-HTTP local dev. |
| `SESSION_TTL_HOURS` | `12` | Session lifetime. |
| `SAMPLE_STORE` | `./samples` | Directory of the raw malware samples (one file per SHA-256, never executed). Exclude it from the server's antivirus and include it in backups. |
| `SAMPLE_MAX_MB` | `100` | Per-file size limit for sample uploads. |
| `YARA_RULES` | `app/yara` | Directory of the built-in YARA rule files (`*.yar`); admin rules live in the database. |

**Compose** (root `.env` — see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DB_PASSWORD` | `nik` | PostgreSQL password (shared by the `db` and `api` services). |
| `SECRET_KEY` | — | Backend secret. Use a long random value (e.g. `openssl rand -hex 32`). |
| `COOKIE_SECURE` | `false` | Keep `false` while anyone still uses plain HTTP on `:8080`; set `true` (recommended) once everyone is on HTTPS. |
| `WEB_PORT` | `8080` | Host port the UI is published on (plain HTTP). |
| `WEB_TLS_PORT` | `8443` | Host port the UI is published on (HTTPS). |
| `TLS_HOSTNAME` | `localhost` | Name embedded in the auto-generated certificate (CN + SAN) — set it to what users type in the browser. |
| `SESSION_TTL_HOURS` | `12` | Session lifetime. |
| `SAMPLE_MAX_MB` | `100` | Per-file size limit for malware samples; the files live on the `sample-store` volume. |

> **Two things that will bite you over plain HTTP:**
>
> 1. With `COOKIE_SECURE=true` the browser **drops** the `nik_session` cookie
>    on `http://` origins, so login won't stick. Use the HTTPS port (`:8443`)
>    in production — the self-signed certificate the stack generates is fine
>    on an internal network, an internal-CA one is better.
> 2. The copy-to-clipboard buttons use the Clipboard API, which only works in a
>    **secure context** (`https://` or `http://localhost`).

---

## 2. Production deployment

> **Upgrading from a "CSAP"-era deployment?** The database role and name are now
> `nik` (was `csap`). A pre-existing Postgres volume still holds the old `csap`
> role/database, so either start on a **fresh** volume (`docker volume rm
> nik_db-data` / your project's `*_db-data`), or keep the old names by setting
> `DB_USER`, `DB_NAME` and the compose `POSTGRES_*` back to `csap`, or rename in
> place with `ALTER ROLE csap RENAME TO nik;` and `ALTER DATABASE csap RENAME TO
> nik;`. The session cookie also changed name, so everyone re-logs in once.

### 2.1 Docker / Podman in production

The Compose stack publishes plain HTTP on `:8080` and HTTPS on `:8443`. On
first start the `web` container **self-signs a certificate** (for
`TLS_HOSTNAME`, default `localhost`) into the `web-certs` volume, so HTTPS
works out of the box — browsers show the usual warning until the certificate
is trusted or replaced. For a real deployment set `COOKIE_SECURE=true` and
pick one of:

- **Option A (recommended):** provide your own certificate — internal CA or
  Let's Encrypt — as `nik.crt` / `nik.key` in `/etc/nginx/certs`; the
  startup script never overwrites an existing pair. Easiest wiring: swap the
  named volume for a bind mount in `docker-compose.yml`
  (`- ./certs:/etc/nginx/certs`).
- **Option B:** front the stack with a host reverse proxy that terminates TLS
  (nginx, Caddy, Traefik) proxying to `127.0.0.1:8080`, and remove the
  `8443` port mapping.

To regenerate the self-signed certificate (e.g. after changing
`TLS_HOSTNAME`): `docker compose down && docker volume rm nik_web-certs`,
then start the stack again.

Notes for Podman on RHEL:

- **Rootless** works out of the box — only host ports below 1024 require
  rootful Podman (or lowering `net.ipv4.ip_unprivileged_port_start`).
- **Start on boot:** generate a systemd unit with
  `podman generate systemd --files --name …`, or use a **Quadlet** unit under
  `/etc/containers/systemd/`.
- **SELinux:** named volumes (as used here) are relabeled automatically. If you
  switch to a bind mount, add `:Z` to that mount.

**Backups & updates.** Data lives in the `db-data` PostgreSQL volume and
survives `up`/`down`/rebuilds. For an application-level backup file (works
across database engines), use the in-app **Full backup**
([§6](#6-full-platform-backup)):

```bash
# Backup / restore the database
docker compose exec db pg_dump -U nik nik > nik-backup.sql
cat nik-backup.sql | docker compose exec -T db psql -U nik nik

# Update to a new version (rebuild images, recreate containers, keep data)
git pull
docker compose up -d --build
```

### 2.2 Manual deployment on RHEL

Tested on **RHEL 8 and 9** (same steps on Rocky/AlmaLinux). nginx serves the
static bundle and reverse-proxies `/api/` to the backend, so the browser talks
to a single origin — no CORS, and the session cookie just works. All commands
assume a `sudo`-capable user.

Because incidents, users and the audit log live in **PostgreSQL on the
server**, back up the **database** (`pg_dump`) or use the in-app **Full
backup** ([§6](#6-full-platform-backup)) — the per-incident JSON export
([§5](#5-incident-export--import-json)) is an exchange/archival format, not the
primary backup.

#### Step 1 — Build the static bundle

Build on the RHEL host or on any machine with Node 20+ and copy `dist/` over.
To install Node on RHEL (NodeSource, works on 8 and 9):

```bash
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo dnf install -y nodejs
```

Then, from the project directory:

```bash
npm ci            # clean, reproducible install from package-lock.json
npm run build     # outputs the static site into dist/
```

#### Step 2 — Install and configure PostgreSQL

```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# Application role and database:
sudo -u postgres createuser --pwprompt nik
sudo -u postgres createdb -O nik nik
```

**Enable password authentication.** A fresh RHEL cluster uses `ident`/`peer`
auth for local TCP connections, which rejects the app's `nik` login. Edit
`/var/lib/pgsql/data/pg_hba.conf` so the local lines use `scram-sha-256`:

```conf
# TYPE  DATABASE  USER  ADDRESS         METHOD
host    nik      nik  127.0.0.1/32    scram-sha-256
host    nik      nik  ::1/128         scram-sha-256
```

Then `sudo systemctl reload postgresql`. The connection string for the backend
is:

```
postgresql+psycopg://nik:STRONG_PASSWORD@localhost/nik
```

Tables (`users`, `sessions`, `incidents`, `audit_log`, `settings`) are created
automatically on the API's first startup — no migration step.

#### Step 3 — Deploy the FastAPI backend (systemd)

The backend needs **Python 3.11+** (RHEL 9 ships it; on RHEL 8 install
`python3.11`). Copy `backend/` to `/opt/nik/backend` and build a virtualenv:

```bash
sudo dnf install -y python3 python3-pip
sudo useradd --system --home /opt/nik --shell /sbin/nologin nik

sudo mkdir -p /opt/nik
sudo cp -r backend /opt/nik/backend
cd /opt/nik/backend

sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R nik:nik /opt/nik
```

Keep the secrets in `/etc/nik/nik.env` (readable only by root and the
service account):

```bash
sudo mkdir -p /etc/nik
sudo tee /etc/nik/nik.env >/dev/null <<'EOF'
DATABASE_URL=postgresql+psycopg://nik:STRONG_PASSWORD@localhost/nik
SECRET_KEY=replace-with-a-long-random-string   # e.g. `openssl rand -hex 32`
COOKIE_SECURE=true                             # requires HTTPS
EOF
sudo chmod 640 /etc/nik/nik.env
sudo chown root:nik /etc/nik/nik.env
```

Create `/etc/systemd/system/nik-api.service` — the API binds to **loopback
only**; nginx is the sole public entry point:

```ini
[Unit]
Description=Nik FastAPI backend (gunicorn/uvicorn)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=nik
Group=nik
WorkingDirectory=/opt/nik/backend
EnvironmentFile=/etc/nik/nik.env
ExecStart=/opt/nik/backend/.venv/bin/gunicorn \
    -k uvicorn.workers.UvicornWorker \
    app.main:app \
    --bind 127.0.0.1:8000 \
    --workers 3
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nik-api.service
curl -s http://127.0.0.1:8000/api/health      # → {"status":"ok"}
```

#### Step 4 — Install nginx and place the static files

```bash
sudo dnf install -y nginx
sudo systemctl enable --now nginx

sudo mkdir -p /var/www/nik
sudo cp -r dist/* /var/www/nik/
```

#### Step 5 — SELinux (enforced by default on RHEL)

```bash
# a) Let nginx connect to the backend — without this, /api/ returns
#    502 Bad Gateway with an "AVC denied … name_connect" in the audit log:
sudo setsebool -P httpd_can_network_connect 1

# b) Label the static-file directory — or nginx returns 403 Forbidden:
sudo dnf install -y policycoreutils-python-utils
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/nik(/.*)?"
sudo restorecon -Rv /var/www/nik
```

#### Step 6 — TLS certificate

For an internal host a self-signed certificate is enough (clients must trust it
or accept the browser warning). Replace the CN/SANs with your host:

```bash
sudo mkdir -p /etc/pki/nginx/private
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/pki/nginx/private/nik.key \
  -out    /etc/pki/nginx/nik.crt \
  -subj "/CN=nik.example.internal" \
  -addext "subjectAltName=DNS:nik.example.internal,IP:10.0.0.10"
```

For an internet-facing host use a real certificate instead (e.g. Let's Encrypt:
`sudo dnf install -y certbot python3-certbot-nginx`).

#### Step 7 — Ensure the `.wasm` MIME type

sql.js loads a WebAssembly module. RHEL 9's nginx already maps it; RHEL 8's
does not. Add the line to the `types { … }` block of `/etc/nginx/mime.types` if
missing:

```nginx
application/wasm  wasm;
```

#### Step 8 — nginx server block

Create `/etc/nginx/conf.d/nik.conf`:

```nginx
# Redirect plain HTTP to HTTPS (the app requires a secure context)
server {
    listen 80;
    server_name nik.example.internal;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name nik.example.internal;

    ssl_certificate     /etc/pki/nginx/nik.crt;
    ssl_certificate_key /etc/pki/nginx/private/nik.key;

    # Large JSON payloads (backup restore, incidents with parsed artifacts)
    # blow past nginx's 1m default and get rejected with 413.
    client_max_body_size 200m;

    root  /var/www/nik;
    index index.html;

    # Reverse-proxy the REST API to the gunicorn/uvicorn backend.
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Fingerprinted assets can be cached forever…
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # …but never cache the HTML entry point, so updates are picked up.
    location = /index.html {
        add_header Cache-Control "no-cache";
    }

    # Serve static files; fall back to index.html
    location / {
        try_files $uri /index.html;
    }
}
```

> If `/api/` returns `502 Bad Gateway`, the usual culprit is SELinux — confirm
> `httpd_can_network_connect` is on (Step 5a) and that `nik-api.service` is
> running (`curl http://127.0.0.1:8000/api/health`).

#### Step 9 — Open the firewall and reload

Only **80/443** are exposed; the backend stays on `127.0.0.1:8000`:

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload

sudo nginx -t
sudo systemctl reload nginx
```

Browse to `https://nik.example.internal`, create the first (admin) user and
sign in.

#### Updating to a new version

```bash
# Frontend — rebuild and replace the static files:
npm ci && npm run build
sudo rm -rf /var/www/nik/*
sudo cp -r dist/* /var/www/nik/
sudo restorecon -Rv /var/www/nik

# Backend — refresh code and dependencies, restart the service:
sudo cp -r backend/* /opt/nik/backend/
sudo /opt/nik/backend/.venv/bin/pip install -r /opt/nik/backend/requirements.txt
sudo chown -R nik:nik /opt/nik
sudo systemctl restart nik-api.service
```

Upgrades do **not** wipe data: everything persists in PostgreSQL, and new
tables are created on startup. Take a `pg_dump` (or an in-app full backup,
[§6](#6-full-platform-backup)) before upgrading if you want a rollback point.

---

## REST API and interactive docs

Nik can be driven without the browser through a REST API. It is the same API the
web app uses, so anything the UI does — create / edit / delete incidents, add and
remove notes, and upload raw artifact files (parsed **server-side**) — is
available programmatically.

### Interactive documentation

Open **`/api/docs`** (e.g. `https://localhost:8443/api/docs`) for the Swagger UI.
It is **public to view** (no login) and always in sync with the running server.
Click **Authorize**, paste an API key, and every endpoint gains a *Try it out*
button. A link is also shown on the sign-in screen.

### Authentication

Write endpoints accept **either** a browser session **or** an **API key**. Send
the key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: nik_XXXXXXXX…" https://localhost:8443/api/incidents
```

Create and revoke keys in the app under **Settings → API keys** (admin only). The
plaintext key is shown **once**, at creation. Each key carries **permissions set
at creation** (bound to the key):

- **role** — `analyst` (incidents, notes, uploads, read settings) or `admin`
  (also users, backup, keys, webhooks).
- **scopes** — `read` / `write`; a read-only key (`scopes:["read"]`) can fetch
  but not mutate.
- **expiry** — optional; an expired key is rejected.

Actions performed with a key are recorded in the audit log as `api:<label>`.

### Endpoints

| Method & path | Purpose |
|---|---|
| `GET /api/incidents` | List incidents. Query: `limit`/`offset`, `q`/`host`/`username`, `view=summary` (light rows: id, name, host, username, os, timestamps — no document body). `X-Total-Count` header. |
| `GET /api/incidents/{id}` | One incident (returns an `ETag`). Send `If-None-Match: <ETag>` to get `304` (no body) while your copy is current. |
| `POST /api/incidents` | Create/upsert (id generated if omitted). |
| `PATCH /api/incidents/{id}` | `application/json`: replace the given top-level fields. `application/merge-patch+json`: apply an [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396) merge patch (nested merge, `null` deletes). Honors `If-Match` (→ `412` on a stale version). |
| `DELETE /api/incidents/{id}` | Delete an incident. |
| `POST /api/incidents/{id}/notes` · `PATCH`/`DELETE …/{noteId}` | Add / edit / remove notes. |
| `POST /api/incidents/{id}/upload` | Upload a raw artifact file (multipart). `?async=true` → `202 { jobId }`. |
| `GET /api/jobs/{id}` | Poll an async upload job. |
| `POST /api/incidents/{id}/samples` | Upload a malware sample (multipart `file`): stored by SHA-256, analysed statically, attached to the incident. A known file reuses its analysis. |
| `GET /api/samples/{sha256}` · `…/strings` | Metadata and full analysis (hashes, type, entropy blocks, indicators, first 5,000 strings); `/strings?q=&minLength=&encoding=` scans the stored file on demand. |
| `GET /api/samples/{sha256}/download` | The sample inside an AES-256 zip: `?password=` (default `infected`), `?name=` for the inner file name. Audited. |
| `DELETE /api/incidents/{id}/samples/{sha256}` | Detach the sample; the file is deleted once no incident references it. |
| `POST /api/samples/{sha256}/reanalyse` | Run the current analysis engine and YARA rules again on the stored file. |
| `GET/POST/PUT/DELETE /api/yara-rules` · `POST …/validate` | Admin-managed YARA rule sets compiled with the built-in ones (**admin** to change; any caller may list). A source must compile before it is saved. |
| `GET /api/settings` | Read the shared detection rules / business hours. |
| `GET/POST/DELETE /api/webhooks` | Manage event subscriptions (**admin**). |
| `GET/POST/DELETE /api/users` | User management (**admin**). |
| `GET/POST/DELETE /api/keys` | API-key management (**admin**). |
| `GET/POST /api/backup/{export,import}` | Full platform backup (**admin**). |
| `GET /api/health` · `/api/ready` · `/api/metrics` | Liveness · readiness (DB) · Prometheus metrics. |

The endpoints marked **admin** accept an admin session **or an admin-role API
key** (a non-admin/read-only key gets `403`).

### Automation & ops

- **Pagination & filtering** on `GET /incidents` and `/audit`
  (`limit`/`offset`/`q`/…); `view=summary` returns light rows without the heavy
  document — list at scale, then fetch one incident's full document. Total in
  the `X-Total-Count` header.
- **Optimistic concurrency**: `GET` returns an `ETag`; send it back as
  `If-Match` on `PATCH` — a stale write gets `412`, so an automation and an
  analyst can't clobber each other.
- **Conditional GET**: send the `ETag` as `If-None-Match` on
  `GET /incidents/{id}` to get `304 Not Modified` while nothing changed (the
  check reads only the version column, not the document).
- **Partial updates**: `PATCH` with `Content-Type: application/merge-patch+json`
  updates only the nested members you send, e.g.
  `{"flags": {"<key>": null}}` removes one flag without resending the rest.
- **Idempotency**: send an `Idempotency-Key` header on `POST` notes/upload to
  make retries safe (the first result is replayed).
- **Async uploads**: `POST …/upload?async=true` → `202 { jobId }`, parsed in
  the background; poll `GET /api/jobs/{jobId}`.
- **Webhooks**: subscribe URLs to events (`incident.created/updated/deleted`,
  `note.added`, `upload.completed`). Each delivery is HMAC-SHA256 signed
  (`X-Nik-Signature: sha256=…`) with the subscription secret (shown once).
- **Rate limiting** (per IP) protects the API; **`/api/metrics`** exposes
  Prometheus counters/latency and every response carries an `X-Request-ID`.
- **Versioning**: the current API is v1 under `/api`; breaking changes would
  ship under a new prefix. Generate a typed client from the live spec, e.g.
  `openapi-generator generate -i https://HOST/api/openapi.json -g python`.

### Uploading files

`POST /api/incidents/{id}/upload` takes a multipart `file` plus query parameters
that route it to the right parser (mirroring the app's tabs). The server parses
the raw file and merges the normalized result into the incident.

```bash
# Browser history (Chromium History SQLite → data.browser.browsers.chrome)
curl -H "X-API-Key: $KEY" -F file=@History \
  "https://localhost:8443/api/incidents/$ID/upload?tab=browser&browser=chrome&source=history"

# Shell history (.bash_history → data.commands.shells.bash)
curl -H "X-API-Key: $KEY" -F file=@.bash_history \
  "https://localhost:8443/api/incidents/$ID/upload?tab=commands&shell=bash"

# Endpoint artifact (cron file or tool CSV → data.endpoint.categories.persistence)
curl -H "X-API-Key: $KEY" -F file=@crontab \
  "https://localhost:8443/api/incidents/$ID/upload?tab=endpoint&category=persistence&source=cron"
```

Routing parameters: `tab=browser` needs `browser` (chrome/firefox/edge/brave/opera/safari)
and `source` (history/bookmarks/shortcuts/places; Safari: history/downloads/bookmarks),
plus an optional `profile` — the profile **name**, matched case-insensitively and
created if missing (default `Default`); the response's `target` reads
`browser/<id>/<profile>/<source>` and `profileId` names the profile; `tab=commands` needs `shell`
(bash/zsh/fish/powershell); `tab=endpoint` needs `category`
(execution/persistence/fileaccess/usb) and `source` (the source key, e.g. cron).
The server ports the client-side parsers (`backend/app/parsing/`), so uploads
produce exactly the same normalized shapes the browser does.

---

## 3. Architecture

### 3.1 High-level design

```
        Analyst's browser                         Server
┌──────────────────────────────┐     ┌────────────────────────────────┐
│  React SPA (Vite build)      │     │  nginx                         │
│  ├─ artifact parsing (WASM)  │────▶│  ├─ static files (dist/)       │
│  ├─ SOC detection engine     │ TLS │  └─ /api/ ──▶ FastAPI (:8000)  │
│  └─ REST client (/api)       │     │              └─▶ PostgreSQL    │
└──────────────────────────────┘     └────────────────────────────────┘
```

The split is deliberate:

- **Parsing stays in the browser.** Raw artifact files (SQLite databases, JSON,
  CSV) are read and normalized client-side; only the resulting entries are sent
  to the API as part of the incident document.
- **State lives on the server.** Incidents, users, settings and the audit log
  are stored in the database and shared by all analysts; nothing is kept in
  the browser's storage.
- **Single origin.** nginx serves the SPA and proxies `/api/` to the backend,
  so no CORS configuration is needed and the httpOnly session cookie flows
  transparently. In development, the Vite proxy plays nginx's role.

The REST API (`/api`) exposes: `auth` (bootstrap/login/logout/me), `users`,
`incidents`, `audit`, `settings` and `backup` routers, plus `GET /api/health`
as a liveness probe.

### 3.2 Why parsing is client-side

All artifact parsing — including Chromium's `History`, a binary **SQLite**
database — happens in the browser via `sql.js` (SQLite compiled to
WebAssembly). Rationale:

1. **Privacy / chain of custody** — forensic artifacts can hold personal and
   sensitive data (a subject's browsing history, credentials in URLs…). The raw
   files never leave the analyst's machine; only normalized entries are stored.
2. **No upload pipeline** — no file-size limits, no multipart handling, no
   temporary storage of evidence on the server.
3. **Works in the field** — the parsing layer needs no connectivity beyond the
   API calls that persist results.

The sql.js WASM module (~1 MB) is loaded **lazily** on the first SQLite import
(see `src/services/sqliteParser.js`): analysts who only work with JSON/CSV
exports never download it.

**File schema per engine.** Chromium browsers (Chrome/Edge/Brave/Opera) share
Chrome's SQLite schema (`History` with `urls`/`visits`/`downloads`, a JSON
`Bookmarks` file, a `Shortcuts` database). **Firefox** is different: a single
`places.sqlite` database (`moz_*` schema) holds history, bookmarks and
downloads. **Safari** (macOS only) keeps history in a `History.db` database
(`history_items`/`history_visits`) and downloads and bookmarks in two property
lists, `Downloads.plist` and `Bookmarks.plist`, usually binary. Timestamps differ too — see [§4.3](#43-browsers-parsers-and-formats).

**Heavy formats** (EVTX, PCAP, disk images) are a natural fit for server-side
parsing with mature Python libraries (`python-evtx`, `scapy`, DFIR tooling).
The seam is ready: every browser import goes through
`parseBrowserSource(file, engine, source)` in `src/services/fileParsers.js`,
which returns normalized entries — a server-side parser only needs to return
the same shape, and the rest of the app (contexts, tables, detection) does not
change.

**The one exception: malware samples.** The Malware Analysis tab sends the
file itself to the server, because the sample *is* the evidence under study
(not a container of entries to normalize) and the later analysis stages
(disassembly, decompilation) can only run server-side. See
[§3.7](#37-malware-samples).

### 3.3 Folder structure

```
├── index.html                      # HTML shell (mount point #root)
├── package.json                    # Frontend dependencies and npm scripts
├── vite.config.js                  # React + Tailwind plugins, /api proxy (dev and preview)
├── playwright.config.js            # E2E: starts backend (SQLite) + vite preview
├── e2e/smoke.spec.js               # End-to-end smoke test of the whole stack
├── docs/                           # GitHub Pages site (plain HTML + one stylesheet)
├── docker-compose.yml              # db + api + web stack
├── .env.example                    # Compose configuration template
├── deploy/
│   ├── web.Dockerfile              # Multi-stage: build SPA with Node, serve with nginx
│   └── nginx.conf                  # Container nginx: static + /api reverse proxy
├── backend/
│   ├── Dockerfile                  # FastAPI image (gunicorn + uvicorn workers)
│   ├── requirements.txt
│   ├── .env.example                # Backend configuration template
│   └── app/
│       ├── main.py                 # FastAPI app: create_all on startup, /api routers
│       ├── config.py               # Env-based settings (DATABASE_URL, SECRET_KEY, …)
│       ├── db.py                   # SQLAlchemy engine / session factory
│       ├── models.py               # users, sessions, incidents, audit_log, settings
│       ├── browser_profiles.py     # browser profiles: legacy conversion, upload routing
│       ├── schemas.py              # Pydantic request/response models
│       ├── security.py             # bcrypt hashing, session-auth dependencies
│       ├── defaults.py             # Factory defaults for detection settings
│       ├── samples.py              # Malware sample store (files by SHA-256) + protected zip
│       ├── parsing/malware.py      # Static analysis: hashes, type, entropy, strings, IOC
│       ├── parsing/executables.py  # PE (pefile), ELF and Mach-O structure, imphash
│       ├── yara_rules.py           # YARA: built-in + admin rules compiled together, scan
│       ├── yara/                   # Built-in YARA rule files (*.yar)
│       └── routers/                # auth, users, incidents, audit, settings, backup, samples, yara_rules
└── src/
    ├── main.jsx                    # Entry: StrictMode > AuditProvider > AuthProvider
    │                               #   > SettingsProvider > IncidentProvider > App
    ├── index.css                   # Tailwind v4, design tokens (@theme), bundled fonts,
    │                               #   base + scrollbar
    ├── assets/fonts/               # Inter + JetBrains Mono (woff2, OFL-1.1 licence files)
    ├── App.jsx                     # Shell + auth gate: Sidebar | Header + TabBar + tab content
    │                               #   + TailPanel
    │
    ├── config/                     # ★ DECLARATIVE EXTENSION POINTS ★
    │   ├── tabs.js                 # ANALYSIS_TABS registry: the ONLY file to touch
    │   │                           #   to register a new tab. buildDefaultIncidentData().
    │   ├── os.js                   # Host OS registry (Windows/macOS/Linux)
    │   ├── browsers.js             # BROWSER registry: engine, file sources, per-OS paths
    │   ├── shells.js               # SHELL registry (Bash/Zsh/Fish/PowerShell): per-OS paths
    │   ├── artifacts.js            # ENDPOINT ARTIFACT registry (execution/persistence/
    │   │                           #   fileaccess/usb): columns, CSV aliases, per-OS sources
    │   └── detectionRules.js       # Factory keyword + command + artifact rules, business
    │                               #   hours (keywords managed at runtime from Settings).
    │
    ├── context/
    │   ├── AuditContext.jsx        # useAudit(): global audit log via the API
    │   ├── AuthContext.jsx         # useAuth(): session auth (login/logout/me), users
    │   ├── SettingsContext.jsx     # useSettings(): keywords + business hours (server-side);
    │   │                           #   useSocEngine(): memoized detection engine
    │   └── IncidentContext.jsx     # useIncidents(): incident state, CRUD, flags, notes,
    │                               #   export/import — optimistic model backed by the API
    │
    ├── services/
    │   ├── api.js                  # The ONLY file that talks to the server (fetch wrapper)
    │   ├── fileParsers.js          # parseBrowserSource(file, engine, source): dispatch
    │   │                           #   SQLite/plist/JSON/CSV + lenient field mapping
    │   ├── sqliteParser.js         # Chromium (History/Shortcuts), Firefox (places.sqlite) and
    │   │                           #   Safari (History.db) parsers via sql.js (lazy WASM)
    │   ├── plistParser.js          # parsePlist(buffer): binary (bplist00) + XML property lists
    │   ├── safariParser.js         # Safari Downloads.plist / Bookmarks.plist → shared shapes
    │   ├── __fixtures__/           # binary plist test fixtures (+ the script that makes them)
    │   ├── shellParsers.js         # parseShellHistory(file, shell): bash/zsh/fish/PSReadLine
    │   ├── artifactParsers.js      # parseArtifactImport(file, category, source): xbel/plist/
    │   │                           #   configlines/setupapi/knowledgeC + CSV/JSON (script mode)
    │   └── demoData.js             # getDemoBrowserData/getDemoShellData/getDemoArtifactData
    │
    ├── utils/
    │   ├── id.js                   # generateId() → crypto.randomUUID (with fallback)
    │   ├── path.js                 # fileNameFromPath (Windows/POSIX paths, file:// URIs)
    │   ├── mergePatch.js           # createMergePatch(prev, next) — RFC 7396 diff (+ .test.js)
    │   ├── asciiSkull.js           # renderSkull(): the loading/error/empty skull (+ .test.js)
    │   ├── browserProfiles.js      # browser profiles: normalize, order, names, labels (+ .test.js)
    │   ├── time.js                 # webkitToMs, firefoxToMs, macToMs, anyToMs, formatDateTime…
    │   ├── url.js                  # extractDomain, extractSearchQuery, topDomains…
    │   ├── malware.js              # IOC detection, sample severity, timeline events (+ .test.js)
    │   ├── events.js               # buildEvents, historyEventType, redirect helpers
    │   ├── commands.js             # buildCommandEvents, extractBinary, topBinaries
    │   ├── artifacts.js            # buildArtifactEvents (endpoint records → events)
    │   ├── timeline.js             # buildTimelineEvents (merge all timestamped events)
    │   └── soc.js                  # createSocEngine({keywords, commandKeywords,
    │                               #   artifactKeywords, businessHours}) → analyze()
    │
    └── components/
        ├── ui/                     # Reusable UI kit (Button, Card, Badge, Modal, DataTable,
        │                           #   EmptyState, SearchInput, Select, StatCard, AsciiSkull)
        ├── auth/                   # AuthLayout (banner + live status), FirstRunSetup, LoginScreen
        ├── backup/                 # BackupModal (full export/restore, admin only)
        ├── settings/               # SettingsPanel + sections/ (detection rules, business
        │                           #   hours, accounts, API keys, audit log)
        ├── layout/                 # Sidebar, Header, TabBar, OsPicker, IncidentLoadingState,
        │                           #   TailPanel (tail -f of the timeline)
        └── tabs/
            ├── NetworkLogsTab.jsx      # Placeholder, ready for expansion
            ├── summary/                # SummaryTab, IncidentTimeline, NoteBlock
            ├── browser/                # BrowserAnalysisTab, ProfileBar, FileUploadZone, EventsSection,
            │                           #   filters, widgets, bookmarks/shortcuts tables
            ├── commands/               # CommandHistoryTab, CommandsSection, TopBinariesWidget
            ├── endpoint/               # EndpointArtifactsTab, ArtifactSection (generic table)
            ├── malware/                # MalwareAnalysisTab, SampleList, SampleDetail, EntropyChart,
            │                           #   StructureSection, YaraSection, IocSection, StringsSection,
            │                           #   DownloadDialog
            └── timeline/               # TimelineTab (the super-timeline)
```

Each incident is tied to a single host and carries an **operating system**
(`windows` | `macos` | `linux`, see `src/config/os.js`), chosen when the
incident is created and editable from the Summary tab. The OS drives the
host-specific bits of the UI: the artifact paths suggested in Browser
Forensics, which shells appear in Command History, and the incident icon shown
in the sidebar and header.

The **Command History** tab mirrors Browser Forensics for terminal activity:
one sub-tab per shell (Bash / Zsh / Fish / PowerShell, see
`src/config/shells.js`), parsing the native history files (`.bash_history`,
`.zsh_history`, `fish_history`, PSReadLine `ConsoleHost_history.txt`) plus
JSON/CSV exports. Commands run through the SOC engine — the shared keyword
rules plus a built-in command ruleset (`DEFAULT_COMMAND_KEYWORDS` in
`src/config/detectionRules.js`: download-and-execute, encoded payloads, reverse
shells, credential access, defense evasion, persistence, exfiltration, history
tampering…) — can be flagged, searched, filtered by the suspicious window, and
appear on the incident timeline exactly like browser events.

The **Endpoint Artifacts** tab covers host forensic artifacts that neither the
browser nor the shell captures, one sub-tab per category built from one or more
**sources** (see `src/config/artifacts.js`): **Program Execution** (BAM,
KnowledgeC), **Persistence** (Run keys, Scheduled Tasks, services, startup,
WMI, cron, systemd, SSH keys, rc files, LaunchAgents), **File & Folder Access**
(GTK recently-used) and **USB & Devices** (USBSTOR, setupapi log, kernel
journal). The table shows the union of every source's records, tagged by which
source produced them, and runs the shared keywords plus a built-in artifact
ruleset (`DEFAULT_ARTIFACT_KEYWORDS`: execution from temp/user-writable paths,
LOLBins, double extensions, suspicious persistence, known offensive tool names).

Crucially, every source is collected **without any third-party tool**, in one
of two ways driven by the incident's host OS:

- **file** — the data already lives in a plain text / XML / log / SQLite file,
  so the analyst uploads that existing file and it is parsed in-browser (custom
  parsers in `src/services/artifactParsers.js`: `recently-used.xbel`,
  `authorized_keys` / cron / rc files, LaunchAgent `.plist`, `setupapi.dev.log`,
  and `knowledgeC.db` via sql.js).
- **script** — the data is live system state (registry, service manager,
  kernel journal), so the tab shows a native collection script
  (`src/config/collectionScripts.js`, PowerShell / systemctl / journalctl only)
  with copy/download buttons; it writes a CSV whose headers match the importer
  1:1, which the analyst then imports.

Artifacts that can only be recovered with third-party DFIR parsers (Prefetch,
Amcache, ShimCache, UserAssist, LNK, JumpLists, ShellBags, RecentDocs) are
intentionally left out; a category with no custom source on a given OS shows an
explicit note rather than a dead end.

The **Timeline** tab is the super-timeline: it merges every *timestamped* event
from the Browser, Command History and Endpoint Artifacts tabs into a single
chronological, filterable table (by source, detection and time window). Entries
without a reliable timestamp (e.g. PSReadLine commands) are intentionally left
out. Any row can be flagged straight from the timeline.

The **sidebar is resizable**: drag its right edge to widen the incident list up
to a quarter of the window; the width is remembered per browser.

Platform configuration lives in one sectioned **Settings** panel (opened from
the header, or deep-linked from the sidebar's Accounts / Audit buttons):
detection rules (with the built-in rulesets shown for reference), business
hours, account management and the audit log.

### 3.4 State and the data model

#### IncidentContext

All incident state lives in `src/context/IncidentContext.jsx`, exposed through
the `useIncidents()` hook:

```js
const {
  incidents,              // IncidentSummary[] — light rows {id, name, host, username, os, createdAt, updatedAt}
  activeIncident,         // Incident | null — full document of the selected incident, once loaded
  activeIncidentId,       // string | null
  activeSummary,          // IncidentSummary | null — the selected row (available immediately)
  activeLoading,          // boolean — the selected incident's document is downloading
  activeLoadError,        // string | null — the download failed
  activeLoadProgress,     // {received, total} | null — bytes of the first download (total null if unknown)
  retryActiveIncident,    // () => void — retry after activeLoadError
  loading,                // boolean — true until the incident LIST has loaded
  storageError,           // string | null — persistence error surfaced in the UI

  createIncident,         // ({host, username, os}) => Incident — creates AND activates
  updateIncidentMeta,     // (id, patch) => void — edit host/username/os/suspicious window
  deleteIncident,         // (id) => void — if active, activates the first remaining one
  selectIncident,         // (id) => void

  updateTabData,          // (id, dataKey, patch) => void — shallow-merge into data[dataKey]
  clearTabData,           // (id, dataKey) => void — reset to the registry defaultData

  updateBrowserData,      // (id, browserId, profileId, patch, auditInfo?) => void — per-profile merge
  setActiveBrowser,       // (id, browserId) => void — switch browser sub-tab (local only)
  setActiveProfile,       // (id, browserId, profileId) => void — switch profile (local only)
  addBrowserProfile,      // (id, browserId, name) => profileId | null — create AND activate
  renameBrowserProfile,   // (id, browserId, profileId, name) => void — also renames its flags
  deleteBrowserProfile,   // (id, browserId, profileId) => void — never the last one; keeps flags
  clearBrowserData,       // (id, browserId, profileId) => void — clear ONE profile
  removeBrowserSource,    // (id, browserId, profileId, sourceKey, producedKeys) => void — ONE file

  updateShellData,        // (id, shellId, patch, auditInfo?) => void — per-shell merge
  setActiveShell,         // (id, shellId) => void — switch shell sub-tab (local only)
  clearShellData,         // (id, shellId) => void — clear ONE shell's commands

  updateArtifactSource,   // (id, categoryId, sourceKey, patch, auditInfo?) => void — per-source
  clearArtifactSource,    // (id, categoryId, sourceKey) => void — clear ONE source
  clearArtifactCategory,  // (id, categoryId) => void — clear ALL sources of a category

  toggleFlag,             // (id, flaggable) => void — flag/unflag an entry
  addFlagComment,         // (id, flagKey, text) => void
  removeFlagComment,      // (id, flagKey, commentId) => void

  addNote,                // (id, text) => void
  updateNote,             // (id, noteId, text) => void
  removeNote,             // (id, noteId) => void

  exportIncident,         // async (id) => void — download the JSON (fetches it if not opened yet; see §5)
  importIncidentFromFile, // async (file) => Incident — throws Error(msg) if invalid
} = useIncidents()
```

Loading is **lazy**. After authentication only the light list is fetched
(`GET /api/incidents?view=summary`). Opening an incident downloads its full
document (`GET /api/incidents/{id}`) while the main area shows a non-blocking
loading state — the sidebar stays usable and opening another incident cancels
the pending download. Documents stay cached in memory for the session;
reopening one shows it at once and revalidates it with `If-None-Match`
(`304` when unchanged, refreshed when someone else edited it).

The cache is an **optimistic model**: every mutation updates local state
immediately and persists only what changed, as an RFC 7396 JSON Merge Patch
generated by `src/utils/mergePatch.js` from the previous and next document
(`POST` / `PATCH` / `DELETE /api/incidents/{id}`). Toggling a flag therefore
sends the flag, not the incident's artifacts. A failed write surfaces in
`storageError`, shown by `App.jsx` as a red banner. `setActiveBrowser`, `setActiveProfile` and
`setActiveShell` are view preferences, never sent on their own.

#### Shape of an incident

```js
{
  id:        'uuid',
  host:      'WKS-FINANCE-01',             // identity (NOT unique — the id is the key)
  username:  'm.rossi',                    //   "
  name:      'WKS-FINANCE-01 - m.rossi',   // derived: "host - username" | host | username
  suspiciousStart: 1751871120000,          // Unix ms | null — start of suspicious activity
  suspiciousEnd:   1751899999000,          // Unix ms | null — end of suspicious activity
  createdAt: '2026-07-07T09:00:00.000Z',   // ISO 8601
  updatedAt: '2026-07-07T11:30:00.000Z',   // bumped on every change
  createdBy: 'analyst',                    // username of the creator

  data: {
    // one key per tab registered in config/tabs.js:
    summary: {},                           // the Summary tab reads incident.* directly
    browser: {
      activeBrowser: 'chrome',
      browsers: {                          // data PER BROWSER, then PER PROFILE
        chrome: {
          activeProfile: 'default',
          profiles: {                      // keyed by a stable id; shown in createdAt order
            default: { id: 'default', name: 'Default', createdAt: '1970-01-01T00:00:00.000Z',
                       history: [], downloads: [], bookmarks: [], shortcuts: [],
                       meta: { history: null, bookmarks: null, shortcuts: null } },
            '<uuid>': { id: '<uuid>', name: 'Work', createdAt: '2026-07-07T09:10:00.000Z', … },
          },
        },
        firefox: { activeProfile, profiles: { … meta: { places: null } } },
        edge: { … }, brave: { … }, opera: { … },
        safari:  { activeProfile, profiles: { … meta: { history, downloads, bookmarks } } },
      },
    },
    network:  {},
    endpoint: {},
  },

  // Entries the analyst flagged as malicious (keyed by the event id):
  flags: {
    '<eventId>': {
      key, browserId, section, eventType, title, url, time,   // the flagged snapshot
      profileId, profileName,                                  // browser flags only (2.0.0+)
      flaggedAt, flaggedBy,                                    // provenance
      comments: [ { id, text, at, author } ],                  // per-flag comments
    },
  },

  // Free-form notes shown on the Summary timeline:
  notes: [ { id, text, createdAt, updatedAt, author } ],
}
```

> `meta` is indexed by **file source** (keys vary per engine: Chromium has
> `history`/`bookmarks`/`shortcuts`, Firefox has `places`). Each entry
> describes the imported file: `{ fileName, format, rows, importedAt }`.

`data` is built by `buildDefaultIncidentData()` (`src/config/tabs.js`), which
iterates the tab registry: each tab contributes `structuredClone(defaultData)`
under its own `dataKey`. Every incident loaded from the server or imported from
a file passes through `normalizeIncident()`, which merges the registry defaults
with the stored `data` — so **adding a tab requires no data migration**:
existing incidents receive the new tab's `defaultData` automatically (see
[§4.1](#41-add-a-new-analysis-tab)).

#### Where things are stored

| Store | Content |
|---|---|
| Database `incidents` | all incidents, imported artifacts included |
| Database `users` / `sessions` | accounts (bcrypt hash) and server-side sessions |
| Database `audit_log` | the global audit trail |
| Database `settings` | detection keywords + business hours (shared by all analysts) |

### 3.5 Authentication, sessions and the audit log

#### Authentication

Passwords are hashed with **bcrypt on the server** (`backend/app/security.py`).
A successful `POST /api/auth/login` creates a server-side session row and sets
the **httpOnly** `nik_session` cookie (with the `Secure` flag when
`COOKIE_SECURE=true`); `credentials: 'include'` on every fetch keeps it
flowing. Sessions expire after `SESSION_TTL_HOURS`.

User shape: `{ id, username, role: 'admin' | 'analyst', createdAt, createdBy }`
— the password hash never leaves the backend.

The App shell (`App.jsx`) implements a three-state **auth gate**, driven by
`GET /api/auth/bootstrap` and `GET /api/auth/me`:

- **no users at all** → `FirstRunSetup`: the first `POST /api/users` succeeds
  without authentication and the created account is **forced to the `admin`
  role**;
- **users exist but not signed in** → `LoginScreen`;
- **signed in** → the main app.

Admins manage accounts from the **User management** modal: add a user
(username + password + role) or delete one — never the last remaining user, and
never your own account. All other user operations require an admin session,
enforced server-side.

#### Audit log

`src/context/AuditContext.jsx` records every meaningful action through the API:
**who** (actor), **when** (`at`), **what** (`action`), the **details**, and
which **incident** it belonged to. Entries are returned newest-first, capped at
5000.

Entry shape: `{ id, at, actor, action, target, details, incidentId, incidentName }`.

Action strings emitted include: `user.create`, `user.delete`, `auth.login`,
`auth.logout`, `incident.create` / `.update` / `.delete` / `.export` /
`.import`, `browser.upload` / `.demo` / `.clear` / `.removeFile`, `flag.add` /
`.remove` / `.comment`, `note.add`, and `backup.export` / `backup.import`.

The read-only **Audit log** modal (`AuditLogView.jsx`, opened from the sidebar)
surfaces the trail in a searchable table; an **admin** can clear the whole log
behind an inline confirmation step.

### 3.6 Large data sets

A browser history of a few hundred thousand visits has to stay usable, so the
Browser tab keeps its per-row work to a minimum:

- `buildEvents()` parses each URL **once** (`analyzeUrl` in `utils/url.js`) and
  stores `domain` and `searchQuery` on the event; the stat cards, the ranking
  widgets and the table cells read those fields instead of parsing again
  (`entryDomain()` / `entrySearchQuery()` fall back to parsing for raw entries).
- `DataTable` sorts text with one shared `Intl.Collator`: `localeCompare` with
  options builds a collator per comparison, which made a 300k-row sort take
  seconds. The search box uses `useDeferredValue`, so typing never waits for
  the filter.
- `buildTimelineEvents()` takes `incident.data`, not the incident: flags and
  notes do not change the timeline, so toggling a flag does not rebuild the
  Timeline tab or the tail panel.

Tables stay paginated (25 rows by default), so the DOM never holds more than
one page; the cost of a large incident is in these data passes, not in
rendering. When you add a per-row computation, do it once in the `build*`
helper, not in a cell renderer.

### 3.7 Malware samples

The **Malware Analysis** tab is the one place where a raw file reaches the
server. The flow:

1. The analyst drops a file; the frontend posts it as is to
   `POST /api/incidents/{id}/samples` (`services/api.js` → `upload()`, with
   progress).
2. The server (`routers/samples.py`) computes the SHA-256 and writes the bytes
   **once** to the sample store (`app/samples.py`: `SAMPLE_STORE/<sha256>.bin`,
   read-only, no execute bit), runs the static analysis
   (`parsing/malware.py`: hashes, magic-byte type, entropy overall and per
   64 KB block, ASCII/UTF-16 strings, indicators) and stores the result in the
   `samples` table. The incident document gets only a light reference under
   `data.malware.samples` (`sha256`, `fileName`, type, size, who and when).
3. The tab fetches `GET /api/samples/{sha256}` when a sample is selected and
   runs the SOC engine on the indicators client-side (`utils/malware.js`),
   with the built-in malware ruleset (`DEFAULT_MALWARE_KEYWORDS`) on top of
   the shared keywords, exactly like the other tabs.
4. Downloads go through `GET /api/samples/{sha256}/download`, which wraps the
   file in an AES-256 zip (`pyzipper`) protected by `infected` or a password
   the analyst types; the plain bytes never leave the server. Uploads,
   downloads and removals are written to the audit log by the server.

Design points: the same file in two incidents is stored and analysed once and
deleted only when the last reference goes; the first 5,000 strings are stored
with the analysis and the rest is recomputed from the file on demand
(`/strings`); nothing ever opens the sample with a library that interprets its
format. On the host, **exclude the sample store from the antivirus** (it would
quarantine the evidence) and include it in backups (§6).

**Structure and YARA.** For executables the analysis also parses the format
(`parsing/executables.py`): PE through `pefile` (machine, subsystem, compile
time, sections with entropy and flags, imports by library, exports,
resources, imphash, Authenticode presence, rich header, PDB path), ELF and
Mach-O with Nik's own header parsers (segments, sections, needed libraries or
dylibs, interpreter, code signature). Malformed headers, the norm in malware,
become `warnings` instead of failures. Every sample is then scanned with YARA
(`yara_rules.py`): the built-in rule files under `app/yara/` (`YARA_RULES`)
plus the rule sets admins add in **Settings → YARA rules**, which are compiled
on their own before being saved and recompiled together on change. A match's
`meta.severity` (`high` / `medium`) and `meta.description` drive the badges;
YARA severity counts towards the sample's severity. The analysis records its
`analysisVersion`; **Re-analyse** (`POST /api/samples/{sha256}/reanalyse`)
runs the current engine on the stored file, so older samples catch up after
an upgrade or a rule change.

---

## 4. Extending the platform

### 4.1 Add a new analysis tab

The `src/config/tabs.js` registry is the **only existing file to modify**.
Example: a "DNS Logs" tab.

**Step 1 — Create the tab component.** Every tab is a component with a default
export that receives the active `incident` as a prop. Create
`src/components/tabs/DnsLogsTab.jsx`:

```jsx
import { useState } from 'react'
import { Network, Upload, Trash2 } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { generateId } from '../../utils/id.js'
import { Card, Button, DataTable, EmptyState, Badge } from '../ui/index.js'
import { formatDateTime, anyToMs } from '../../utils/time.js'

export default function DnsLogsTab({ incident }) {
  const { updateTabData, clearTabData } = useIncidents()
  const dns = incident.data.dns ?? { queries: [], meta: null }
  const [error, setError] = useState(null)

  async function handleFile(file) {
    setError(null)
    try {
      const rows = JSON.parse(await file.text()) // [{ timestamp, domain, type, client }]
      const queries = rows
        .filter((r) => r.domain)
        .map((r) => ({
          id: generateId(),
          domain: r.domain,
          type: r.type ?? 'A',
          client: r.client ?? null,
          timestamp: anyToMs(r.timestamp),
        }))
      updateTabData(incident.id, 'dns', {
        queries,
        meta: { fileName: file.name, format: 'json',
                rows: queries.length, importedAt: new Date().toISOString() },
      })
    } catch (err) {
      setError(err.message ?? 'Invalid file.')
    }
  }

  if (dns.queries.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No DNS logs loaded"
        message="Import a JSON export of DNS queries to start the analysis."
        action={
          <label className="cursor-pointer">
            <Button variant="primary" icon={Upload}>Import DNS logs</Button>
            <input type="file" hidden accept=".json"
                   onChange={(e) => e.target.files[0] && handleFile(e.target.files[0])} />
          </label>
        }
      />
    )
  }

  return (
    <div className="space-y-6">
      {error && <p className="text-sm text-red-500">{error}</p>}
      <Card
        title="DNS queries"
        icon={Network}
        actions={
          <Button variant="ghost" size="sm" icon={Trash2}
                  onClick={() => clearTabData(incident.id, 'dns')}>
            Clear data
          </Button>
        }
      >
        <DataTable
          data={dns.queries}
          searchKeys={['domain', 'client']}
          defaultSort={{ key: 'timestamp', dir: 'desc' }}
          columns={[
            { key: 'timestamp', label: 'Date/Time', sortable: true,
              className: 'font-mono text-xs',
              render: (row) => formatDateTime(row.timestamp) },
            { key: 'domain', label: 'Domain', sortable: true, className: 'font-mono text-xs' },
            { key: 'type', label: 'Type', render: (row) => <Badge color="cyan">{row.type}</Badge> },
            { key: 'client', label: 'Client', className: 'font-mono text-xs' },
          ]}
          emptyMessage="No query matches the filters"
        />
      </Card>
    </div>
  )
}
```

**Step 2 — Register the tab** in `src/config/tabs.js`:

```js
// at the top of the file, next to the other lazy tabs:
const DnsLogsTab = lazy(() => import('../components/tabs/DnsLogsTab.jsx'))

// inside ANALYSIS_TABS (array order = order in the TabBar):
{
  id: 'dns',                  // unique, used to select the tab
  label: 'DNS Logs',          // label in the TabBar
  icon: Network,              // lucide-react icon (import at the top)
  component: DnsLogsTab,      // lazy component → separate build chunk
  dataKey: 'dns',             // key under incident.data
  defaultData: {              // initial structure for every new incident
    queries: [],
    meta: null,
  },
},
```

**Step 3 — Nothing else is needed.** The TabBar maps `ANALYSIS_TABS`, `App.jsx`
renders the active component inside `<Suspense>`, and
`buildDefaultIncidentData()` includes the new `dataKey` in every new incident.
Existing incidents are covered by `normalizeIncident()`, which fills missing
`dataKey`s with the registry `defaultData` on load — no manual migration. The
registry `defaultData` is also the reset state used by `clearTabData`.

### 4.2 Extend the SOC detection rules

**End users** edit rules at runtime from **Settings** (the ⚙ icon in the
header): add/edit/remove suspicious keywords and change the business hours.
Changes are stored server-side and apply to all analysts and all incidents.
This section is about extending things via **code**.

The engine has three parts:

- `src/config/detectionRules.js` — the **factory defaults**
  (`DEFAULT_SUSPICIOUS_KEYWORDS`, `DEFAULT_BUSINESS_HOURS`);
- `src/context/SettingsContext.jsx` — the runtime state (`useSettings()`) plus
  `useSocEngine()`, a memoized engine;
- `src/utils/soc.js` — `createSocEngine({ keywords, businessHours })`, which
  compiles the regexes and analyzes events (`engine.analyze(entry)`).

**Add a default keyword rule** — add an object to
`DEFAULT_SUSPICIOUS_KEYWORDS`; regexes are compiled case-insensitively and
applied to **URL + title + file name** of each event:

```js
{
  id: 'rat-tools',                 // unique rule identifier
  label: 'RAT / C2',               // badge text in the UI
  // Regex (string source → escape backslashes twice).
  // Use \\b for short keywords that risk false positives: without it,
  // "rat" would match "administrator" or "strategy".
  pattern: '\\brat\\b|cobalt[-_ ]?strike|meterpreter|\\bc2\\b',
  severity: 'high',                // 'high' (red) | 'medium' (amber)
  description: 'References to a Remote Access Trojan or a C2 framework.',
},
```

Severity logic in `engine.analyze()`: at least one `high` match → red row; only
`medium` matches (or just a time anomaly) → amber row.

**Business hours** — factory default in `detectionRules.js`:

```js
export const DEFAULT_BUSINESS_HOURS = {
  startHour: 8,        // start of the window (inclusive)
  endHour: 18,         // end of the window (exclusive)
  flagWeekends: true,  // if true, the whole weekend is "outside hours"
}
```

`isOutsideBusinessHours(ms, businessHours)` treats hours
`< startHour || >= endHour` as outside, plus the weekend when `flagWeekends` is
set.

**Add a new type of detection** (example: URLs pointing at a bare IP address, a
classic C2/phishing indicator) — extend `src/utils/soc.js` in three places:

```js
// a) the analysis function:
export function isRawIpUrl(url) {
  try {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(new URL(url).hostname)
  } catch {
    return false
  }
}

// b) include it in analyze() inside createSocEngine:
const isRawIp = isRawIpUrl(entry.url)
// … and let it contribute to `severity` and the returned object.
```

```jsx
// c) render it in EventsSection.jsx, next to the keyword badges:
{event.soc.isRawIp && (
  <Badge color="amber" title="URL with a literal IP address: possible C2/phishing">
    direct IP
  </Badge>
)}
```

If the new signal should appear in the StatCards, update `computeSocStats`
accordingly; optionally add an option to the detection filter in the events
section.

### 4.3 Browsers, parsers and formats

**Add a browser.** Browsers are a registry in `src/config/browsers.js`: adding
an entry to the `BROWSERS` array makes the sub-tab appear and wires up upload,
path hints and sections automatically. Each browser declares `id`, `label`,
`icon`, `engine` (`'chromium'` | `'firefox'` | `'safari'`), `accent`, optional
`platforms` (host OSes it exists on — Safari is `['macos']`; the path note warns
when the incident's OS is not listed), `profilePaths`, `artifacts` and `sources`
(the files to load, each with `key`, `produces`, `paths` and `hint`). A
Chromium browser can reuse `chromiumSources(bases)`; a brand-new engine also
needs a branch in the parsers, and in `backend/app/parsing/` for API uploads.
Paths may contain `<profile>`, explained by the optional `profileHint`.

**Profiles.** Every browser holds one or more profiles; the profile helpers
(normalization of pre-2.0.0 data, ordering, name validation, labels) live in
`src/utils/browserProfiles.js` and mirror `backend/app/browser_profiles.py`. A
browser always keeps at least one profile; deleting one keeps the flags placed
on its rows, shown as coming from a deleted profile.

**The parsing dispatcher.** All parsing goes through
`parseBrowserSource(file, engine, source)` in `src/services/fileParsers.js`:

```js
parseBrowserSource(file, engine, source)
  → Promise<{ produced, format }>
// produced: { history?, downloads?, bookmarks?, shortcuts? }
// format:   'sqlite' | 'plist' | 'json' | 'csv'
```

Pipeline: `isSqliteBuffer()` (magic string in the first 16 bytes) → if SQLite,
delegate to `parseSqliteSource(buffer, engine, sourceKey)` in
`sqliteParser.js` (Chromium parsers over `urls`/`visits`/`downloads`/
`omni_box_shortcuts`, Firefox parsers over `moz_places`/`moz_historyvisits`/
`moz_bookmarks`/`moz_annos`, Safari over `history_items`/`history_visits`);
else, a property list (`bplist00` header or an XML `<plist>`) is decoded by
`plistParser.js` — dependency-free — and mapped by `safariParser.js`
(Safari only); otherwise decode as text → JSON or CSV (papaparse). Field mapping is **lenient** (multiple aliases per field, English
and Italian column names), timestamps are normalized, and every row gets a
unique `id`.

A source **owns** its `produces`: re-importing it replaces those artifacts;
removing it (`removeBrowserSource`) zeroes them. Errors are always
`throw new Error('<message>')`, surfaced by `FileUploadZone`.

**Add a field alias or a format.** For a tool that names fields differently
(e.g. `visited_at`), extend the relevant `*_ALIASES` chain in `fileParsers.js`.
For a new format (e.g. NDJSON), add a branch in `parseBrowserSource` before the
CSV fallback and reuse the existing mappers (`mapHistoryRows`,
`mapDownloadRows`, `mapBookmarkRows`, `mapShortcutRows`). A new `format` value
also needs its color in the `Badge` in `FileUploadZone.jsx`.

**Timestamps: mind the engine.**

- **Chromium** uses "WebKit time" (µs since **1601**) → `webkitToMs`
  (`ms = µs / 1000 − 11644473600000`).
- **Firefox** uses "PRTime" (µs since **1970**) → `firefoxToMs`
  (`ms = µs / 1000`).
- **Safari** uses Mac absolute time (seconds since **2001**, fractional) →
  `macToMs` (`ms = (s + 978307200) × 1000`); plist dates are decoded to `Date`.

Getting the conversion wrong shifts dates by ~369 years: always use the right
helper for the engine.

### 4.4 UI kit reference

All components live in `src/components/ui/` with a default export, re-exported
from the barrel `src/components/ui/index.js`:

```js
import { Button, Card, Badge, Modal, DataTable, EmptyState,
         SearchInput, Select, StatCard, AsciiSkull, MicroSkull } from '../ui/index.js'
```

**DataTable** — the workhorse for every tabular view (events, bookmarks,
shortcuts, the audit log and any future tab). Memoized internal pipeline:
**filter (search) → sort → paginate**.

```js
<DataTable
  columns={[ /* see below */ ]}
  data={rows}                       // rows (pre-filtered by the parent for custom filters)
  searchKeys={['url', 'title']}     // string keys for the built-in search; [] = no search bar
  searchPlaceholder="Search…"
  defaultPageSize={25}
  pageSizeOptions={[10, 25, 50, 100]}
  defaultSort={{ key: 'time', dir: 'desc' }}  // null = no initial sort
  rowClassName={(row) => ''}        // extra classes per row (highlight anomalies)
  toolbar={<Select … />}            // node rendered next to the search
  emptyMessage="No data available"
  rowKey={(row, i) => row.id ?? i}
/>
```

Column definition:

```js
{
  key: 'time',                 // data key (also used for sorting)
  label: 'Date/Time',          // header
  sortable: true,              // header click: asc → desc cycle
  render: (row) => node,       // custom cell render (optional)
  sortAccessor: (row) => any,  // alternative value for sorting (optional)
  className: 'font-mono text-xs',
  headerClassName: '',
  align: 'left' | 'right',
}
```

Guaranteed behaviours: case-insensitive search on `searchKeys`; sort icons;
pagination with a page-size selector and an "X–Y of Z results" count; reset to
page 1 when search or data change; `overflow-x-auto` on the container.

> Tip: the parent cannot reset the DataTable's internal search/sort/pagination
> directly. `EventsSection` clears them on "Reset filters" by bumping a
> `resetToken` used as the DataTable `key`, forcing a remount.

**Main components:**

```js
Button({ variant = 'primary' | 'secondary' | 'ghost' | 'danger',
         size = 'md' | 'sm' | 'xs', icon: LucideIcon?, children?, … })

Card({ title?, icon: LucideIcon?, actions? /* node right of the title */,
       children, className = '', bodyClassName = '' })

Badge({ color = 'slate' | 'cyan' | 'red' | 'amber' | 'emerald' | 'violet',
        children, title?, className = '' })
  // slate = neutral, cyan = info, red = HIGH, amber = MED, emerald = ok/accent

Modal({ open, onClose, title, children, footer?, maxWidth = 'max-w-lg' })
  // blurred backdrop; closes on Escape and on backdrop click

EmptyState({ icon: LucideIcon, illustration?: ReactNode, title, message?, action?, className = '' })
  // `illustration` (e.g. an <AsciiSkull />) replaces the icon

SearchInput({ value, onChange /* (string) => void */, placeholder, className })

Select({ value, onChange /* (string) => void */,
         options: [{ value, label }], label?, className = '' })

StatCard({ icon: LucideIcon, label, value,
           tone = 'default' | 'accent' | 'danger' | 'warn' | 'ok', hint? })

AsciiSkull({ preset = 'block' | 'large' | 'medium' | 'small',
             eyes = 'animated' | 'open' | 'closed' | 'x',
             tone = 'accent' | 'muted', className = '' })
  // decorative (aria-hidden): pair it with a role="status" text

MicroSkull({ mood = 'animated' | 'closed' | 'x', className = '' })
  // inline "(o.o)" for busy buttons and status lines
```

**Loading, error and empty states** use the ASCII skull, generated by
`renderSkull()` in `src/utils/asciiSkull.js` (any size, always symmetric):

| Where | Skull |
|---|---|
| Opening an incident (`IncidentLoadingState`) | `block`, looking around, with the real download progress |
| Loading a tab's code (`Suspense` fallback in `App.jsx`) | `medium`, looking around |
| An incident failed to load | `medium`, eyes crossed out, muted |
| No incident open | `medium`, eyes closed (asleep), muted |
| Parsing an uploaded file (`FileUploadZone`) | `small`, looking around |
| Connecting, loading the list, busy buttons, server unreachable | `MicroSkull` — `(o.o)`, or `(x.x)` on errors |

The `large` preset is kept for future use. With *reduce motion* enabled in
the operating system the skulls stay still.

**Look and tokens.** Nik has a single dark, terminal-style theme. Colours
are **named tokens** declared once in `src/index.css` (`@theme`), and
components use the names, never raw palette classes:

| Token | Use |
|---|---|
| `sunken` · `canvas` · `panel` · `raised` | surfaces, darkest to lightest (sidebar/terminal panes, page, cards and inputs, hover) |
| `line` · `line-soft` | borders · table row dividers |
| `fg` · `fg-muted` · `fg-subtle` | text · secondary text · decoration and disabled only |
| `accent` (+ `-strong`, `-fg`, `-soft`) | the green prompt: primary actions, focus rings, active tab |
| `link` (+ `-fg`) · `info` (+ `-line`, `-soft`) | links · informational badges |
| `high` (+ `-fg`, `-line`, `-soft`) · `med` (…) | SOC severities HIGH (red) and MED (amber) |
| `violet` (+ `-line`, `-soft`) | commands / anti-forensics |

Tailwind turns each token into utilities (`bg-panel`, `text-fg-muted`,
`border-line`, `ring-accent`…). Other conventions:

- Corners are square; borders are 1 px `border-line`.
- Monospace (`font-mono`, JetBrains Mono) for data, labels, tabs and
  headings; Inter (`font-sans`) for prose and buttons. Both fonts are bundled
  (`src/assets/fonts/`), no CDN.
- Severities differ in lightness as well as hue, so they stay readable for
  colour-blind analysts.

- Flagged rows use the accent (`bg-accent-soft border-l-accent-strong`),
  SOC rows their severity (`bg-high-soft border-l-high-line`, `med` alike), so
  an analyst's flag never looks like a detection.

**`tail -f` panel.** `TailPanel` (in `components/layout/`) lists the latest
60 timestamped events of the open incident — oldest first, newest at the
bottom, kept scrolled to the end — with the source, severity (`!!` HIGH, `!`
MED) and flags. It is toggled from the tab bar and remembered per tab (open on
Summary by default); it needs a wide screen (`lg`) and is unmounted when
closed, so it costs nothing then. Its lines come from `tailLines()` in
`utils/timeline.js`, over the same `buildTimelineEvents()` as the Timeline tab.

---

## 5. Incident export / import (JSON)

### Export

`exportIncident(id)` (from `useIncidents()`) downloads
`nik-<normalized-name>.json` with this envelope:

```json
{
  "app": "Nik",
  "version": 4,
  "exportedAt": "2026-07-07T11:30:00.000Z",
  "incident": {
    "id": "b3f1c9e2-…",
    "host": "WKS-FINANCE-01",
    "username": "m.rossi",
    "name": "WKS-FINANCE-01 - m.rossi",
    "suspiciousStart": 1751871120000,
    "suspiciousEnd": 1751899999000,
    "createdAt": "2026-07-01T09:00:00.000Z",
    "updatedAt": "2026-07-07T11:29:58.000Z",
    "createdBy": "analyst",
    "data": {
      "summary": {},
      "browser": {
        "activeBrowser": "chrome",
        "browsers": {
          "chrome": { "activeProfile": "default", "profiles": { "default": {
            "id": "default", "name": "Default", "createdAt": "1970-01-01T00:00:00.000Z",
            "history":   [ { "id": "…", "url": "https://…", "title": "…",
                             "visitCount": 3, "visitTime": 1751871120000,
                             "visitId": 100, "fromVisitId": 99, "isRedirect": false } ],
            "downloads": [ { "id": "…", "fileName": "toolkit.zip",
                             "url": "https://…", "referrer": "https://…",
                             "startTime": 1751871120000, "totalBytes": 24000000 } ],
            "bookmarks": [ { "id": "…", "name": "…", "url": "…",
                             "folder": "Bookmarks bar > Work",
                             "dateAdded": 1751871120000 } ],
            "shortcuts": [ { "id": "…", "text": "…", "url": "…", "title": "…",
                             "lastAccessTime": 1751871120000, "hits": 5 } ],
            "meta": {
              "history": { "fileName": "History", "format": "sqlite",
                           "rows": 1240, "importedAt": "2026-07-07T10:00:00.000Z" },
              "bookmarks": null, "shortcuts": null
            }
          } } },
          "firefox": { "activeProfile": "default", "profiles": { "default": {
                       "id": "default", "name": "Default", "createdAt": "…",
                       "history": [], "downloads": [], "bookmarks": [],
                       "shortcuts": [], "meta": { "places": null } } } }
        }
      },
      "network":  {},
      "endpoint": {}
    },
    "flags": { "…": { } },
    "notes": [ { "id": "…", "text": "…", "createdAt": "…", "updatedAt": "…", "author": "…" } ]
  }
}
```

All entry timestamps are **Unix epoch in milliseconds** — native browser
formats are converted at import time (`webkitToMs` / `firefoxToMs`).

### Import

`importIncidentFromFile(file)` (async) accepts the envelope above (version 4,
or 3 and older — their single-profile browser data lands in a "Default"
profile) or a **bare incident object**. Minimal validation: `data` must be an object, otherwise an
`Error` is thrown (surfaced by the sidebar). On import the incident:

- always receives a **new `id`** — importing the same file twice creates two
  distinct copies, no collisions;
- passes through `normalizeIncident()`, so the `dataKey`s of tabs added after
  the export are filled in with their `defaultData`;
- is inserted at the top of the list, **activated automatically**, and
  persisted to the server (`POST /api/incidents`);
- is recorded as `incident.import` in the audit log.

> The JSON export is self-contained (it holds all imported data, flags and
> notes), which makes it a convenient exchange/archival format between Nik
> installations.

---

## 6. Full platform backup

Admins can export and restore the **entire platform** — every incident
(imported artifacts, flags and notes included), every user account, the audit
log and the shared detection settings — from the sidebar's **Full backup**
button. Typical uses: a safety copy before an upgrade, or moving a deployment
to another machine (including SQLite dev → PostgreSQL production, since the
backup is database-agnostic).

> Routine upgrades do **not** require this: data persists in PostgreSQL across
> frontend/backend updates and container rebuilds. The full backup is
> insurance and a migration vehicle, complementary to `pg_dump`.

> The backup envelope holds the **analysis** of every malware sample, not the
> raw files: those live in the sample store (`SAMPLE_STORE`, the
> `sample-store` volume in Compose). Copy that directory alongside the backup
> if the samples themselves must survive.

### Export

`GET /api/backup/export` (admin only, logged as `backup.export`) downloads
`nik-backup-<timestamp>.json`:

```json
{
  "app": "Nik",
  "type": "backup",
  "version": 1,
  "exportedAt": "2026-07-08T09:00:00.000Z",
  "users":     [ { "id": "…", "username": "…", "passwordHash": "…",
                   "role": "admin", "createdAt": "…", "createdBy": null } ],
  "incidents": [ { "…full incident documents, artifacts included…": "" } ],
  "audit":     [ { "id": "…", "at": "…", "actor": "…", "action": "…" } ],
  "settings":  { "keywords": [ ], "businessHours": { } }
}
```

⚠️ The file contains **bcrypt password hashes**: treat it like a database dump
(store it encrypted / access-controlled).

### Restore

`POST /api/backup/import` (admin only, logged as `backup.import`) **replaces
all current data** with the file's content, in a single all-or-nothing
transaction. The UI asks for explicit confirmation and shows what the file
contains before sending anything.

Guarantees:

- **Atomic** — on any validation or database error, nothing is changed.
- **No lockout** — the importing admin stays signed in: if their username
  exists in the backup, the session re-attaches to that account (whose
  password becomes the one from the backup); otherwise their current account
  is re-inserted unchanged alongside the imported users.
- **Sessions are reset** — every other analyst must sign in again (with the
  credentials from the backup).

After a successful restore the app reloads and every context refetches the
restored data.
