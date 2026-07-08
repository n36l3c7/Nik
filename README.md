# CSAP — Cyber Security Analysis Platform

A full-stack web platform for analysing digital-forensics artifacts, laid out
like a SOC dashboard. Analysts organise their work into **incidents** (forensic
cases identified by a host and/or username), import browser artifacts, flag
suspicious events and build a timeline of the malicious activity — with every
action attributed to a named analyst and recorded in a global audit log.

**Key traits:**

- **Client-side artifact parsing** — SQLite artifacts (Chromium `History`,
  Firefox `places.sqlite`, …) are parsed **in the analyst's browser** via
  WebAssembly (`sql.js`). Raw forensic files are never uploaded anywhere: only
  the normalized entries reach the server.
- **Centralized storage** — incidents, users, settings and the audit log live
  in PostgreSQL behind a FastAPI REST API. Every analyst who signs in sees the
  same data, from any machine, and work is attributable across the team.
- **Browser forensics** — one sub-tab per browser (Chrome, Firefox, Edge,
  Brave, Opera): browsing history, downloads, bookmarks and omnibox shortcuts,
  with event classification (visit / search / redirect).
- **SOC detection engine** — editable suspicious-keyword rules and a
  configurable business-hours window highlight suspicious events automatically.
- **Case management** — per-event flags with comments, free-form notes, a
  vertical incident timeline, and self-contained JSON export/import for
  exchanging cases between analysts.
- **Full backup** — admins can export the entire platform (all incidents,
  users, settings and the audit log) to a single JSON file and restore it
  later, e.g. when moving the deployment to another machine.
- **Authentication & audit** — session-based login (bcrypt hashes, httpOnly
  cookie), `admin` / `analyst` roles, and a global audit trail of every
  meaningful action.

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

Open **http://localhost:8080** and create the first user — that account becomes
the **admin**. Database tables are created automatically on the API's first
start, so there is nothing to migrate.

```bash
docker compose logs -f api    # follow backend logs
docker compose ps             # container status
docker compose down           # stop (keeps the database volume)
docker compose down -v        # stop AND delete the database volume (wipes data)
```

Podman is a drop-in replacement (rootless is fine for port 8080):

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
```

Tailwind v4 is wired in through the Vite plugin (`@tailwindcss/vite`), so there
is no `tailwind.config.js` and no extra setup step.

### 1.3 Configuration reference

**Backend** (environment variables, optionally from `backend/.env` — see
`backend/.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./csap.db` | SQLAlchemy URL. Production: `postgresql+psycopg://csap:PASS@host/csap`. |
| `SECRET_KEY` | `dev-insecure-change-me` | Signing/entropy secret. Set a long random value in production. |
| `COOKIE_SECURE` | `true` | `Secure` flag on the session cookie (HTTPS only). Set `false` only for plain-HTTP local dev. |
| `SESSION_TTL_HOURS` | `12` | Session lifetime. |

**Compose** (root `.env` — see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DB_PASSWORD` | `csap` | PostgreSQL password (shared by the `db` and `api` services). |
| `SECRET_KEY` | — | Backend secret. Use a long random value (e.g. `openssl rand -hex 32`). |
| `COOKIE_SECURE` | `false` | Keep `false` only for plain-HTTP testing on `:8080`; set `true` behind HTTPS. |
| `WEB_PORT` | `8080` | Host port the UI is published on. |
| `SESSION_TTL_HOURS` | `12` | Session lifetime. |

> **Two things that will bite you over plain HTTP:**
>
> 1. With `COOKIE_SECURE=true` the browser **drops** the `csap_session` cookie
>    on `http://` origins, so login won't stick. Serve over HTTPS in production
>    (a self-signed or internal-CA certificate is fine on an internal network).
> 2. The copy-to-clipboard buttons use the Clipboard API, which only works in a
>    **secure context** (`https://` or `http://localhost`).

---

## 2. Production deployment

### 2.1 Docker / Podman in production

The Compose file publishes plain HTTP on `:8080` for a fast start. For a real
deployment, put TLS in front and set `COOKIE_SECURE=true`:

- **Option A (recommended):** keep the container on `:8080` and front it with a
  host reverse proxy that terminates TLS (nginx, Caddy, Traefik), proxying to
  `127.0.0.1:8080`.
- **Option B:** add a `443` listener + certificate to `deploy/nginx.conf`,
  mount the certificate into the `web` container, and map `- "8443:443"`.

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
docker compose exec db pg_dump -U csap csap > csap-backup.sql
cat csap-backup.sql | docker compose exec -T db psql -U csap csap

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
sudo -u postgres createuser --pwprompt csap
sudo -u postgres createdb -O csap csap
```

**Enable password authentication.** A fresh RHEL cluster uses `ident`/`peer`
auth for local TCP connections, which rejects the app's `csap` login. Edit
`/var/lib/pgsql/data/pg_hba.conf` so the local lines use `scram-sha-256`:

```conf
# TYPE  DATABASE  USER  ADDRESS         METHOD
host    csap      csap  127.0.0.1/32    scram-sha-256
host    csap      csap  ::1/128         scram-sha-256
```

Then `sudo systemctl reload postgresql`. The connection string for the backend
is:

```
postgresql+psycopg://csap:STRONG_PASSWORD@localhost/csap
```

Tables (`users`, `sessions`, `incidents`, `audit_log`, `settings`) are created
automatically on the API's first startup — no migration step.

#### Step 3 — Deploy the FastAPI backend (systemd)

The backend needs **Python 3.11+** (RHEL 9 ships it; on RHEL 8 install
`python3.11`). Copy `backend/` to `/opt/csap/backend` and build a virtualenv:

```bash
sudo dnf install -y python3 python3-pip
sudo useradd --system --home /opt/csap --shell /sbin/nologin csap

sudo mkdir -p /opt/csap
sudo cp -r backend /opt/csap/backend
cd /opt/csap/backend

sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R csap:csap /opt/csap
```

Keep the secrets in `/etc/csap/csap.env` (readable only by root and the
service account):

```bash
sudo mkdir -p /etc/csap
sudo tee /etc/csap/csap.env >/dev/null <<'EOF'
DATABASE_URL=postgresql+psycopg://csap:STRONG_PASSWORD@localhost/csap
SECRET_KEY=replace-with-a-long-random-string   # e.g. `openssl rand -hex 32`
COOKIE_SECURE=true                             # requires HTTPS
EOF
sudo chmod 640 /etc/csap/csap.env
sudo chown root:csap /etc/csap/csap.env
```

Create `/etc/systemd/system/csap-api.service` — the API binds to **loopback
only**; nginx is the sole public entry point:

```ini
[Unit]
Description=CSAP FastAPI backend (gunicorn/uvicorn)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=csap
Group=csap
WorkingDirectory=/opt/csap/backend
EnvironmentFile=/etc/csap/csap.env
ExecStart=/opt/csap/backend/.venv/bin/gunicorn \
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
sudo systemctl enable --now csap-api.service
curl -s http://127.0.0.1:8000/api/health      # → {"status":"ok"}
```

#### Step 4 — Install nginx and place the static files

```bash
sudo dnf install -y nginx
sudo systemctl enable --now nginx

sudo mkdir -p /var/www/csap
sudo cp -r dist/* /var/www/csap/
```

#### Step 5 — SELinux (enforced by default on RHEL)

```bash
# a) Let nginx connect to the backend — without this, /api/ returns
#    502 Bad Gateway with an "AVC denied … name_connect" in the audit log:
sudo setsebool -P httpd_can_network_connect 1

# b) Label the static-file directory — or nginx returns 403 Forbidden:
sudo dnf install -y policycoreutils-python-utils
sudo semanage fcontext -a -t httpd_sys_content_t "/var/www/csap(/.*)?"
sudo restorecon -Rv /var/www/csap
```

#### Step 6 — TLS certificate

For an internal host a self-signed certificate is enough (clients must trust it
or accept the browser warning). Replace the CN/SANs with your host:

```bash
sudo mkdir -p /etc/pki/nginx/private
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/pki/nginx/private/csap.key \
  -out    /etc/pki/nginx/csap.crt \
  -subj "/CN=csap.example.internal" \
  -addext "subjectAltName=DNS:csap.example.internal,IP:10.0.0.10"
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

Create `/etc/nginx/conf.d/csap.conf`:

```nginx
# Redirect plain HTTP to HTTPS (the app requires a secure context)
server {
    listen 80;
    server_name csap.example.internal;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name csap.example.internal;

    ssl_certificate     /etc/pki/nginx/csap.crt;
    ssl_certificate_key /etc/pki/nginx/private/csap.key;

    root  /var/www/csap;
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
> `httpd_can_network_connect` is on (Step 5a) and that `csap-api.service` is
> running (`curl http://127.0.0.1:8000/api/health`).

#### Step 9 — Open the firewall and reload

Only **80/443** are exposed; the backend stays on `127.0.0.1:8000`:

```bash
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload

sudo nginx -t
sudo systemctl reload nginx
```

Browse to `https://csap.example.internal`, create the first (admin) user and
sign in.

#### Updating to a new version

```bash
# Frontend — rebuild and replace the static files:
npm ci && npm run build
sudo rm -rf /var/www/csap/*
sudo cp -r dist/* /var/www/csap/
sudo restorecon -Rv /var/www/csap

# Backend — refresh code and dependencies, restart the service:
sudo cp -r backend/* /opt/csap/backend/
sudo /opt/csap/backend/.venv/bin/pip install -r /opt/csap/backend/requirements.txt
sudo chown -R csap:csap /opt/csap
sudo systemctl restart csap-api.service
```

Upgrades do **not** wipe data: everything persists in PostgreSQL, and new
tables are created on startup. Take a `pg_dump` (or an in-app full backup,
[§6](#6-full-platform-backup)) before upgrading if you want a rollback point.

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
  are stored in the database and shared by all analysts. The only per-device
  value is the UI theme (light/dark), kept in `localStorage`.
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
downloads. Timestamps differ too — see [§4.3](#43-browsers-parsers-and-formats).

**Heavy formats** (EVTX, PCAP, disk images) are a natural fit for server-side
parsing with mature Python libraries (`python-evtx`, `scapy`, DFIR tooling).
The seam is ready: every browser import goes through
`parseBrowserSource(file, engine, source)` in `src/services/fileParsers.js`,
which returns normalized entries — a server-side parser only needs to return
the same shape, and the rest of the app (contexts, tables, detection) does not
change.

### 3.3 Folder structure

```
├── index.html                      # HTML shell (mount point #root)
├── package.json                    # Frontend dependencies and npm scripts
├── vite.config.js                  # React + Tailwind plugins, /api dev proxy
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
│       ├── schemas.py              # Pydantic request/response models
│       ├── security.py             # bcrypt hashing, session-auth dependencies
│       ├── defaults.py             # Factory defaults for detection settings
│       └── routers/                # auth, users, incidents, audit, settings, backup
└── src/
    ├── main.jsx                    # Entry: StrictMode > ThemeProvider > AuditProvider
    │                               #   > AuthProvider > SettingsProvider > IncidentProvider > App
    ├── index.css                   # Tailwind v4, @custom-variant dark, base + scrollbar
    ├── App.jsx                     # Shell + auth gate: Sidebar | Header + TabBar + tab content
    │
    ├── config/                     # ★ DECLARATIVE EXTENSION POINTS ★
    │   ├── tabs.js                 # ANALYSIS_TABS registry: the ONLY file to touch
    │   │                           #   to register a new tab. buildDefaultIncidentData().
    │   ├── browsers.js             # BROWSER registry (Chrome/Firefox/Edge/Brave/Opera):
    │   │                           #   engine, file sources, paths, artifacts.
    │   └── detectionRules.js       # Factory keyword rules and business hours
    │                               #   (managed at runtime from Settings).
    │
    ├── context/
    │   ├── ThemeContext.jsx        # useTheme() → { theme, setTheme, toggleTheme }
    │   ├── AuditContext.jsx        # useAudit(): global audit log via the API
    │   ├── AuthContext.jsx         # useAuth(): session auth (login/logout/me), users
    │   ├── SettingsContext.jsx     # useSettings(): keywords + business hours (server-side);
    │   │                           #   useSocEngine(): memoized detection engine
    │   └── IncidentContext.jsx     # useIncidents(): incident state, CRUD, flags, notes,
    │                               #   export/import — optimistic model backed by the API
    │
    ├── services/
    │   ├── api.js                  # The ONLY file that talks to the server (fetch wrapper)
    │   ├── storage.js              # Local preference: UI theme in localStorage
    │   ├── fileParsers.js          # parseBrowserSource(file, engine, source): dispatch
    │   │                           #   SQLite/JSON/CSV + lenient field mapping
    │   ├── sqliteParser.js         # Chromium (History/Shortcuts) and Firefox (places.sqlite)
    │   │                           #   parsers via sql.js (lazy WASM)
    │   └── demoData.js             # getDemoBrowserData(browser): demonstration dataset
    │
    ├── utils/
    │   ├── id.js                   # generateId() → crypto.randomUUID (with fallback)
    │   ├── time.js                 # webkitToMs, firefoxToMs, anyToMs, formatDateTime…
    │   ├── url.js                  # extractDomain, extractSearchQuery, topDomains…
    │   ├── events.js               # buildEvents, historyEventType, redirect helpers
    │   └── soc.js                  # createSocEngine({keywords, businessHours}) → analyze()
    │
    └── components/
        ├── ui/                     # Reusable UI kit (Button, Card, Badge, Modal, DataTable,
        │                           #   EmptyState, SearchInput, Select, StatCard, Spinner)
        ├── auth/                   # FirstRunSetup, LoginScreen, UserManagement
        ├── audit/                  # AuditLogView (read-only modal)
        ├── backup/                 # BackupModal (full export/restore, admin only)
        ├── settings/               # SettingsModal (keywords + business hours)
        ├── layout/                 # Sidebar, Header, TabBar
        └── tabs/
            ├── NetworkLogsTab.jsx      # Placeholder, ready for expansion
            ├── EndpointArtifactsTab.jsx# Placeholder, ready for expansion
            ├── summary/                # SummaryTab, IncidentTimeline, NoteBlock
            └── browser/                # BrowserAnalysisTab, FileUploadZone, EventsSection,
                                        #   filters, widgets, bookmarks/shortcuts tables
```

### 3.4 State and the data model

#### IncidentContext

All incident state lives in `src/context/IncidentContext.jsx`, exposed through
the `useIncidents()` hook:

```js
const {
  incidents,              // Incident[] — all incidents
  activeIncident,         // Incident | null — selected incident
  activeIncidentId,       // string | null
  loading,                // boolean — true until the initial API load finishes
  storageError,           // string | null — persistence error surfaced in the UI

  createIncident,         // ({host, username}) => Incident — creates AND activates
  updateIncidentMeta,     // (id, patch) => void — edit host/username/suspicious window
  deleteIncident,         // (id) => void — if active, activates the first remaining one
  selectIncident,         // (id) => void

  updateTabData,          // (id, dataKey, patch) => void — shallow-merge into data[dataKey]
  clearTabData,           // (id, dataKey) => void — reset to the registry defaultData

  updateBrowserData,      // (id, browserId, patch, auditInfo?) => void — per-browser merge
  setActiveBrowser,       // (id, browserId) => void — switch browser sub-tab (local only)
  clearBrowserData,       // (id, browserId) => void — clear ONE browser
  removeBrowserSource,    // (id, browserId, sourceKey, producedKeys) => void — remove ONE file

  toggleFlag,             // (id, flaggable) => void — flag/unflag an entry
  addFlagComment,         // (id, flagKey, text) => void
  removeFlagComment,      // (id, flagKey, commentId) => void

  addNote,                // (id, text) => void
  updateNote,             // (id, noteId, text) => void
  removeNote,             // (id, noteId) => void

  exportIncident,         // (id) => void — download the JSON (see §5)
  importIncidentFromFile, // async (file) => Incident — throws Error(msg) if invalid
} = useIncidents()
```

Incidents are loaded once after authentication (`GET /api/incidents`) and kept
in memory as an **optimistic model**: every mutation updates local state
immediately and persists the changed top-level keys to the server
(`POST` / `PATCH` / `DELETE /api/incidents/{id}`). A failed write surfaces in
`storageError`, shown by `App.jsx` as a red banner. `setActiveBrowser` is the
one exception — a pure view preference, never sent to the server.

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
      browsers: {                          // data PER BROWSER
        chrome:  { history: [], downloads: [], bookmarks: [], shortcuts: [],
                   meta: { history: null, bookmarks: null, shortcuts: null } },
        firefox: { history: [], downloads: [], bookmarks: [], shortcuts: [],
                   meta: { places: null } },
        edge: { … }, brave: { … }, opera: { … },
      },
    },
    network:  {},
    endpoint: {},
  },

  // Entries the analyst flagged as malicious (keyed by the event id):
  flags: {
    '<eventId>': {
      key, browserId, section, eventType, title, url, time,   // the flagged snapshot
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
| Browser `localStorage csap:theme` | `'dark'` \| `'light'` — the only per-device value |

### 3.5 Authentication, sessions and the audit log

#### Authentication

Passwords are hashed with **bcrypt on the server** (`backend/app/security.py`).
A successful `POST /api/auth/login` creates a server-side session row and sets
the **httpOnly** `csap_session` cookie (with the `Secure` flag when
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
`icon`, `engine` (`'chromium'` | `'firefox'`), `accent`, `profilePath`,
`artifacts` and `sources` (the files to load, each with `key`, `produces`,
`path` and `hint`). A Chromium browser can reuse `chromiumSources(base)`; a
brand-new engine also needs a branch in the parsers.

**The parsing dispatcher.** All parsing goes through
`parseBrowserSource(file, engine, source)` in `src/services/fileParsers.js`:

```js
parseBrowserSource(file, engine, source)
  → Promise<{ produced, format }>
// produced: { history?, downloads?, bookmarks?, shortcuts? }
// format:   'sqlite' | 'json' | 'csv'
```

Pipeline: `isSqliteBuffer()` (magic string in the first 16 bytes) → if SQLite,
delegate to `parseSqliteSource(buffer, engine, sourceKey)` in
`sqliteParser.js` (Chromium parsers over `urls`/`visits`/`downloads`/
`omni_box_shortcuts`, Firefox parsers over `moz_places`/`moz_historyvisits`/
`moz_bookmarks`/`moz_annos`); otherwise decode as text → JSON or CSV
(papaparse). Field mapping is **lenient** (multiple aliases per field, English
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

Getting the conversion wrong shifts dates by ~369 years: always use the right
helper for the engine.

### 4.4 UI kit reference

All components live in `src/components/ui/` with a default export, re-exported
from the barrel `src/components/ui/index.js`:

```js
import { Button, Card, Badge, Modal, DataTable, EmptyState,
         SearchInput, Select, StatCard, Spinner } from '../ui/index.js'
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

Badge({ color = 'slate' | 'cyan' | 'red' | 'amber' | 'emerald',
        children, title?, className = '' })

Modal({ open, onClose, title, children, footer?, maxWidth = 'max-w-lg' })
  // blurred backdrop; closes on Escape and on backdrop click

EmptyState({ icon: LucideIcon, title, message?, action?, className = '' })

SearchInput({ value, onChange /* (string) => void */, placeholder, className })

Select({ value, onChange /* (string) => void */,
         options: [{ value, label }], label?, className = '' })

StatCard({ icon: LucideIcon, label, value,
           tone = 'default' | 'accent' | 'danger' | 'warn' | 'ok', hint? })

Spinner({ className = '' })
```

**Style conventions:**

- Surfaces: `bg-white border-slate-200 dark:bg-slate-900 dark:border-slate-800`;
  a card is `rounded-xl border` + surfaces.
- Primary accent is **cyan** (`text-cyan-600 dark:text-cyan-400`); danger
  red-500/600, warning amber-500, ok emerald-500.
- Technical data (URLs, timestamps, queries) uses `font-mono text-xs`.
- SOC-flagged rows: high → `bg-red-500/5 dark:bg-red-500/10 border-l-2
  border-l-red-500`; medium → same in amber. Entries **manually flagged** by
  the analyst use a distinct cyan highlight (`border-l-cyan-500`).
- **Every color class must have its `dark:` counterpart** (class-based theme,
  see `@custom-variant dark` in `index.css`).

---

## 5. Incident export / import (JSON)

### Export

`exportIncident(id)` (from `useIncidents()`) downloads
`csap-<normalized-name>.json` with this envelope:

```json
{
  "app": "CSAP",
  "version": 3,
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
          "chrome": {
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
          },
          "firefox": { "history": [], "downloads": [], "bookmarks": [],
                       "shortcuts": [], "meta": { "places": null } }
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

`importIncidentFromFile(file)` (async) accepts the envelope above or a **bare
incident object**. Minimal validation: `data` must be an object, otherwise an
`Error` is thrown (surfaced by the sidebar). On import the incident:

- always receives a **new `id`** — importing the same file twice creates two
  distinct copies, no collisions;
- passes through `normalizeIncident()`, so the `dataKey`s of tabs added after
  the export are filled in with their `defaultData`;
- is inserted at the top of the list, **activated automatically**, and
  persisted to the server (`POST /api/incidents`);
- is recorded as `incident.import` in the audit log.

> The JSON export is self-contained (it holds all imported data, flags and
> notes), which makes it a convenient exchange/archival format between CSAP
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

### Export

`GET /api/backup/export` (admin only, logged as `backup.export`) downloads
`csap-backup-<timestamp>.json`:

```json
{
  "app": "CSAP",
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
