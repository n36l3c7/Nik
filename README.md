# Nik — Forensic analysis platform

![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Python_3.11+-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)
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
  or XML), shell histories and DFIR CSV/JSON exports are parsed the same way. Raw forensic files stay on the analyst's machine: only the
  normalized entries reach the server. Binary formats a browser cannot read
  (Windows `.evtx` logs) and malware samples are the exceptions, sent to the
  Nik server on purpose.
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
- **Windows event logs** — raw `.evtx` files are parsed **on the server**
  (records left after a log clear are recovered too) or the events are
  exported live by a native PowerShell script; about 50 curated event IDs are
  kept (logons, process creation, services, scheduled tasks, accounts and
  groups, PowerShell, RDP, Defender, Sysmon). A coverage chart shows each
  log's span, silences and clears against the suspicious window, logons are
  paired into sessions, and a built-in ruleset flags log clearing, brute
  force, RDP outside hours, suspicious PowerShell, services from user paths
  and new admins.
- **Malware analysis** — suspicious files are stored on the Nik server (named
  by SHA-256, never executed) and analysed statically: hashes, file type,
  entropy per block, strings and indicators of compromise, PE/ELF/Mach-O
  structure with imphash, YARA matches (built-in and admin rules), and a
  **Code view** from an isolated rizin worker: functions, call graph,
  control-flow graphs laid out like a disassembler's graph view, and the
  **pseudo-C** of each function from Ghidra's decompiler. Library code it
  recognises (FLIRT signatures, Rust crates) is hidden by default, a
  **Start here** list ranks the functions worth reading first, indicators
  link to the functions that use them, and analysts rename and comment
  functions for everyone working on the same sample. A **Capabilities**
  view from Mandiant capa, in its own isolated worker, lists what the code
  can do mapped to MITRE ATT&CK and the Malware Behavior Catalog. All of it is
  flaggable like any other event, with links to VirusTotal and MalwareBazaar
  and a download only inside a password-protected zip.
- **Mail analysis** — phishing triage of reported messages (`.eml`, or `.msg`
  saved from Outlook): the route the message took (Received headers with
  delays and clock anomalies, the sending server), SPF, DKIM and DMARC checked
  by Nik through DNS next to what your own mail servers reported, sender
  mismatches (display name, Reply-To, Return-Path, look-alike domains), every
  link unwrapped from Safe Links / Proofpoint / Google and judged (text that
  shows another site, look-alikes and punycode, shorteners, throwaway TLDs,
  forms), the body in a **sandboxed frame** that runs nothing and loads
  nothing until asked (hidden text revealed, tracking pixels blocked), and
  every attachment by its real type: macros (olevba), encrypted archives with
  the password found in the text, executables in disguise, QR codes,
  calendar links, attached messages analysed in turn. The evidence adds up to
  a score and a verdict (phishing, suspicious, no strong signs), each finding
  explained; attachments open in a hex view, download in a protected zip or
  go to Malware Analysis in one click. **Previews**: documents (PDF, Word,
  Excel, PowerPoint, OpenDocument, RTF, images) as page images rendered in an
  isolated worker (LibreOffice with macros disabled, pdfium), and HTML
  attachments and links in an **isolated browser**: Chromium runs the page in
  its own container and the analyst clicks, types and scrolls on its
  screenshots; no network by default, internet only when the analyst allows it
  for one session (never private addresses). Its **Network panel** shows every
  request like DevTools, refused ones and form posts included, with bodies in
  clear; submissions are **held** until the analyst sends them.
- **Network analysis** — pcap and pcapng files (up to 500 MB) read by
  **Wireshark's own engine** in an isolated worker: the packet list with
  Wireshark's colouring rules, the protocol tree, the bytes with the selected
  field highlighted, **display filters** in Wireshark syntax, **Follow Stream**
  (TCP, UDP, HTTP, TLS), **Export Objects** (HTTP, SMB, FTP, TFTP, IMF) to a
  protected zip or Malware Analysis, TLS decryption with a key log
  (`SSLKEYLOGFILE`, stored encrypted), and a summary: hosts, DNS, HTTP, TLS
  server names, submissions, **beacons** (regular connections), Expert Info.
  Sessions of the isolated browser become captures too: the log exports as
  **HAR** and as a **pcapng** rebuilt with HTTPS already in clear.
- **IOC correlation** — the server indexes the indicators of every tab (IP
  addresses, domains, URLs, e-mail addresses, MD5/SHA-1/SHA-256) each time an
  incident is saved; an **IOCs** tab lists them with the number of other
  incidents each one appears in, any value opens **Where seen** across every
  analyst's incidents, a shared allowlist hides well-known domains and private
  addresses, and indicators export as CSV, STIX 2.1 or a MISP event.
- **Threat intelligence** — the reputation of indicators from VirusTotal,
  AbuseIPDB, abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AlienVault OTX,
  urlscan.io, GreyNoise, Shodan InternetDB and Google Safe Browsing: a
  **Reputation** column in the IOCs tab and every provider's answer in
  **Where seen**, with **Check now**. Automatic lookups are turned on per type
  (IP addresses, URLs and domains, file hashes) and respect each free tier's
  limits; private addresses, internal names, allowlisted values and values of
  TLP:RED incidents are never sent. API keys are stored encrypted.
- **Global search** — <kbd>Ctrl</kbd>/<kbd>Cmd</kbd>+<kbd>K</kbd> or <kbd>/</kbd>
  opens a `nik>` prompt over incidents, indicators from every incident and
  samples, plus the open incident's events and notes; `>` lists actions (go to
  a tab, new incident, export, settings…).
- **Incident report** — built by the server as a printable HTML page or a
  **PDF** (also through the API): executive summary and key facts, flagged
  events, MITRE ATT&CK techniques from capa, YARA and the SOC rules,
  indicators, samples, e-mails, event-log coverage, notes and an evidence appendix
  with the SHA-256 of every imported file; TLP classification, English or
  Italian, the organisation's name and logo from Settings.
- **Super-timeline** — every timestamped event across all tabs merged into one
  chronological, filterable view, plus a collapsible `tail -f` side panel with
  the latest events on every tab.
- **SOC detection engine** — editable suspicious-keyword rules plus built-in
  command, endpoint and event-log rulesets, and a configurable business-hours window,
  highlight suspicious events automatically.
- **Case management** — incidents named after the ticket of your tracker
  (`[INC-2041] Invoice phishing`) with a severity tag, per-event flags with
  comments, free-form notes, a vertical incident timeline, and self-contained
  JSON export/import for exchanging cases between analysts.
- **Right-click and drag-and-drop everywhere** — a right-click menu on
  indicators (where seen, search, copy, copy defanged, allowlist), on event
  rows (flag, comment, copy, show in the timeline) and on incidents (open,
  report, export, copy link, delete); a file dropped anywhere opens a dialog
  that recognises it (executables by their header, e-mails, `.evtx`, browser
  databases, shell histories…) and imports it into the open incident or a new
  one.
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
| Frontend | [React](https://react.dev) 19 · [Vite](https://vite.dev) 8 · [Tailwind CSS](https://tailwindcss.com) 4 · [lucide-react](https://lucide.dev) · [sql.js](https://sql.js.org) (SQLite → WASM) · [papaparse](https://www.papaparse.com) |
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

Every image in the Dockerfiles and the Compose file names its registry
(`docker.io/...`), so Podman never has to guess one from
`/etc/containers/registries.conf` (on RHEL it would try `registry.redhat.io`
first and ask for Red Hat credentials). Keep it that way when you add an
image: `deploy/images.test.js` fails on a short name.

### 1.2 Local development setup

**Prerequisites:** Node.js 22+ (with npm; 20.19 or later also works) and Python 3.11–3.13. No database
server is needed: the backend defaults to a local SQLite file. The incident
report's **PDF** needs the Pango libraries WeasyPrint uses (Debian/Ubuntu:
`apt install libpango-1.0-0 libpangoft2-1.0-0`; Fedora/RHEL:
`dnf install pango`; macOS: `brew install pango`); everything else, the HTML
report included, works without them. The container image installs them.

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
npm run lint       # ESLint (recommended + React hooks rules), must report no problems
npm run format     # Prettier: rewrite JS/JSX, CSS, JSON, HTML and YAML in place
npm run format:check  # Prettier in check mode (what CI runs)
npm run test:e2e   # Playwright smoke test of the whole stack (build first)
```

Line endings are LF everywhere, including Windows checkouts:
`.gitattributes` sets `* text=auto eol=lf`, which overrides `core.autocrlf`,
so Prettier and Ruff see the same files as CI.

The end-to-end test (`e2e/smoke.spec.js`, `playwright.config.js`) starts the
backend on a throw-away SQLite database and the production build behind
`vite preview` (which proxies `/api`, like the dev server), then drives the app
as an analyst would: first-run setup, sign-in, a new incident, demo data in
every tab, the timeline and the `tail -f` panel. It needs `npm run build`, the
backend dependencies on `PATH` (activate the venv) and a Chromium from
`npx playwright install chromium`. With the analyzer worker running and
`E2E_ANALYZER_URL` / `E2E_ANALYZER_TOKEN` set (CI does both), it also checks
the Code view against real rizin output; likewise `E2E_CAPA_URL` /
`E2E_CAPA_TOKEN` for the Capabilities view and the capa worker. Without them
it checks the "not configured" messages.

**Analyzer worker in development.** The Code view needs the rizin worker
(`analyzer/`). With Docker:

```bash
docker build -t nik-analyzer analyzer
docker run -d --name nik-analyzer -p 127.0.0.1:8700:8700 \
  -v "$PWD/backend/samples:/samples:ro" -e ANALYZER_TOKEN=dev-token nik-analyzer
# backend/.env: ANALYZER_URL=http://127.0.0.1:8700  ANALYZER_TOKEN=dev-token
```

Its own checks: `cd analyzer && ruff check . && python -m pytest tests` (the
tests use recorded rizin output; the live test runs only where `rizin` is
installed).

**capa worker in development.** The Capabilities view needs the capa worker
(`capa/`):

```bash
docker build -t nik-capa capa
docker run -d --name nik-capa -p 127.0.0.1:8710:8710 --read-only --tmpfs /tmp \
  -v "$PWD/backend/samples:/samples:ro" -e CAPA_TOKEN=dev-capa-token nik-capa
# backend/.env: CAPA_URL=http://127.0.0.1:8710  CAPA_TOKEN=dev-capa-token
```

Its own checks: `cd capa && ruff check . && python -m pytest tests` (on a
recorded capa report; capa itself is not needed).

Backend tests run with `pytest`, the linter with `ruff check .` and the
formatter with `ruff format .` (`--check` in CI), all from `backend/` after
`pip install -r requirements-dev.txt`; Ruff settings live in `backend/ruff.toml`.
Formatting is enforced, not reviewed: run the formatters before committing.
Markdown is excluded from Prettier (see `.prettierignore`). CI runs the linters,
the format checks, both unit suites (the backend one on SQLite, and on
PostgreSQL 16 and 18 after `alembic upgrade head`), the build and then the
end-to-end test; a change is done only when all of them pass. The documentation site in `docs/`
is updated in the same change as the behaviour it describes.

**Dependency audits.** The `Audit` workflow (`.github/workflows/audit.yml`)
runs `pip-audit` on the backend and the capa worker, `npm audit
--audit-level=high` and `shellcheck` on every pull request and every Monday,
so a new CVE in an unchanged dependency fails the build without waiting for
a code change. Locally: `pip-audit -r backend/requirements.txt` and
`npm audit`. **Dependabot** (`.github/dependabot.yml`) opens one grouped
pull request a month per ecosystem (npm, pip, Docker, Compose, Actions) with
the minor and patch releases, and a pull request as soon as a dependency gets
a security fix; enable the latter in the repository's *Settings → Code
security*. Major releases are left out (except for Actions): they need
migration work and are planned as their own change.

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
| `SAMPLE_MAX_MB` | `100` | Per-file size limit for sample and e-mail uploads. |
| `YARA_RULES` | `app/yara` | Directory of the built-in YARA rule files (`*.yar`); admin rules live in the database. |
| `ANALYZER_URL` | — | Base URL of the rizin worker (e.g. `http://analyzer:8700`). Empty: the Code view reports "not configured". |
| `ANALYZER_TOKEN` | — | Shared secret sent to the worker in `X-Analyzer-Token`; the worker refuses to start without one. |
| `ANALYZER_TIMEOUT` | `600` | Seconds rizin may spend on one sample before the worker stops it. |
| `CAPA_URL` | — | Base URL of the capa worker (e.g. `http://capa:8710`). Empty: the Capabilities view reports "not configured". |
| `CAPA_TOKEN` | — | Shared secret sent to the capa worker in `X-Analyzer-Token`; the worker refuses to start without one. |
| `CAPA_TIMEOUT` | `1800` | Seconds capa may spend on one sample before the worker stops it (large binaries take ten minutes or more). |
| `PCAP_URL` / `PCAP_TOKEN` | — | Packet capture worker (`pcap/`, e.g. `http://pcap:8740`) and its shared secret (`X-Pcap-Token`). Empty: captures are stored but not analysed. |
| `PCAP_MAX_MB` | `500` | Largest packet capture accepted, in MB (nginx's `client_max_body_size` must allow it). |
| `DOCVIEW_URL` / `DOCVIEW_TOKEN` | — | Document viewer worker (`docview/`, e.g. `http://docview:8720`) and its shared secret (`X-Docview-Token`). Empty: the Preview buttons say "not configured". |
| `BROWSER_URL` / `BROWSER_TOKEN` | — | Isolated browser worker (`browser/`, e.g. `http://browser:8730`) and its shared secret (`X-Browser-Token`). Empty: "Open in isolated browser" says "not configured". |
| `ENRICHMENT_WORKER` | `true` | Background thread of the automatic threat-intelligence lookups (one API process works at a time). `false` disables it; "Check now" still works. |

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
| `SAMPLE_MAX_MB` | `100` | Per-file size limit for malware samples and e-mails; the files live on the `sample-store` volume. |
| `ANALYZER_TOKEN` | — | Shared secret between the `api` and `analyzer` services; set a long random value. |
| `ANALYZER_TIMEOUT` | `600` | Per-sample time limit of the rizin worker, in seconds. |
| `ANALYZER_DECOMPILE_SECONDS` | `300` | Share of that time the analysis spends decompiling functions up front; the rest are decompiled when first opened. |
| `ANALYZER_MAX_FUNCTIONS` | `20000` | Safety cap on the functions listed per sample (past it the list is marked truncated). |
| `ANALYZER_WARM_SESSIONS` / `ANALYZER_WARM_IDLE` | `1` / `600` | Analysed rizin sessions kept open so that decompiling on demand takes seconds (`0` disables; each holds ~1 GB on a large binary), and how long an unused one stays open, in seconds. |
| `ANALYZER_MEMORY` / `ANALYZER_CPUS` | `4g` / `2` | Memory and CPU limits of the `analyzer` container (two analyses plus a kept session). |
| `CAPA_TOKEN` | — | Shared secret between the `api` and `capa` services; set a long random value, different from `ANALYZER_TOKEN`. |
| `CAPA_TIMEOUT` | `1800` | Per-sample time limit of the capa worker, in seconds. |
| `CAPA_MEMORY` / `CAPA_CPUS` | `4g` / `2` | Memory and CPU limits of the `capa` container. |
| `DOCVIEW_TOKEN` | — | Shared secret between the `api` and `docview` services; set a long random value. |
| `DOCVIEW_MEMORY` / `DOCVIEW_CPUS` | `2g` / `1` | Memory and CPU limits of the `docview` container (LibreOffice). |
| `BROWSER_TOKEN` | — | Shared secret between the `api` and `browser` services; set a long random value. |
| `BROWSER_MAX_SESSIONS` | `3` | Isolated browser sessions open at once (each idle one closes after 5 minutes, any after 30). |
| `BROWSER_MEMORY` / `BROWSER_CPUS` | `2g` / `2` | Memory and CPU limits of the `browser` container (Chromium). |
| `PCAP_TOKEN` | — | Shared secret between the `api` and `pcap` services; set a long random value. |
| `PCAP_MAX_MB` | `500` | Largest packet capture accepted, in MB. |
| `PCAP_MEMORY` / `PCAP_CPUS` | `4g` / `2` | Memory and CPU limits of the `pcap` container (sharkd keeps an open capture in memory: a few times its size). |

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
> nik_db-data-18` / your project's `*_db-data-18`), or keep the old names by setting
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
- **Start on boot:** `restart: unless-stopped` does not bring the stack back
  after a reboot with `podman-compose`. Install the systemd units (next
  paragraph): `nik.service` runs `podman compose up -d` at boot.
- **SELinux:** named volumes (as used here) are relabeled automatically. If you
  switch to a bind mount, add `:Z` to that mount.

**Start on boot and nightly backups (systemd).** From the repository root,
as root:

```bash
sudo deploy/install-systemd.sh
```

It installs and enables three units, with the repository path and the compose
command (`podman compose`, or `docker compose` where Podman is absent) filled
in:

- `nik.service` — `compose up -d` at boot, `compose down` at shutdown;
- `nik-backup.timer` + `nik-backup.service` — `deploy/backup.sh` every night
  at 02:30 (a run missed while the server was off happens at the next boot).

Options: `--backup-dir /srv/nik-backups` (default `/var/backups/nik`),
`--keep-days 30` (default 14), `--backup-time 03:15`, `--no-backup`,
`--uninstall`. Check with `systemctl status nik.service nik-backup.timer`
and `journalctl -u nik-backup`; run a backup now with
`systemctl start nik-backup.service`.

**Backups & restore.** Each backup is a directory
`nik-YYYYMMDD-HHMMSS/`, readable by root only, with:

| File | Content |
|---|---|
| `db.dump` | PostgreSQL dump (`pg_dump -Fc`): incidents, users, settings, audit log, sample analyses |
| `samples.tar` | the sample store: **live malware**, keep the backups private |
| `env` | the `.env` file (secrets, database password) |
| `SHA256SUMS` | checksums: `sha256sum -c SHA256SUMS` before restoring |

`deploy/backup.sh` also runs by hand (`ENGINE`, `BACKUP_DIR`, `KEEP_DAYS`
in the environment). It reaches the `db` and `api` containers with
`podman exec` / `docker exec`, found by their Compose labels, never through
`compose exec`: `podman-compose` prints diagnostics on stdout, which would
corrupt the dump. To restore on a running stack (`B` = the backup
directory; container names as in `podman ps`):

```bash
cd "$B" && sha256sum -c SHA256SUMS
podman exec -i nik_db_1 pg_restore -U nik -d nik --clean --if-exists < "$B/db.dump"
podman exec -i nik_api_1 tar -C /app/samples -xf - < "$B/samples.tar"
podman restart nik_api_1    # also gives the restored samples their permissions
```

On a new server, put `env` back as `.env` before the first `compose up`, so
the database password matches the dump. The in-app **Full backup**
([§6](#6-full-platform-backup)) remains the way to move data across database
engines; it does not include the sample files.

**Updates:**

```bash
git pull
podman compose up -d --build    # rebuild images, recreate containers, keep data
```

Release notes say when an update needs more than this, as the move to
PostgreSQL 18 below does.

#### Upgrading to PostgreSQL 18 (2.12.2)

Releases up to 2.12.1 run PostgreSQL 16 on the `db-data` volume. From 2.12.2
the Compose file runs **PostgreSQL 18** on a new `db-data-18` volume.
PostgreSQL 18 cannot open the data files of 16, so the data moves once, with a
dump and a restore, by `deploy/upgrade-postgres.sh`. Plan a short maintenance
window: the app is down for the dump, the restore and the restart, a few
minutes for a typical database.

1. Pull the new release, but **do not** run `compose up` yet; the running
   stack is still the old one:

   ```bash
   cd /opt/Nik && git pull
   ```

2. Run the upgrade as root:

   ```bash
   sudo deploy/upgrade-postgres.sh
   ```

   It takes a full backup with `deploy/backup.sh` (under `/var/backups/nik`,
   or `BACKUP_DIR`), counts the rows of every table, stops the stack, starts
   PostgreSQL 18 on the new volume, restores the dump, compares the row counts
   and starts the whole stack again. It stops at the first error and deletes
   nothing. Running it again is always safe: it carries on from where
   a previous run stopped, or says there is nothing to do.

3. Check the app (sign in, open an incident), then the database version:

   ```bash
   podman exec nik_db_1 psql -U nik -d nik -Atc 'SHOW server_version'
   ```

**If `compose up` already ran** on 2.12.2 before the script, the `db`
container restarts in a loop and its log says
`run deploy/upgrade-postgres.sh`: it refuses to create an empty database while
the old data has not been moved (`deploy/db-entrypoint.sh`). Run the script
anyway: it dumps the old volume with a temporary PostgreSQL 16 container
instead.

**The old data stays.** The `db-data` volume is not modified; the new `db`
container mounts it read-only. Keep it **14 days**, then remove it (the
script prints the exact name):

```bash
podman volume rm nik_db-data
```

**Rollback** (within those 14 days): go back to the previous release and
start it; it runs PostgreSQL 16 on the untouched `db-data` volume. Anything
recorded after the upgrade is not in it: export the incidents you need first
(incident JSON export, or the in-app **Full backup**, which restores across
database versions).

```bash
podman compose down
git checkout v2.12.1
podman compose up -d --build
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

Build on the RHEL host or on any machine with Node 22+ and copy `dist/` over.
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

Any PostgreSQL from 14 on works (CI tests 16 and 18); use the version your
RHEL release ships.

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

    # Large uploads (packet captures up to PCAP_MAX_MB, backup restore,
    # incidents with parsed artifacts) blow past nginx's 1m default and get
    # rejected with 413.
    client_max_body_size 600m;

    root  /var/www/nik;
    index index.html;

    # Reverse-proxy the REST API to the gunicorn/uvicorn backend.
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        # Opening a large packet capture in Wireshark's engine takes minutes.
        proxy_read_timeout 330s;
        proxy_send_timeout 330s;
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
| `GET /api/incidents` | List incidents. Query: `limit`/`offset`, `q` (name, host, user or ticket)/`host`/`username`, `view=summary` (light rows: id, name, host, username, os, ticketId, severity, hasMail, timestamps — no document body). `X-Total-Count` header. |
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
| `POST /api/incidents/{id}/mails` | Analyse an e-mail (multipart `file`, `.eml` or Outlook `.msg`, up to `SAMPLE_MAX_MB`) and attach it to the incident: route, SPF/DKIM/DMARC (DNS) and the servers' reports, sender, links, body, attachments, `score` and `verdict` (`phishing` ≥ 70, `suspicious` 40–69, `clean`). A known file reuses its analysis. `422` for a file that is not an e-mail. |
| `GET /api/mails/{sha256}` · `POST …/reanalyse` | The full analysis and the incidents holding the message; `reanalyse` repeats it (DNS checks, Settings → Mail). |
| `GET /api/mails/{sha256}/source` | The `.eml` as text (`available: false` for a `.msg`). |
| `GET /api/mails/{sha256}/attachments/{path}/bytes?offset=&length=` | A slice (≤ 64 KiB, base64) of an attachment for the hex view. `path` is its index, `2.0` for the first attachment of the attached message at index 2. |
| `GET /api/mails/{sha256}/attachments/{path}/download?password=` | The attachment inside an AES-256 zip (default `infected`). Audited. |
| `GET /api/previews/status` | Which preview workers are configured (`documents`, `browser`). |
| `POST /api/mails/{sha256}/attachments/{path}/preview` | The attachment's first 20 pages as PNG (`pages: [{ png, width, height }]`, `total`, `converted`), rendered by the document viewer; `422` for a file that is not a document, `503` without the worker. |
| `POST /api/browser/sessions` | Open an HTML attachment (`{ mail, path }`) or a link (`{ url }`) in the isolated browser, `network` true or false (default), `incident` to keep the session's network log in that incident. Returns the state: `id`, `url`, `title`, `screenshot` (JPEG, base64), `blocked`, `log` (request counts), `releasePosts`, `events`, `captureId`. Audited. |
| `POST /api/browser/sessions/{id}/action` · `DELETE …/{id}` | Replay an action (`click`/`dblclick` `{x, y}`, `type` `{text}`, `key` `{key}`, `scroll` `{dy}`, `navigate` `{url}`, `back`, `forward`, `reload`, `refresh`, `policy` `{releasePosts}`: send the page's submissions instead of holding them, audited) and get the new state; close the session (its log becomes a capture). Only the analyst who opened it. |
| `GET /api/browser/sessions/{id}/network` | The session's requests without bodies (the live Network panel). |
| `POST /api/incidents/{id}/captures` | Upload a packet capture (multipart `file`: pcap, pcapng or gzip, up to `PCAP_MAX_MB`; optional `keylog`: a TLS key log). Stored, then analysed in the background (`status`: indexing → ready / error). Audited. |
| `GET /api/incidents/{id}/captures` | The incident's captures (references), isolated browser sessions opened by any analyst included; ended sessions are finalized. |
| `GET /api/captures/{id}` · `POST …/reanalyse` · `DELETE /api/incidents/{id}/captures/{captureId}` | The capture's state and summary (hosts, DNS, HTTP, TLS server names, posts, beacons, objects, Expert Info); analyse it again; remove it with its files. |
| `POST /api/captures/{id}/rpc` | A read-only call to Wireshark's engine (sharkd): `frames` (`filter`, `skip`, `limit`, `time`: relative/absolute/delta), `frame` (protocol tree and bytes), `follow` (`follow`: TCP, UDP, HTTP, HTTP2, TLS, QUIC, WebSocket… with a `filter`), `tap` (`eo:http`, `eo:smb`, `eo:ftp-data`, `eo:tftp`, `eo:imf`, `eo:dicom`, `expert`), `check` (a display filter), `complete`, `status`. Answers `{ result }`, sharkd's result. |
| `GET /api/captures/{id}/objects/download?token=&password=` · `POST /api/incidents/{id}/captures/{captureId}/objects/sample` | An exported object in an AES-256 zip (audited), or sent to Malware Analysis. |
| `GET /api/captures/{id}/file` · `…/har` | The capture file (audited); an isolated browser session's log as HAR 1.2. |
| `GET /api/captures/{id}/requests` · `…/requests/{entryId}` | An isolated browser session's requests (light), and one request in full (headers, bodies base64, timings, WebSocket messages). |
| `PUT/DELETE /api/captures/{id}/keylog` | Attach (multipart `file`, stored encrypted) or remove a TLS key log; the capture is analysed again. |
| `POST /api/incidents/{id}/mails/{sha256}/attachments/{path}/sample` | Send an attachment to Malware Analysis as a sample of the incident. |
| `DELETE /api/incidents/{id}/mails/{sha256}` | Detach the message; the file is deleted once no incident references it. |
| `GET/POST/PUT/DELETE /api/yara-rules` · `POST …/validate` | Admin-managed YARA rule sets compiled with the built-in ones (**admin** to change; any caller may list). A source must compile before it is saved. |
| `GET/POST /api/samples/{sha256}/code` | Disassembly by the rizin worker: `GET` returns the state (`none` / `queued` / `running` / `done` / `error`) and, when done, the engine, binary info and functions with their calls; `POST` (re)starts it (`202`, `503` when no worker is configured). |
| `GET/POST /api/samples/{sha256}/capabilities` | capa on the capa worker: `GET` returns the state (`none` / `queued` / `running` / `done` / `error` / `unsupported`) and, when done, the engine and the capabilities with their namespace, scope, ATT&CK and MBC mappings and addresses; `POST` (re)starts it (`202`; `503` when no worker is configured, `422` for a file type capa does not read). |
| `GET /api/samples/{sha256}/annotations` · `PUT …/annotations/{addr}` | Analysts' names and comments for the sample's functions (shared by every incident holding the file, removed with it). `PUT` takes `{ name, comment }` and returns the annotation, or `null` when both are empty (it is removed); `409` before the sample is disassembled, `404` for an address that is not a function. Audited as `sample.annotate`. |
| `GET/POST /api/capa-rules` · `PUT/DELETE …/{id}` · `POST …/validate` | capa rules (YAML, one rule each) matched with capa's bundled set (**admin** to change; any caller may list). The capa worker checks each rule against the bundled rules and the other admin rules before it is saved (`503` when no worker is configured); a rule another enabled rule `match`es cannot be renamed, disabled or deleted (`409`). |
| `GET/POST /api/flirt-signatures` · `PUT/DELETE …/{id}` | FLIRT signatures (`.sig` or `.pat`, multipart `name` + `file`, up to 32 MB) the analyzer worker applies on top of rizin's bundled ones (**admin** to change; any caller may list). `PUT` takes `{ name, enabled }`. They apply from the next disassembly. |
| `GET /api/samples/{sha256}/code/functions/{addr}` | Control-flow graph of one function: basic blocks with their instructions and `jump` / `fail` successors. |
| `GET /api/samples/{sha256}/code/functions/{addr}/decompiled` | Pseudo-C of one function (rz-ghidra): `code` plus highlight `spans` (`[start, end, kind]`, or `[start, end, "f", address]` for a call target). Stored by the analysis (`source: "analysis"`) or decompiled on first request and kept (`source: "on-demand"`); `502` when the worker fails, `503` when none is configured. |
| `GET /api/incidents/{id}/iocs` | The incident's indicators of compromise (`type`, `value`, `sources`, `count`, `firstSeen`, `lastSeen`, `otherIncidents`, `allowlisted`, `reputation`: `{ verdict, flagged, checked }` from the threat-intelligence cache or null), indexed from every tab each time its data is saved. |
| `GET /api/enrichment/providers` | Threat-intelligence providers: types, key requirement, whether a key is set (with its last four characters, never the key), free-tier note, and the `enrichment` settings. |
| `PUT/DELETE /api/enrichment/providers/{id}/key` | Store (`{ key }`, encrypted) or remove a provider's API key (**admin**). Audited. |
| `GET /api/enrichment?type=&value=` | The cached answers about an indicator (`provider`, `verdict` malicious/suspicious/harmless/unknown, `summary`, `link`, `data`, `checkedAt`), the providers that would be asked, and `blocked` (why it is never sent, or null). |
| `POST /api/enrichment/check` | `{ type, value, force }`: ask every usable provider now (fresh answers reused unless `force`); `skipped` lists providers waiting for their rate limit. `422` for a value that is never sent (private, internal, allowlisted, TLP:RED). Audited. |
| `GET /api/iocs/lookup?type=&value=` | Every incident an indicator appears in ("where seen"). `type`: ip, domain, url, email, md5, sha1, sha256. |
| `GET /api/iocs/shared` | Indicators seen in two or more incidents, most widespread first (allowlisted values left out). |
| `GET /api/incidents/{id}/iocs/export?format=csv\|stix\|misp` | Download the indicators as CSV, a STIX 2.1 bundle (identity, one indicator each, a report) or a MISP event (unpublished, organisation only). `types=ip,domain,…` narrows them; allowlisted values are left out unless `allowlisted=true`. Audited as `ioc.export`. |
| `POST /api/incidents/{id}/report` | The incident report, as a PDF (default) or HTML. Body (all optional): `format` (`pdf`/`html`), `lang` (`en`/`it`), `tlp` (`clear`, `green`, `amber`, `amber+strict`, `red`), `sections` (summary, timeline, attack, iocs, samples, mails, network, eventlogs, notes, evidence), `executiveSummary`, `detections` (`[{ id, label, severity, count, attack: [technique ids] }]`, the SOC rule hits the app computes). Missing options come from the incident's saved `report` settings, then the defaults (English, TLP:AMBER, every section). Audited as `report.generate`. |
| `GET /api/search?q=` | Global search (at least 2 characters): incidents by name, host or user; indicators from every incident (3 characters or more) with the number of incidents; samples by hash prefix (6 hex characters or more) or file type. `limit` per group (default 8). |
| `GET /api/settings` | Read the shared detection rules, business hours, IOC allowlist (`iocAllowlist`, plus the factory list as `iocAllowlistDefault`) report header (`report: { orgName, logo }`, the logo a PNG/JPEG/SVG `data:` URI up to 256 KB) Mail Analysis settings (`mail: { orgDomains, trustedAuthServers }`) and threat intelligence (`enrichment: { auto: { ip, url, hash }, ttlHours, providers: { id: bool } }`, never the keys). `PUT` replaces them; a body without `iocAllowlist`, `report`, `mail` or `enrichment` keeps the stored value. |
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

# Windows event log (.evtx → data.eventlogs.channels.Security), parsed in the background
curl -H "X-API-Key: $KEY" -F file=@Security.evtx \
  "https://localhost:8443/api/incidents/$ID/upload?tab=eventlogs&async=true"
```

Routing parameters: `tab=browser` needs `browser` (chrome/firefox/edge/brave/opera/safari)
and `source` (history/bookmarks/shortcuts/places; Safari: history/downloads/bookmarks),
plus an optional `profile` — the profile **name**, matched case-insensitively and
created if missing (default `Default`); the response's `target` reads
`browser/<id>/<profile>/<source>` and `profileId` names the profile; `tab=commands` needs `shell`
(bash/zsh/fish/powershell); `tab=endpoint` needs `category`
(execution/persistence/fileaccess/usb) and `source` (the source key, e.g. cron);
`tab=eventlogs` needs nothing else: the channel comes from the file, the result
lists it in `channels`, and the file's SHA-256 is kept in the channel's `meta`.
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

**Heavy binary formats** are parsed on the server instead. Windows event logs
(`.evtx`, chunks of binary XML) are the first: the Event Logs tab uploads the
file, `backend/app/parsing/eventlog.py` parses it with the `evtx` package (a
Rust parser) in a background job and merges the curated events into the
incident, in the same shape the browser produces from the collection script's
JSON. PCAP and disk images would follow the same path.

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
├── docker-compose.yml              # db + api + analyzer + capa + docview + browser + pcap + web stack
├── docview/                        # document viewer worker: Dockerfile (LibreOffice, pdfium),
│                                   #   nik_docview.py (Office → PDF → page PNGs), server.py, tests/
├── browser/                        # isolated browser worker: Dockerfile (Playwright Chromium),
│                                   #   nik_browser.py (sessions, network rules), netlog.py (the
│                                   #   DevTools-like request log), server.py, tests/
├── pcap/                           # packet capture worker: Dockerfile (tshark, sharkd),
│                                   #   nik_pcap.py (summary, sharkd sessions), server.py, tests/
├── capa/                           # capa worker: Dockerfile (pinned capa, rules, signatures),
│                                   #   nik_capa.py (run + reduce the report), server.py, tests/
├── analyzer/                       # rizin worker: Dockerfile, nik_analyzer.py (pipe + transforms),
│                                   #   server.py (HTTP, token, job slots), tests/ (recorded output)
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
│       ├── models.py               # users, sessions, incidents, audit_log, settings, samples, …
│       ├── browser_profiles.py     # browser profiles: legacy conversion, upload routing
│       ├── schemas.py              # Pydantic request/response models
│       ├── security.py             # bcrypt hashing, session-auth dependencies
│       ├── defaults.py             # Factory defaults for detection settings
│       ├── samples.py              # Sample store (files by SHA-256, e-mails as .mail) + protected zip
│       ├── vault.py                # Encryption of API keys and TLS key logs (Fernet, HKDF of SECRET_KEY)
│       ├── network/                # Network Analysis: store (capture files, browser logs), service (analysis,
│       │                           #   references, browser log sync), pcapng (log → pcapng), har (HAR 1.2)
│       ├── enrichment/             # Threat intelligence: providers (one function each), service (what may be
│       │                           #   sent, rate limits, cache), worker (background lookups, lease)
│       ├── mail/                   # Mail analysis: parse (.eml/.msg, LZFu RTF), headers (route,
│       │                           #   sender, Authentication-Results), verify (SPF/DKIM/DMARC),
│       │                           #   links, content (nh3, QR, pressure), attachments, analyze
│       ├── parsing/malware.py      # Static analysis: hashes, type, entropy, strings, IOC
│       ├── parsing/executables.py  # PE (pefile), ELF and Mach-O structure, imphash
│       ├── parsing/eventlog.py     # Windows .evtx → curated events + coverage (evtx package)
│       ├── iocs.py                 # IOC extraction from incidents, index, allowlist, STIX/MISP
│       ├── routers/search.py       # GET /api/search (incidents, indicators, samples)
│       ├── report.py               # Incident report: HTML (EN/IT, TLP, ATT&CK) and PDF (WeasyPrint)
│       ├── yara_rules.py           # YARA: built-in + admin rules compiled together, scan
│       ├── flirt.py                # Admin FLIRT signature files (validation, store, worker paths)
│       ├── capa_rules.py           # Admin capa rules (worker validation, store, dependencies)
│       ├── analyzer.py             # rizin worker client + disassembly job
│       ├── capa.py                 # capa worker client + capabilities job (one at a time)
│       ├── yara/                   # Built-in YARA rule files (*.yar)
│       └── routers/                # auth, users, incidents, audit, settings, backup, samples,
│                                   #   mails, enrichment, annotations, yara_rules, flirt, capa_rules
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
    │   ├── eventLogs.js            # Windows event-log channels, curated event IDs (label,
    │   │                           #   category, summary) and the collection script
    │   └── detectionRules.js       # Factory keyword + command + artifact + event-log rules, business
    │                               #   hours (keywords managed at runtime from Settings).
    │
    ├── context/
    │   ├── AuditContext.jsx        # useAudit(): global audit log via the API
    │   ├── AuthContext.jsx         # useAuth(): session auth (login/logout/me), users
    │   ├── SettingsContext.jsx     # useSettings(): keywords, business hours, IOC allowlist;
    │   │                           #   useSocEngine(): memoized detection engine
    │   ├── IncidentContext.jsx     # useIncidents(): incident state, CRUD, flags, notes,
    │   │                           #   export/import — optimistic model backed by the API
    │   ├── IocLookupContext.jsx    # useIocLookup(): "Where seen", allowlist dialog, IOC menu; <IocValue>
    │   ├── ContextMenuContext.jsx  # useContextMenu(): the app's right-click menu, askText()
    │   ├── NavigationContext.jsx   # useNavigation(): go to a tab, open the search, import a file
    │   └── ToastContext.jsx        # useToast(): short notices with an optional Undo
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
    │   ├── code.js                 # Code view: API reach, call graph, CFG, pseudo-C lines (+ .test.js)
    │   ├── triage.js               # Function origin, strings/IOC links, Start here (+ .test.js)
    │   ├── events.js               # buildEvents, historyEventType, redirect helpers
    │   ├── commands.js             # buildCommandEvents, extractBinary, topBinaries
    │   ├── artifacts.js            # buildArtifactEvents (endpoint records → events)
    │   ├── iocs.js                 # IOC types, source labels, guessIocType
    │   ├── search.js               # searchIncident (open incident), matchActions
    │   ├── incidentName.js         # deriveIncidentName ([ticket] title | host - user), severities
    │   ├── fileRouting.js          # detectFileRoute: which tab a dropped file belongs to
    │   ├── report.js               # report options, reportDetections (SOC hits + ATT&CK)
    │   ├── hash.js                 # sha256Hex: digest of an imported file, in the browser
    │   ├── eventLogs.js            # parseEventLogJson, buildEventLogEvents (event-log
    │   │                           #   ruleset), logonSessions, coverage
    │   ├── timeline.js             # buildTimelineEvents (merge all timestamped events)
    │   └── soc.js                  # createSocEngine({keywords, commandKeywords,
    │                               #   artifactKeywords, businessHours}) → analyze()
    │
    └── components/
        ├── ui/                     # Reusable UI kit (Button, Card, Badge, Modal, DataTable,
        │                           #   EmptyState, SearchInput, Select, StatCard, AsciiSkull,
        │                           #   ErrorBoundary)
        ├── auth/                   # AuthLayout (banner + live status), FirstRunSetup, LoginScreen
        ├── backup/                 # BackupModal (full export/restore, admin only)
        ├── settings/               # SettingsPanel + sections/ (detection rules, business
        │                           #   hours, IOC allowlist, report header, accounts, API keys, YARA rules,
        │                           #   FLIRT signatures, capa rules, audit log)
        ├── search/                 # CommandPalette (Ctrl/Cmd+K: nik> search and > actions)
        ├── incident/               # IncidentFields (ticket, title, severity…), AddFileDialog
        ├── menu/                   # useRowMenu (flag, comment, copy, timeline on any event row)
        ├── report/                 # ReportDialog (options, preview, PDF/HTML download)
        ├── layout/                 # Sidebar, Header, TabBar, OsPicker, IncidentLoadingState,
        │                           #   TailPanel (tail -f of the timeline)
        └── tabs/
            ├── summary/                # SummaryTab, IncidentTimeline, NoteBlock
            ├── browser/                # BrowserAnalysisTab, ProfileBar, FileUploadZone, EventsSection,
            │                           #   filters, widgets, bookmarks/shortcuts tables
            ├── commands/               # CommandHistoryTab, CommandsSection, TopBinariesWidget
            ├── endpoint/               # EndpointArtifactsTab, ArtifactSection (generic table)
            ├── iocs/                   # IocsTab (indicators, cross-incident counts, reputation, export),
            │                           #   IocReputation (external answers, Check now)
            ├── eventlogs/              # EventLogsTab, EvtxUpload (server-side parse + job poll),
            │                           #   CoverageChart, EventsSection
            ├── malware/                # MalwareAnalysisTab, SampleList, SampleDetail, EntropyChart,
            │                           #   StructureSection, YaraSection, IocSection, StringsSection,
            │                           #   CapabilitiesSection, useWorkerJob (polled worker state),
            │                           #   DownloadDialog; code/ CodeSection, GraphCanvas (ELK),
            │                           #   DecompiledView, StartHere, FunctionNotes, hooks
            ├── mail/                   # MailAnalysisTab, MailDetail, MailHeaders, MailBody (sandboxed
            │                           #   frame), MailLinks, MailAttachments, HexView, RemoteBrowser
            ├── network/                # NetworkAnalysisTab, CaptureDetail, PacketView (list, tree, bytes),
            │                           #   FollowStream, RequestLog (DevTools-like Network panel)
            └── timeline/               # TimelineTab (the super-timeline)
```

**Naming an incident.** An incident has a **ticket ID** (the reference in your
tracker), a **short title**, a **host** and a **user**, all optional but at
least one. Its name is built from them: the ticket first, in square brackets,
then the title when there is one, otherwise `host - user`:
`[INC-2041] Invoice phishing, finance`, `[INC-2039] WKS-042 - m.rossi`,
`SRV-FILE-01`. The **severity** (low, medium, high, critical) is a tag the
analysts set, shown next to the name in the sidebar and the header but never
part of it. Everything is editable from the Summary tab; the search palette and
`GET /api/incidents?q=` also find incidents by ticket.

**Right-click.** One menu for the whole app (`src/context/ContextMenuContext.jsx`):
on an indicator (anywhere it is shown: the IOCs tab, a sample's indicators,
event-log addresses) *Where else was this seen?*, *Search for it*, *Copy*,
*Copy defanged* (`hxxps[:]//evil[.]top`) and *Add to the allowlist…*; on an
event row (Browser, Commands, Endpoint, Event Logs, Timeline) *Flag* or
*Remove the flag*, *Add a comment…*, *Copy as text*, *Copy as JSON* and *Show in
the Timeline*; on an incident in the sidebar *Open*, *Incident report…*,
*Export (JSON)*, *Copy link* and *Delete…*. Text fields and selected text keep
the browser's menu, and so does Shift + right-click. **Add to the allowlist**
(also the shield button on each IOC row) proposes the value or a wider entry —
its domain or a parent domain, its /24 network — and writes it to the shared
allowlist with a comment line saying who added it and when; *Undo* stays
available for a few seconds. Any analyst can do it.

**Drag-and-drop anywhere.** Drop a file on any part of the app (outside the
tabs' own drop zones) and a dialog proposes where it goes, from its first bytes
and its name (`src/utils/fileRouting.js`): PE, ELF and Mach-O executables, PDF,
Office documents, scripts and archives → Malware Analysis; `.evtx` and the
event-log script's JSON → Event Logs; Chromium `History` / `Shortcuts` /
`Bookmarks`, Firefox `places.sqlite`, Safari `History.db` and plists → Browser
Forensics; shell histories → Command History; CSV → Endpoint Artifacts. The
dialog always asks whether the file goes into the open incident or a new one
(with its ticket, title, severity, host, user and OS), lets you change the tab
and the source, then opens the tab and imports the file as its own drop zone
would.

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

The **Event Logs** tab (Windows) holds curated events from the host's event
logs, per channel (Security, System, PowerShell, PowerShell classic, RDP
sessions and authentication, Defender, Task Scheduler, Sysmon; see
`src/config/eventLogs.js`). They arrive two ways: raw `.evtx` files copied
from `C:\Windows\System32\winevt\Logs\` (or a disk image), uploaded and
parsed on the server, which also recovers records left in the file's unused
space after a clear and keeps the file's SHA-256; or the JSON written by a
native `Get-WinEvent` collection script on a live host, parsed in the
browser. Only about 50 curated event IDs are stored (at most 20,000 per
channel, the newest); the rest is counted. The tab shows:

- the **log coverage**: one bar per channel from its first to its last record,
  with silences of 6 hours or more hatched, clears marked in red and the
  incident's suspicious window behind them — a gap or a clear inside the
  window is where evidence may be missing;
- the **logon sessions**: each 4624 paired with its logoff (4634/4647) and
  admin privileges (4672) by logon id, service logons and machine accounts
  left out;
- every **event** with a readable summary, filters by detection, category,
  channel and time, and a detail view with all its fields.

Command lines (4688, Sysmon 1) and PowerShell script blocks go through the
command-line ruleset; the built-in event-log ruleset (`DEFAULT_EVENTLOG_RULES`,
logic in `src/utils/eventLogs.js`) adds log cleared, audit policy changed,
service installed (high when the binary sits in a user-writable path or runs a
shell), suspicious PowerShell, brute force (10 failed logons for one account or
source within 10 minutes), a logon right after 5 failures, RDP outside business
hours, account created, member added to a privileged group, Defender alerts and
scheduled task created. Machine activity (service logons, boots) is not judged
by the clock. Linux (journald, `auth.log`) and macOS unified logs will follow.

The **Timeline** tab is the super-timeline: it merges every *timestamped* event
from the Browser, Command History, Endpoint Artifacts and Event Logs tabs into a single
chronological, filterable table (by source, detection and time window). Entries
without a reliable timestamp (e.g. PSReadLine commands) are intentionally left
out. Any row can be flagged straight from the timeline.

The **sidebar is resizable**: drag its right edge to widen the incident list up
to a quarter of the window; the width is remembered per browser.

The **IOCs** tab lists the incident's indicators of compromise. The server
builds them (`backend/app/iocs.py`) whenever the incident's data is saved —
a merge patch that only touches flags or notes leaves them alone — and keeps
one `ioc_index` row per incident, type and value, so "where else have we seen
this?" is one indexed query for every analyst, whoever owns the other
incident. The sources:

- browser history: the visited **hosts** (not every URL); downloads: the URL,
  its referrer and their hosts;
- shell commands and endpoint records: URLs, IP addresses, domains (known
  TLDs), e-mail addresses and MD5/SHA-1/SHA-256 digests in the text;
- event logs: address and host fields (`IpAddress`, `DestinationIp`,
  `QueryName`…), Sysmon `Hashes`, and the indicators in command lines, script
  blocks and service paths;
- malware samples: the sample's hashes and the network indicators in its
  strings;
- e-mails: sender addresses and domain, sending IP, link targets and hosts,
  attachment hashes, QR-code and invitation links (`mail:<file name>`).

Indicators also seen in other incidents come first, in red. Clicking a value
here, in a sample's IOC table or in the Event Logs tab opens **Where seen**:
every incident it appears in, with the sources, count and first/last time, and
a link to open it. Settings → **IOC allowlist** (one entry per line: a domain
and its subdomains, an IP or CIDR network, or an exact value) starts with
private and loopback ranges and common vendor and CDN domains; matching values
are hidden by default and never exported. The index keeps them, so editing the
list applies at once. Exports: CSV, a **STIX 2.1** bundle and a **MISP** event,
for a TIP or a firewall blocklist. Incidents saved before 2.12.0 are indexed on
the api's first start.

**Incident report.** The report button in the header (or `> report` in the
search palette) opens the report dialog: language (English or Italian), TLP
classification, the sections to include and an executive summary — all saved
with the incident (`report` key of the document) — a preview, and the
download as PDF or HTML. The server builds the report (`backend/app/report.py`)
as one self-contained HTML page styled for print, and renders the PDF with
WeasyPrint: A4 pages with the organisation and the TLP label at the top and
page numbers at the bottom. Its sections:

- **executive summary** and key facts (flagged events, SOC detections,
  indicators, samples, techniques);
- **flagged events** in time order, with the analysts' comments;
- **MITRE ATT&CK** techniques from capa's capabilities, the YARA rules'
  `mitre_attack` metadata (the built-in rules carry it) and the SOC rules that
  matched (each built-in rule names its techniques in
  `src/config/detectionRules.js`), each with where it was seen;
- **indicators of compromise** outside the allowlist, those seen in other
  incidents first (up to 500; the rest are in the CSV/STIX/MISP export);
- **malware samples** with their hashes, YARA matches and capa capabilities;
- **Windows event logs**: each channel's coverage and when it was cleared;
- **analyst notes**;
- an **evidence appendix**: every imported file with its format, rows, import
  time and SHA-256. Browser, shell-history, endpoint and event-log JSON files
  are hashed in the browser when they are imported (the file still never
  leaves the machine); `.evtx` files and samples are hashed by the server.

The organisation name and logo come from Settings → **Report header**. API
clients get the same report from `POST /api/incidents/{id}/report`.

**Global search.** <kbd>Ctrl</kbd>/<kbd>Cmd</kbd>+<kbd>K</kbd> anywhere, or
<kbd>/</kbd> outside a text field, or the *search…* button in the header,
opens a `nik>` prompt. As you type it asks the server (`GET /api/search`) for
incidents, indicators from **every** incident and samples, and searches the
**open** incident in memory: its timeline events (every tab), notes and
samples (by file name too). Enter opens the result: an incident is selected,
an indicator or a sample opens *Where seen*, an event jumps to its tab, a note
to the Summary. A query starting with `>` lists actions instead: go to any
tab, new incident, export the incident, toggle the `tail -f` panel, settings,
the IOC allowlist, sign out. On PostgreSQL the substring matches use the
trigram (`pg_trgm`) indexes of migration `0012`; when the extension cannot be
created the search works without them.

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

  setEventLogChannels,    // (id, { [channel]: { events, meta } }, auditInfo?) => void — script JSON / demo
  clearEventLogs,         // (id, channel?) => void — one channel, or all of them
  retryActiveIncident,    // () => void — refetch the open incident (after a server-side .evtx parse)

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
  ticketId:  'INC-2041',                   // identity (NOT unique — the id is the key),
  title:     '',                           //   all optional, at least one set
  host:      'WKS-FINANCE-01',             //   "
  username:  'm.rossi',                    //   "
  name:      '[INC-2041] WKS-FINANCE-01 - m.rossi', // derived: "[ticket] title" | "[ticket] host - username"
  severity:  'high',                       // 'low' | 'medium' | 'high' | 'critical' | null — a tag
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
    network: {                             // packet captures: light references, the packets
      captures: [ { id, kind: 'pcap' | 'browser', fileName, size, sha256, status, packets,
                    first, last, keylog, label, held: [{ method, url, time }], posts,
                    beacons: [{ destination, port, count, interval }], objects } ],
    },                                     //   come from POST /api/captures/{id}/rpc
    endpoint: {},
    eventlogs: {
      channels: {                          // one key per Windows event-log channel
        Security: {
          events: [ { id: 'evt:Security:9120', time, eventId: 4624, channel: 'Security', provider,
                      computer, recordId: 9120, level, data: { TargetUserName, LogonType, … },
                      recovered /* only when recovered after a clear */ } ],
          meta: { fileName, format: 'evtx' | 'json' | 'demo', importedAt, rows, total, kept,
                  dropped, recovered, first, last, gaps: [[start, end]], sha256 /* evtx */ },
        },
      },
    },
    mail: {                                // analysed e-mails: light references, the analysis
      messages: [ { sha256, fileName, format: 'eml' | 'msg', size, subject, from, date,
                    verdict: 'phishing' | 'suspicious' | 'clean', score, importedAt, importedBy } ],
    },                                     //   is fetched from GET /api/mails/{sha256}
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

**Code view (disassembly and decompilation).** Both run in a separate
worker, `analyzer/`, built on the official `rizin/rizin` image, which ships
**rz-ghidra** (Ghidra's decompiler, Apache-2.0, as a rizin plugin, LGPL-3.0):
no Java and no extra build step. The backend never runs rizin itself:

1. After an upload (and on Re-analyse, or the **Disassemble** button) the
   backend queues a job (`sample_code` table) and calls the worker's
   `POST /analyze` with the sample's SHA-256 and the shared
   `X-Analyzer-Token`.
2. The worker opens `<store>/<sha256>.bin` from its **read-only** mount in
   rizin's pipe mode (`rizin -q0`, driven by `nik_analyzer.py`, standard
   library only), runs `aaa` and returns functions (`aflj`), their calls (from
   the `call` instructions), and for each function its basic blocks (`afbj`)
   with their instructions (`pdfj`). A timer kills rizin after
   `ANALYZER_TIMEOUT`; at most `ANALYZER_MAX_JOBS` requests run at once.
   Every function is listed: a 5,000-function Rust binary takes about 75 s;
   `ANALYZER_MAX_FUNCTIONS` (20,000) is only a safety cap.
3. In the same session the worker decompiles functions with `pdgj` for up to
   `ANALYZER_DECOMPILE_SECONDS` (entry point and `main` first, then the
   functions the worker does not recognise as library code — no FLIRT match,
   no Rust crate, not a thunk — then the rest, smallest first within each
   group). rz-ghidra's annotations are reduced to highlight spans and call
   targets, about a tenth of their size. A function that takes over 30 s is
   skipped. Functions left out are decompiled when first opened
   (`POST /decompile` on the worker) and kept.
4. The worker then keeps the analysed rizin session open
   (`ANALYZER_WARM_SESSIONS`, default 1, for `ANALYZER_WARM_IDLE` seconds),
   so a decompilation on demand takes seconds instead of a new `aaa` (on the
   5,000-function sample: 0.1–3 s instead of 13 s and more). A session is lent
   to one request at a time; if rizin died in the meantime the request falls
   back to a fresh analysis. Each kept session holds rizin's memory for that
   file (about 1 GB on a large binary), hence the 4 GB default limit.
5. The backend stores the function list with the job (`sample_code`) and
   each function's CFG and pseudo-C as a row of `sample_functions`, which the
   UI fetches one function at a time
   (`GET /api/samples/{sha256}/code/functions/{addr}` and `…/decompiled`):
   the graphs of a large binary add up to tens of megabytes, and opening a
   function reads only its own.

rizin 0.9 can crash (segfault) after thousands of commands in one session,
on a function it handles fine in a fresh one. The worker survives it: it
reopens the sample and retries that function once; a second crash skips the
function (it is listed, marked, without CFG). After three restarts in one
request it gives up with an error.

In Compose the worker runs as the image's non-root user, with a read-only
filesystem, no capabilities, memory and CPU limits, no published port and no
route outside the internal `analysis` network: the sample is read and
disassembled, never executed. Without a worker (`ANALYZER_URL` unset) the
Code view says so and everything else keeps working.

The UI (`components/tabs/malware/code/`) lists the functions with the
severity of the APIs they reach (the SOC malware ruleset applied to callee
names, propagated through the call graph by `utils/code.js`) and draws the
**call graph** around the selected function and its **control-flow graph**
with `elkjs`: ELK's layered algorithm places the blocks (main path in a
column, branches on the sides), routes edges orthogonally in their own lanes
and sends loops back along the side, as a disassembler's graph view does.
Nik draws the result as SVG with its own tokens, with pan, zoom, a minimap and
click to select. `elkjs` (~1.4 MB) is imported only when the Code view opens;
it is licensed EPL-2.0 / GPL-3.0 and used unmodified. The **Decompiled** panel
shows the pseudo-C with the decompiler's own highlighting (font ligatures off,
so `!=` reads as written); a call to another function of the sample is a link
that opens it, and calls to suspicious APIs are red.

**Function triage.** A real binary has thousands of functions, most of them
library code. The worker reports, per function, what it can tell about its
origin, and the UI (`utils/triage.js`) sorts the list with it:

- *Library*: functions matched by a FLIRT signature (rizin's bundled set
  plus the `.sig` / `.pat` files admins upload in **Settings → FLIRT
  signatures**, stored under `SAMPLE_STORE/_flirt/` and passed to the
  worker, which applies them with `Fs` after `aaa`), and, in Rust binaries,
  functions whose panic locations point at a crate's sources
  (`…\.cargo\registry\src\…\<crate>-x.y.z\src\…rs`, or
  `/rustc/<hash>/library/std/…` for the standard library). The worker finds
  those paths among the strings, follows the `Location` structs that point
  at them, and credits each function with the crates its instructions
  reference. The crates found are listed above the table.
- *Runtime* (compiler start-up and C runtime support, by name), *thunk*
  (jumps to imports, switch fragments) and *import*.
- *Not recognised*: everything else. Release builds leave much library code
  without a signature or a path, so this is "not recognised", not "the
  author's code".

**Hide recognised library code** (on by default) keeps only the
unrecognised functions in the list. **Start here** ranks those that call
suspicious APIs directly, use an indicator of compromise, reach a suspicious
API through their callees or are complex. The worker also reports the file
offsets of the strings each function references; matched against the
analysis strings, they give each function's **strings used** and, in the IOC
table, a **Used by** column that opens the function in the Code view.
Analysts **rename** and **comment** functions (`function_annotations`
table): names replace rizin's in the list, the graphs and the pseudo-C for
everyone opening the same sample.

**Capabilities (capa).** [Mandiant capa](https://github.com/mandiant/capa)
matches a community rule set against the program's code and reports what it
can do (send data on a socket, create a process, encrypt with RC4, resolve
APIs at runtime…), mapped to MITRE ATT&CK and the Malware Behavior Catalog.
It runs in a third worker, `capa/`, built on `python:3.12-slim` with
`flare-capa`, its rules and its library signatures at a pinned version (the
rules and signatures are checked against their SHA-256 at build time); capa
uses its pure-Python vivisect backend, so no Java or IDA is needed. capa,
capa-rules and vivisect are Apache-2.0.

1. After an upload and on Re-analyse (or the **Run capa** button) the
   backend queues a job (`sample_capa` table) for x86 / x64 PE and ELF
   files; other types are marked `unsupported` without calling the worker.
2. The worker (`server.py`, standard library) runs `capa -j` on
   `<store>/<sha256>.bin` from its read-only mount, kills it after
   `CAPA_TIMEOUT`, and reduces the report (megabytes on a large binary) to
   the capabilities with their namespace, scope, ATT&CK / MBC mappings and up
   to 200 addresses each, a few kilobytes. Rules capa marks as library
   helpers are dropped, as capa's own report does.
3. capa is CPU-bound — seconds on a small file, ten minutes or more on a
   large one — so the worker runs one analysis at a time and the backend
   sends its jobs one after the other, waiting while the worker is busy.

The **Capabilities** view lists them by namespace with ATT&CK and MBC badges.
capa and rizin split a binary into functions differently, so each address
capa reports is credited to the rizin function containing it
(`placeCapabilities` in `utils/triage.js`): the view links each capability to
those functions, the Code view shows the capabilities of each function, and
**Start here** counts them — only for functions not recognised as library
code, since crypto and TLS crates match many rules. Capabilities do not
change the sample's severity. The `capa` service has the same isolation as
`analyzer` (read-only store and filesystem, internal network only, no
capabilities, memory / CPU / time limits).

**capa rules of your own.** Admins add capa rules in **Settings → capa
rules** (`capa_rules` table, one YAML rule each). Since only the worker has
capa, the backend asks it to check a rule (`POST /validate`: parsed by capa
and loaded together with the bundled rules and the other enabled admin rules,
so syntax errors, unknown features, duplicate names and missing `match:`
dependencies are caught) before saving it. Saved rules are written to
`SAMPLE_STORE/_capa_rules/<id>.yml` and the enabled ones are passed to the
worker with each analysis, as extra `-r` rule paths next to the bundled set.
A rule another enabled rule matches cannot be renamed, disabled or deleted.
Their matches carry a **custom** badge in the Capabilities view; new or
changed rules apply from the next analysis (Re-analyse).

### 3.8 Mail analysis

The **Mail Analysis** tab triages reported messages. Like samples, the file
goes to the server once: `POST /api/incidents/{id}/mails` stores it in the
sample store as `<sha256>.mail` (read-only), analyses it
(`app/mail/analyze.py`) and keeps the result in the `mails` table; the
incident gets a light reference under `data.mail.messages` and the
`incidents.has_mail` column (mirrored, for the mail icon in the sidebar).
Nothing in an attachment is opened by the program it is meant for.

- **Parsing** (`mail/parse.py`): `.eml` with the standard library; `.msg`
  (an OLE compound file of MAPI properties) with `olefile`: the original
  Internet headers when Outlook kept them, the bodies (Outlook's compressed
  RTF is decompressed, MS-OXRTFCP), the attachments and attached messages
  (parsed in turn, three levels deep).
- **Headers** (`mail/headers.py`): the `Received` chain in travel order with
  the delay of each hop and clocks going back; the sending server is the
  first public IP that is not one of your servers. Authentication-Results
  (and ARC, Received-SPF) are read as written, but only those of your own
  servers (**Settings → Mail analysis**) are believed: anyone can put such a
  header in a message. A header without an authserv-id (Exchange Online) is
  credited to the server that received the message last.
- **Authentication** (`mail/verify.py`): DKIM signatures verified with
  `dkimpy`, SPF of the sending IP with `pyspf`, DMARC policy and alignment
  (relaxed/strict, organisational domain from the bundled Public Suffix List)
  with `dnspython`. The server needs DNS; each lookup times out after 3 s and
  a failure reads `temperror`, never a pass. These say what the DNS says
  *now* (a rotated DKIM key fails), so the servers' verdicts are shown next
  to them. A `.msg` keeps no original body: its DKIM cannot be checked.
- **Links** (`mail/links.py`): anchors, forms and URLs in the text, unwrapped
  from Safe Links, Proofpoint (v1–v3), Google, Facebook and Barracuda
  redirects; look-alikes of well-known brands (Italian banks and public
  services included) and of your own domains are found by folding
  confusable characters and comparing edit distance, so punycode and
  `rn`→`m` tricks show.
- **Body** (`mail/content.py`): the HTML is cleaned with `nh3` (no scripts,
  handlers, frames, objects or forms), inline `cid:` images become `data:`
  URIs, hidden text is revealed. The browser shows it in an
  `<iframe sandbox="">` (no scripts, no same-origin, no navigation of the
  app) whose Content-Security-Policy refuses every request; links lose their
  target (shown as a tooltip) and remote images load only after a warning,
  tracking pixels never. Urgency, payment, credential and secrecy phrases
  are listed (English and Italian).
- **Attachments** (`mail/attachments.py`): type from the magic bytes against
  the extension, double extensions and right-to-left tricks, VBA/XLM macros
  (`oletools`), zip listings (the password is looked for in the text and
  tried; the archive is never extracted to disk), PDF actions, QR codes in
  images (`zxing-cpp`), calendar invitations.
- **Verdict**: each finding weighs a fixed number of points (e.g. a
  look-alike sender domain 40, DMARC failing 30, a password-protected archive
  35, urgency 8); the score is capped at 100. It is an aid to triage, not a
  proof: a clean score means nothing stood out.

The message's indicators (sender addresses and domain, sending IP, link
targets and hosts, attachment hashes, QR and invitation links) go into the
IOC index as `mail:<file name>`; the timeline shows each message at the time
it was sent, high when the verdict is phishing; the report has an **E-mails**
section.

### 3.9 Threat intelligence

Indicators get a reputation from external services (`app/enrichment/`).
Each provider is one function in `providers.py` that turns the service's
answer into `{ verdict, summary, link, data }`; `verdict` is `malicious`,
`suspicious`, `harmless` or `unknown` (not known, or nothing conclusive).

| Provider | Types | Key | Free tier (as Nik paces it) |
|---|---|---|---|
| VirusTotal | IP, domain, URL, hash | required | 1 request / 15 s, 500 a day |
| AbuseIPDB | IP | required | 1,000 a day |
| abuse.ch: ThreatFox, URLhaus, MalwareBazaar | IP, domain, URL, hash | required (one Auth-Key) | — |
| AlienVault OTX | IP, domain, URL, hash | required | — |
| urlscan.io (search of public scans, nothing submitted) | domain, URL | optional | 1,000 a day |
| GreyNoise Community | IP | optional | 50 a day |
| Shodan InternetDB | IP | none | — |
| Google Safe Browsing | domain, URL | required | 10,000 a day |

**What is never sent** (`service.blocked`), whoever asks: private, loopback
and other non-public addresses, internal names (no dot, `.local`, `.lan`,
`.internal`, `.corp`, `.home.arpa`…) and URLs on them; values on the IOC
allowlist; values seen in an incident whose report is classified
**TLP:RED**; e-mail addresses. MD5 and SHA-1 of stored samples and mail
attachments are not looked up automatically: their SHA-256 is.

**Automatic lookups** are off until an analyst turns them on in **Settings
→ Threat intelligence**, per type: IP addresses, URLs and domains, file
hashes. Every API process starts a worker thread (`worker.py`); a lease row
(`leases`) lets only one of them work at a time, so several gunicorn workers
do not multiply the requests. Every 30 seconds it checks the indexed
indicators not in the cache (newest incidents first) with every enabled
provider that takes their type, pacing each provider to its free tier. An
answer is kept for the cache period (24 h by default, up to 30 days), an
error is retried after an hour; a provider that answers 429 waits an hour,
one that refuses its key six hours.

**Check now** in Where seen asks every usable provider at once (fresh
answers are reused unless "Check again"). The IOCs tab's **Reputation**
column shows the worst cached verdict and how many providers flag the value.

**Keys** are entered by admins and stored in `integration_keys`, encrypted
with Fernet under a key derived from `SECRET_KEY` (HKDF, `vault.py`): the
API returns only whether a key is set and its last four characters. Changing
`SECRET_KEY` makes the stored keys unreadable (Settings says so): enter them
again. Requests use the standard library (`urllib`), so `HTTPS_PROXY` /
`NO_PROXY` apply; a transparent proxy needs nothing.

### 3.10 Attachment previews and the isolated browser

Two more workers show what an attachment looks like without opening it on
the analyst's machine. Like `analyzer` and `capa` they run as unprivileged
users with a read-only filesystem, no capabilities, memory and CPU limits,
no published port, and answer only the backend's shared token.

**Documents** (`docview/`, internal network only). The Mail Analysis tab's
**Preview** sends the attachment to
`POST /api/mails/{sha256}/attachments/{path}/preview`; the backend forwards
it to the worker, which converts Word, Excel, PowerPoint, OpenDocument and
RTF to PDF with LibreOffice (a fresh profile per conversion: macro security
"very high", macros disabled, links to other files or the network never
updated, killed after 90 s) and renders the first 20 pages of the PDF with
pdfium; images are re-encoded with Pillow. The browser receives PNG images
only. The pages are kept under `SAMPLE_STORE/_previews/<sha256>.json` and
removed with the last message that holds the attachment.

**Isolated browser** (`browser/`). HTML attachments (**Open in isolated
browser**) and links (Links view) open in Chromium, run by Playwright inside
the worker's container. The analyst sees a JPEG of the viewport; clicks,
double-clicks, typing, Enter / Tab / arrows and the wheel are sent to
`POST /api/browser/sessions/{id}/action` and replayed there, with back,
forward, reload and an address bar. Scripts of the page run in the worker,
never in the analyst's browser.

- **Network, chosen for each session.** Without network (the default) the
  page is the attachment itself: every other request (images, scripts,
  frames, form posts, links) is refused, and a navigation shows a "blocked
  by Nik" page. With network, http and https go out through the server's
  connection (the `browser-egress` network, the only one with a route
  outside), except to private, loopback or link-local addresses and internal
  names, so a page cannot reach the organisation's own network. Every
  session is audited (`browser.open`), with or without network.
- Downloads are refused and reported, alert / confirm / prompt dialogs are
  dismissed and reported, permission prompts denied, a new tab replaces the
  current one. A session belongs to the analyst who opened it, closes after
  5 minutes without an action (30 minutes at most) and when the window is
  closed; at most `BROWSER_MAX_SESSIONS` are open at once.
- Chromium's own sandbox needs privileges the container does not give, so
  it runs with `--no-sandbox`: the container is the sandbox.

### 3.11 Network analysis

The **Network Analysis** tab reads packet captures with Wireshark's own
engine, in the `pcap` worker (`pcap/`): Debian's `tshark` and `sharkd`, run
as an unprivileged user in a container with a read-only filesystem and the
sample store mounted read-only, no capabilities (nothing is ever captured)
and the internal network only.

- **Upload** (`POST /api/incidents/{id}/captures`): pcap or pcapng, gzip
  too, up to `PCAP_MAX_MB` (500), checked by its magic bytes, written to
  `SAMPLE_STORE/_captures/<id>/` (read-only) and recorded in the
  `network_captures` table. The worker then reads it once with tshark for
  the **summary**: hosts by bytes, DNS names and answers, HTTP requests, TLS
  server names, POST / PUT / PATCH requests, **beacons** (six or more
  connections to the same address and port, at least 5 s apart, intervals
  within 15 %), the exported objects with their SHA-256 and the Expert Info
  counts. These feed the IOC index (`network:<file>`), the timeline and the
  report's **Network** section.
- **Viewing** goes through `sharkd`, Wireshark's daemon for web front ends,
  one process per open capture (two at most, closed after 15 minutes
  unused): the packet list with Wireshark's colouring rules, paged; the
  protocol tree with the byte range of every field; Follow Stream; Export
  Objects. The backend forwards a fixed set of read-only calls
  (`POST /api/captures/{id}/rpc`); columns are never taken from the caller,
  since some custom column definitions crash sharkd.
- **TLS** is decrypted with a key log (`SSLKEYLOGFILE`, NSS format) added at
  upload or later. It is stored encrypted like the API keys and written to
  the worker's `/tmp` only while a capture is open.
- Packets can be flagged into the incident timeline (`pcap:<capture>:<n>`).

**Isolated browser sessions.** The browser worker records every request of
a session (`netlog.py`): method, URL, type, headers, bodies in clear (the
browser sees HTTPS decrypted, 2 MB per body and 50 MB per session, past that
size and SHA-256 only), response, server address, certificate, timings and
WebSocket messages; refused requests (no network, private address) and held
submissions included. In a session with network, POST / PUT / PATCH /
DELETE requests are **held** by default: recorded, not sent, the page shows
"Submission held by Nik"; the analyst may send them for the session (audited).
Opened from an incident, the session's log is copied after every action
(`network/service.py`) and shown live in the window's **Network panel**,
DevTools-like. When the window closes (or the session expires) the log is
rebuilt as **pcapng** (`network/pcapng.py`): a DNS answer per host, a TCP
handshake and HTTP/1.1 in clear per request, a comment saying it is a
reconstruction and marking held and refused requests, so Wireshark's
filters, Follow Stream and Export Objects work on it, then analysed like an
upload. It also exports as **HAR 1.2** (`network/har.py`).

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
import { Button, Card, Badge, Modal, DataTable, EmptyState, ErrorBoundary,
         SearchInput, Select, StatCard, AsciiSkull, MicroSkull } from '../ui/index.js'
```

**ErrorBoundary** — keeps a rendering error inside the view that threw it.
`App` wraps the active analysis tab in one, and the Code view wraps its graph
and pseudo-C panels: the broken view shows the error and a *Reload this view*
button while the rest of Nik keeps working. Pass a `resetKey` (e.g. tab and
incident) so that moving elsewhere clears the error. New tabs get it for free.

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
