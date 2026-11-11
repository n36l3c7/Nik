# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-11

The safe configuration is now the only one. Upgrading from 2.x needs one
extra command (`deploy/init-env.sh`): see "Upgrading to 3.0" in the
deployment guide.

### Changed

- **BREAKING: secrets are required.** `docker-compose.yml` has no default
  for `DB_PASSWORD`, `SECRET_KEY` and the five worker tokens, and the
  backend and the workers refuse the values of `.env.example`, which are
  public. `deploy/init-env.sh` creates or completes `.env` with random
  values and is safe to run again.
- **BREAKING: HTTPS only.** Port 8080 answers every request with a redirect
  to the HTTPS port, and the session cookie is `Secure` by default
  (`COOKIE_SECURE=true`). The self-signed certificate is still generated on
  first start when none is mounted.
- **BREAKING: `/api/metrics` is not published by nginx** any more. Scrape
  `http://api:8000/api/metrics` on the compose network; `METRICS_TOKEN`
  optionally requires a bearer token.
- The backend container runs as an unprivileged user on a read-only
  filesystem, with no capabilities left after start-up and with memory, CPU
  and process limits (`API_MEMORY`, `API_CPUS`). A sample store created by
  an older release is handed to that user on the first start.
- The web container is read-only, with the capabilities nginx needs and
  nothing else; nginx is pinned to 1.30.
- `web` waits for `api` to be healthy, so the app does not answer 502 while
  migrations run. Every container has a process limit and rotated logs.

### Added

- `deploy/init-env.sh`.
- `SECRET_KEY_PREVIOUS`: change `SECRET_KEY` without losing the provider API
  keys and TLS key logs stored in the database. They are re-encrypted with
  the new key at the next start.
- Security headers on every page: a Content-Security-Policy that lets only
  the app's own scripts run, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy` and HSTS. The end-to-end tests
  run under the same policy.

### Fixed

- Rate limits and account lock-outs counted every user as one client (the
  address of the nginx container): ten failed sign-ins by anyone locked the
  sign-in for everyone. They are counted per client address now, as nginx
  sees it; a forwarded address sent by the client is ignored.
- A scanner requesting random paths created one Prometheus time series per
  path; unknown paths are counted under one label.

### Security

- A stack started without editing `.env` ran with a public `SECRET_KEY` (so
  the "encrypted" API keys in a database dump were readable) and public
  worker tokens. It no longer starts.

## [2.28.0] - 2026-11-11

### Added

- **Account management for admins**: the pencil on an account changes its
  username, role and password, or disables it (`PATCH /api/users/{id}`). A
  renamed account keeps the incidents assigned to it; a disabled one keeps
  its history, cannot sign in and is signed out at once. The server always
  keeps one admin able to sign in.
- **My account** section for every user, to change one's own password
  (`PUT /api/users/me/password`); the account's other sessions end.
- An account is **locked for five minutes** after ten wrong passwords in a
  row (`429`); an admin's password reset unlocks it.
- New audit entries: `auth.login`, `auth.logout`, `auth.locked`,
  `user.create`, `user.update`, `user.delete`, `user.password`,
  `apikey.create`, `apikey.revoke`, `settings.update`, `evidence.update`,
  `audit.clear`.
- Migration `0021`: `users.disabled`, `users.failed_logins`,
  `users.locked_until`.

### Changed

- **The audit log is written by the server.** Every change is recorded by
  the handler that makes it, for a browser session as for an API key, and a
  merge patch is described by what it means (a flag, a comment, a note, the
  status, an evidence file). The app no longer reports what it did, and the
  log is read when its section opens instead of at every sign-in.
- `POST /api/audit` accepts only `incident.export` (an action that happens
  in the browser alone) and answers `400` to anything else.
- `PUT /api/settings` accepts a key with the write scope, as documented. The
  report header, the mail settings and the threat-intelligence options are
  changed by admins only (their Settings sections are shown to admins only);
  sent by anyone else they are left as they are.
- `GET /api/users/names` leaves disabled accounts out.

### Fixed

- A request sent outside the app with a session cookie (deleting an
  incident, for instance) left no audit entry.
- Any signed-in user could write arbitrary entries to the audit log, and
  change the threat-intelligence and report settings.
- Clearing the audit log left no trace of who did it.
- A failed sign-in with an unknown username answered faster than one with a
  wrong password; expired sessions were never purged.

### Security

- Sessions end when the account's password is changed or the account is
  disabled.

## [2.27.0] - 2026-11-11

### Added

- **Saves that cannot be lost.** Changes to an incident go through a save
  queue: one request at a time, in order; a save that fails is retried on
  its own and reported by a bar with **Retry now** until it goes through,
  and closing the window with unsaved changes asks first.
- **Working on the same incident.** When a colleague saved meanwhile, their
  version is read and merged with the local changes instead of being
  overwritten: notes, comments and flags added by two analysts all survive.
  A window that regains the focus checks the open incident again.
- **Session expired** dialog: when the session ends while working, the app
  stays on screen, asks for the password again and then saves what was
  waiting.
- **Undo** after removing a flag (from the menu or with `F`), since its
  comments go with it.
- `ETag` on `POST /api/incidents`; every `PATCH` answers with the new one.

### Changed

- An incident's `ETag` is now a revision counter kept by the server
  (`incidents.rev`, migration `0020`), one more at every write of the
  document, instead of the client-supplied `updatedAt`. Clients that treat
  it as opaque are unaffected.
- Deleting an incident removes it from the list once the server has deleted
  it, instead of before.

### Fixed

- Two analysts saving the same incident could erase each other's notes,
  comments or references: every writer of an incident document (patches,
  notes, sample, e-mail, capture and URL scan references, background
  uploads) now takes the row lock before reading it, and `If-Match` is
  checked under that lock.
- A failed save was dropped, and its error message disappeared at the next
  successful one.
- A comment added to a row that was not flagged sent two requests that could
  overtake each other.
- Two browser files parsed at the same time could leave one of them marked
  as not loaded.
- Removing a sample, an e-mail or a capture could undo a change made while
  the server was answering.
- In the report dialog, a section toggled right after typing the executive
  summary discarded the summary.

## [2.26.0] - 2026-11-11

### Added

- **Keyboard shortcuts** on the row under the pointer (or the focused row):
  `F` flags it or removes its flag, `C` asks for a comment. They run the
  same items as the row's right-click menu, so they work in every list
  that has one (events, samples, e-mails, captures, addresses, indicators,
  functions, packets), and are off while typing or while a dialog is open.
- `?`, or the keyboard button in the header, lists every shortcut. The
  right-click menu shows the key next to Flag and Comment.

## [2.25.0] - 2026-11-11

### Added

- **Incident status and assignee.** An incident is open, in progress or
  closed, and can be assigned to an analyst.
  - Set from the Summary tab, or from the right-click menu of the incidents
    panel (Mark as in progress / closed / open, Assign to me, Remove the
    assignee), also on incidents that were never opened.
  - The panel shows both under the name and filters the list by status and
    to the incidents assigned to the analyst ("mine"); the header shows them
    for the open incident.
  - The report states the status and the assignee.
- API: `status` and `assignee` in the rows of `GET /api/incidents?view=summary`,
  the `status` and `assignee` filters of `GET /api/incidents`, and
  `GET /api/users/names` (the usernames an incident can be assigned to).

### Changed

- Database migration `0019`: `incidents.status` and `incidents.assignee`.
  Existing incidents are open and unassigned. Applied on start-up.

## [2.24.0] - 2026-11-11

### Changed

- **The incident report lists what was flagged**, so it stays about the
  incident instead of everything that was imported:
  - the indicators flagged by hand (it used to list every indicator, up to
    the cap);
  - the samples, e-mails, captures and scanned addresses that are flagged
    or hold something flagged (an indicator or a function of a sample, a
    packet, a held submission or a beacon of a capture);
  - the ATT&CK techniques of those samples and of the detections on flagged
    events; the event logs that hold a flagged event;
  - an evidence appendix with only the imported files that hold something
    flagged.
  Flagged events and notes are listed as before. A section with nothing
  flagged says so.
- **Include everything** in the report dialog (kept per incident), or
  `"scope": "all"` in `POST /api/incidents/{id}/report`, gives the full
  inventory as before.

## [2.23.0] - 2026-11-11

### Added

- **Right-click everywhere**: one menu, built from the parts that apply, on
  every row and item.
  - The lists of samples, e-mails, captures and scanned addresses: flag,
    comment, open as an artifact, copy, show in the Timeline, remove from
    the incident.
  - The artifacts panel and the artifact page (incident, tag and related
    chips).
  - The tables that had no menu: bookmarks and omnibox shortcuts, a
    sample's indicators, strings, sections, capabilities and functions,
    logon sessions, the audit log.
  - URL Analysis (findings, redirects, forms), the request log of a
    capture, the flagged items and the notes of the Summary.
- **Flag a sample, an e-mail, a capture or an address** from its list (a
  small flag marks it), not only from the Timeline.
- **Flag an indicator by hand** from its menu, wherever it is shown (IOCs
  tab, samples, e-mails, captures, scans).

### Fixed

- The right-click menu no longer closes by itself when the list under it
  reloads: it closes when the analyst scrolls, clicks elsewhere or resizes
  the window.

## [2.22.1] - 2026-11-11

### Changed

- **Tab bar**: when the full labels do not fit it switches to one-word
  labels, then to icons only, instead of scrolling sideways. The open tab
  keeps its full label; every tab keeps its full name as a tooltip and for
  assistive technology.
- **Controls line up**: buttons have a fixed height per size (36, 32 and
  28 px) and icon-only buttons are square; the header's search, report, user
  and sign-out controls share one height.
- The lists of the Mail, Malware and Network tabs remember whether they were
  closed; the URL tab's list can be closed too.

### Added

- A real favicon for the app (SVG, with PNG versions for older browsers and
  home screens) and for the documentation site.

## [2.22.0] - 2026-11-11

### Added

- **Paste or drag text**: Ctrl+V outside a text field, or selected text
  dragged onto the app, is checked for something Nik can act on. A small
  panel then offers what to do; nothing is opened until the analyst chooses.
  - An address: **Analyse URL** (the isolated browser scans it).
  - A hash, an IP address, a domain or an e-mail address: **Search in Nik**
    and **Where seen** (incidents and reputation). A domain can also be
    visited; a SHA-256 of a file already analysed opens that analysis.
  - Defanged text is read as it was meant (`hxxps://evil[.]top`,
    `1.2.3[.]4`, `user[at]evil.top`). Sentences and longer text are ignored.
- A file copied to the clipboard and pasted on the app is handled like a
  dropped file.

## [2.21.0] - 2026-11-11

### Added

- **URL Analysis**: give Nik a link and the isolated browser visits it for
  you, with network access (never private or internal hosts) and without
  typing, clicking or submitting anything.
  - A screenshot, the final address, title, server and certificate; every
    navigation that led there; the page's forms; the requests of the visit,
    kept as a capture.
  - A **verdict** with its reasons and points: a lookalike domain, a page
    that asks for a password (worse over http, or under a brand's name), a
    form that sends what is typed elsewhere, a throwaway top-level domain, a
    shortener, a chain through several domains, a certificate issued days
    ago, a download the page started. 70 or more is phishing, 40 to 69
    suspicious.
  - A new **URL Analysis** tab in incidents (threats group) and a `url`
    artifact kind: scan an address on its own from **New analysis**, link it
    to incidents later. Defanged text (`hxxps://evil[.]top`) is understood;
    an address already scanned is recognised.
  - Scanned addresses join the incident's indicators, timeline and report.
  - API: `POST /api/artifacts/urls`, `GET /api/urls/{id}`, `…/rescan`,
    `…/screenshot`. Migration `0018` (`url_scans`).
- Isolated browser worker: the `inspect` action returns what a page asks for
  (its forms), read from the DOM.

## [2.20.0] - 2026-11-11

### Added

- **Analyse without an incident**, in the interface.
  - **New analysis** (artifacts panel, empty screen and the search palette):
    drop or choose an e-mail, a suspicious file or a packet capture; Nik
    recognises it and analyses it on its own.
  - A file dropped anywhere now offers **Start analysis** next to the open
    incident and a new incident.
  - The **artifact page** (`/artifact/<id>`): the same analysis views as in
    an incident, plus the incidents that reference the artifact, **Link to
    incident**, **New incident from this**, tags, related artifacts (the
    e-mail an attachment came from, the objects taken out of a capture) and
    Delete.
  - A file already analysed is recognised before the upload: who added it,
    in which incidents, and a button to open the existing analysis.
- **Rail and side panel**: a narrow column of icons chooses what the side
  panel lists, incidents or artifacts (for the whole team, with a text
  filter, kind chips and "mine"). Clicking the active icon closes the panel.
  The rail also opens the search, the audit log, the users, the full backup
  and the settings.

### Changed

- The sidebar's brand block, its footer buttons and the header's settings
  gear moved to the rail.
- "Remove" on a sample, an e-mail or a capture says that it stays as an
  artifact.

## [2.19.0] - 2026-11-11

### Added

- **Artifacts** (API): a file, an e-mail or a packet capture can be analysed
  **without an incident** and linked to incidents later.
  - `POST /api/artifacts/files`, `/mails`, `/captures` start an analysis on
    its own (or in an incident with the `incident` field).
  - `GET /api/artifacts` lists them for the whole team, with search, kind,
    tag, "mine" and linked filters, and the incidents that reference each.
  - `POST /api/artifacts/{id}/links` and `DELETE …/links/{incidentId}` link
    and unlink; a file or an e-mail can be in several incidents, a capture
    in one.
  - `GET /api/artifacts/lookup?sha256=` tells whether a file is already
    known before it is uploaded.
  - Tags (`PUT …/tags`) and relations: an attachment analysed as a file, an
    object taken out of a capture and an isolated browser session opened
    from an e-mail are recorded as children of their source.
- Migration `0017`: the `artifacts`, `artifact_links` and
  `artifact_relations` tables; `network_captures.incident_id` becomes
  optional. What is already stored is registered on the first start.

### Changed

- Removing a sample, an e-mail or a capture from an incident no longer
  deletes it when no other incident references it: it stays as an artifact.
  `DELETE /api/artifacts/{id}` deletes it everywhere.
- Deleting an incident deletes the samples, e-mails and captures that only
  that incident references (samples and e-mails used to stay on disk with
  nothing pointing at them); those another incident references stay.

## [2.18.3] - 2026-11-11

### Changed

- Backend dependencies: the minimum versions of FastAPI (0.162.2),
  dnspython (2.9.2), publicsuffixlist (1.1.2.20261107), Pillow (13.0.0) and
  cryptography (46.0.7) are raised to the releases already tested by CI.

## [2.18.2] - 2026-11-11

### Changed

- **Documentation**: the README is now a short introduction (what Nik does,
  installation, the settings to change, development) and points to the site.
  The GitHub Pages site has a short homepage and new pages: a **user guide**
  with screenshots (incidents, evidence, every analysis tab, search, report,
  settings), **Deployment**, **Architecture** and a **Developer guide**, which
  take the README's former technical sections.
- The guide's screenshots are taken by a Playwright script,
  `npm run docs:screenshots` in `frontend/`, so they can be retaken after a
  change to the interface.
- The end-to-end test's generated PE sample and phishing e-mail live in
  `frontend/e2e/helpers.js`, shared with the screenshot script.

## [2.18.1] - 2026-11-11

### Security

- Sample store paths: a SHA-256 is now matched in full (a digest followed by
  a newline was accepted), and every stored sample and e-mail path is proven
  to stay inside the store before it is opened.
- The analyzer and capa workers check the same way every path they receive
  (sample, FLIRT signatures, capa rules) before taking a job slot.
- A malformed executable no longer sends the parser's internal error message
  to the client: Malware Analysis shows a fixed warning and the server log
  keeps the detail.
- The CI and Audit workflows run with a read-only token.

## [2.18.0] - 2026-11-10

### Changed

- The analysis tabs follow the investigation, in three groups separated by a
  thin rule: the overview (Summary, Timeline, IOCs), the threats (Mail,
  Malware, Network) and the host (Endpoint Artifacts, Event Logs, Browser
  Forensics, Command History).
- The end-to-end test imports real evidence files (`frontend/e2e/fixtures/`)
  dropped on the app instead of the demo data.

### Removed

- **Load demo data** in Browser Forensics, Command History, Endpoint
  Artifacts and Event Logs. Incidents that already hold demo data keep it
  and open as before.
- The **`tail -f`** side panel and its command; the Timeline tab shows the
  same events.

## [2.17.1] - 2026-11-10

### Changed

- **Repository layout**: one folder per component. The single-page app
  moved to `frontend/` (with its Dockerfile, nginx configuration and the
  end-to-end tests), the five analysis workers to `workers/` (`analyzer`,
  `capa`, `docview`, `browser`, `pcap`). Run the npm scripts from
  `frontend/`; Compose builds the web image from that folder only, so the
  workers, their fixtures and the docs no longer enter its build context.
- Backend package split by concern: `app/core/` (configuration, database,
  models, schemas, security, vault, rate limit, observability),
  `app/workers/` (worker clients) and `app/malware/` (sample store, YARA and
  capa rules, FLIRT signatures, built-in YARA rules).
- Frontend sources split by kind: `src/lib/` (generic helpers),
  `src/domain/` (forensic logic) and `src/parsers/` (client-side file
  parsers) replace `src/utils/` and most of `src/services/`.
- One Ruff configuration (`ruff.toml`) for every Python component; the
  analyzer extends it for Python 3.9.
- The registry-name check on every image is a shell script,
  `deploy/check-images.sh`, run by the Audit workflow.
- Dependabot also watches the Dockerfiles of the web image and of the
  document viewer, isolated browser and packet capture workers.

### Removed

- Python bytecode (`__pycache__`) committed by mistake; `.gitignore` now
  excludes it everywhere.

### Upgrading

- Compose: nothing to do (`git pull`, then `compose up -d --build`); the
  volumes keep their names.
- Development: delete the old `node_modules/` at the repository root and
  run `npm ci` in `frontend/`.

## [2.17.0] - 2026-11-10

### Added

- **Network Analysis** tab (replaces the Network Logs placeholder): packet
  captures read by **Wireshark's own engine** in a new isolated `pcap`
  worker (Debian's tshark and sharkd, read-only store, internal network, no
  capabilities).
  - pcap and pcapng (gzip too) up to `PCAP_MAX_MB` (500), uploaded or
    dropped anywhere in the app.
  - Wireshark's main window: the packet list with Wireshark's colouring
    rules and three time formats, the protocol tree, the bytes in hex and
    ASCII with the selected field highlighted, **display filters** in
    Wireshark syntax (checked as you type), right-click on a field to apply
    it as a filter.
  - **Follow Stream** (TCP, UDP, HTTP, TLS…) in ASCII or hex, client and
    server coloured.
  - **Export Objects** (HTTP, SMB, FTP-DATA, TFTP, IMF, DICOM) with their
    SHA-256, downloaded in a protected zip or sent to Malware Analysis.
  - **TLS decryption** with a key log (`SSLKEYLOGFILE`), added at upload or
    later, stored encrypted.
  - A summary: hosts by bytes, DNS names and answers, HTTP requests, TLS
    server names, POST / PUT / PATCH requests, **beacons** (regular
    connections to the same address and port), Expert Info, protocols.
  - Packets can be flagged into the incident timeline.
- **Isolated browser: network capture.**
  - Every request of a session is recorded (method, URL, type, headers,
    bodies in clear with HTTPS already decrypted, response, server address,
    certificate, timings, WebSocket messages), refused ones included; bodies
    up to 2 MB each and 50 MB per session, past that size and SHA-256.
  - A **Network panel** in the browser window, as in DevTools: type filters,
    search, "blocked / held" and "submissions only", a waterfall, and per
    request Headers, Payload (form fields), Preview (sandboxed), Response,
    Timing and Messages.
  - In a session with network, **submissions (POST, PUT, PATCH, DELETE) are
    held** by default: recorded, not sent; the analyst may send them for the
    session (audited).
  - A session opened from an incident is kept in it: when it ends, its log
    becomes a capture in Network Analysis, rebuilt as a **pcapng** with HTTPS
    in clear (a comment marks it as a reconstruction), and exports as **HAR**.
- Captures in the **IOC index** (`network:<file>`: public addresses, DNS
  names, URLs and hosts, TLS server names, beacon destinations, object
  hashes), the **timeline** (each capture, held submissions as high, beacons
  as medium) and the **report** (a Network section; captures in the evidence
  appendix).
- API: `POST /api/incidents/{id}/captures`, `GET /api/captures/{id}`,
  `POST /api/captures/{id}/rpc`, `…/objects/download`, `…/file`, `…/har`,
  `…/requests`, `PUT/DELETE …/keylog`, `POST …/reanalyse`,
  `POST /api/incidents/{id}/captures/{captureId}/objects/sample`,
  `DELETE /api/incidents/{id}/captures/{captureId}`,
  `GET /api/browser/sessions/{id}/network`; `incident` on
  `POST /api/browser/sessions` and the `policy` action.
- Compose: the `pcap` service; `PCAP_URL` / `PCAP_TOKEN` / `PCAP_MAX_MB`,
  `PCAP_MEMORY` / `PCAP_CPUS`. Migration `0016`: `network_captures`.

### Changed

- nginx accepts uploads up to 600 MB and waits up to 330 s for the API
  (opening a large capture takes minutes).
- CI tests PostgreSQL 18 only (production moved to 18 in 2.12.2), lints the
  new worker and runs its tests inside its image.
- The configuration page of the documentation lists the document viewer,
  isolated browser and threat-intelligence settings it was missing.

### Security

- `minimatch` 11.0.6 (moderate denial-of-service advisory; a dependency of
  ESLint, build tooling only) through an npm override.

### Upgrade

- Set `PCAP_TOKEN` in `.env` (a long random value), then
  `podman compose up -d --build`: the `pcap` image (about 400 MB) is built
  and migration `0016` runs.

## [2.16.0] - 2026-11-10

### Added

- **Previews of mail attachments.** Documents (PDF, Word, Excel, PowerPoint,
  OpenDocument, RTF, images) open as page images with **Preview**: a new
  `docview` worker converts Office formats to PDF with LibreOffice (fresh
  profile, macro security "very high", macros disabled, links never updated,
  90 s limit) and renders the first 20 pages with pdfium. It runs on the
  internal network only; the analyst's browser receives PNG images. Pages are
  cached and removed with the last message holding the attachment.
- **Isolated browser.** HTML attachments (**Open in isolated browser**) and
  links (Links view) run in Chromium inside a new `browser` worker; the
  analyst sees screenshots and clicks, types, scrolls, goes back and forward
  or types an address, replayed in the worker. Scripts never run in the
  analyst's browser.
  - **Network chosen per session**: none by default (only the attachment
    loads, every other request is refused and a navigation shows a "blocked
    by Nik" page); with network, http and https go out through the server,
    never to private addresses or internal names. Every session is audited
    with its choice.
  - Downloads refused and reported, dialogs dismissed and reported, new
    tabs shown in place; a session belongs to its analyst and closes after 5
    minutes idle (30 at most), at most `BROWSER_MAX_SESSIONS` (3) at once.
- API: `GET /api/previews/status`,
  `POST /api/mails/{sha256}/attachments/{path}/preview`,
  `POST /api/browser/sessions`, `POST /api/browser/sessions/{id}/action`,
  `DELETE /api/browser/sessions/{id}`.
- Compose: `docview` and `browser` services (read-only, no capabilities,
  memory / CPU limits, no published port); `browser` alone is on the new
  `browser-egress` network. Settings: `DOCVIEW_URL`/`DOCVIEW_TOKEN`,
  `BROWSER_URL`/`BROWSER_TOKEN`, `BROWSER_MAX_SESSIONS`, memory and CPU
  limits.

### Fixed

- The E2E test server could not restart when the sample store held a
  sub-directory.

### Upgrade

- Set `DOCVIEW_TOKEN` and `BROWSER_TOKEN` in `.env` (long random values), then
  `podman compose up -d --build`: the two new images are built (about 700 MB
  and 1 GB).

## [2.15.0] - 2026-11-10

### Added

- **Threat intelligence**: the reputation of indicators from VirusTotal,
  AbuseIPDB, abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AlienVault OTX,
  urlscan.io (search of public scans), GreyNoise Community, Shodan
  InternetDB and Google Safe Browsing. Each answer is reduced to a verdict
  (malicious, suspicious, harmless, unknown), a one-line summary and a link
  to the provider's page.
  - A **Reputation** column in the IOCs tab (worst verdict, how many
    providers flag the value) and an **External reputation** section in
    Where seen with every provider's answer and **Check now**.
  - **Automatic lookups**, off until turned on in Settings → Threat
    intelligence, per type: IP addresses, URLs and domains, file hashes.
    One API process works at a time (a lease), pacing each provider to its
    free tier; answers are cached 24 h by default (6 h to 30 days), errors
    retried after an hour, a provider answering 429 waits an hour.
  - **Never sent**, automatically or on request: private and reserved
    addresses, internal names and URLs on them, allowlisted values, values of
    incidents whose report is TLP:RED, e-mail addresses.
  - **API keys** entered by admins, stored encrypted (Fernet, key derived from
    `SECRET_KEY`), never returned by the API (only the last four characters).
    Providers can be turned off one by one.
- API: `GET /api/enrichment/providers`, `PUT/DELETE
  /api/enrichment/providers/{id}/key`, `GET /api/enrichment`,
  `POST /api/enrichment/check`; `reputation` on each indicator of
  `GET /api/incidents/{id}/iocs`; `enrichment` in the settings.
- `ENRICHMENT_WORKER` (default `true`) turns the background thread off.
- Migration `0015`: `ioc_enrichment`, `integration_keys`, `leases`.

### Dependencies

- Backend: `cryptography` listed directly (it was already installed with
  `oletools`). Requests use the standard library; `HTTPS_PROXY` applies.

## [2.14.0] - 2026-11-10

### Added

- **Mail Analysis** tab: phishing triage of reported messages, `.eml` or
  Outlook `.msg` (read with `olefile`, compressed RTF bodies included).
  - **Headers made readable**: the route (Received chain with the delay of
    each hop, clocks going back, the sending server), the sender and its
    mismatches (display name showing another address, Reply-To and
    Return-Path on other domains), every header searchable.
  - **SPF, DKIM and DMARC** checked by Nik through DNS (`pyspf`, `dkimpy`,
    `dnspython`, alignment from the Public Suffix List), next to the
    Authentication-Results of the receiving servers; only those of your own
    servers are believed. A DNS failure reads `temperror`, never a pass.
  - **Links** unwrapped from Microsoft Safe Links, Proofpoint, Google,
    Facebook and Barracuda redirects and judged: text showing another site,
    look-alikes of well-known brands and of your own domains (confusable
    characters, punycode, one-letter swaps), shorteners, IP hosts, `@` in the
    address, throwaway TLDs, pages on cloud services, forms.
  - **Body** in a sandboxed frame: the HTML is sanitised on the server
    (`nh3`), the frame runs no script and follows no link, and its
    Content-Security-Policy blocks every request; remote images load only
    after a warning, tracking pixels never. Hidden text is revealed; urgency,
    payment, credential and secrecy phrases (English and Italian) are listed.
    Text and source views too.
  - **Attachments** by their real type: executables in disguise, double
    extensions, right-to-left tricks, VBA/XLM macros (`oletools`), encrypted
    zip archives (the password is looked for in the message and tried),
    PDF actions, QR codes in images (`zxing-cpp`), calendar invitations;
    attached messages are analysed in turn. A hex view, a protected-zip
    download, and **Send to Malware Analysis**.
  - A **score and a verdict** (phishing ≥ 70, suspicious 40–69, no strong
    signs), each finding with its points.
- **Settings → Mail analysis**: your organisation's domains and your mail
  servers and gateways (Exchange Online, Google, Proofpoint, Mimecast…).
- E-mails in the **IOC index** (`mail:<file>`: sender, sending IP, links,
  attachment hashes, QR and invitation links), the **timeline** (high when the
  verdict is phishing), the **report** (an E-mails section) and the evidence
  appendix; a mail icon next to the incident in the sidebar.
- Dropping an `.eml` or `.msg` anywhere opens it in Mail Analysis.
- API: `POST /api/incidents/{id}/mails`, `GET /api/mails/{sha256}` (and
  `/reanalyse`, `/source`, `/attachments/{path}/bytes|download`),
  `POST /api/incidents/{id}/mails/{sha256}/attachments/{path}/sample`,
  `DELETE /api/incidents/{id}/mails/{sha256}`; `hasMail` in the light incident
  list; `mail` in the settings. Migration `0014` adds the `mails` table and
  `incidents.has_mail`.

### Changed

- The file type check recognises PNG, JPEG and GIF images.
- A sample sent from an e-mail records its origin in the incident and the
  audit log.

### Dependencies

- Backend: `dkimpy`, `pyspf`, `dnspython`, `publicsuffixlist`, `nh3`,
  `olefile`, `oletools`, `zxing-cpp` and `pillow` (already installed with
  WeasyPrint). No system package; the API needs DNS resolution.

## [2.13.0] - 2026-11-10

### Added

- **Ticket ID, short title and severity** for incidents. The name puts the
  ticket first in square brackets, then the short title when set (it
  replaces host and user): `[INC-2041] Invoice phishing, finance`. The
  severity (low, medium, high, critical) is a tag shown next to the name in
  the sidebar and the header, never part of it. Editable in the Summary tab;
  the light incident list, `?q=` and the search palette include the ticket
  (migration `0013` mirrors ticket and severity into columns).
- **Right-click menu** across the app: on indicators (where seen, search,
  copy, copy defanged, add to the allowlist), on event rows of Browser,
  Commands, Endpoint, Event Logs and Timeline (flag, comment, copy as text or
  JSON, show in the timeline) and on incidents in the sidebar (open, report,
  export, copy link, delete). Text fields, selected text and Shift +
  right-click keep the browser's menu.
- **One-click allowlist** from the IOCs tab (a shield button on each row) or
  the right-click menu: the value or a wider entry (its domain or a parent
  domain, its /24 network), with a comment line saying who added it, and
  Undo. Any analyst can do it.
- **Drop a file anywhere**: Nik recognises it from its first bytes and its
  name (executables, Office documents, PDF, scripts and archives, `.evtx` and
  the event-log JSON, browser databases and plists, shell histories, CSV) and
  asks, every time, whether it goes into the open incident or a new one, then
  imports it into the right tab and source.
- The incident report shows the ticket and the severity.


## [2.12.3] - 2026-11-10

### Fixed

- `deploy/upgrade-postgres.sh` could stop with "the new db container is not
  PostgreSQL 18": on a new volume the image creates the database with a
  temporary server that listens on the Unix socket only, and the script took
  it for the final one. Readiness is now checked over TCP. A run that stopped
  there (PostgreSQL 18 running with an empty database) is resumed: run the
  script again.

## [2.12.2] - 2026-11-10

### Changed

- **PostgreSQL 18** in the Compose file, on a new `db-data-18` volume.
  **Upgrading needs one manual step**: after `git pull`, before
  `compose up`, run `sudo deploy/upgrade-postgres.sh` (README § 2.1). It
  takes a full backup, moves the data with a dump and a restore, compares the
  row counts of every table and restarts the stack. The PostgreSQL 16
  `db-data` volume is left untouched for a rollback; remove it after 14 days.
  If `compose up` runs first, the `db` container refuses to create an empty
  database while the old data is unmoved (`deploy/db-entrypoint.sh`) and the
  script dumps the old volume with a temporary PostgreSQL 16.
- CI runs the backend suite on PostgreSQL 16 and 18 too, after
  `alembic upgrade head`.

## [2.12.1] - 2026-11-10

### Changed

- Frontend toolchain on its new major releases: **Vite 8** (Rolldown: the
  production build takes about 1.5 s instead of 13 s, and the main bundle
  shrinks from 427 kB to 335 kB) with `@vitejs/plugin-react` 6, **ESLint 10**
  (its scope analysis tracks JSX, so `eslint-plugin-react` is gone) and
  **lucide-react 1.x**. React 19.3, Tailwind 4.3.5, sql.js 1.16, elkjs 0.12.1.
  No visible change, except that Chrome's sub-tab icon is now an aperture
  (lucide dropped the brand logos).
- Local development needs Node.js 22 (or 20.19+), declared in `engines`.
- Dependabot's monthly grouped pull requests carry minor and patch releases
  only; major releases (PostgreSQL, Vite, ESLint, Node…) are planned as their
  own changes. CI builds and tests the frontend on Node 26, as the image does.

### Fixed

- Network errors keep the original error as their `cause`.
- The search palette's input is focused as it opens, so keys typed right after
  Ctrl/Cmd+K are not lost.

## [2.12.0] - 2026-11-10

### Added

- **Start on boot and nightly backups** with systemd:
  `deploy/install-systemd.sh` installs `nik.service` (`compose up -d` at
  boot, `down` at shutdown) and `nik-backup.timer`, which runs
  `deploy/backup.sh` every night. Each backup holds a `pg_dump` of the
  database, the sample store, the `.env` file and their SHA-256 sums, in a
  root-only directory; old backups are deleted after `--keep-days` (14 by
  default). README § 2.1 documents the restore.
- **Event Logs tab** (Windows). Raw `.evtx` files are uploaded and parsed on
  the server in a background job (the new `evtx` dependency, a Rust parser
  with prebuilt wheels), which also recovers records left in the file after a
  log clear and keeps the file's SHA-256; on a live host a native
  `Get-WinEvent` script exports the same events as JSON, parsed in the
  browser. About 50 curated event IDs are kept across Security, System,
  PowerShell, RDP, Defender, Task Scheduler and Sysmon. The tab shows a
  coverage chart per channel (silences of 6 h or more, clears, the
  suspicious window), logon sessions paired from 4624/4634/4672, and every
  event with a readable summary and its fields. A built-in `eventlog`
  ruleset flags log cleared, audit policy changed, services (high from user
  paths), suspicious PowerShell, brute force, a logon right after failures,
  RDP outside hours, new accounts, privileged group changes, Defender alerts
  and new scheduled tasks; command lines and script blocks also go through
  the command ruleset. Events join the Timeline and the `tail -f` panel.
  `POST /api/incidents/{id}/upload?tab=eventlogs` takes `.evtx` files from
  scripts too.
- **IOC correlation**. The server indexes the indicators of every tab — IP
  addresses, domains, URLs, e-mail addresses and MD5/SHA-1/SHA-256 digests
  from browser hosts and downloads, command lines, endpoint records, event
  logs and samples — in a new `ioc_index` table (migration `0011`) each time
  an incident's data is saved; existing incidents are indexed on the first
  start. A new **IOCs** tab lists them with the number of other incidents
  each one appears in; clicking a value (there, in a sample's indicators or
  in the Event Logs tab) opens **Where seen** across every analyst's
  incidents. A shared **IOC allowlist** in Settings (private ranges, common
  vendor and CDN domains to start) hides well-known values, and the
  indicators export as CSV, a STIX 2.1 bundle or a MISP event. New
  endpoints: `GET /api/incidents/{id}/iocs`, `/iocs/export`,
  `GET /api/iocs/lookup` and `/iocs/shared`.
- **Global search**: <kbd>Ctrl</kbd>/<kbd>Cmd</kbd>+<kbd>K</kbd> (or <kbd>/</kbd>
  outside a text field, or the header's *search…* button) opens a `nik>`
  prompt over incidents, indicators from every incident and samples (new
  `GET /api/search`), plus the open incident's events, notes and samples.
  A query starting with `>` lists actions: go to a tab, new incident,
  export, `tail -f` panel, settings, IOC allowlist, sign out. On PostgreSQL
  migration `0012` adds `pg_trgm` indexes for the substring matches.
- **Incident report**, built by the server as a printable HTML page or a
  **PDF** (WeasyPrint): executive summary and key facts, flagged events with
  comments, MITRE ATT&CK techniques from capa, YARA (`mitre_attack` meta,
  now on the built-in rules) and the SOC rules that matched (each built-in
  rule names its techniques), indicators outside the allowlist, samples,
  event-log coverage and clears, notes, and an evidence appendix listing
  every imported file with its SHA-256. TLP classification, English or
  Italian (default English), sections to include; the options and the
  summary are saved with the incident. The organisation name and logo come
  from the new Settings → **Report header**. Opened from the header's report
  button or the search palette; `POST /api/incidents/{id}/report` serves the
  same to API clients.
- Imported browser, shell-history, endpoint and event-log JSON files are
  hashed (SHA-256) in the browser and the digest is kept with the import
  metadata, for the report's evidence appendix.
- **Dependency audits** in a new `Audit` workflow, on every pull request and
  every Monday: `pip-audit` (backend, capa worker), `npm audit` and
  `shellcheck`. **Dependabot** opens grouped monthly update pull requests
  (at most one per ecosystem) and immediate security updates.

### Changed

- The backend image installs Pango, HarfBuzz and the DejaVu fonts for
  WeasyPrint (about 80 MB larger); CI installs Pango for the backend tests.

### Security

- `pyzipper` 0.4.0 (PYSEC-2026-3044): the password-protected sample zips use
  AE-2 and no longer carry the plaintext CRC32 of the sample in the header.

## [2.11.2] - 2026-11-10

### Fixed

- Samples first stored by a release before 2.7.0 (mode `0440`) could not be
  read by the analyzer and capa workers, which run as another user: the Code
  view said "rizin stopped unexpectedly" and Capabilities "capa failed: 13".
  The api now gives every stored sample mode `0444` at startup and whenever
  a known sample is uploaded again (the file was previously left untouched).
- Both workers check that the sample is readable before starting rizin or
  capa and say so plainly ("cannot read the sample (permission denied)")
  instead of reporting a crash or an exit code.

## [2.11.1] - 2026-11-10

### Fixed

- `podman compose up --build` on RHEL: every image is now named with its
  registry (`docker.io/rizin/rizin`, `docker.io/library/python`, `node`,
  `nginx`, `postgres`). Podman resolved the short names through
  `/etc/containers/registries.conf`, tried `registry.redhat.io` first and
  failed asking for Red Hat credentials. A test keeps every `FROM` and
  Compose `image` fully qualified.
- The capa worker no longer needs a tmpfs with `uid` / `gid` options, which
  Podman rejects (`unknown mount option "uid=1000"`): the image sets
  `HOME=/tmp`, so capa's rule cache and vivisect's settings live in the plain
  `/tmp` tmpfs of the read-only container.

## [2.11.0] - 2026-11-10

### Added

- **capa rules of your own** (Settings → capa rules, admin): one YAML rule
  each, checked by the capa worker against the bundled rules and the other
  admin rules before it is saved (syntax, features, unique name, `match:`
  dependencies), then matched with the bundled set from the next analysis.
  Their matches carry a **custom** badge in the Capabilities view; a rule
  another enabled rule matches cannot be renamed, disabled or deleted.
  REST API: `GET/POST /api/capa-rules`, `PUT/DELETE /api/capa-rules/{id}`,
  `POST /api/capa-rules/validate`; capa worker: `POST /validate`.
- rizin worker settings `ANALYZER_MAX_FUNCTIONS` (default 20000),
  `ANALYZER_WARM_SESSIONS` (default 1) and `ANALYZER_WARM_IDLE` (default
  600 s).

### Changed

- The Code view lists **every function** of large binaries: the 3,000-function
  limit is gone (a 5,000-function Rust binary is disassembled in about 75 s;
  20,000 remains as a safety cap). Each function's control-flow graph and
  pseudo-C are stored as a row of the new `sample_functions` table instead of
  two JSON columns read in full on every request, so opening a function stays
  fast however large the binary (Alembic migration
  `0010_function_rows_capa_rules` moves existing data).
- **Decompiling on demand takes seconds**: the rizin worker keeps the
  analysed session open after an analysis or a decompilation (0.1–3 s instead
  of 13 s and more on a 5,000-function binary) and falls back to a fresh one
  if rizin died meanwhile. The up-front pass decompiles the functions not
  recognised as library code before the others. The Compose default memory
  limit of the `analyzer` service rises from 2g to 4g to hold the kept
  session.
- Passwords are hashed with **bcrypt directly**; the unmaintained passlib is
  removed and bcrypt is no longer pinned below 4.1. Existing hashes keep
  working (the same `$2b$` format, passwords cut at 72 bytes as before).

## [2.10.0] - 2026-11-10

### Added

- **Capabilities** view for malware samples: what the code can do according
  to [Mandiant capa](https://github.com/mandiant/capa) (send data on a
  socket, create a process, encrypt with RC4, resolve APIs at runtime…),
  grouped by namespace and mapped to MITRE ATT&CK and the Malware Behavior
  Catalog, with links to the Code view functions where each capability was
  found.
- **capa worker** (`capa/`): capa 10.0.0 with its rules and library
  signatures pinned and checksum-verified, in its own container with the
  same isolation as the rizin worker (read-only sample store and
  filesystem, internal network only, no capabilities, memory / CPU / time
  limits). It runs after upload and Re-analyse, for x86 / x64 PE and ELF
  files, one sample at a time; other file types are reported as
  unsupported.
- The Code view shows the capabilities of each function, and **Start here**
  ranks unrecognised functions with capabilities higher. Capabilities do not
  change a sample's severity.
- Configuration: `CAPA_URL`, `CAPA_TOKEN`, `CAPA_TIMEOUT` (backend),
  `CAPA_TOKEN`, `CAPA_TIMEOUT`, `CAPA_MEMORY`, `CAPA_CPUS` (Compose).
- REST API: `GET/POST /api/samples/{sha256}/capabilities`. Alembic
  migration `0009_sample_capa`.

## [2.9.0] - 2026-11-10

### Added

- **Function triage** in the Code view. Each function gets an origin:
  *library* (matched by a FLIRT signature, or, in Rust binaries, credited to
  the crate whose sources its panic locations name), *runtime*, *thunk* or
  *not recognised*. **Hide recognised library code** is on by default; the
  Rust crates found in the binary are listed above the table.
- **Start here**: the unrecognised functions most worth reading first, with
  the reasons (suspicious APIs called directly, indicators used, suspicious
  APIs reached through callees, complexity).
- The analyzer worker reports the strings each function references. The
  Code view lists a function's **strings used** with their indicators, and
  the IOC table gains a **Used by** column that opens the function.
- Analysts **rename and comment functions**. Annotations belong to the
  sample (every incident holding the same file sees them), replace rizin's
  names in the list, the graphs and the pseudo-C, and are audited
  (`sample.annotate`).
- **Settings → FLIRT signatures** (admin): upload `.sig` or `.pat` files
  that the worker applies on top of rizin's bundled signatures from the next
  disassembly.
- REST API: `GET /api/samples/{sha256}/annotations`,
  `PUT /api/samples/{sha256}/annotations/{addr}`,
  `GET/POST /api/flirt-signatures`, `PUT/DELETE /api/flirt-signatures/{id}`.
  Worker: `/analyze` and `/decompile` accept `signatures`. Alembic migration
  `0008_annotations_flirt`.

## [2.8.1] - 2026-11-09

### Fixed

- Switching functions in the Code view with the call graph or the
  control-flow graph open could blank the whole application ("can't access
  property 'hot'"): the new graph was drawn for a moment with the previous
  function's layout. A layout is now used only for the graph it was computed
  for, and edges are matched by id.

### Added

- A rendering error in one view no longer takes the whole application down:
  each analysis tab, and each panel of the Code view, shows what went wrong
  with a button to reload it, while the rest of Nik keeps working.

## [2.8.0] - 2026-11-09

### Added

- **Decompiled** panel in the Code view: the pseudo-C of the selected
  function from rz-ghidra (Ghidra's decompiler, shipped as a rizin plugin in
  the official image the analyzer worker already uses), with the decompiler's
  highlighting, line numbers, a copy button, links from each call to the
  called function, and calls to suspicious APIs in red.
- The analysis decompiles functions up front within
  `ANALYZER_DECOMPILE_SECONDS` (default 300; entry point and `main` first,
  then the smallest); the others are decompiled the first time they are
  opened and kept. A function that takes over 30 s is skipped.
- REST API: `GET /api/samples/{sha256}/code/functions/{addr}/decompiled`.
  Worker: `POST /decompile`. Alembic migration `0007_sample_code_decompiled`.

### Changed

- The CFGs and the pseudo-C of a sample are loaded only when one function is
  asked for, not with the function list.
- Line endings are LF in every checkout (`.gitattributes`), so formatting
  checks pass on Windows too.

### Fixed

- The analyzer worker survives rizin crashes: rizin 0.9 can segfault after
  thousands of commands in one session (seen on a 5 MB binary), which used to
  lose the whole analysis. The worker now reopens the sample, retries the
  function once and skips it if it crashes again, up to three restarts.
- A function without basic blocks no longer leaves the Control flow panel
  waiting forever.

## [2.7.0] - 2026-11-09

### Added

- **Code view** in the Malware Analysis tab: disassembly by a new rizin
  worker. Functions with address, basic blocks and the suspicious APIs they
  reach (malware ruleset, propagated through the call graph), flaggable; the
  **call graph** around the selected function and its **control-flow graph**
  with full disassembly per block, true / false / jump edges and loops,
  laid out with `elkjs` (layered, orthogonal routing) and drawn in SVG with
  pan, zoom, minimap and selection.
- **Analyzer worker** (`analyzer/`): a container on the official
  `rizin/rizin:v0.9.1` image with a small standard-library HTTP front
  (`POST /analyze`, `GET /health`), a shared token, a per-sample time limit
  and a cap on concurrent jobs. In Compose it reads the sample store
  read-only, runs as a non-root user on a read-only filesystem without
  capabilities, with memory / CPU limits and no route outside the internal
  network.
- Disassembly runs in the background after each upload and Re-analyse, or on
  demand. REST API: `GET/POST /api/samples/{sha256}/code` and
  `GET /api/samples/{sha256}/code/functions/{addr}`; audit action
  `sample.disassemble`.
- Configuration: `ANALYZER_URL`, `ANALYZER_TOKEN`, `ANALYZER_TIMEOUT`
  (backend); `ANALYZER_TOKEN`, `ANALYZER_TIMEOUT`, `ANALYZER_MEMORY`,
  `ANALYZER_CPUS` (Compose). Alembic migration `0006_sample_code`. New
  frontend dependency `elkjs` (EPL-2.0 / GPL-3.0, loaded on demand).
- CI builds the worker image and runs the end-to-end test against real
  rizin output; the worker has its own lint and tests.

### Changed

- Stored samples are world-readable (`0444`, still never executable) so the
  worker, running as another user, can read them through its read-only mount.
- `DataTable` rows can be selectable (`onRowClick`).

### Fixed

- The sample figures use the red / amber tones they were meant to (entropy
  above 7.0, high / medium indicators); "nothing above 7.0" replaces a dash.

## [2.6.0] - 2026-11-09

### Added

- Executable structure in the Malware Analysis tab (**Structure** view): PE
  (machine, subsystem, compile time, entry point, sections with entropy and
  flags, imports by library, exports, resources, **imphash**, Authenticode
  presence, rich header, PDB path, checksum) via `pefile`; ELF (type, machine,
  interpreter, segments, sections, needed libraries) and Mach-O (CPU, load
  commands, dylibs, rpaths, code signature, encryption, universal slices)
  with Nik's own parsers. Malformed headers become warnings, never errors.
- **YARA** scanning on upload and on re-analysis (`yara-python`): a built-in
  rule set (`backend/app/yara/`) plus admin-managed rule sets in
  Settings → YARA rules (validated before saving, enable / disable, edit,
  delete). Matches show rule, severity and description in the sample's
  **YARA** view and raise the sample's severity.
- **Re-analyse** on a sample: runs the current engine and rules again on the
  stored file; samples analysed by an older engine show a notice.
- REST API: `POST /api/samples/{sha256}/reanalyse`; `GET/POST/PUT/DELETE
  /api/yara-rules` and `POST /api/yara-rules/validate` (admin). Audit actions
  `sample.reanalyse`, `yara.add`, `yara.update`, `yara.delete`.
- Configuration: `YARA_RULES` (directory of the built-in rule files). Alembic
  migration `0005_yara_rules`. New backend dependencies `pefile` and
  `yara-python` (the wheel bundles libyara).

## [2.5.0] - 2026-11-09

### Added

- **Malware Analysis** tab: drop suspicious files to store them on the Nik
  server (named by SHA-256, never executed) and analyse them statically:
  MD5 / SHA-1 / SHA-256 / SHA-512, file type from magic bytes (PE, ELF,
  Mach-O, PDF, archives, scripts…), entropy overall and per 64 KB block with a
  chart, printable strings (ASCII and UTF-16, the first 5,000 stored, the
  whole file searchable on demand) and indicators of compromise (URLs,
  domains, IPs, e-mails, registry keys, paths, Windows APIs) that can be
  flagged like any other event. Hashes link to VirusTotal and MalwareBazaar.
- Built-in **malware ruleset** for the SOC engine (process injection,
  anti-analysis, persistence, C2 patterns, encoded PowerShell, throwaway TLDs,
  ransomware hints, credential access), listed in Settings → Detection rules.
- Samples enter the Timeline and the `tail -f` panel at their import time.
- REST API: `POST /api/incidents/{id}/samples`, `GET /api/samples/{sha256}`,
  `GET /api/samples/{sha256}/strings`, `GET /api/samples/{sha256}/download`
  (AES zip, password `infected` or a custom one) and
  `DELETE /api/incidents/{id}/samples/{sha256}`; uploads, downloads and
  removals are recorded in the audit log.
- Configuration: `SAMPLE_STORE` (directory of the raw files) and
  `SAMPLE_MAX_MB` (default 100); the Compose stack keeps the store on a named
  volume. Alembic migration `0004_samples`. New backend dependency
  `pyzipper` for writing encrypted archives.

## [2.4.0] - 2026-11-09

### Added

- End-to-end smoke test on Playwright (`npm run test:e2e`), run in CI after the
  unit suites: first-run setup, sign-in, a new incident, demo data in every
  tab, the timeline and the `tail -f` panel against the real backend and the
  production build.
- Documentation site in `docs/` for GitHub Pages (plain HTML, one stylesheet,
  no build step): overview, installation, usage, configuration, API reference
  and release notes.
- Prettier (`npm run format`, `npm run format:check`) for JS/JSX, CSS, JSON,
  HTML and YAML, and `ruff format` for the backend; CI checks both. The whole
  code base was reformatted once in this release, with no behaviour change.

### Changed

- Large browser histories (hundreds of thousands of visits) stay responsive:
  each URL is parsed once per event and reused by the stat cards, the ranking
  widgets and the table cells; text columns sort with a shared collator (a
  300k-row sort drops from seconds to a fraction of a second); the table
  search no longer blocks typing; toggling a flag no longer rebuilds the
  Timeline tab or the tail panel.

### Security

- Updated the frontend build dependencies flagged by `npm audit` (Vite 6.4.6,
  PostCSS, nanoid, browserslist, source-map-js): no vulnerabilities reported.
  These are development-time tools; the shipped bundle was not affected.

## [2.3.1] - 2026-11-09

### Added

- ESLint (`npm run lint`, React and hooks rules) for the frontend and Ruff
  (`ruff check .`, `backend/ruff.toml`) for the backend; CI runs both.

### Fixed

- The Events, Commands, Artifacts and Timeline tabs no longer recompute their
  memoized rows on every render when an incident has no flags.
- Backend errors re-raised as HTTP or validation errors keep their original
  cause (exception chaining).
- Removed unused parameters, variables, imports and lint suppressions.

## [2.3.0] - 2026-11-06

### Added

- `tail -f` side panel: the latest 60 timestamped events of the open incident
  (browser, commands, endpoint), newest at the bottom, with source, severity
  and flags. Toggled from the tab bar on wide screens, remembered per tab and
  open on Summary by default.

### Changed

- Terminal look, step 2: Summary, Browser Forensics (profiles, upload zones,
  events, bookmarks, shortcuts, widgets), Command History, Endpoint
  Artifacts, Timeline, Network Logs, Settings (rules, business hours,
  accounts, API keys, audit log) and Full backup use the design tokens.
- Analyst flags use the green accent and SOC rows their severity colour, so a
  flag never looks like a detection.
- The Summary counters wrap to two rows of three below very wide screens.

### Removed

- The `dark:` Tailwind variant and the `dark` class on `<html>`: no
  component uses them any more.

## [2.2.0] - 2026-11-06

### Added

- Terminal look, step 1: named colour tokens in `src/index.css` (surfaces,
  text, green accent, HIGH/MED severities…) used by the UI kit and the
  application shell.
- Bundled fonts: Inter and JetBrains Mono (woff2, OFL-1.1), no CDN.
  JetBrains Mono covers the block and box-drawing characters, so the ASCII
  skull and banners render without fallback fonts.
- Sign-in and first-run screens with the NIK banner and a `$ nik status` box
  showing the real API and database status (public health endpoints).

### Changed

- The UI kit (buttons, cards, badges, modals, tables, inputs, stat cards,
  empty states), the sidebar, header, tab bar and OS picker use the terminal
  look: square corners, monospace labels, green accent.
- The header shows the incident as `host / user` with its OS.
- `index.html` is in English (`lang="en"`) and has a terminal favicon.

### Removed

- The light theme and its toggle: Nik is dark only. `ThemeContext` and the
  `nik:theme` local-storage preference are gone.

## [2.1.0] - 2026-11-06

### Added

- ASCII skull loaders: a symmetric skull drawn in text characters, generated
  at any size by `src/utils/asciiSkull.js` and rendered by the new
  `AsciiSkull` / `MicroSkull` UI components (presets block, large, medium,
  small; eyes that look around and blink, closed, or crossed out).
- Opening an incident shows the block skull with the real download progress
  (percentage and megabytes, from the response's Content-Length) and a Cancel
  button that returns to no incident.
- `EmptyState` accepts an `illustration` in place of its icon.

### Changed

- Loading a tab, a failed incident load (eyes crossed out), the "no active
  incident" state (asleep) and file parsing in the upload zones now use the
  skull; connecting, loading the incident list, an unreachable server and
  busy buttons (backup export/restore, API key creation, incident export) use
  the inline micro skull.
- Skulls stay still when the operating system asks to reduce motion.

### Removed

- The `Spinner` UI component, replaced everywhere by the skulls.

## [2.0.0] - 2026-11-04

### Added

- Several profiles per browser (Chrome "Default", "Profile 1", "Work", …):
  add, rename and delete them in Browser Forensics; each profile has its own
  files and data, and the browser badge sums all profiles.
- Timeline and flags name the profile ("Chrome · Work") when a browser has
  more than one; flags on a deleted profile are kept and marked as such.
- `profile` query parameter on `POST /api/incidents/{id}/upload` (profile
  name, case-insensitive, created if missing; default `Default`) and a
  `profile` argument on the Cortex XSOAR `nik-upload-artifact` command.
- Alembic migration `0003_browser_profiles`, moving existing browser data
  into a "Default" profile.

### Changed

- **BREAKING:** an incident's browser data is now
  `data.browser.browsers[<id>] = { activeProfile, profiles: { <profileId>:
  { id, name, createdAt, history, downloads, bookmarks, shortcuts, meta } } }`
  instead of the artifact lists directly under `browsers[<id>]`. API clients
  reading `data.browser` must follow the new shape.
- **BREAKING:** the upload response `target` is now
  `browser/<id>/<profile>/<source>` and includes `profileId`.
- Path hints show `<profile>` in place of the Chromium/Firefox profile folder.
- Incident exports are envelope version 4; versions 3 and older still import.
- Creating, patching, fetching and restoring incidents convert any pre-2.0.0
  browser data, so old exports, backups and clients keep working.

### Upgrade notes

Back up, then run `alembic upgrade head` (automatic in the Docker image): the
migration rewrites every incident once, which can take a while on large
databases.

## [1.2.0] - 2026-11-04

### Added

- Safari in Browser Forensics (macOS only): `History.db` (browsing history
  with redirect chains), `Downloads.plist` and `Bookmarks.plist` (Favorites,
  folders and Reading List, with the date each item was added).
- A dependency-free property list parser for the browser, reading both binary
  (`bplist00`) and XML plists.
- Browser registry `platforms` field: the "where to find files" note warns
  when a browser does not exist on the incident's host OS.
- Safari uploads through the REST API (`browser=safari`, `source` =
  `history` / `downloads` / `bookmarks`).

## [1.1.0] - 2026-11-04

### Added

- `GET /api/incidents/{id}` answers `304 Not Modified` to a matching
  `If-None-Match`, checking only the version column (not the document body).
- `PATCH /api/incidents/{id}` accepts `Content-Type: application/merge-patch+json`
  (RFC 7396): nested members are merged and `null` removes one, so a client
  can send only what changed. Plain `application/json` keeps its behaviour.
- `os` in the `view=summary` incident listing, stored in a new `incidents.os`
  column (Alembic migration `0002_incident_os_column` backfills it).
- Frontend unit tests on Node's built-in test runner (`npm test`), run in CI.

### Changed

- Opening Nik downloads only the light incident list. An incident's artifacts
  are fetched when it is opened, behind a non-blocking loading state (the
  sidebar stays usable; switching incident cancels the pending download), and
  stay cached for the session with ETag revalidation on reopen.
- Every edit (flags, notes, uploads, metadata) sends only the changed part of
  the incident as a merge patch instead of the whole `data` blob.
- Exporting an incident that was not opened yet fetches it first.

### Fixed

- The backend test fixture resets the rate limiter between tests, so the
  login limit no longer makes the suite fail as it grows.

## 1.0.0 - 2026-07-11

### Added

- First release of Nik: forensic analysis platform with browser, command
  history and endpoint artifact analysis, a super-timeline, SOC detection
  rules, case management, full backup, authentication and audit, and the
  external REST API.

[Unreleased]: https://github.com/n36l3c7/Nik/compare/v2.17.0...HEAD
[2.17.0]: https://github.com/n36l3c7/Nik/compare/v2.16.0...v2.17.0
[2.16.0]: https://github.com/n36l3c7/Nik/compare/v2.15.0...v2.16.0
[2.15.0]: https://github.com/n36l3c7/Nik/compare/v2.14.0...v2.15.0
[2.14.0]: https://github.com/n36l3c7/Nik/compare/v2.13.0...v2.14.0
[2.13.0]: https://github.com/n36l3c7/Nik/compare/v2.12.3...v2.13.0
[2.12.3]: https://github.com/n36l3c7/Nik/compare/v2.12.2...v2.12.3
[2.12.2]: https://github.com/n36l3c7/Nik/compare/v2.12.1...v2.12.2
[2.12.1]: https://github.com/n36l3c7/Nik/compare/v2.12.0...v2.12.1
[2.12.0]: https://github.com/n36l3c7/Nik/compare/v2.11.2...v2.12.0
[2.11.2]: https://github.com/n36l3c7/Nik/compare/v2.11.1...v2.11.2
[2.11.1]: https://github.com/n36l3c7/Nik/compare/v2.11.0...v2.11.1
[2.11.0]: https://github.com/n36l3c7/Nik/compare/v2.10.0...v2.11.0
[2.10.0]: https://github.com/n36l3c7/Nik/compare/v2.9.0...v2.10.0
[2.9.0]: https://github.com/n36l3c7/Nik/compare/v2.8.1...v2.9.0
[2.8.1]: https://github.com/n36l3c7/Nik/compare/v2.8.0...v2.8.1
[2.8.0]: https://github.com/n36l3c7/Nik/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/n36l3c7/Nik/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/n36l3c7/Nik/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/n36l3c7/Nik/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/n36l3c7/Nik/compare/v2.3.1...v2.4.0
[2.3.1]: https://github.com/n36l3c7/Nik/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/n36l3c7/Nik/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/n36l3c7/Nik/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/n36l3c7/Nik/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/n36l3c7/Nik/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/n36l3c7/Nik/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/n36l3c7/Nik/releases/tag/v1.1.0
